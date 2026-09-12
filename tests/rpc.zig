//! RPC integration tests: the full client stack — `rpc.Client` over the
//! encrypted session over TCP-full — against an in-process test server on
//! real loopback sockets.
//!
//! The choreography follows `tests/message_session.zig`: client and server
//! alternate strictly on one thread, so blocking one-shot helpers are
//! exercised as their `send`/`wait` halves (the wait pump reads the reply
//! the server already buffered; `invoke`/`call` are those halves joined).
//! The server independently validates every client→server rule and stamps
//! real-clock ids (the client checks the ±30/300 s receive window), and
//! answers with `rpc_result` payloads — plain objects, `rpc_error`,
//! `gzip_packed` (spec-correct stored-block gzip members) — singly or
//! packed in one container.

const std = @import("std");
const net = std.Io.net;
const td = @import("td");

const message = td.mtproto.message;
const Writer = td.tl.Writer;
const TcpFull = td.transport.TcpFull;
const tcp_full = td.transport.tcp_full;
const Client = td.rpc.Client;
const api = td.api;

// Shared authorization key (varied bytes so the per-direction auth_key
// windows genuinely differ).
const auth_key = blk: {
    var k: [256]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 97 +% 5);
    break :blk k;
};

fn startServer(io: std.Io) !net.Server {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    return addr.listen(io, .{ .reuse_address = true });
}

fn writeAllRaw(io: std.Io, stream: *net.Stream, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, &.{bytes[sent..]}, 1);
        sent += n;
    }
}

fn readExactRaw(io: std.Io, stream: *net.Stream, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        var iovec = [1][]u8{buf[got..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &iovec);
        if (n == 0) return error.EndOfStream;
        got += n;
    }
}

fn serverReadFrame(io: std.Io, stream: *net.Stream, arena: std.mem.Allocator) ![]u8 {
    var h: [8]u8 = undefined;
    try readExactRaw(io, stream, &h);
    const parsed = tcp_full.Codec.parseHeader(&h);
    if (parsed.length < tcp_full.frame_overhead) return error.BadFrame;
    const payload = try arena.alloc(u8, parsed.length - tcp_full.frame_overhead);
    try readExactRaw(io, stream, payload);
    var trailer: [4]u8 = undefined;
    try readExactRaw(io, stream, &trailer);
    if (tcp_full.Codec.checksum(&h, payload) != std.mem.readInt(u32, &trailer, .little))
        return error.BadFrame;
    return payload;
}

/// Sends header+payload+trailer as one vectored write: three separate
/// small writes interact with Nagle + delayed ACK into ~40 ms stalls on
/// a request/response exchange.
fn sendFrameRaw(io: std.Io, stream: *net.Stream, h: []const u8, payload: []const u8, trailer: []const u8) !void {
    const parts = [3][]const u8{ h, payload, trailer };
    const total = h.len + payload.len + trailer.len;
    var sent: usize = 0;
    while (sent < total) {
        var iovecs: [3][]const u8 = undefined;
        var n_iov: usize = 0;
        var idx: usize = 0;
        var off: usize = sent;
        while (idx < parts.len) : (idx += 1) {
            if (off >= parts[idx].len) {
                off -= parts[idx].len;
                continue;
            }
            iovecs[n_iov] = parts[idx][off..];
            n_iov += 1;
            off = 0;
        }
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, iovecs[0..n_iov], 1);
        if (n == 0) return error.IoFailed;
        sent += n;
    }
}

fn serverSendFrame(io: std.Io, stream: *net.Stream, payload: []const u8, out_seq: *u32) !void {
    const h = tcp_full.Codec.header(payload.len, out_seq.*);
    const crc = tcp_full.Codec.checksum(&h, payload);
    var trailer: [4]u8 = undefined;
    std.mem.writeInt(u32, &trailer, crc, .little);
    try sendFrameRaw(io, stream, &h, payload, &trailer);
    out_seq.* += 1;
}

/// Server msg_id base from the real clock — the client validates the
/// receive window, so ids must track real time (unlike the fixed clock
/// tests/message_session.zig can use).
fn nowBase(io: std.Io) i64 {
    const s = @divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s);
    return @as(i64, @intCast(s)) << 32;
}

/// Minimal MTProto peer with rpc answering helpers.
const TestServer = struct {
    salt: i64 = 0x51a1,
    session_id: i64,
    next_low: u32 = 1,
    content: u32 = 0,
    last_client_id: i64 = 0,
    client_content: u32 = 0,
    out_seq: u32 = 0,
    /// msg_id of the most recent frame produced by `frame`.
    last_sent_id: i64 = 0,

    fn send(self: *TestServer, io: std.Io, stream: *net.Stream, payload: []const u8) !void {
        try serverSendFrame(io, stream, payload, &self.out_seq);
    }

    fn nextMsgId(self: *TestServer, io: std.Io) i64 {
        const id = nowBase(io) | self.next_low;
        self.next_low += 4;
        return id;
    }

    fn nextSeqNo(self: *TestServer, content_related: bool) i32 {
        const seq: i32 = @intCast(2 * self.content + @as(u32, if (content_related) 1 else 0));
        if (content_related) self.content += 1;
        return seq;
    }

    /// One encrypted server frame carrying `body`.
    fn frame(self: *TestServer, io: std.Io, arena: std.mem.Allocator, content_related: bool, body: []const u8) ![]u8 {
        var prng = std.Random.DefaultPrng.init(0xabc);
        const buf = try arena.alloc(u8, message.frameLength(body.len));
        const id = self.nextMsgId(io);
        self.last_sent_id = id;
        try message.writeEncrypted(&auth_key, .server_to_client, .{
            .salt = self.salt,
            .session_id = self.session_id,
            .msg_id = id,
            .seq_no = self.nextSeqNo(content_related),
            .body = body,
        }, prng.random(), buf);
        return buf;
    }

    /// `rpc_result#f35c6d01 req_msg_id:long result:Object` body.
    fn rpcResult(arena: std.mem.Allocator, req_msg_id: i64, result: []const u8) ![]const u8 {
        var w = Writer.init(arena);
        try w.writeConstructorId(message.rpc_result_id);
        try w.writeLong(req_msg_id);
        try w.writeRaw(result);
        return w.items();
    }

    /// One content-related frame answering `req_msg_id` with `result`.
    fn replyRpc(self: *TestServer, io: std.Io, stream: *net.Stream, arena: std.mem.Allocator, req_msg_id: i64, result: []const u8) !void {
        try self.send(io, stream, try self.frame(io, arena, true, try rpcResult(arena, req_msg_id, result)));
    }

    const View = struct {
        dec: message.Decrypted,
        count: usize,
        inner: []message.Incoming,
    };

    /// Reads, decrypts and validates one client frame. Returns the
    /// envelope plus container entries (when the client containered).
    fn read(self: *TestServer, io: std.Io, stream: *net.Stream, arena: std.mem.Allocator, out: []message.Incoming) !View {
        const payload = try serverReadFrame(io, stream, arena);
        const dec = try message.readEncrypted(&auth_key, .client_to_server, self.session_id, payload);

        if (!message.isValidClientMsgId(dec.msg_id)) return error.BadClientId;
        if (dec.msg_id <= self.last_client_id) return error.ClientIdOutOfOrder;

        var count: usize = 0;
        if (dec.body.len >= 4 and std.mem.readInt(u32, dec.body[0..4], .little) == message.msg_container_id) {
            count = try message.readContainer(dec.body, out);
            var prev: i64 = 0;
            var c = self.client_content;
            for (out[0..count]) |m| {
                if (!message.isValidClientMsgId(m.msg_id)) return error.BadClientId;
                if (m.msg_id <= prev or m.msg_id >= dec.msg_id) return error.BadContainerIds;
                prev = m.msg_id;
                if (try checkSeq(c, m.seq_no)) c += 1;
            }
            if (try checkSeq(c, dec.seq_no)) return error.ContainerNotService;
            self.client_content = c;
        } else {
            if (try checkSeq(self.client_content, dec.seq_no)) self.client_content += 1;
        }
        self.last_client_id = dec.msg_id;
        return .{ .dec = dec, .count = count, .inner = out[0..count] };
    }
};

fn checkSeq(base: u32, seq_no: i32) !bool {
    const content = message.isContentRelated(seq_no);
    const expected: i32 = @intCast(2 * base + @as(u32, if (content) 1 else 0));
    if (seq_no != expected) return error.BadSeqNo;
    return content;
}

/// One client + server pair on a fresh loopback connection. `tcp_storage`
/// and `ts_storage` are caller-provided so the borrowed transport and the
/// server state outlive the pair.
const Pair = struct {
    client: Client,
    tcp: *TcpFull,
    server: net.Server,
    srv: net.Stream,
    ts: *TestServer,

    fn deinitPair(self: *Pair, io: std.Io) void {
        self.client.deinit();
        self.srv.close(io);
        self.server.deinit(io);
        self.tcp.close(io);
    }
};

// The RNG backs the client's session ids and frame padding; it must
// outlive every pair.
var pair_prng = std.Random.DefaultPrng.init(7);

fn makePair(
    io: std.Io,
    tcp_storage: *TcpFull,
    ts_storage: *TestServer,
    tcp_opts: tcp_full.Options,
    rpc_opts: td.rpc.Options,
) !Pair {
    // Bound idle reads: a blocking driver readv cannot be interrupted by
    // the pump budget, only by the transport's own read timeout.
    var topts = tcp_opts;
    if (topts.read_timeout == null) topts.read_timeout = std.Io.Duration.fromMilliseconds(100);
    var server = try startServer(io);
    errdefer server.deinit(io);

    tcp_storage.* = TcpFull.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        topts,
    );
    try tcp_storage.connect(io);
    errdefer tcp_storage.close(io);

    var srv = try server.accept(io);
    errdefer srv.close(io);

    const client = try Client.init(
        std.testing.allocator,
        tcp_storage.transport(),
        &auth_key,
        0x51a1,
        pair_prng.random(),
        rpc_opts,
    );
    ts_storage.* = .{ .session_id = client.session.session_id };
    return .{
        .client = client,
        .tcp = tcp_storage,
        .server = server,
        .srv = srv,
        .ts = ts_storage,
    };
}

/// A request struct shaped like a generated function: carries the `Result`
/// decl `invoke` resolves. Body: ctor id + one i32.
const TestRequest = struct {
    pub const Result = api.Bool;

    query_id: i32,

    pub fn serialize(self: *const TestRequest, w: *Writer) td.TlError!void {
        try w.writeConstructorId(0x0d91a548);
        try w.writeInt(self.query_id);
    }
};

const bool_true_bytes = [_]u8{ 0xb5, 0x75, 0x72, 0x99 }; // boolTrue#997275b5 LE
const bool_false_bytes = [_]u8{ 0x37, 0x97, 0x79, 0xbc }; // boolFalse#bc799737 LE

test "typed request roundtrip with acknowledgement" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    // Typed send: the request serializes through the generic path.
    const h = try client.send(io, TestRequest{ .query_id = 7 });

    // Server: one content-related query, correct ctor, correct body.
    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);
    try std.testing.expectEqual(@as(i32, 1), view.dec.seq_no);
    try std.testing.expectEqual(@as(u32, 0x0d91a548), std.mem.readInt(u32, view.dec.body[0..4], .little));
    try std.testing.expectEqual(@as(i32, 7), std.mem.readInt(i32, view.dec.body[4..8], .little));

    ts.replyRpc(io, &pair.srv, arena, view.dec.msg_id, &bool_true_bytes) catch return error.TestUnexpectedResult;
    const reply1_id = ts.last_sent_id;

    var res = try client.wait(io, h);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);

    // The rpc_result was content-related: the client must have
    // acknowledged it while pumping.
    const ack_view = try ts.read(io, &pair.srv, arena, &out);
    var ack_body = try message.parseServiceBody(arena, ack_view.dec.body);
    defer ack_body.deinit(arena);
    try std.testing.expectEqual(@as(usize, 1), ack_body.msgs_ack.msg_ids.len);
    try std.testing.expectEqual(reply1_id, ack_body.msgs_ack.msg_ids[0]);

    // A second request on the same connection keeps both counters in
    // lockstep (client seq 3, server's next reply id strictly greater).
    const h2 = try client.send(io, TestRequest{ .query_id = 8 });
    const view2 = try ts.read(io, &pair.srv, arena, &out);
    try std.testing.expectEqual(@as(i32, 3), view2.dec.seq_no);
    ts.replyRpc(io, &pair.srv, arena, view2.dec.msg_id, &bool_false_bytes) catch return error.TestUnexpectedResult;
    var res2 = try client.wait(io, h2);
    defer res2.deinit();
    try std.testing.expect(res2.value == .boolFalse);
}

test "generated function invoked and decoded into generated types" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    // A real generated function request (users.getUsers): serialize it and
    // send through the raw path — the typed `send` needs the `Result`
    // decls the committed API gains on its next regeneration.
    const req = api.users.getUsers{ .id = try arena.dupe(api.InputUser, &.{
        .{ .inputUser = .{ .user_id = 1, .access_hash = 0xdead_beef } },
        .{ .inputUser = .{ .user_id = 2, .access_hash = 0xcafe_babe } },
    }) };
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try req.serialize(&w);
    const h = try client.sendRaw(io, w.items());

    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);
    try std.testing.expectEqual(api.users.getUsers.constructor_id, std.mem.readInt(u32, view.dec.body[0..4], .little));
    // Vector<InputUser>: vector ctor + count 2.
    try std.testing.expectEqual(td.tl.vector_constructor_id, std.mem.readInt(u32, view.dec.body[4..8], .little));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, view.dec.body[8..12], .little));

    // Answer with vector<Bool> — a result shape only the generic decoder
    // handles (top-level vector, union elements).
    var rw = Writer.init(arena);
    try rw.writeConstructorId(td.tl.vector_constructor_id);
    try rw.writeVectorLength(2);
    try rw.writeRaw(&bool_true_bytes);
    try rw.writeRaw(&bool_false_bytes);
    ts.replyRpc(io, &pair.srv, arena, view.dec.msg_id, rw.items()) catch return error.TestUnexpectedResult;

    const bytes = try client.waitRaw(io, h);
    defer std.testing.allocator.free(bytes);

    var dec_arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer dec_arena_state.deinit();
    const value = try td.rpc.decodeResult([]api.Bool, dec_arena_state.allocator(), bytes);
    try std.testing.expectEqual(@as(usize, 2), value.len);
    try std.testing.expect(value[0] == .boolTrue);
    try std.testing.expect(value[1] == .boolFalse);
}

test "rpc_error surfaces code and message" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    const h = try client.send(io, TestRequest{ .query_id = 1 });

    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);

    var ew = Writer.init(arena);
    try ew.writeConstructorId(message.rpc_error_id);
    try ew.writeInt(420);
    try ew.writeString("FLOOD_WAIT_60");
    ts.replyRpc(io, &pair.srv, arena, view.dec.msg_id, ew.items()) catch return error.TestUnexpectedResult;

    try std.testing.expectError(error.RpcError, client.wait(io, h));
    try std.testing.expectEqual(@as(i32, 420), client.lastRpcError().code);
    try std.testing.expectEqualStrings("FLOOD_WAIT_60", client.lastRpcError().message);
}

test "gzip_packed result is inflated before decoding" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    const h = try client.send(io, TestRequest{ .query_id = 2 });

    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);

    // gzip_packed{ stored-block gzip of the boolTrue object }.
    const gz = try td.rpc.decode.buildGzipStored(arena, &bool_true_bytes);
    var gw = Writer.init(arena);
    try gw.writeConstructorId(message.gzip_packed_id);
    try gw.writeBytes(gz);
    ts.replyRpc(io, &pair.srv, arena, view.dec.msg_id, gw.items()) catch return error.TestUnexpectedResult;

    var res = try client.wait(io, h);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);
}

test "bad_server_salt triggers re-send under the new salt" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    const h = try client.send(io, TestRequest{ .query_id = 3 });

    // Server: stale salt, here is the current one (technical message).
    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);

    const new_salt: i64 = 0xfeed_face;
    var bw = Writer.init(arena);
    try bw.writeConstructorId(message.bad_server_salt_id);
    try bw.writeLong(view.dec.msg_id);
    try bw.writeInt(view.dec.seq_no);
    try bw.writeInt(message.err_salt_invalid);
    try bw.writeLong(new_salt);
    try ts.send(io, &pair.srv, try ts.frame(io, arena, false, bw.items()));
    ts.salt = new_salt;

    // The client re-sends automatically while pumping; pump once to
    // process the bad_server_salt and let the server see the query again
    // under the new salt with a fresh msg_id. The pump ends with the
    // transport's read timeout on the now-silent link.
    client.pump(io, std.Io.Duration.fromMilliseconds(500)) catch {};
    const view2 = try ts.read(io, &pair.srv, arena, &out);
    try std.testing.expectEqual(new_salt, view2.dec.salt);
    try std.testing.expect(view2.dec.msg_id > view.dec.msg_id);
    try std.testing.expectEqual(@as(u32, 0x0d91a548), std.mem.readInt(u32, view2.dec.body[0..4], .little));

    ts.replyRpc(io, &pair.srv, arena, view2.dec.msg_id, &bool_true_bytes) catch return error.TestUnexpectedResult;

    var res = try client.wait(io, h);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);
}

test "pipelined requests answered in one container" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    // Two outstanding requests.
    const h1 = try client.send(io, TestRequest{ .query_id = 10 });
    const h2 = try client.send(io, TestRequest{ .query_id = 20 });

    var out: [4]message.Incoming = undefined;
    const view1 = try ts.read(io, &pair.srv, arena, &out);
    const view2 = try ts.read(io, &pair.srv, arena, &out);

    // One container carrying both answers: inner content messages stamped
    // seq 1 and 3, the envelope is the following service message (seq 4).
    // Ids/seqs/bodies are computed in explicit order (struct-literal field
    // evaluation order is unspecified).
    const seq1 = ts.nextSeqNo(true);
    const body1 = try TestServer.rpcResult(arena, view1.dec.msg_id, &bool_true_bytes);
    const seq2 = ts.nextSeqNo(true);
    const body2 = try TestServer.rpcResult(arena, view2.dec.msg_id, &bool_false_bytes);
    const id1 = ts.nextMsgId(io);
    const id2 = ts.nextMsgId(io);
    var inner = [_]message.Incoming{
        .{ .msg_id = id1, .seq_no = seq1, .body = body1 },
        .{ .msg_id = id2, .seq_no = seq2, .body = body2 },
    };
    var cw = Writer.init(arena);
    try message.writeContainer(&cw, &inner);
    try ts.send(io, &pair.srv, try ts.frame(io, arena, false, cw.items()));

    // The pump flattens the container and completes both requests; each
    // wait returns its own answer.
    var r1 = try client.wait(io, h1);
    defer r1.deinit();
    try std.testing.expect(r1.value == .boolTrue);
    var r2 = try client.wait(io, h2);
    defer r2.deinit();
    try std.testing.expect(r2.value == .boolFalse);

    // Both server ids were acknowledged in one batched msgs_ack.
    const ack_view = try ts.read(io, &pair.srv, arena, &out);
    var ack_body = try message.parseServiceBody(arena, ack_view.dec.body);
    defer ack_body.deinit(arena);
    try std.testing.expectEqual(@as(usize, 2), ack_body.msgs_ack.msg_ids.len);
}

test "ping answered by pong" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const ts = pair.ts;

    // The pong is buffered before the ping is even sent: pings are matched
    // by their ping_id (a nonce), not by msg_id. The client's first ping
    // uses ping_id 1.
    var pw = Writer.init(arena);
    try pw.writeConstructorId(message.pong_id);
    try pw.writeLong(0); // msg_id of the ping (not checked by the client)
    try pw.writeLong(1); // ping_id
    try ts.send(io, &pair.srv, try ts.frame(io, arena, false, pw.items()));

    try pair.client.ping(io);

    // The ping itself traveled as a technical message (even seq_no).
    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);
    try std.testing.expectEqual(@as(i32, 0), view.dec.seq_no);
    try std.testing.expectEqual(message.ping_id, std.mem.readInt(u32, view.dec.body[0..4], .little));
    try std.testing.expectEqual(@as(i64, 1), std.mem.readInt(i64, view.dec.body[4..12], .little));
}

test "wait timeout is retryable and the connection survives it" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(
        io,
        &tcp_storage,
        &ts_storage,
        .{ .read_timeout = std.Io.Duration.fromSeconds(1) },
        .{ .response_timeout = std.Io.Duration.fromSeconds(1) },
    );
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    const h = try client.send(io, TestRequest{ .query_id = 4 });

    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);

    // The server stays silent past the deadline: the wait times out with
    // the request still registered (retryable), the connection usable.
    try std.testing.expectError(error.TimedOut, client.wait(io, h));

    // The late answer completes the very same handle on the second wait.
    ts.replyRpc(io, &pair.srv, arena, view.dec.msg_id, &bool_true_bytes) catch return error.TestUnexpectedResult;
    var res = try client.wait(io, h);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);

    // And the connection still carries a fresh round trip.
    // The wait pump flushed the acknowledgement for the late rpc_result;
    // drain it so the next read sees the fresh query.
    _ = try ts.read(io, &pair.srv, arena, &out);
    const h2 = try client.send(io, TestRequest{ .query_id = 5 });
    const view2 = try ts.read(io, &pair.srv, arena, &out);
    ts.replyRpc(io, &pair.srv, arena, view2.dec.msg_id, &bool_false_bytes) catch return error.TestUnexpectedResult;
    var res2 = try client.wait(io, h2);
    defer res2.deinit();
    try std.testing.expect(res2.value == .boolFalse);
}

test "server-pushed updates are counted, not fatal" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    const h = try client.send(io, TestRequest{ .query_id = 6 });

    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);

    // An unknown API object (an update, content-related) arrives before
    // the answer; the pump must ack it and keep going.
    var uw = Writer.init(arena);
    try uw.writeConstructorId(0x1f2f3f4f); // no such constructor in any schema
    try uw.writeInt(1);
    try ts.send(io, &pair.srv, try ts.frame(io, arena, true, uw.items()));

    ts.replyRpc(io, &pair.srv, arena, view.dec.msg_id, &bool_true_bytes) catch return error.TestUnexpectedResult;

    var res = try client.wait(io, h);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);
    try std.testing.expectEqual(@as(usize, 1), client.updates_seen);

    // Each content message (the update, then the rpc_result) arrived in
    // its own frame, so each is acknowledged by its own msgs_ack.
    for (0..2) |_| {
        const ack_view = try ts.read(io, &pair.srv, arena, &out);
        var ack_body = try message.parseServiceBody(arena, ack_view.dec.body);
        defer ack_body.deinit(arena);
        try std.testing.expectEqual(@as(usize, 1), ack_body.msgs_ack.msg_ids.len);
    }
}

test "migration rpc error switches the current DC" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage, .{}, .{});
    defer pair.deinitPair(io);
    const client = &pair.client;
    const ts = pair.ts;

    const h = try client.send(io, TestRequest{ .query_id = 9 });

    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &pair.srv, arena, &out);

    // The canonical 303: the phone is registered on DC 5, go there.
    var ew = Writer.init(arena);
    try ew.writeConstructorId(message.rpc_error_id);
    try ew.writeInt(303);
    try ew.writeString("PHONE_MIGRATE_5");
    ts.replyRpc(io, &pair.srv, arena, view.dec.msg_id, ew.items()) catch return error.TestUnexpectedResult;

    try std.testing.expectError(error.RpcError, client.wait(io, h));
    const m = td.dc.migration.fromRpcError(client.lastRpcError()).?;
    try std.testing.expect(m.kind == .phone);
    try std.testing.expectEqual(@as(i32, 5), m.dc);

    var dcs = try td.dc.DataCenters.init(std.testing.allocator, .production);
    defer dcs.deinit();
    try std.testing.expect(try dcs.migrate(m));
    try std.testing.expectEqual(@as(i32, 5), dcs.current);
}
