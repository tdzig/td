//! Session-persistence integration tests — Step 11's definition of done:
//! a client disconnects, persists its session, restarts, reloads it and
//! reconnects **without repeating authorization**, continuing the same
//! logical session.
//!
//! Choreography follows `tests/rpc.zig`: an in-process MTProto peer over
//! real loopback TCP-full sockets, strictly alternating on one thread.
//! The peer independently validates every client→server rule, and on the
//! reconnect it starts its expectations *from the persisted counters* —
//! session id, msg_id high-water mark and content-message count — so a
//! client that restarted from zero (fresh ids, reset seq) would be
//! rejected. The `bad_server_salt` correction in the first phase also
//! proves the captured salt is the *current* one, not the handshake-time
//! one.

const std = @import("std");
const net = std.Io.net;
const td = @import("td");

const message = td.mtproto.message;
const Writer = td.tl.Writer;
const TcpFull = td.transport.TcpFull;
const tcp_full = td.transport.tcp_full;
const Client = td.rpc.Client;
const api = td.api;
const session = td.session;

// Shared authorization key (varied bytes so the per-direction auth_key
// windows genuinely differ).
const auth_key = blk: {
    var k: [256]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 89 +% 3);
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

fn nowBase(io: std.Io) i64 {
    const s = @divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s);
    return @as(i64, @intCast(s)) << 32;
}

fn unixSeconds(io: std.Io) u64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

/// Minimal MTProto peer with rpc answering helpers. The reconnect test
/// seeds `client_content`/`last_client_id` from the persisted session so
/// continuation (not restart) is what the validation demands.
const TestServer = struct {
    salt: i64 = 0x51a1,
    session_id: i64,
    next_low: u32 = 1,
    content: u32 = 0,
    /// Client-side expectations, seeded from persisted state on the
    /// reconnect.
    last_client_id: i64 = 0,
    client_content: u32 = 0,
    out_seq: u32 = 0,
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

    fn rpcResult(arena: std.mem.Allocator, req_msg_id: i64, result: []const u8) ![]const u8 {
        var w = Writer.init(arena);
        try w.writeConstructorId(message.rpc_result_id);
        try w.writeLong(req_msg_id);
        try w.writeRaw(result);
        return w.items();
    }

    fn replyRpc(self: *TestServer, io: std.Io, stream: *net.Stream, arena: std.mem.Allocator, req_msg_id: i64, result: []const u8) !void {
        try self.send(io, stream, try self.frame(io, arena, true, try rpcResult(arena, req_msg_id, result)));
    }

    const View = struct {
        dec: message.Decrypted,
        count: usize,
        inner: []message.Incoming,
    };

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

/// One client + server pair on a fresh loopback connection.
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

var pair_prng = std.Random.DefaultPrng.init(11);

fn makePair(
    io: std.Io,
    tcp_storage: *TcpFull,
    ts_storage: *TestServer,
    server_salt: i64,
) !Pair {
    var server = try startServer(io);
    errdefer server.deinit(io);

    tcp_storage.* = TcpFull.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{ .read_timeout = std.Io.Duration.fromMilliseconds(100) },
    );
    try tcp_storage.connect(io);
    errdefer tcp_storage.close(io);

    var srv = try server.accept(io);
    errdefer srv.close(io);

    const client = try Client.init(
        std.testing.allocator,
        tcp_storage.transport(),
        &auth_key,
        server_salt,
        pair_prng.random(),
        .{},
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

/// The stored form of the key, as `DataCenters.setAuthKey` would have
/// received it from the handshake: salt bytes are the wire (LE) form.
fn handshakeKey(salt: i64) td.mtproto.AuthKey {
    var key: td.mtproto.AuthKey = undefined;
    @memcpy(&key.key, &auth_key);
    key.id = td.crypto.authKeyId(&auth_key);
    for (&key.aux_hash, 0..) |*b, i| b.* = @truncate(i *% 19 +% 6);
    std.mem.writeInt(i64, &key.server_salt, salt, .little);
    return key;
}

test "definition of done: disconnect, persist, restart, reload, reconnect" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // ------------------------------------------------ first "process run"
    const initial_salt: i64 = 0x51a1;
    const new_salt: i64 = 0xfeed_face;
    var mem = session.MemoryStore.init(std.testing.allocator);
    defer mem.deinit();
    var out: [4]message.Incoming = undefined;

    // Phase A lives in its own block: leaving it tears the connection
    // and the manager down — the "disconnect" and "shutdown".
    const captured = blk: {
        var dcs = try td.dc.DataCenters.init(std.testing.allocator, .production);
        defer dcs.deinit();
        // connect() would store the handshake's key; simulate exactly that.
        try dcs.setAuthKey(2, handshakeKey(initial_salt));
        try dcs.setCurrent(2);

        var tcp_a: TcpFull = undefined;
        var ts_a_storage: TestServer = undefined;
        var pair_a = try makePair(io, &tcp_a, &ts_a_storage, initial_salt);
        defer pair_a.deinitPair(io);
        const client_a = &pair_a.client;
        const ts_a = pair_a.ts;

        // A live round trip, with a salt correction along the way: the
        // first query goes out under a stale salt, the server answers
        // bad_server_salt, the client re-sends under the new one.
        const h = try client_a.send(io, TestRequest{ .query_id = 21 });
        const view = try ts_a.read(io, &pair_a.srv, arena, &out);

        var bw = Writer.init(arena);
        try bw.writeConstructorId(message.bad_server_salt_id);
        try bw.writeLong(view.dec.msg_id);
        try bw.writeInt(view.dec.seq_no);
        try bw.writeInt(message.err_salt_invalid);
        try bw.writeLong(new_salt);
        try ts_a.send(io, &pair_a.srv, try ts_a.frame(io, arena, false, bw.items()));
        ts_a.salt = new_salt;

        // Pump once so the client processes the bad_server_salt and
        // re-sends the query under the new salt.
        client_a.pump(io, std.Io.Duration.fromMilliseconds(50)) catch {};
        const view2 = try ts_a.read(io, &pair_a.srv, arena, &out);
        try std.testing.expectEqual(new_salt, view2.dec.salt);

        ts_a.replyRpc(io, &pair_a.srv, arena, view2.dec.msg_id, &bool_true_bytes) catch
            return error.TestUnexpectedResult;
        var res = try client_a.wait(io, h);
        defer res.deinit();
        try std.testing.expect(res.value == .boolTrue);
        // Drain the acknowledgement the pump sent for the rpc_result.
        _ = try ts_a.read(io, &pair_a.srv, arena, &out);

        // Capture and persist while everything is still live.
        const c = session.State.capture(&dcs, client_a) orelse
            return error.TestUnexpectedResult;
        try mem.store().saveState(io, c);

        // The captured salt is the *corrected* one, not the stored
        // handshake one.
        try std.testing.expectEqual(
            new_salt,
            std.mem.readInt(i64, &c.auth_key.server_salt, .little),
        );
        try std.testing.expectEqual(client_a.session.session_id, c.session_id);
        try std.testing.expectEqual(client_a.session.content_count, c.content_count);

        // Disconnect: transport down (the block's defers free the rest).
        pair_a.client.close(io);
        break :blk c;
    };

    // --------------------------------------------------- second "process run"
    // Everything is rebuilt from the store alone: no handshake ran, no
    // key was re-derived.
    const loaded = (try mem.store().loadState(io, std.testing.allocator)) orelse
        return error.TestUnexpectedResult;
    // The store roundtrip is lossless.
    try std.testing.expectEqualSlices(u8, &captured.auth_key.key, &loaded.auth_key.key);
    try std.testing.expectEqual(captured.session_id, loaded.session_id);

    var dcs2 = try td.dc.DataCenters.init(std.testing.allocator, .production);
    defer dcs2.deinit();
    try loaded.applyTo(&dcs2);
    try std.testing.expectEqual(@as(i32, 2), dcs2.current);
    // The stored key is what makes `DataCenters.connect` skip the
    // handshake for this DC.
    const stored_key = dcs2.authKey(2) orelse return error.TestUnexpectedResult;

    var tcp_b: TcpFull = undefined;
    var ts_b_storage: TestServer = undefined;
    // The same composition `DataCenters.connect` applies: wire-form salt
    // bytes → i64.
    var pair_b = try makePair(io, &tcp_b, &ts_b_storage, std.mem.readInt(i64, &stored_key.server_salt, .little));
    defer pair_b.deinitPair(io);
    const client_b = &pair_b.client;

    // Continue the captured logical session.
    loaded.adoptOn(client_b, unixSeconds(io));

    // The peer enforces continuation: expectations start from the
    // persisted counters, so a fresh identity (new session id, restarted
    // ids/seq) would fail its validation below.
    const ts_b = pair_b.ts;
    ts_b.salt = new_salt;
    ts_b.session_id = loaded.session_id;
    ts_b.client_content = loaded.content_count;
    ts_b.last_client_id = loaded.last_msg_id;
    // The peer's outgoing counter continues from the persisted incoming
    // counter — a remembering server, like production.
    ts_b.content = loaded.remote_content_count;

    try std.testing.expectEqual(loaded.session_id, client_b.session.session_id);

    // A round trip on the restored connection, under the restored salt
    // and the continued counters.
    const h2 = try client_b.send(io, TestRequest{ .query_id = 22 });
    const view_b = try ts_b.read(io, &pair_b.srv, arena, &out);
    try std.testing.expectEqual(new_salt, view_b.dec.salt);
    // seq_no continued from the persisted content count (odd, content).
    try std.testing.expectEqual(
        @as(i32, @intCast(2 * loaded.content_count + 1)),
        view_b.dec.seq_no,
    );

    ts_b.replyRpc(io, &pair_b.srv, arena, view_b.dec.msg_id, &bool_true_bytes) catch
        return error.TestUnexpectedResult;
    var res2 = try client_b.wait(io, h2);
    defer res2.deinit();
    try std.testing.expect(res2.value == .boolTrue);

    // The acknowledgement is a service message in the same continued
    // sequence (even seq, content count advanced).
    const ack_view = try ts_b.read(io, &pair_b.srv, arena, &out);
    try std.testing.expectEqual(
        @as(i32, @intCast(2 * (loaded.content_count + 1))),
        ack_view.dec.seq_no,
    );
}

test "session survives a file store roundtrip across a restart" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fmt.allocPrint(
        std.testing.allocator,
        ".zig-cache/tmp/{s}/session.bin",
        .{&tmp.sub_path},
    );
    defer std.testing.allocator.free(path);

    // A live client whose state to capture.
    var dcs = try td.dc.DataCenters.init(std.testing.allocator, .production);
    defer dcs.deinit();
    try dcs.setAuthKey(4, handshakeKey(0x11));

    var tcp: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp, &ts_storage, 0x11);
    defer pair.deinitPair(io);

    // One content message so the counters are non-trivial.
    const h = try pair.client.send(io, TestRequest{ .query_id = 1 });
    var out: [4]message.Incoming = undefined;
    const view = try pair.ts.read(io, &pair.srv, arena, &out);
    pair.ts.replyRpc(io, &pair.srv, arena, view.dec.msg_id, &bool_true_bytes) catch
        return error.TestUnexpectedResult;
    var res = try pair.client.wait(io, h);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);
    _ = try pair.ts.read(io, &pair.srv, arena, &out); // drain the ack

    const captured = session.State.capture(&dcs, &pair.client) orelse
        return error.TestUnexpectedResult;

    // Persist through one FileStore; reload through a *different*
    // instance — the bytes came back from disk, not memory.
    {
        var fs = try session.FileStore.init(std.testing.allocator, path);
        defer fs.deinit();
        try fs.store().saveState(io, captured);
    }
    var fs2 = try session.FileStore.init(std.testing.allocator, path);
    defer fs2.deinit();
    const loaded = (try fs2.store().loadState(io, std.testing.allocator)) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(captured.environment, loaded.environment);
    try std.testing.expectEqual(captured.dc, loaded.dc);
    try std.testing.expectEqualSlices(u8, &captured.auth_key.key, &loaded.auth_key.key);
    try std.testing.expectEqualSlices(u8, &captured.auth_key.id, &loaded.auth_key.id);
    try std.testing.expectEqualSlices(u8, &captured.auth_key.server_salt, &loaded.auth_key.server_salt);
    try std.testing.expectEqual(captured.session_id, loaded.session_id);
    try std.testing.expectEqual(captured.last_msg_id, loaded.last_msg_id);
    try std.testing.expectEqual(captured.content_count, loaded.content_count);
}
