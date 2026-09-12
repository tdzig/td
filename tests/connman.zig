//! Connection-management integration tests: `connman.Manager` over the
//! full stack — TCP-full transport + encrypted session + RPC — against
//! an in-process MTProto peer on real loopback sockets.
//!
//! The choreography follows `tests/rpc.zig` (client and server alternate
//! strictly on one thread, so one-shot `call`/`invoke` decompose into
//! their `send`/`wait` halves). On top of that, the server here *dies
//! and comes back*: sockets are closed mid-request without answering,
//! the listener is torn down and re-opened, and health pings go
//! deliberately unanswered. After every reconnect the server rebuilds
//! its crypto peer from the client's fresh wire session id and
//! independently re-validates every msg_id/seq_no rule — a reconnect
//! that corrupted the MTProto state fails here, loudly.

const std = @import("std");
const net = std.Io.net;
const td = @import("td");

const message = td.mtproto.message;
const Writer = td.tl.Writer;
const Manager = td.connman.Manager;
const api = td.api;

// Shared authorization key (varied bytes so the per-direction auth_key
// windows genuinely differ).
const auth_key = blk: {
    var k: [256]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 97 +% 5);
    break :blk k;
};

/// Tight budgets: everything below stays well under a second, and the
/// transport's read timeout (100 ms) fires before the RPC response
/// timeout so waits observe deadlines between reads.
fn testOptions() td.connman.Options {
    return .{
        .max_connect_attempts = 5,
        .max_retry_rounds = 4,
        .backoff_base = std.Io.Duration.fromMilliseconds(1),
        .backoff_max = std.Io.Duration.fromMilliseconds(10),
        .ping_interval = std.Io.Duration.fromSeconds(3600),
        .ping_timeout = std.Io.Duration.fromMilliseconds(250),
        .ping_disconnect_delay = null,
        // The harness peer below speaks the TCP-full framing; the library
        // default (abridged) and the other modes live in
        // tests/transport.zig.
        .transport = .full,
        .tcp = .{ .read_timeout = std.Io.Duration.fromMilliseconds(100) },
        .rpc = .{ .response_timeout = std.Io.Duration.fromMilliseconds(250) },
    };
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
    const parsed = td.transport.tcp_full.Codec.parseHeader(&h);
    if (parsed.length < td.transport.tcp_full.frame_overhead) return error.BadFrame;
    const payload = try arena.alloc(u8, parsed.length - td.transport.tcp_full.frame_overhead);
    try readExactRaw(io, stream, payload);
    var trailer: [4]u8 = undefined;
    try readExactRaw(io, stream, &trailer);
    if (td.transport.tcp_full.Codec.checksum(&h, payload) != std.mem.readInt(u32, &trailer, .little))
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
    const h = td.transport.tcp_full.Codec.header(payload.len, out_seq.*);
    const crc = td.transport.tcp_full.Codec.checksum(&h, payload);
    var trailer: [4]u8 = undefined;
    std.mem.writeInt(u32, &trailer, crc, .little);
    try sendFrameRaw(io, stream, &h, payload, &trailer);
    out_seq.* += 1;
}

/// Server msg_id base from the real clock — the client validates the
/// receive window on every reconnect.
fn nowBase(io: std.Io) i64 {
    const s = @divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s);
    return @as(i64, @intCast(s)) << 32;
}

/// Minimal MTProto peer with rpc answering helpers. One instance per
/// accepted connection: a manager reconnect resets its wire session, so
/// the peer (session id, counters, frame sequence) rebuilds too.
const TestServer = struct {
    salt: i64 = 0x51a1,
    session_id: i64,
    next_low: u32 = 1,
    content: u32 = 0,
    last_client_id: i64 = 0,
    client_content: u32 = 0,
    out_seq: u32 = 0,

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

    /// Reads, decrypts and validates one client frame — the independent
    /// re-check that keeps a recovered session honest.
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

/// One listener plus its currently accepted connection. The manager
/// reconnects against the same listener; `accept` picks up each new
/// connection and re-binds the peer state to the client's fresh wire
/// session.
const Harness = struct {
    io: std.Io,
    server: net.Server,
    srv: ?net.Stream = null,
    ts: TestServer = undefined,

    fn init(io: std.Io) !Harness {
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        return .{ .io = io, .server = try addr.listen(io, .{ .reuse_address = true }) };
    }

    fn port(self: *const Harness) u16 {
        return self.server.socket.address.getPort();
    }

    fn dropConn(self: *Harness) void {
        if (self.srv) |s| {
            s.close(self.io);
            self.srv = null;
        }
    }

    /// Accepts the next client connection (a fresh session after a
    /// reconnect) and rebuilds the peer state for it.
    fn accept(self: *Harness, mgr: *const Manager) !void {
        self.dropConn();
        self.srv = try self.server.accept(self.io);
        self.ts = .{ .session_id = mgr.client.?.session.session_id };
    }

    fn deinit(self: *Harness) void {
        self.dropConn();
        self.server.deinit(self.io);
    }
};

// The RNG backs the client's session ids and frame padding; it must
// outlive every manager.
var harness_prng = std.Random.DefaultPrng.init(0x0dd11);

fn newManager(allocator: std.mem.Allocator, h: *const Harness) Manager {
    return Manager.init(
        allocator,
        .{ .host = "127.0.0.1", .port = h.port() },
        &auth_key,
        0x51a1,
        harness_prng.random(),
        testOptions(),
    );
}

/// A request struct shaped like a generated function: carries the
/// `Result` decl. Body: ctor id + one i32.
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

test "typed request round trip through the manager" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var h = try Harness.init(io);
    defer h.deinit();
    var mgr = newManager(std.testing.allocator, &h);
    defer mgr.deinit(io);

    try std.testing.expectEqual(td.connman.State.idle, mgr.state());

    // First use dials; the server picks the connection up and answers.
    const hdl = try mgr.send(io, TestRequest{ .query_id = 1 });
    try h.accept(&mgr);

    var out: [4]message.Incoming = undefined;
    const view = try h.ts.read(io, &h.srv.?, arena, &out);
    try std.testing.expectEqual(@as(i32, 1), view.dec.seq_no);
    try std.testing.expectEqual(@as(u32, 0x0d91a548), std.mem.readInt(u32, view.dec.body[0..4], .little));
    h.ts.replyRpc(io, &h.srv.?, arena, view.dec.msg_id, &bool_true_bytes) catch return error.TestUnexpectedResult;

    var res = try mgr.wait(io, hdl);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);
    // The wait pump flushed the acknowledgement for the rpc_result;
    // drain it so the next read sees the next query.
    _ = try h.ts.read(io, &h.srv.?, arena, &out);

    try std.testing.expectEqual(td.connman.State.connected, mgr.state());
    try std.testing.expectEqual(@as(u64, 1), mgr.health.generation);
    try std.testing.expectEqual(@as(u64, 0), mgr.health.reconnects);
    try std.testing.expectEqual(@as(u64, 0), mgr.health.recovered_requests);

    // A second request on the same connection keeps the counters in
    // lockstep (content seq 3 after the first query).
    const hdl2 = try mgr.send(io, TestRequest{ .query_id = 2 });
    const view2 = try h.ts.read(io, &h.srv.?, arena, &out);
    try std.testing.expectEqual(@as(i32, 3), view2.dec.seq_no);
    h.ts.replyRpc(io, &h.srv.?, arena, view2.dec.msg_id, &bool_false_bytes) catch return error.TestUnexpectedResult;
    var res2 = try mgr.wait(io, hdl2);
    defer res2.deinit();
    try std.testing.expect(res2.value == .boolFalse);
    try std.testing.expectEqual(@as(u64, 1), mgr.health.generation);
}

test "connection dropped mid-request: reconnect recovers the unanswered query" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var h = try Harness.init(io);
    defer h.deinit();
    var mgr = newManager(std.testing.allocator, &h);
    defer mgr.deinit(io);

    // Establish, then drop the connection without answering: the request
    // was sent, no rpc_error ever arrived — the recoverable case.
    const hdl = try mgr.send(io, TestRequest{ .query_id = 7 });
    try h.accept(&mgr);
    var out: [4]message.Incoming = undefined;
    const view1 = try h.ts.read(io, &h.srv.?, arena, &out);
    const session_before = mgr.client.?.session.session_id;
    h.dropConn();

    // The wait detects the dead connection, reconnects (backoff, fresh
    // session) and re-sends the query under a fresh msg_id — then waits
    // for an answer that has not been produced yet (bounded timeout).
    try std.testing.expectError(error.TimedOut, mgr.wait(io, hdl));

    try std.testing.expectEqual(@as(u64, 2), mgr.health.generation);
    try std.testing.expectEqual(@as(u64, 1), mgr.health.reconnects);
    try std.testing.expectEqual(@as(u64, 1), mgr.health.recovered_requests);
    try std.testing.expect(mgr.client.?.session.session_id != session_before);

    // The server accepts the re-established connection: the query
    // arrives again, same constructor, valid fresh-session counters.
    try h.accept(&mgr);
    const view2 = try h.ts.read(io, &h.srv.?, arena, &out);
    try std.testing.expectEqual(
        std.mem.readInt(u32, view1.dec.body[0..4], .little),
        std.mem.readInt(u32, view2.dec.body[0..4], .little),
    );
    try std.testing.expectEqual(@as(i32, 7), std.mem.readInt(i32, view2.dec.body[4..8], .little));
    try std.testing.expectEqual(@as(i32, 1), view2.dec.seq_no);

    // The original handle completes through the recovered request.
    h.ts.replyRpc(io, &h.srv.?, arena, view2.dec.msg_id, &bool_true_bytes) catch return error.TestUnexpectedResult;
    var res = try mgr.wait(io, hdl);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);
    try std.testing.expectEqual(td.connman.State.connected, mgr.state());
}

test "connect budget exhausted surfaces CannotConnect; endpoint revival recovers" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var h = try Harness.init(io);
    var mgr = newManager(std.testing.allocator, &h);
    defer mgr.deinit(io);

    // Endpoint down: every attempt is refused, the budget exhausts.
    const listen_port = h.port();
    h.dropConn();
    h.server.deinit(io);
    try std.testing.expectError(error.CannotConnect, mgr.send(io, TestRequest{ .query_id = 3 }));
    try std.testing.expectEqual(@as(u32, 5), mgr.health.consecutive_failures);
    try std.testing.expect(mgr.health.last_error != null);
    try std.testing.expectEqual(td.connman.State.backing_off, mgr.state());

    // Endpoint back on the same port: the very next operation connects.
    const addr = try net.IpAddress.parse("127.0.0.1", listen_port);
    h.server = try addr.listen(io, .{ .reuse_address = true });
    const hdl = try mgr.send(io, TestRequest{ .query_id = 4 });
    try std.testing.expectEqual(@as(u32, 0), mgr.health.consecutive_failures);
    try std.testing.expectEqual(@as(u64, 1), mgr.health.generation);

    try h.accept(&mgr);
    var out: [4]message.Incoming = undefined;
    const view = try h.ts.read(io, &h.srv.?, arena, &out);
    h.ts.replyRpc(io, &h.srv.?, arena, view.dec.msg_id, &bool_true_bytes) catch return error.TestUnexpectedResult;
    var res = try mgr.wait(io, hdl);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);
}

test "late answer completes the same handle without a reconnect" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var h = try Harness.init(io);
    defer h.deinit();
    var mgr = newManager(std.testing.allocator, &h);
    defer mgr.deinit(io);

    const hdl = try mgr.send(io, TestRequest{ .query_id = 5 });
    try h.accept(&mgr);
    var out: [4]message.Incoming = undefined;
    const view = try h.ts.read(io, &h.srv.?, arena, &out);

    // Server stays silent: the wait times out, the request stays
    // registered, the connection stays up.
    try std.testing.expectError(error.TimedOut, mgr.wait(io, hdl));
    try std.testing.expectEqual(@as(u64, 1), mgr.health.generation);
    try std.testing.expectEqual(@as(usize, 1), mgr.client.?.pending.items.len);

    // The late answer completes the very same handle.
    h.ts.replyRpc(io, &h.srv.?, arena, view.dec.msg_id, &bool_false_bytes) catch return error.TestUnexpectedResult;
    var res = try mgr.wait(io, hdl);
    defer res.deinit();
    try std.testing.expect(res.value == .boolFalse);
    try std.testing.expectEqual(@as(u64, 0), mgr.health.recovered_requests);
}

test "health check: pong refreshes, silence forces a reconnect" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var h = try Harness.init(io);
    defer h.deinit();
    var mgr = newManager(std.testing.allocator, &h);
    defer mgr.deinit(io);

    // Establish; leave one request outstanding and cancel it — it only
    // serves to get the connection accepted.
    const stray = try mgr.send(io, TestRequest{ .query_id = 6 });
    try h.accept(&mgr);
    var out: [4]message.Incoming = undefined;
    _ = try h.ts.read(io, &h.srv.?, arena, &out);
    mgr.cancel(stray);

    // A pre-buffered pong completes the ping (matched by ping_id, so it
    // can arrive before the ping is sent).
    var pw = Writer.init(arena);
    try pw.writeConstructorId(message.pong_id);
    try pw.writeLong(0); // msg_id of the ping (not checked)
    try pw.writeLong(1); // the client's first ping_id
    try h.ts.send(io, &h.srv.?, try h.ts.frame(io, arena, false, pw.items()));
    try mgr.ping(io);
    try std.testing.expectEqual(@as(usize, 1), mgr.client.?.pongs_seen);
    // Drain the plain ping frame before the health-check exchange.
    _ = try h.ts.read(io, &h.srv.?, arena, &out);

    // Now the check fires with keep-alive semantics and a silent server:
    // ping_delay_disconnect goes out, no pong comes back, the manager
    // drops the stale ping, re-establishes and ends connected.
    mgr.opts.ping_interval = std.Io.Duration.zero;
    mgr.opts.ping_disconnect_delay = 30;
    try mgr.maintain(io);

    try std.testing.expectEqual(@as(u64, 2), mgr.health.generation);
    try std.testing.expectEqual(td.connman.State.connected, mgr.state());
    try std.testing.expectEqual(error.TimedOut, mgr.health.last_error.?);
    try std.testing.expectEqual(@as(usize, 0), mgr.client.?.pending.items.len);

    // The server saw a real ping_delay_disconnect on the old connection.
    const pv = try h.ts.read(io, &h.srv.?, arena, &out);
    try std.testing.expectEqual(
        message.ping_delay_disconnect_id,
        std.mem.readInt(u32, pv.dec.body[0..4], .little),
    );
    // Body layout: ctor (4) + ping_id (8) + disconnect_delay (4).
    try std.testing.expectEqual(@as(i32, 30), std.mem.readInt(i32, pv.dec.body[12..16], .little));

    // The re-established connection carries traffic.
    try h.accept(&mgr);
    const hdl = try mgr.send(io, TestRequest{ .query_id = 8 });
    const view = try h.ts.read(io, &h.srv.?, arena, &out);
    h.ts.replyRpc(io, &h.srv.?, arena, view.dec.msg_id, &bool_true_bytes) catch return error.TestUnexpectedResult;
    var res = try mgr.wait(io, hdl);
    defer res.deinit();
    try std.testing.expect(res.value == .boolTrue);
}

test "pump drains a container of answers and acknowledges once" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var h = try Harness.init(io);
    defer h.deinit();
    var mgr = newManager(std.testing.allocator, &h);
    defer mgr.deinit(io);

    // Two outstanding requests, answered in one container.
    const h1 = try mgr.send(io, TestRequest{ .query_id = 10 });
    const h2 = try mgr.send(io, TestRequest{ .query_id = 20 });
    try h.accept(&mgr);
    var out: [4]message.Incoming = undefined;
    const view1 = try h.ts.read(io, &h.srv.?, arena, &out);
    const view2 = try h.ts.read(io, &h.srv.?, arena, &out);

    const seq1 = h.ts.nextSeqNo(true);
    const body1 = try TestServer.rpcResult(arena, view1.dec.msg_id, &bool_true_bytes);
    const seq2 = h.ts.nextSeqNo(true);
    const body2 = try TestServer.rpcResult(arena, view2.dec.msg_id, &bool_false_bytes);
    const id1 = h.ts.nextMsgId(io);
    const id2 = h.ts.nextMsgId(io);
    var inner = [_]message.Incoming{
        .{ .msg_id = id1, .seq_no = seq1, .body = body1 },
        .{ .msg_id = id2, .seq_no = seq2, .body = body2 },
    };
    var cw = Writer.init(arena);
    try message.writeContainer(&cw, &inner);
    try h.ts.send(io, &h.srv.?, try h.ts.frame(io, arena, false, cw.items()));

    // The read loop completes both (budget expiry with a healthy
    // connection is success).
    try mgr.pump(io, std.Io.Duration.fromMilliseconds(50));

    var r1 = try mgr.wait(io, h1);
    defer r1.deinit();
    try std.testing.expect(r1.value == .boolTrue);
    var r2 = try mgr.wait(io, h2);
    defer r2.deinit();
    try std.testing.expect(r2.value == .boolFalse);

    // Both answers were acknowledged in one batched msgs_ack.
    const ack_view = try h.ts.read(io, &h.srv.?, arena, &out);
    var ack_body = try message.parseServiceBody(arena, ack_view.dec.body);
    defer ack_body.deinit(arena);
    try std.testing.expectEqual(@as(usize, 2), ack_body.msgs_ack.msg_ids.len);
}

test "cancel and graceful shutdown gate" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var h = try Harness.init(io);
    defer h.deinit();
    var mgr = newManager(std.testing.allocator, &h);
    defer mgr.deinit(io);

    // Cancel an outstanding request: its handle goes stale.
    const hdl = try mgr.send(io, TestRequest{ .query_id = 11 });
    try h.accept(&mgr);
    var out: [4]message.Incoming = undefined;
    _ = try h.ts.read(io, &h.srv.?, arena, &out);
    mgr.cancel(hdl);
    try std.testing.expectEqual(@as(usize, 0), mgr.client.?.pending.items.len);
    try std.testing.expectError(error.StaleHandle, mgr.wait(io, hdl));

    // Graceful shutdown: terminal state, every operation gated, the
    // outstanding request freed (the allocator leak-check below is part
    // of the assertion).
    const outstanding = try mgr.send(io, TestRequest{ .query_id = 12 });
    mgr.close(io);
    try std.testing.expectEqual(td.connman.State.closed, mgr.state());
    mgr.close(io); // idempotent
    try std.testing.expectError(error.Closed, mgr.send(io, TestRequest{ .query_id = 13 }));
    try std.testing.expectError(error.Closed, mgr.wait(io, outstanding));
    try std.testing.expectError(error.Closed, mgr.waitRaw(io, .{ .id = 99 }));
    try std.testing.expectError(error.Closed, mgr.ping(io));
    try std.testing.expectError(error.Closed, mgr.pump(io, std.Io.Duration.fromMilliseconds(1)));
    try std.testing.expectError(error.Closed, mgr.maintain(io));
    try std.testing.expectError(error.Closed, mgr.ensureConnected(io));
}

test "manager dials the configured transport mode" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Whatever the mode, the manager's first request must land on the
    // wire framed exactly as that mode spells it — selection happens at
    // dial time, with no per-call involvement.
    inline for ([_]td.transport.TransportMode{ .abridged, .intermediate, .padded_intermediate, .full }) |mode| {
        var prng = std.Random.DefaultPrng.init(0x50da);
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        var server = try addr.listen(io, .{ .reuse_address = true });
        defer server.deinit(io);

        var mgr = Manager.init(
            std.testing.allocator,
            .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
            &auth_key,
            0,
            prng.random(),
            .{ .transport = mode, .tcp = .{ .read_timeout = std.Io.Duration.fromMilliseconds(250) } },
        );
        defer mgr.deinit(io);

        // Connecting exchanges no bytes; the first request carries the
        // mode's framing onto the wire. Body: ctor id + one int (8 bytes).
        try mgr.ensureConnected(io);
        var srv = try server.accept(io);
        defer srv.close(io);
        _ = try mgr.sendRaw(io, &[_]u8{ 0x48, 0xa5, 0x91, 0x0d, 0, 0, 0, 0 });

        const frame_len = message.frameLength(8);
        var head: [8]u8 = undefined;
        try readExactRaw(io, &srv, head[0..4]);
        switch (mode) {
            .abridged => {
                // head = tag, length byte, first payload bytes.
                try std.testing.expectEqual(@as(u8, 0xef), head[0]);
                // frame_len/4 fits the short form (88/4 = 22 < 127).
                try std.testing.expectEqual(@as(u8, @intCast(frame_len / 4)), head[1]);
            },
            .intermediate, .padded_intermediate => {
                const tag: []const u8 = if (mode == .intermediate)
                    "\xee\xee\xee\xee"
                else
                    "\xdd\xdd\xdd\xdd";
                try std.testing.expectEqualSlices(u8, tag, head[0..4]);
                try readExactRaw(io, &srv, head[0..4]);
                const tlen = std.mem.readInt(u32, head[0..4], .little);
                // Padded frames add 0..15 bytes of padding to the length.
                if (mode == .intermediate) {
                    try std.testing.expectEqual(@as(u32, @intCast(frame_len)), tlen);
                } else {
                    try std.testing.expect(tlen >= frame_len and tlen < frame_len + 16);
                }
            },
            .full => {
                // length counts the whole frame; the sequence starts at 0.
                try readExactRaw(io, &srv, head[4..8]);
                try std.testing.expectEqual(
                    @as(u32, @intCast(frame_len + 12)),
                    std.mem.readInt(u32, head[0..4], .little),
                );
                try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, head[4..8], .little));
            },
        }
        mgr.close(io);
    }
}
