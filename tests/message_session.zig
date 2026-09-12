//! Encrypted-message session integration tests: the td session layer
//! end-to-end over the TCP-full transport on real loopback sockets.
//!
//! The client side is a real `td.mtproto.Session`. The test-side
//! "server" speaks the same protocol from the `td.mtproto.message`
//! primitives with independently tracked counters, validating everything
//! the spec demands of client→server traffic (msg_id parity, ordering,
//! the seq_no formula) and stamping server-conformant ids itself
//! (≡ 1 mod 4, strictly increasing). Both sides must agree on every
//! envelope field, container shape and acknowledgement for a test to
//! pass — the same choreography `tests/transport.zig` uses, one layer
//! up the stack.

const std = @import("std");
const net = std.Io.net;
const td = @import("td");

const message = td.mtproto.message;
const Session = td.mtproto.Session;
const Writer = td.tl.Writer;
const TcpFull = td.transport.TcpFull;
const tcp_full = td.transport.tcp_full;

// Deterministic clock for every id and window check in this file.
const now: u64 = 1_800_000_000;
const base_id = @as(i64, now) << 32;

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

/// Raw server-side writer. splat=1: the buffer is written exactly once.
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

/// Reads one raw TCP-full frame on the server side (allocated from
/// `arena`; checksum verified).
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

/// Sends one raw TCP-full frame from the server side; the server's
/// outbound sequence numbers start fresh per TestServer.
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

/// Minimal MTProto peer: decrypts client frames and independently
/// validates them, and stamps server frames (ids ≡ 1 mod 4, strictly
/// increasing; seq_nos per the spec formula).
const TestServer = struct {
    salt: i64 = 0x51a1,
    session_id: i64,
    next_low: u32 = 1,
    content: u32 = 0,
    last_client_id: i64 = 0,
    client_content: u32 = 0,
    out_seq: u32 = 0,

    /// Sends one encrypted server frame (built by `frame`) as a raw
    /// TCP-full frame.
    fn send(self: *TestServer, io: std.Io, stream: *net.Stream, payload: []const u8) !void {
        try serverSendFrame(io, stream, payload, &self.out_seq);
    }

    fn nextMsgId(self: *TestServer) i64 {
        const id = base_id | self.next_low;
        self.next_low += 4;
        return id;
    }

    fn nextSeqNo(self: *TestServer, content_related: bool) i32 {
        const seq: i32 = @intCast(2 * self.content + @as(u32, if (content_related) 1 else 0));
        if (content_related) self.content += 1;
        return seq;
    }

    /// Encrypts one server→client frame (allocated from `arena`) carrying
    /// `body`, stamped with the next server id/seq.
    fn frame(self: *TestServer, arena: std.mem.Allocator, content_related: bool, body: []const u8) ![]u8 {
        var prng = std.Random.DefaultPrng.init(0xabc);
        const buf = try arena.alloc(u8, message.frameLength(body.len));
        try message.writeEncrypted(&auth_key, .server_to_client, .{
            .salt = self.salt,
            .session_id = self.session_id,
            .msg_id = self.nextMsgId(),
            .seq_no = self.nextSeqNo(content_related),
            .body = body,
        }, prng.random(), buf);
        return buf;
    }

    const View = struct {
        dec: message.Decrypted,
        /// Inner messages when the client sent a container, else 0.
        count: usize,
        inner: []message.Incoming,
    };

    /// Reads, decrypts and validates one client frame against the
    /// client→server rules. Container entries land in `out`.
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
            // The container envelope itself is a service message.
            if (try checkSeq(c, dec.seq_no)) return error.ContainerNotService;
            self.client_content = c;
        } else {
            if (try checkSeq(self.client_content, dec.seq_no)) self.client_content += 1;
        }
        self.last_client_id = dec.msg_id;
        return .{ .dec = dec, .count = count, .inner = out[0..count] };
    }
};

/// Shared seq_no formula check (both directions use it).
fn checkSeq(base: u32, seq_no: i32) !bool {
    const content = message.isContentRelated(seq_no);
    const expected: i32 = @intCast(2 * base + @as(u32, if (content) 1 else 0));
    if (seq_no != expected) return error.BadSeqNo;
    return content;
}

test "encrypted exchange with acknowledgements over tcp full" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    var prng = std.Random.DefaultPrng.init(7);
    var client = try Session.init(std.testing.allocator, &auth_key, 0x51a1, prng.random());
    defer client.deinit();
    var ts = TestServer{ .session_id = client.session_id };

    // Client pings (a technical, non-content message: seq 0, no ack).
    var w = Writer.init(arena);
    const ping = message.Ping{ .ping_id = 0xcafe };
    try ping.serialize(&w);
    var cframe: [message.frameLength(12)]u8 = undefined;
    const sent = try client.encode(now, false, w.items(), &cframe);
    try tcp.write(io, &cframe);

    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &srv, arena, &out);
    try std.testing.expectEqual(@as(i32, 0), view.dec.seq_no);
    try std.testing.expectEqual(message.ping_id, std.mem.readInt(u32, view.dec.body[0..4], .little));
    try std.testing.expectEqual(@as(i64, 0xcafe), std.mem.readInt(i64, view.dec.body[4..12], .little));

    // Server answers pong (also technical) referencing the ping's msg_id.
    var rw = Writer.init(arena);
    try rw.writeConstructorId(message.pong_id);
    try rw.writeLong(sent.msg_id);
    try rw.writeLong(0xcafe);
    try ts.send(io, &srv, try ts.frame(arena, false, rw.items()));

    const reply = try tcp.read(io, arena);
    var rout: [1]message.Incoming = undefined;
    const got = try client.receive(reply, now, &rout);
    try std.testing.expect(!got.is_container);
    var body = try message.parseServiceBody(arena, got.messages[0].body);
    defer body.deinit(arena);
    try std.testing.expectEqual(sent.msg_id, body.pong.msg_id);
    try std.testing.expectEqual(@as(i64, 0xcafe), body.pong.ping_id);
    try std.testing.expectEqual(@as(usize, 0), client.pendingAckCount()); // pong: nothing to ack

    // Server pushes a content message (rpc_result, seq 1): the client
    // must queue its acknowledgement.
    var cw = Writer.init(arena);
    try cw.writeConstructorId(message.rpc_result_id);
    try cw.writeLong(0x999);
    try cw.writeInt(0);
    try ts.send(io, &srv, try ts.frame(arena, true, cw.items()));

    const push = try tcp.read(io, arena);
    var pout: [1]message.Incoming = undefined;
    const pushed = try client.receive(push, now, &pout);
    var pbody = try message.parseServiceBody(arena, pushed.messages[0].body);
    defer pbody.deinit(arena);
    try std.testing.expectEqual(@as(i64, 0x999), pbody.rpc_result.req_msg_id);
    try std.testing.expectEqual(@as(usize, 1), client.pendingAckCount());

    // The drained ack travels as a msgs_ack service message and the
    // server decodes the very id it pushed.
    const alen = client.pendingAckFrameLength();
    const adst = try arena.alloc(u8, alen);
    try std.testing.expect((try client.flushAcks(now, adst)) != null);
    try tcp.write(io, adst);

    const ack_view = try ts.read(io, &srv, arena, &out);
    var ack_body = try message.parseServiceBody(arena, ack_view.dec.body);
    defer ack_body.deinit(arena);
    try std.testing.expectEqual(@as(usize, 1), ack_body.msgs_ack.msg_ids.len);
    try std.testing.expectEqual(base_id | 5, ack_body.msgs_ack.msg_ids[0]); // second server id
    try std.testing.expectEqual(@as(usize, 0), client.pendingAckCount());
}

test "container with mixed content over tcp full" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    var prng = std.Random.DefaultPrng.init(11);
    var client = try Session.init(std.testing.allocator, &auth_key, 0x51a1, prng.random());
    defer client.deinit();
    var ts = TestServer{ .session_id = client.session_id };

    // One container: a content-related query and a technical ping.
    var w = Writer.init(arena);
    const ping = message.Ping{ .ping_id = 5 };
    try ping.serialize(&w);
    const entries = [_]td.mtproto.session.ContainerEntry{
        .{ .body = w.items(), .content_related = true },
        .{ .body = w.items(), .content_related = false },
    };
    const cbuf = try arena.alloc(u8, Session.containerFrameLength(&entries));
    const csent = try client.encodeContainer(now, &entries, cbuf);
    try tcp.write(io, cbuf);

    var out: [4]message.Incoming = undefined;
    const view = try ts.read(io, &srv, arena, &out);
    try std.testing.expectEqual(@as(usize, 2), view.count);
    try std.testing.expectEqual(csent.msg_id, view.dec.msg_id);
    // Content entry: odd seq; technical entry and the container envelope:
    // even seq after one content message.
    try std.testing.expectEqual(@as(i32, 1), view.inner[0].seq_no);
    try std.testing.expectEqual(@as(i32, 2), view.inner[1].seq_no);
    try std.testing.expectEqual(@as(i32, 2), view.dec.seq_no);
    try std.testing.expect(view.inner[0].msg_id < view.inner[1].msg_id); // strictly increasing
    try std.testing.expect(view.inner[1].msg_id < view.dec.msg_id); // container id strictly greatest
    for (view.inner) |m| try std.testing.expectEqualSlices(u8, w.items(), m.body);
}

test "bad_server_salt recovery over tcp full" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    var prng = std.Random.DefaultPrng.init(13);
    var client = try Session.init(std.testing.allocator, &auth_key, 0x51a1, prng.random());
    defer client.deinit();
    var ts = TestServer{ .session_id = client.session_id };

    // Client query (content-related: an RPC query in real life).
    var w = Writer.init(arena);
    const ping = message.Ping{ .ping_id = 77 };
    try ping.serialize(&w);
    var cframe: [message.frameLength(12)]u8 = undefined;
    const sent = try client.encode(now, true, w.items(), &cframe);
    try tcp.write(io, &cframe);

    var out: [4]message.Incoming = undefined;
    _ = try ts.read(io, &srv, arena, &out);

    // Server: your salt is stale — here is the current one.
    const new_salt: i64 = 0xfeed_face;
    var bw = Writer.init(arena);
    try bw.writeConstructorId(message.bad_server_salt_id);
    try bw.writeLong(sent.msg_id);
    try bw.writeInt(sent.seq_no);
    try bw.writeInt(message.err_salt_invalid);
    try bw.writeLong(new_salt);
    try ts.send(io, &srv, try ts.frame(arena, false, bw.items()));
    ts.salt = new_salt;

    const reply = try tcp.read(io, arena);
    var rout: [1]message.Incoming = undefined;
    const got = try client.receive(reply, now, &rout);
    try std.testing.expectEqual(@as(usize, 0), client.pendingAckCount()); // technical message
    var body = try message.parseServiceBody(arena, got.messages[0].body);
    defer body.deinit(arena);
    try std.testing.expectEqual(sent.msg_id, body.bad_server_salt.bad_msg_id);
    try std.testing.expectEqual(new_salt, body.bad_server_salt.new_server_salt);
    client.setServerSalt(body.bad_server_salt.new_server_salt);

    // Re-send the query under the new salt; the server sees it and the
    // client's pong comes back referencing the re-sent msg_id.
    const resent = try client.encode(now, true, w.items(), &cframe);
    try tcp.write(io, &cframe);
    const view2 = try ts.read(io, &srv, arena, &out);
    try std.testing.expectEqual(new_salt, view2.dec.salt);
    try std.testing.expect(view2.dec.msg_id > sent.msg_id);

    var rw = Writer.init(arena);
    try rw.writeConstructorId(message.pong_id);
    try rw.writeLong(resent.msg_id);
    try rw.writeLong(77);
    try ts.send(io, &srv, try ts.frame(arena, false, rw.items()));

    const reply2 = try tcp.read(io, arena);
    const got2 = try client.receive(reply2, now, &rout);
    var body2 = try message.parseServiceBody(arena, got2.messages[0].body);
    defer body2.deinit(arena);
    try std.testing.expectEqual(resent.msg_id, body2.pong.msg_id);
}

test "new_session_created is acknowledged over tcp full" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    var prng = std.Random.DefaultPrng.init(17);
    var client = try Session.init(std.testing.allocator, &auth_key, 0x51a1, prng.random());
    defer client.deinit();
    var ts = TestServer{ .session_id = client.session_id };

    // The server opens the session: new_session_created is content-related
    // (odd seq_no) and must be acknowledged by the client.
    var nw = Writer.init(arena);
    try nw.writeConstructorId(message.new_session_created_id);
    try nw.writeLong(base_id | 4);
    try nw.writeLong(0x5eed_c0de);
    try nw.writeLong(0x51a1);
    try ts.send(io, &srv, try ts.frame(arena, true, nw.items()));

    const reply = try tcp.read(io, arena);
    var rout: [1]message.Incoming = undefined;
    const got = try client.receive(reply, now, &rout);
    try std.testing.expectEqual(@as(i64, 0x51a1), got.salt);
    var body = try message.parseServiceBody(arena, got.messages[0].body);
    defer body.deinit(arena);
    try std.testing.expectEqual(base_id | 4, body.new_session_created.first_msg_id);
    try std.testing.expectEqual(@as(usize, 1), client.pendingAckCount());

    const alen = client.pendingAckFrameLength();
    const adst = try arena.alloc(u8, alen);
    try std.testing.expect((try client.flushAcks(now, adst)) != null);
    try tcp.write(io, adst);

    var out: [4]message.Incoming = undefined;
    const ack_view = try ts.read(io, &srv, arena, &out);
    var ack_body = try message.parseServiceBody(arena, ack_view.dec.body);
    defer ack_body.deinit(arena);
    try std.testing.expectEqual(@as(usize, 1), ack_body.msgs_ack.msg_ids.len);
    try std.testing.expectEqual(base_id | 1, ack_body.msgs_ack.msg_ids[0]); // the very first server id
}
