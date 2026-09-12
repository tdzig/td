//! Transport integration tests: all four TCP framings — full, abridged,
//! intermediate, padded intermediate — over real sockets on the loopback
//! interface.
//!
//! Everything runs single-threaded on a blocking `Io.Threaded` driver:
//! client and "server" alternate on blocking reads/writes in one thread,
//! which keeps the choreography deterministic (the TCP handshake completes
//! in the kernel backlog before `accept`, so connect → accept ordering is
//! safe). Golden byte vectors pin each wire format against the
//! specification, so a shared client/server layout mistake cannot pass
//! silently.

const std = @import("std");
const net = std.Io.net;
const td = @import("td");

const transport = td.transport;
const TcpFull = transport.TcpFull;
const tcp_full = transport.tcp_full;
const message = td.mtproto.message;

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

/// Reads one raw frame on the server side; verifies the checksum and
/// returns the payload (allocated from `arena`) and its sequence number.
fn serverReadFrame(io: std.Io, stream: *net.Stream, arena: std.mem.Allocator) !struct { payload: []u8, seq: u32 } {
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
    return .{ .payload = payload, .seq = parsed.seq };
}

/// Sends one raw frame from the server side with an explicit sequence
/// number; `corrupt_checksum` flips the crc for negative tests.
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

fn serverSendFrame(io: std.Io, stream: *net.Stream, payload: []const u8, seq: u32, corrupt_checksum: bool) !void {
    const h = tcp_full.Codec.header(payload.len, seq);
    var crc = tcp_full.Codec.checksum(&h, payload);
    if (corrupt_checksum) crc ^= 0xffff_ffff;
    var trailer: [4]u8 = undefined;
    std.mem.writeInt(u32, &trailer, crc, .little);
    try sendFrameRaw(io, stream, &h, payload, &trailer);
}

test "tcp full: framed roundtrip over loopback" {
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

    // Client sends two frames; the server checks the exact wire layout:
    // sequence numbers start at zero and advance per frame.
    try tcp.write(io, "hello, telegram");
    try tcp.write(io, "second frame");
    const f1 = try serverReadFrame(io, &srv, arena);
    try std.testing.expectEqualStrings("hello, telegram", f1.payload);
    try std.testing.expectEqual(@as(u32, 0), f1.seq);
    const f2 = try serverReadFrame(io, &srv, arena);
    try std.testing.expectEqualStrings("second frame", f2.payload);
    try std.testing.expectEqual(@as(u32, 1), f2.seq);

    // Server replies; the client reassembles frame from raw bytes.
    try serverSendFrame(io, &srv, "pong", 0, false);
    const reply = try tcp.read(io, arena);
    try std.testing.expectEqualStrings("pong", reply);
}

test "tcp full: inbound sequence numbers verified when enabled" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = TcpFull.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{ .verify_sequence = true },
    );
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    try serverSendFrame(io, &srv, "first", 0, false);
    const f = try tcp.read(io, arena);
    try std.testing.expectEqualStrings("first", f);

    // A sequence gap must be rejected and the connection torn down.
    try serverSendFrame(io, &srv, "skipped-one", 2, false);
    try std.testing.expectError(error.InvalidFrame, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp full: corrupt checksum rejected" {
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

    try serverSendFrame(io, &srv, "tampered", 0, true);
    try std.testing.expectError(error.InvalidFrame, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp full: impossible frame length rejected" {
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

    // A length that cannot even fit the overhead is not a frame.
    var bad: [8]u8 = undefined;
    std.mem.writeInt(u32, bad[0..4], 8, .little);
    std.mem.writeInt(u32, bad[4..8], 0, .little);
    try writeAllRaw(io, &srv, &bad);
    try std.testing.expectError(error.InvalidFrame, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp full: oversized frame rejected" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = TcpFull.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{ .max_payload = 16 },
    );
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    var hdr: [8]u8 = undefined;
    std.mem.writeInt(u32, hdr[0..4], 1024, .little);
    std.mem.writeInt(u32, hdr[4..8], 0, .little);
    try writeAllRaw(io, &srv, &hdr);
    try std.testing.expectError(error.MessageTooLarge, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp full: peer close surfaces as Disconnected" {
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

    try srv.shutdown(io, .send);
    try std.testing.expectError(error.Disconnected, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp full: reconnect establishes a fresh session" {
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

    var srv1 = try server.accept(io);
    defer srv1.close(io);

    try tcp.write(io, "first session");
    const f1 = try serverReadFrame(io, &srv1, arena);
    try std.testing.expectEqual(@as(u32, 0), f1.seq);

    // The server drops the connection; reconnect() (through the
    // type-erased interface) must produce a brand-new session whose
    // sequence numbers restart at zero.
    try srv1.shutdown(io, .send);
    const t = tcp.transport();
    try t.reconnect(io);

    var srv2 = try server.accept(io);
    defer srv2.close(io);

    try tcp.write(io, "second session");
    const f2 = try serverReadFrame(io, &srv2, arena);
    try std.testing.expectEqualStrings("second session", f2.payload);
    try std.testing.expectEqual(@as(u32, 0), f2.seq);
}

test "tcp full: clean read timeout leaves the connection usable" {
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

    // A zero timeout is already expired: the read must fail without
    // consuming any bytes and without killing the connection.
    tcp.options.read_timeout = std.Io.Duration.zero;
    try std.testing.expectError(error.TimedOut, tcp.read(io, arena));
    try std.testing.expect(tcp.isConnected());

    tcp.options.read_timeout = null;
    try serverSendFrame(io, &srv, "late reply", 0, false);
    const reply = try tcp.read(io, arena);
    try std.testing.expectEqualStrings("late reply", reply);
}

test "tcp full: empty payload frames" {
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

    // An empty payload is the smallest valid frame (length field 12).
    try tcp.write(io, "");
    const f1 = try serverReadFrame(io, &srv, arena);
    try std.testing.expectEqual(@as(usize, 0), f1.payload.len);
    try std.testing.expectEqual(@as(u32, 0), f1.seq);

    try serverSendFrame(io, &srv, "", 0, false);
    const reply = try tcp.read(io, arena);
    try std.testing.expectEqual(@as(usize, 0), reply.len);

    // Framing stays aligned afterwards; the counter advanced.
    try tcp.write(io, "after empty");
    const f2 = try serverReadFrame(io, &srv, arena);
    try std.testing.expectEqualStrings("after empty", f2.payload);
    try std.testing.expectEqual(@as(u32, 1), f2.seq);
}

test "tcp full: lifecycle errors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = TcpFull.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{ .max_payload = 8 },
    );

    try std.testing.expect(!tcp.isConnected());
    try std.testing.expectError(error.NotConnected, tcp.write(io, "x"));
    try std.testing.expectError(error.NotConnected, tcp.read(io, arena));

    try tcp.connect(io);
    defer tcp.close(io);
    var srv = try server.accept(io);
    defer srv.close(io);

    try std.testing.expectError(error.AlreadyConnected, tcp.connect(io));

    // The outbound size limit is checked before the socket is touched, so
    // the connection survives it.
    // "short" (5) fits; "too long" (9) exceeds — a payload of exactly
    // max_payload bytes is legal.
    try std.testing.expectError(error.MessageTooLarge, tcp.write(io, "too long!"));
    try std.testing.expect(tcp.isConnected());
    try tcp.write(io, "short");

    tcp.close(io);
    try std.testing.expectError(error.NotConnected, tcp.write(io, "x"));
    try std.testing.expectError(error.NotConnected, tcp.read(io, arena));

    // Closing twice is safe.
    tcp.close(io);
}

test "tcp full: type-erased Transport interface drives a session" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    const t = tcp.transport();

    try t.connect(io);
    defer t.close(io);
    try std.testing.expect(t.isConnected());

    var srv = try server.accept(io);
    defer srv.close(io);

    try t.write(io, "via interface");
    const f = try serverReadFrame(io, &srv, arena);
    try std.testing.expectEqualStrings("via interface", f.payload);

    try serverSendFrame(io, &srv, "interface reply", 0, false);
    const reply = try t.read(io, arena);
    try std.testing.expectEqualStrings("interface reply", reply);
}

// ---------------------------------------------------------------------------
// Abridged / intermediate / padded intermediate
//
// The three tag-prefixed framings share `tcp_framed.Framed`; the tests
// below pin each wire format with golden bytes (spec-anchored, so the
// client and the test-side server cannot share a mirror-image bug) and
// exercise the shared machinery: timeouts, truncation, reconnects.

/// One raw write of all `parts` in a single vectored push (separate small
/// writes stall on Nagle + delayed ACK in a request/response exchange).
fn writeVecRaw(io: std.Io, stream: *net.Stream, parts: []const []const u8) !void {
    var total: usize = 0;
    for (parts) |p| total += p.len;
    var sent: usize = 0;
    while (sent < total) {
        var iovecs: [4][]const u8 = undefined;
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

/// Server side: the stream must start with exactly `tag`.
fn expectTag(io: std.Io, stream: *net.Stream, tag: []const u8) !void {
    var got: [4]u8 = undefined;
    try readExactRaw(io, stream, got[0..tag.len]);
    try std.testing.expectEqualSlices(u8, tag, got[0..tag.len]);
}

/// Server side: one abridged frame, golden-parsed. Returns the payload.
fn abridgedReadFrame(io: std.Io, stream: *net.Stream, arena: std.mem.Allocator) ![]u8 {
    try expectTag(io, stream, "\xef");
    var probe: [1]u8 = undefined;
    try readExactRaw(io, stream, &probe);
    var plen: usize = undefined;
    switch (probe[0]) {
        0x7f => {
            var rest: [3]u8 = undefined;
            try readExactRaw(io, stream, &rest);
            plen = (@as(usize, rest[0]) | @as(usize, rest[1]) << 8 | @as(usize, rest[2]) << 16) * 4;
        },
        0...0x7e => plen = @as(usize, probe[0]) * 4,
        else => return error.BadFrame,
    }
    const buf = try arena.alloc(u8, plen);
    try readExactRaw(io, stream, buf);
    return buf;
}

/// Server side: one intermediate-style frame (`0xeeee_eeee`, or the
/// padded variant's `0xdddd_dddd` tag). Returns payload+padding as
/// delivered — the padding belongs to the frame.
fn taggedReadFrame(io: std.Io, stream: *net.Stream, arena: std.mem.Allocator, tag: []const u8) ![]u8 {
    try expectTag(io, stream, tag);
    var h: [4]u8 = undefined;
    try readExactRaw(io, stream, &h);
    const plen = std.mem.readInt(u32, &h, .little);
    if (plen >> 31 != 0) return error.BadFrame;
    const buf = try arena.alloc(u8, plen);
    try readExactRaw(io, stream, buf);
    return buf;
}

test "tcp abridged: tag and framed roundtrip over loopback" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpAbridged.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // The connection starts with exactly one 0xef tag, then the frame:
    // one byte of length/4 and the payload.
    try tcp.write(io, "abcd");
    try expectTag(io, &srv, "\xef");
    var len_byte: [1]u8 = undefined;
    try readExactRaw(io, &srv, &len_byte);
    try std.testing.expectEqual(@as(u8, 0x01), len_byte[0]);
    var payload: [4]u8 = undefined;
    try readExactRaw(io, &srv, &payload);
    try std.testing.expectEqualStrings("abcd", &payload);

    // The server answers with a hand-written golden frame: length/4 = 1.
    try writeVecRaw(io, &srv, &.{ &[_]u8{0x01}, "pong" });
    const reply = try tcp.read(io, arena);
    try std.testing.expectEqualStrings("pong", reply);

    // A second frame goes out without repeating the tag.
    try tcp.write(io, "second frame"); // 12 bytes -> length/4 = 3
    var len2: [1]u8 = undefined;
    try readExactRaw(io, &srv, &len2);
    try std.testing.expectEqual(@as(u8, 0x03), len2[0]);
    var payload2: [12]u8 = undefined;
    try readExactRaw(io, &srv, &payload2);
    try std.testing.expectEqualStrings("second frame", &payload2);
}

test "tcp abridged: long-form frames over loopback" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpAbridged.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // payload/4 == 127: the smallest long-form payload (0x7f + 3 bytes).
    var big: [508]u8 = undefined;
    @memset(&big, 'A');
    try tcp.write(io, &big);
    const got = try abridgedReadFrame(io, &srv, arena);
    try std.testing.expectEqualSlices(u8, &big, got);

    // The server's long form: 0x7f, then 512/4 = 0x80 little-endian.
    var reply: [512]u8 = undefined;
    @memset(&reply, 'B');
    try writeVecRaw(io, &srv, &.{ &[_]u8{ 0x7f, 0x80, 0x00, 0x00 }, &reply });
    const back = try tcp.read(io, arena);
    try std.testing.expectEqualSlices(u8, &reply, back);
}

test "tcp abridged: frame byte above 0x7f rejected" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpAbridged.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // 0xef is never a valid inbound length byte (quick-ack tokens live
    // there, and this client never requests them).
    try writeAllRaw(io, &srv, &[_]u8{0xef});
    try std.testing.expectError(error.InvalidFrame, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp abridged: oversized long-form frame rejected" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpAbridged.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{ .max_payload = 16 },
    );
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // length/4 = 8 -> a 32-byte payload, above the 16-byte cap.
    try writeAllRaw(io, &srv, &[_]u8{ 0x7f, 8, 0, 0 });
    try std.testing.expectError(error.MessageTooLarge, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp abridged: outbound alignment checked before the socket" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpAbridged.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // A payload not divisible by four cannot be framed; the check fires
    // before any byte is written and the connection survives.
    try std.testing.expectError(error.InvalidFrame, tcp.write(io, "abc"));
    try std.testing.expect(tcp.isConnected());
}

test "tcp abridged: reconnect resends the initial tag" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpAbridged.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv1 = try server.accept(io);
    defer srv1.close(io);
    try tcp.write(io, "session one!");
    _ = try abridgedReadFrame(io, &srv1, arena);

    // A fresh connection carries the tag again.
    try srv1.shutdown(io, .send);
    const t = tcp.transport();
    try t.reconnect(io);

    var srv2 = try server.accept(io);
    defer srv2.close(io);
    try tcp.write(io, "session two!");
    // abridgedReadFrame asserts the tag precedes the frame.
    const got = try abridgedReadFrame(io, &srv2, arena);
    try std.testing.expectEqualStrings("session two!", got);
}

test "tcp abridged: lifecycle errors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpAbridged.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try std.testing.expect(!tcp.isConnected());
    try std.testing.expectError(error.NotConnected, tcp.write(io, "x"));
    try std.testing.expectError(error.NotConnected, tcp.read(io, arena));

    try tcp.connect(io);
    defer tcp.close(io);
    var srv = try server.accept(io);
    defer srv.close(io);
    try std.testing.expectError(error.AlreadyConnected, tcp.connect(io));

    tcp.close(io);
    try std.testing.expectError(error.NotConnected, tcp.write(io, "x"));
    try std.testing.expectError(error.NotConnected, tcp.read(io, arena));
    tcp.close(io); // idempotent
}

test "tcp intermediate: tag and framed roundtrip over loopback" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpIntermediate.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // 0xeeee_eeee tag, then a 4-byte little-endian length counting only
    // the payload.
    try tcp.write(io, "abcd");
    try expectTag(io, &srv, "\xee\xee\xee\xee");
    var h: [4]u8 = undefined;
    try readExactRaw(io, &srv, &h);
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, &h, .little));
    var payload: [4]u8 = undefined;
    try readExactRaw(io, &srv, &payload);
    try std.testing.expectEqualStrings("abcd", &payload);

    // Golden reply: length 4, then the bytes.
    try writeVecRaw(io, &srv, &.{ &[_]u8{ 4, 0, 0, 0 }, "pong" });
    const reply = try tcp.read(io, arena);
    try std.testing.expectEqualStrings("pong", reply);
}

test "tcp intermediate: quick-ack slot rejected" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpIntermediate.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // A length with the most-significant bit set is the quick-ack slot;
    // this client never requests quick acks, so it is a framing error.
    try writeAllRaw(io, &srv, &[_]u8{ 0, 0, 0, 0x80 });
    try std.testing.expectError(error.InvalidFrame, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp intermediate: oversized frame rejected" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpIntermediate.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{ .max_payload = 16 },
    );
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    try writeAllRaw(io, &srv, &[_]u8{ 32, 0, 0, 0 });
    try std.testing.expectError(error.MessageTooLarge, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp intermediate: empty payload frames" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpIntermediate.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // An empty payload is the smallest valid frame (length field 0).
    try tcp.write(io, "");
    try expectTag(io, &srv, "\xee\xee\xee\xee");
    var h: [4]u8 = undefined;
    try readExactRaw(io, &srv, &h);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, &h, .little));

    try writeVecRaw(io, &srv, &.{&[_]u8{ 0, 0, 0, 0 }});
    const reply = try tcp.read(io, arena);
    try std.testing.expectEqual(@as(usize, 0), reply.len);

    // Framing stays aligned afterwards (the tag went out once, above).
    try tcp.write(io, "after empty!");
    var h2: [4]u8 = undefined;
    try readExactRaw(io, &srv, &h2);
    try std.testing.expectEqual(@as(u32, 12), std.mem.readInt(u32, &h2, .little));
    var payload2: [12]u8 = undefined;
    try readExactRaw(io, &srv, &payload2);
    try std.testing.expectEqualStrings("after empty!", &payload2);
}

test "tcp intermediate: truncated frame surfaces as Disconnected" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpIntermediate.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // The header promises 16 bytes; the peer delivers 4 and hangs up.
    try writeVecRaw(io, &srv, &.{ &[_]u8{ 16, 0, 0, 0 }, "abcd" });
    try srv.shutdown(io, .send);
    try std.testing.expectError(error.Disconnected, tcp.read(io, arena));
    try std.testing.expect(!tcp.isConnected());
}

test "tcp intermediate: clean read timeout leaves the connection usable" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var tcp = transport.TcpIntermediate.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    // A zero timeout is already expired: the read must fail without
    // consuming any bytes and without killing the connection.
    tcp.options.read_timeout = std.Io.Duration.zero;
    try std.testing.expectError(error.TimedOut, tcp.read(io, arena));
    try std.testing.expect(tcp.isConnected());

    tcp.options.read_timeout = null;
    try writeVecRaw(io, &srv, &.{ &[_]u8{ 10, 0, 0, 0 }, "late reply" });
    const reply = try tcp.read(io, arena);
    try std.testing.expectEqualStrings("late reply", reply);
}

test "tcp padded intermediate: tag, zero padding without randomness" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    // No randomness source -> zero-length padding: intermediate framing
    // under the padded tag, byte for byte.
    var tcp = transport.TcpPaddedIntermediate.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    try tcp.write(io, "abcd");
    try expectTag(io, &srv, "\xdd\xdd\xdd\xdd");
    var h: [4]u8 = undefined;
    try readExactRaw(io, &srv, &h);
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, &h, .little));
    var payload: [4]u8 = undefined;
    try readExactRaw(io, &srv, &payload);
    try std.testing.expectEqualStrings("abcd", &payload);

    // Inbound frames arrive *with* their padding: length counts
    // payload+padding, and the read returns all seven bytes. Stripping
    // the tail is the MTProto layer's job (it recovers the exact message
    // length from the decrypted frame).
    try writeVecRaw(io, &srv, &.{ &[_]u8{ 7, 0, 0, 0 }, "pong", &[_]u8{ 0xAA, 0xBB, 0xCC } });
    const reply = try tcp.read(io, arena);
    try std.testing.expectEqualStrings("pong\xAA\xBB\xCC", reply);
}

test "tcp padded intermediate: random padding stays within 0..15" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try startServer(io);
    defer server.deinit(io);

    var prng = std.Random.DefaultPrng.init(0xbeef);
    var tcp = transport.TcpPaddedIntermediate.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{ .random = prng.random() },
    );
    try tcp.connect(io);
    defer tcp.close(io);

    var srv = try server.accept(io);
    defer srv.close(io);

    var payload: [16]u8 = undefined;
    @memset(&payload, 'P');
    try tcp.write(io, &payload);

    // tlen = payload + pad, pad in 0..15, and the payload leads the frame.
    try expectTag(io, &srv, "\xdd\xdd\xdd\xdd");
    var h: [4]u8 = undefined;
    try readExactRaw(io, &srv, &h);
    const tlen = std.mem.readInt(u32, &h, .little);
    try std.testing.expect(tlen >= 16 and tlen < 32);
    const frame = try arena.alloc(u8, tlen);
    try readExactRaw(io, &srv, frame);
    try std.testing.expectEqualSlices(u8, &payload, frame[0..16]);
}

test "encrypted mtproto payload passes through every framing unchanged" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // One honest MTProto 2.0 encrypted frame; the transport mode must not
    // touch a single byte of it.
    var key: [256]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @truncate(i *% 61 +% 17);
    var body: [8]u8 = undefined;
    std.mem.writeInt(u32, body[0..4], 0x1fb33026, .little);
    std.mem.writeInt(u32, body[4..8], 0, .little);
    var prng = std.Random.DefaultPrng.init(9);
    var frame: [message.frameLength(body.len)]u8 = undefined;
    try message.writeEncrypted(&key, .client_to_server, .{
        .salt = 0x51a1,
        .session_id = 0x1234,
        .msg_id = (@as(i64, 1_700_000_000) << 32) | 4,
        .seq_no = 1,
        .body = &body,
    }, prng.random(), &frame);

    // Abridged.
    {
        var server = try startServer(io);
        defer server.deinit(io);
        var tcp = transport.TcpAbridged.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
        try tcp.connect(io);
        defer tcp.close(io);
        var srv = try server.accept(io);
        defer srv.close(io);
        try tcp.write(io, &frame);
        try std.testing.expectEqualSlices(u8, &frame, try abridgedReadFrame(io, &srv, arena));
    }
    // Intermediate.
    {
        var server = try startServer(io);
        defer server.deinit(io);
        var tcp = transport.TcpIntermediate.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
        try tcp.connect(io);
        defer tcp.close(io);
        var srv = try server.accept(io);
        defer srv.close(io);
        try tcp.write(io, &frame);
        try std.testing.expectEqualSlices(u8, &frame, try taggedReadFrame(io, &srv, arena, "\xee\xee\xee\xee"));
    }
    // Padded intermediate (zero padding, no randomness source).
    {
        var server = try startServer(io);
        defer server.deinit(io);
        var tcp = transport.TcpPaddedIntermediate.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
        try tcp.connect(io);
        defer tcp.close(io);
        var srv = try server.accept(io);
        defer srv.close(io);
        try tcp.write(io, &frame);
        try std.testing.expectEqualSlices(u8, &frame, try taggedReadFrame(io, &srv, arena, "\xdd\xdd\xdd\xdd"));
    }
    // Full.
    {
        var server = try startServer(io);
        defer server.deinit(io);
        var tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = server.socket.address.getPort() }, .{});
        try tcp.connect(io);
        defer tcp.close(io);
        var srv = try server.accept(io);
        defer srv.close(io);
        try tcp.write(io, &frame);
        const f = try serverReadFrame(io, &srv, arena);
        try std.testing.expectEqualSlices(u8, &frame, f.payload);
    }
}
