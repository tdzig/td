//! Frame-layer benchmarks: MTProto message construction and the
//! encrypted-frame hot path.
//!
//! - `Session.encode` — the full outgoing path (msg_id/seq generation,
//!   msg_key, AES-IGE, padding) into a caller buffer;
//! - `Session.encodeContainer` — 8-entry container envelope;
//! - `readEncrypted` — server-frame decrypt + msg_key verification only;
//! - `Session.receive` — decrypt plus full inbound validation (ids,
//!   time window, seq counter, ack queueing), in a service-message and
//!   a content-message (with ack flush) flavor.
//!
//! Server-side frames are re-encrypted between iterations (decryption is
//! in place and a buffer decrypts exactly once), so each measured op is
//! wrapped in its own timer; the per-op timing overhead is measured once
//! and reported so small-op figures can be read with it in mind.

const std = @import("std");
const td = @import("td");
const common = @import("common.zig");

const message = td.mtproto.message;
const Session = td.mtproto.Session;
const Writer = td.tl.Writer;

const bool_true_wire: [4]u8 = .{ 0xb5, 0x75, 0x72, 0x99 };

/// Stand-in for the peer's encryptor: builds server→client frames with
/// spec-correct ids and sequence numbers off the real clock.
const ServerSide = struct {
    io: std.Io,
    prng_state: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0xabc),
    next_low: u32 = 1,
    content: u32 = 0,

    fn msgId(self: *ServerSide) i64 {
        const s = @divTrunc(std.Io.Timestamp.now(self.io, .real).nanoseconds, std.time.ns_per_s);
        const id = (@as(i64, @intCast(s)) << 32) | self.next_low;
        self.next_low += 4;
        return id;
    }

    fn encryptInto(
        self: *ServerSide,
        session_id: i64,
        content_related: bool,
        body: []const u8,
        dst: []u8,
    ) !void {
        const seq: i32 = @intCast(2 * self.content + @as(u32, if (content_related) 1 else 0));
        if (content_related) self.content += 1;
        try message.writeEncrypted(&common.auth_key, .server_to_client, .{
            .salt = common.test_salt,
            .session_id = session_id,
            .msg_id = self.msgId(),
            .seq_no = seq,
            .body = body,
        }, self.prng_state.random(), dst);
    }
};

fn realNow(io: std.Io) u64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

fn fillPattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
}

pub fn run(gpa: std.mem.Allocator, io: std.Io) !void {
    {
        var total: u64 = 0;
        const t = common.Timer.begin(io);
        for (0..100_000) |_| {
            const x = common.Timer.begin(io);
            total += x.ns();
        }
        const per = t.ns() / 100_000;
        common.keep(total);
        std.debug.print("\n-- frame layer (per-op timing overhead ≈ {d} ns/op, included in figures) --\n", .{per});
    }

    var prng_state = std.Random.DefaultPrng.init(0x5e55);
    var session = try Session.init(gpa, &common.auth_key, common.test_salt, prng_state.random());
    defer session.deinit();

    var peer = ServerSide{ .io = io };

    var body_small: [64]u8 = undefined;
    fillPattern(&body_small);
    var body_large: [8192]u8 = undefined;
    fillPattern(&body_large);

    // rpc_result{boolTrue} body — the smallest realistic content message.
    var rpc_body: [16]u8 = undefined;
    {
        var w = Writer.init(gpa);
        defer w.deinit();
        try w.writeConstructorId(message.rpc_result_id);
        try w.writeLong(1);
        try w.writeRaw(&bool_true_wire);
        @memcpy(&rpc_body, w.items());
    }

    std.debug.print("\n-- message construction --\n", .{});
    try benchEncode(io, gpa, &session, "Session.encode 64 B body", &body_small, true, 200_000);
    try benchEncode(io, gpa, &session, "Session.encode 8 KiB body", &body_large, true, 10_000);
    try benchEncodeContainer(io, gpa, &session, "Session.encodeContainer 8×64 B", &body_small, 20_000);

    std.debug.print("\n-- frame decryption --\n", .{});
    try benchDecrypt(io, gpa, &peer, "readEncrypted 8 KiB frame", &body_large, 10_000);
    try benchReceiveService(io, gpa, &session, &peer, "Session.receive 64 B (service)", &body_small, 50_000);
    try benchReceiveContent(io, gpa, &session, &peer, "Session.receive + ack (content)", &rpc_body, 50_000);

    std.debug.print("\n-- frame-layer allocations --\n", .{});
    try benchFrameAllocs(io, gpa, &body_small, &rpc_body);
}

fn benchEncode(
    io: std.Io,
    gpa: std.mem.Allocator,
    session: *Session,
    label: []const u8,
    body: []const u8,
    content_related: bool,
    iters: usize,
) !void {
    const dst = try gpa.alloc(u8, message.frameLength(body.len));
    defer gpa.free(dst);
    const fixed_now: u64 = 1_700_000_000;

    for (0..100) |_| _ = try session.encode(fixed_now, content_related, body, dst);
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        const sent = try session.encode(fixed_now, content_related, body, dst);
        common.keep(@bitCast(sent.msg_id));
    }
    common.reportLine(label, body.len, t.ns(), iters);
}

fn benchEncodeContainer(
    io: std.Io,
    gpa: std.mem.Allocator,
    session: *Session,
    label: []const u8,
    body: []const u8,
    iters: usize,
) !void {
    var entries: [8]td.mtproto.session.ContainerEntry = undefined;
    for (&entries) |*e| e.* = .{ .body = body, .content_related = true };
    const dst = try gpa.alloc(u8, Session.containerFrameLength(&entries));
    defer gpa.free(dst);
    const fixed_now: u64 = 1_700_000_000;

    for (0..100) |_| _ = try session.encodeContainer(fixed_now, &entries, dst);
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        const sent = try session.encodeContainer(fixed_now, &entries, dst);
        common.keep(@bitCast(sent.msg_id));
    }
    common.reportLine(label, body.len * entries.len, t.ns(), iters);
}

fn benchDecrypt(
    io: std.Io,
    gpa: std.mem.Allocator,
    peer: *ServerSide,
    label: []const u8,
    body: []const u8,
    iters: usize,
) !void {
    const session_id: i64 = 0x1122_3344_5566_7788;
    const frame = try gpa.alloc(u8, message.frameLength(body.len));
    defer gpa.free(frame);

    for (0..100) |_| {
        // Untimed warm-up: a buffer decrypts exactly once, so each op
        // re-encrypts.
        try peer.encryptInto(session_id, false, body, frame);
        const dec = try message.readEncrypted(&common.auth_key, .server_to_client, session_id, frame);
        common.keep(@as(u64, @bitCast(dec.msg_id)));
    }
    var total: u64 = 0;
    for (0..iters) |_| {
        // Untimed: re-encrypt for this iteration.
        try peer.encryptInto(session_id, false, body, frame);
        const t = common.Timer.begin(io);
        const dec = try message.readEncrypted(&common.auth_key, .server_to_client, session_id, frame);
        total += t.ns();
        common.keep(@as(u64, @bitCast(dec.msg_id)));
    }
    common.reportLine(label, body.len, total, iters);
}

fn benchReceiveService(
    io: std.Io,
    gpa: std.mem.Allocator,
    session: *Session,
    peer: *ServerSide,
    label: []const u8,
    body: []const u8,
    iters: usize,
) !void {
    const frame = try gpa.alloc(u8, message.frameLength(body.len));
    defer gpa.free(frame);
    var out: [1]message.Incoming = undefined;

    for (0..100) |_| {
        try peer.encryptInto(session.session_id, false, body, frame);
        const got = try session.receive(frame, realNow(io), &out);
        common.keep(got.messages.len);
    }
    var total: u64 = 0;
    for (0..iters) |_| {
        try peer.encryptInto(session.session_id, false, body, frame);
        const t = common.Timer.begin(io);
        const got = try session.receive(frame, realNow(io), &out);
        total += t.ns();
        common.keep(got.messages.len);
    }
    common.reportLine(label, body.len, total, iters);
}

/// Content-related receives queue an acknowledgement each; the pump
/// flushes them per iteration, so receive + flushAcks is the honest
/// per-message inbound cost. Warm-up acks are drained before the ack
/// buffer is sized, keeping the steady state at one ack per op.
fn benchReceiveContent(
    io: std.Io,
    gpa: std.mem.Allocator,
    session: *Session,
    peer: *ServerSide,
    label: []const u8,
    body: []const u8,
    iters: usize,
) !void {
    const frame = try gpa.alloc(u8, message.frameLength(body.len));
    defer gpa.free(frame);
    var out: [1]message.Incoming = undefined;

    for (0..100) |_| {
        try peer.encryptInto(session.session_id, true, body, frame);
        const got = try session.receive(frame, realNow(io), &out);
        common.keep(got.messages.len);
    }
    const drain_len = session.pendingAckFrameLength();
    const drain = try gpa.alloc(u8, drain_len);
    defer gpa.free(drain);
    while (session.pendingAckCount() > 0) {
        _ = try session.flushAcks(realNow(io), drain);
    }

    // Size the ack buffer from the steady state: exactly one queued ack,
    // flushed immediately so the measured loop starts (and stays) at one.
    try peer.encryptInto(session.session_id, true, body, frame);
    _ = try session.receive(frame, realNow(io), &out);
    const ack_dst = try gpa.alloc(u8, session.pendingAckFrameLength());
    defer gpa.free(ack_dst);
    _ = try session.flushAcks(realNow(io), ack_dst);

    var total: u64 = 0;
    for (0..iters) |_| {
        try peer.encryptInto(session.session_id, true, body, frame);
        const t = common.Timer.begin(io);
        const got = try session.receive(frame, realNow(io), &out);
        _ = try session.flushAcks(realNow(io), ack_dst);
        total += t.ns();
        common.keep(got.messages.len);
    }
    common.reportLine(label, body.len, total, iters);
}

fn benchFrameAllocs(io: std.Io, gpa: std.mem.Allocator, body_small: []const u8, rpc_body: *const [16]u8) !void {
    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var prng_state = std.Random.DefaultPrng.init(0x5e55);
    var session = try Session.init(a, &common.auth_key, common.test_salt, prng_state.random());
    defer session.deinit();
    var peer = ServerSide{ .io = io };
    const fixed_now: u64 = 1_700_000_000;

    // Outgoing single message: the frame is built in a caller-owned
    // buffer, so the steady-state expectation is zero allocations.
    const dst = try a.alloc(u8, message.frameLength(body_small.len));
    defer a.free(dst);
    for (0..100) |_| _ = try session.encode(fixed_now, true, body_small, dst);
    c.reset();
    for (0..1_000) |_| _ = try session.encode(fixed_now, true, body_small, dst);
    common.reportAllocs("Session.encode 64 B", 1_000, &c);

    // Container: the inner-slot array plus the container-body writer.
    var entries: [8]td.mtproto.session.ContainerEntry = undefined;
    for (&entries) |*e| e.* = .{ .body = body_small, .content_related = true };
    const cdst = try a.alloc(u8, Session.containerFrameLength(&entries));
    defer a.free(cdst);
    for (0..100) |_| _ = try session.encodeContainer(fixed_now, &entries, cdst);
    c.reset();
    for (0..1_000) |_| _ = try session.encodeContainer(fixed_now, &entries, cdst);
    common.reportAllocs("Session.encodeContainer 8×64 B", 1_000, &c);

    // Receive + ack flush: decrypt is in place; the ack list append and
    // the msgs_ack writer are the allocation-relevant parts.
    const frame = try a.alloc(u8, message.frameLength(rpc_body.len));
    defer a.free(frame);
    var out: [1]message.Incoming = undefined;
    for (0..100) |_| {
        try peer.encryptInto(session.session_id, true, rpc_body, frame);
        _ = try session.receive(frame, realNow(io), &out);
    }
    const drain_len = session.pendingAckFrameLength();
    const drain = try a.alloc(u8, drain_len);
    defer a.free(drain);
    while (session.pendingAckCount() > 0) {
        _ = try session.flushAcks(realNow(io), drain);
    }

    // Size from the steady state: exactly one queued ack, flushed
    // immediately so the measured loop starts (and stays) at one.
    try peer.encryptInto(session.session_id, true, rpc_body, frame);
    _ = try session.receive(frame, realNow(io), &out);
    const ack_dst = try a.alloc(u8, session.pendingAckFrameLength());
    defer a.free(ack_dst);
    _ = try session.flushAcks(realNow(io), ack_dst);

    c.reset();
    for (0..1_000) |_| {
        try peer.encryptInto(session.session_id, true, rpc_body, frame);
        _ = try session.receive(frame, realNow(io), &out);
        _ = try session.flushAcks(realNow(io), ack_dst);
    }
    common.reportAllocs("Session.receive + ack flush", 1_000, &c);
}
