//! Stateful MTProto session for one encrypted client connection.
//!
//! Owns everything `message.zig` deliberately leaves to the caller:
//!
//! - outgoing msg_id generation (monotone, divisible by 4, low 32 bits
//!   non-empty, tracking unixtime·2^32 — clock regressions are absorbed
//!   by continuing from the last id);
//! - outgoing seq_no generation (`2·content_count + content` per the spec);
//! - inbound validation: msg_id parity/monotonicity/time-window (reject
//!   >30 s future / >300 s past — the codes-16/17/20 family), the strict
//!   seq_no counter (codes 18/19), container id ordering (code 64);
//! - pending acknowledgements: content-related received messages are
//!   queued automatically and drained with `flushAcks` as `msgs_ack`
//!   service messages (grouped per the spec's 8192-id recommendation).
//!
//! Failed validation leaves the session state untouched — counters are
//! committed only after a frame passes every check, so a rejected frame
//! cannot desynchronize the seq_no expectations for later frames.
//!
//! The session is transport-independent: it produces and consumes whole
//! encrypted frames. Wire delivery is the transport layer's job
//! (`tdzig.transport`); see tests/message_session.zig for the composition.
//! `auth_key` is secret — this module never logs anything.

const std = @import("std");
const crypto = @import("../crypto/mod.zig");
const message = @import("message.zig");
const tl = @import("../tl/mod.zig");
const Writer = tl.Writer;
const Reader = tl.Reader;

pub const Error = message.Error;

/// One nested message to place in an outgoing container.
pub const ContainerEntry = struct {
    body: []const u8,
    /// Whether this entry is content-related (needs an ack from the
    /// server); RPC queries are, technical messages are not.
    content_related: bool,
};

/// The flattened result of receiving one server frame.
pub const Received = struct {
    salt: i64,
    outer_msg_id: i64,
    outer_seq_no: i32,
    is_container: bool,
    /// One entry per logical message: a single entry for plain frames,
    /// all nested entries for containers. Bodies borrow from the frame
    /// buffer passed to `receive`.
    messages: []message.Incoming,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    random: std.Random,
    /// Secret; never logged or exposed outside the process.
    auth_key: [crypto.auth_key_size]u8,
    auth_key_id: [8]u8,
    /// Random non-zero id, constant for the connection lifetime; the
    /// server echoes it in every encrypted frame.
    session_id: i64,
    server_salt: i64,

    // Outgoing generation state.
    last_msg_id: i64 = 0,
    content_count: u32 = 0,

    // Inbound validation state. Strictly increasing msg_ids double as
    // duplicate detection (the spec's "last N received msg_ids" store).
    highest_remote_msg_id: i64 = 0,
    remote_content_count: u32 = 0,

    // Pending acknowledgements; consumed from `ack_offset` so partial
    // flushes (spec: group at most 8192 ids) don't shift the queue.
    acks: std.ArrayList(i64) = .empty,
    ack_offset: usize = 0,

    /// Creates a session over an established authorization key. The
    /// session_id is drawn from `random`; `server_salt` is the one the
    /// handshake derived (or a later `bad_server_salt`/`new_session_created`
    /// value, applied with `setServerSalt`).
    pub fn init(
        allocator: std.mem.Allocator,
        auth_key: *const [crypto.auth_key_size]u8,
        server_salt: i64,
        random: std.Random,
    ) Error!Session {
        return .{
            .allocator = allocator,
            .random = random,
            .auth_key = auth_key.*,
            .auth_key_id = crypto.authKeyId(auth_key),
            .session_id = randomSessionId(random),
            .server_salt = server_salt,
        };
    }

    pub fn deinit(self: *Session) void {
        self.acks.deinit(self.allocator);
    }

    /// Adopts a new server salt (from `bad_server_salt` or
    /// `new_session_created`); used for every subsequent outgoing frame.
    pub fn setServerSalt(self: *Session, salt: i64) void {
        self.server_salt = salt;
    }

    /// Resets per-connection state for a reconnect: fresh random
    /// session_id, zeroed counters, dropped pending acks. The auth_key
    /// and the current server salt are kept.
    pub fn reset(self: *Session) void {
        self.session_id = randomSessionId(self.random);
        self.last_msg_id = 0;
        self.content_count = 0;
        self.highest_remote_msg_id = 0;
        self.remote_content_count = 0;
        self.acks.clearRetainingCapacity();
        self.ack_offset = 0;
    }

    /// Next client msg_id: monotonically increasing, divisible by four,
    /// low 32 bits non-empty, ≈ unixtime·2^32.
    pub fn nextMsgId(self: *Session, now_seconds: u64) i64 {
        var candidate: u64 = (@as(u64, now_seconds) << 32) | 4;
        const last: u64 = @bitCast(self.last_msg_id);
        if (candidate <= last) candidate = last + 4;
        self.last_msg_id = @bitCast(candidate);
        return self.last_msg_id;
    }

    /// Next outgoing seq_no per the spec formula
    /// `2·(content messages so far) + (1 if content-related else 0)`;
    /// only content-related messages advance the counter.
    pub fn nextSeqNo(self: *Session, content_related: bool) i32 {
        const seq: i32 = @intCast(2 * self.content_count + @as(u32, if (content_related) 1 else 0));
        if (content_related) self.content_count += 1;
        return seq;
    }

    /// Stamps a fresh msg_id/seq_no and writes the encrypted frame into
    /// `dst` (size it with `message.frameLength(body.len)`).
    pub fn encode(
        self: *Session,
        now_seconds: u64,
        content_related: bool,
        body: []const u8,
        dst: []u8,
    ) Error!message.Sent {
        return self.encodeMessage(.{
            .salt = self.server_salt,
            .session_id = self.session_id,
            .msg_id = self.nextMsgId(now_seconds),
            .seq_no = self.nextSeqNo(content_related),
            .body = body,
        }, dst);
    }

    /// `encode` under an explicit msg_id — for the one wire case where
    /// the body embeds the msg_id it travels under (the PFS
    /// `auth.bindTempAuthKey` payload). The id must come from this
    /// session's own counter (`nextMsgId`); seq_no generation is normal.
    pub fn encodeWithId(
        self: *Session,
        msg_id: i64,
        content_related: bool,
        body: []const u8,
        dst: []u8,
    ) Error!message.Sent {
        return self.encodeMessage(.{
            .salt = self.server_salt,
            .session_id = self.session_id,
            .msg_id = msg_id,
            .seq_no = self.nextSeqNo(content_related),
            .body = body,
        }, dst);
    }

    /// Frame size `encodeContainer` writes for these entries.
    pub fn containerFrameLength(entries: []const ContainerEntry) usize {
        var body: usize = 8; // constructor id + count
        for (entries) |e| body += 16 + e.body.len;
        return message.frameLength(body);
    }

    /// Builds one frame carrying a `msg_container` of the given bodies.
    /// Each entry is stamped individually (content-related entries get
    /// odd seq_nos and advance the counter); the container itself is
    /// stamped last, so its msg_id is strictly greater than every inner
    /// one and its seq_no is the (even) service value — exactly what the
    /// spec requires. `dst` sized via `containerFrameLength`.
    pub fn encodeContainer(
        self: *Session,
        now_seconds: u64,
        entries: []const ContainerEntry,
        dst: []u8,
    ) Error!message.Sent {
        const inner = self.allocator.alloc(message.Incoming, entries.len) catch return error.OutOfMemory;
        defer self.allocator.free(inner);
        for (entries, inner) |entry, *m| {
            m.* = .{
                .msg_id = self.nextMsgId(now_seconds),
                .seq_no = self.nextSeqNo(entry.content_related),
                .body = entry.body,
            };
        }
        var w = Writer.init(self.allocator);
        defer w.deinit();
        message.writeContainer(&w, inner) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidLength,
        };
        return self.encodeMessage(.{
            .salt = self.server_salt,
            .session_id = self.session_id,
            .msg_id = self.nextMsgId(now_seconds),
            .seq_no = self.nextSeqNo(false),
            .body = w.items(),
        }, dst);
    }

    fn encodeMessage(self: *Session, msg: message.Outgoing, dst: []u8) Error!message.Sent {
        try message.writeEncrypted(&self.auth_key, .client_to_server, msg, self.random, dst);
        return .{ .msg_id = msg.msg_id, .seq_no = msg.seq_no };
    }

    /// Decrypts, validates and flattens one server→client frame **in
    /// place** (`buf` is mutated; returned bodies borrow from it).
    /// `out` receives one entry per logical message — plain frames need
    /// capacity 1, containers up to 1024 (`ContainerTooLarge` otherwise).
    /// Content-related messages are queued for acknowledgement; drain
    /// with `flushAcks`. On error the session state is unchanged.
    pub fn receive(
        self: *Session,
        buf: []u8,
        now_seconds: u64,
        out: []message.Incoming,
    ) Error!Received {
        if (out.len == 0) return error.ContainerTooLarge;
        const outer = try message.readEncrypted(&self.auth_key, .server_to_client, self.session_id, buf);

        if (!message.isValidServerMsgId(outer.msg_id)) return error.MsgIdInvalid;
        if (outer.msg_id <= self.highest_remote_msg_id) return error.MsgIdOutOfOrder;
        const now: i64 = @intCast(now_seconds);
        if (!message.msgIdInTimeWindow(outer.msg_id, now)) {
            return if (message.msgIdUnixTime(outer.msg_id) < now) error.MsgIdTooOld else error.MsgIdTooNew;
        }

        var base = self.remote_content_count;
        var is_container = false;
        var count: usize = 1;

        if (outer.body.len >= 4 and std.mem.readInt(u32, outer.body[0..4], .little) == message.msg_container_id) {
            is_container = true;
            count = try message.readContainer(outer.body, out);
            var prev: i64 = 0;
            for (out[0..count]) |m| {
                if (!message.isValidServerMsgId(m.msg_id)) return error.MsgIdInvalid;
                // Strictly increasing inner ids, all below the container's.
                if (m.msg_id <= prev or m.msg_id >= outer.msg_id) return error.ContainerInvalid;
                prev = m.msg_id;
                if (try checkSeqNo(base, m.seq_no)) base += 1;
            }
        } else {
            out[0] = .{ .msg_id = outer.msg_id, .seq_no = outer.seq_no, .body = outer.body };
        }
        // The container envelope itself is a service message, generated
        // after its contents — its seq_no is checked against the
        // post-contents counter, which the ordering above guarantees.
        if (try checkSeqNo(base, outer.seq_no)) base += 1;

        // Commit and queue acks only after every check passed.
        self.remote_content_count = base;
        self.highest_remote_msg_id = outer.msg_id;
        if (is_container) {
            for (out[0..count]) |m| {
                if (message.isContentRelated(m.seq_no)) try self.queueAck(m.msg_id);
            }
        } else if (message.isContentRelated(outer.seq_no)) {
            try self.queueAck(outer.msg_id);
        }

        return .{
            .salt = outer.salt,
            .outer_msg_id = outer.msg_id,
            .outer_seq_no = outer.seq_no,
            .is_container = is_container,
            .messages = out[0..count],
        };
    }

    /// Records a msg_id as needing acknowledgement (deduplicated).
    pub fn queueAck(self: *Session, msg_id: i64) Error!void {
        for (self.acks.items[self.ack_offset..]) |id| {
            if (id == msg_id) return;
        }
        self.acks.append(self.allocator, msg_id) catch return error.OutOfMemory;
    }

    pub fn pendingAckCount(self: *const Session) usize {
        return self.acks.items.len - self.ack_offset;
    }

    /// Frame size the next `flushAcks` writes (0 when nothing is pending).
    pub fn pendingAckFrameLength(self: *const Session) usize {
        const pending = self.pendingAckCount();
        if (pending == 0) return 0;
        // usize: @min against the comptime-known 8192 would narrow the
        // result to u14, and 8 * n then overflows from 2048 acks onward.
        const n: usize = @min(pending, message.max_acks_per_message);
        // msgs_ack ctor + boxed vector ctor + count, then 8 bytes per id.
        return message.frameLength(12 + 8 * n);
    }

    /// Encodes one `msgs_ack` service message carrying up to 8192 pending
    /// ids and removes them from the queue. Returns null when nothing is
    /// pending. `dst` must be sized with `pendingAckFrameLength`.
    pub fn flushAcks(self: *Session, now_seconds: u64, dst: []u8) Error!?message.Sent {
        const pending = self.pendingAckCount();
        if (pending == 0) return null;
        const n: usize = @min(pending, message.max_acks_per_message);

        var w = Writer.init(self.allocator);
        defer w.deinit();
        const ack = message.MsgsAck{ .msg_ids = self.acks.items[self.ack_offset..][0..n] };
        ack.serialize(&w) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidLength,
        };
        const sent = try self.encodeMessage(.{
            .salt = self.server_salt,
            .session_id = self.session_id,
            .msg_id = self.nextMsgId(now_seconds),
            .seq_no = self.nextSeqNo(false),
            .body = w.items(),
        }, dst);

        self.ack_offset += n;
        if (self.ack_offset == self.acks.items.len) {
            self.acks.clearRetainingCapacity();
            self.ack_offset = 0;
        }
        return sent;
    }
};

fn randomSessionId(random: std.Random) i64 {
    var id: i64 = 0;
    while (id == 0) random.bytes(std.mem.asBytes(&id));
    return id;
}

/// Pure seq_no check against a counter baseline; returns whether the
/// message is content-related (i.e. whether the baseline advances).
fn checkSeqNo(base: u32, seq_no: i32) Error!bool {
    const content = message.isContentRelated(seq_no);
    const expected: i32 = @intCast(2 * base + @as(u32, if (content) 1 else 0));
    if (seq_no != expected) return error.SeqNoInvalid;
    return content;
}

// ---------------------------------------------------------------- tests

const test_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 73 +% 11);
    break :blk k;
};

/// The caller's `random` (and whatever backs it) must outlive the
/// session — the interface borrows it, like every RNG in tdzig.
fn newSession(allocator: std.mem.Allocator, salt: i64, random: std.Random) !Session {
    return Session.init(allocator, &test_key, salt, random);
}

/// Encrypts a server→client frame the way the test server would.
fn serverFrame(
    session: *const Session,
    msg_id: i64,
    seq_no: i32,
    body: []const u8,
    dst: []u8,
) !void {
    var prng = std.Random.DefaultPrng.init(9);
    try message.writeEncrypted(&test_key, .server_to_client, .{
        .salt = 0xaaaa,
        .session_id = session.session_id,
        .msg_id = msg_id,
        .seq_no = seq_no,
        .body = body,
    }, prng.random(), dst);
}

test "msg_id generation: monotone, mod 4, non-empty low bits" {
    const now: u64 = 1_700_000_000;
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 1, sprng.random());
    defer s.deinit();

    const a = s.nextMsgId(now);
    const b = s.nextMsgId(now);
    const c = s.nextMsgId(now + 1);
    try std.testing.expect(a < b and b < c);
    for ([_]i64{ a, b, c }) |id| {
        try std.testing.expectEqual(@as(i64, 0), @rem(id, 4));
        try std.testing.expect((@as(u64, @bitCast(id)) & 0xffff_ffff) != 0);
        try std.testing.expectEqual(@as(i64, 0), @rem(id - a, 4));
    }
    try std.testing.expectEqual(@as(i64, 1_700_000_000), message.msgIdUnixTime(a));

    // A regressing clock must never move ids backwards.
    const d = s.nextMsgId(now - 60);
    try std.testing.expect(d > c);
}

test "seq_no generation follows the spec formula" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 1, sprng.random());
    defer s.deinit();

    try std.testing.expectEqual(@as(i32, 1), s.nextSeqNo(true)); // content 1
    try std.testing.expectEqual(@as(i32, 3), s.nextSeqNo(true)); // content 2
    try std.testing.expectEqual(@as(i32, 4), s.nextSeqNo(false)); // service
    try std.testing.expectEqual(@as(i32, 5), s.nextSeqNo(true)); // content 3
    try std.testing.expectEqual(@as(i32, 6), s.nextSeqNo(false)); // service
    try std.testing.expectEqual(@as(i32, 6), s.nextSeqNo(false)); // unchanged until the next content message
}

test "encode produces a frame the peer can decrypt and check" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 0x1234_5678, sprng.random());
    defer s.deinit();

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    const ping = message.Ping{ .ping_id = 42 };
    try ping.serialize(&w);

    var dst: [message.frameLength(12)]u8 = undefined;
    const sent = try s.encode(1_700_000_000, true, w.items(), &dst);
    try std.testing.expectEqual(@as(i32, 1), sent.seq_no);
    try std.testing.expect(message.isValidClientMsgId(sent.msg_id));

    // Server side: decrypt with the shared key, check envelope fields.
    const dec = try message.readEncrypted(&test_key, .client_to_server, s.session_id, &dst);
    try std.testing.expectEqual(@as(i64, 0x1234_5678), dec.salt);
    try std.testing.expectEqual(sent.msg_id, dec.msg_id);
    try std.testing.expectEqual(@as(i32, 1), dec.seq_no);
    try std.testing.expectEqual(message.ping_id, std.mem.readInt(u32, dec.body[0..4], .little));

    // setServerSalt applies to subsequent frames.
    s.setServerSalt(0xdead_beef);
    _ = try s.encode(1_700_000_000, true, w.items(), &dst);
    const dec2 = try message.readEncrypted(&test_key, .client_to_server, s.session_id, &dst);
    try std.testing.expectEqual(@as(i64, 0xdead_beef), dec2.salt);
}

test "encodeContainer stamps inner ids below the container id" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 7, sprng.random());
    defer s.deinit();

    const ping_body = [_]u8{ 0x77, 0xec, 0xbe, 0x7a, 42, 0, 0, 0, 0, 0, 0, 0 }; // ping#7abe77ec ping_id=42
    const entries = [_]ContainerEntry{
        .{ .body = &ping_body, .content_related = true },
        .{ .body = &ping_body, .content_related = false },
    };
    var dst: [Session.containerFrameLength(&entries)]u8 = undefined;
    const sent = try s.encodeContainer(1_700_000_000, &entries, &dst);
    try std.testing.expect(message.isValidClientMsgId(sent.msg_id));
    try std.testing.expectEqual(@as(i32, 2), sent.seq_no); // service, after one content message

    const dec = try message.readEncrypted(&test_key, .client_to_server, s.session_id, &dst);
    var out: [2]message.Incoming = undefined;
    const count = try message.readContainer(dec.body, &out);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(i32, 1), out[0].seq_no); // content
    try std.testing.expectEqual(@as(i32, 2), out[1].seq_no); // service
    try std.testing.expect(out[0].msg_id < sent.msg_id and out[1].msg_id < sent.msg_id);
    try std.testing.expect(out[0].msg_id < out[1].msg_id);
}

test "receive: content message validated and queued for ack" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 1, sprng.random());
    defer s.deinit();

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(message.rpc_result_id);
    try w.writeLong(0x10);
    try w.writeInt(0); // result object placeholder, keeps the body aligned

    const now: u64 = 1_700_000_000;
    const base = @as(i64, now) << 32;
    var frame: [message.frameLength(16)]u8 = undefined;
    try serverFrame(&s, base | 1, 1, w.items(), &frame);

    var out: [1]message.Incoming = undefined;
    const got = try s.receive(&frame, now, &out);
    try std.testing.expect(!got.is_container);
    try std.testing.expectEqual(@as(usize, 1), got.messages.len);
    try std.testing.expectEqual(base | 1, got.messages[0].msg_id);
    try std.testing.expectEqual(@as(i64, 0xaaaa), got.salt);
    try std.testing.expectEqual(@as(usize, 1), s.pendingAckCount());

    // Strictly increasing ids: the same id again is out of order (state
    // must otherwise be valid so the ordering check is what fires).
    var frame2: [message.frameLength(16)]u8 = undefined;
    try serverFrame(&s, base | 1, 1, w.items(), &frame2);
    var out2: [1]message.Incoming = undefined;
    try std.testing.expectError(error.MsgIdOutOfOrder, s.receive(&frame2, now, &out2));
}

test "receive: container flattened, inner acks queued" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 1, sprng.random());
    defer s.deinit();

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(message.pong_id);
    try w.writeLong(1);
    try w.writeLong(2); // 20-byte pong body

    const now: u64 = 1_700_000_000;
    const base = @as(i64, now) << 32;

    var cw = Writer.init(std.testing.allocator);
    defer cw.deinit();
    const inner = [_]message.Incoming{
        .{ .msg_id = base | 1, .seq_no = 1, .body = w.items() },
        .{ .msg_id = base | 5, .seq_no = 3, .body = w.items() },
    };
    try message.writeContainer(&cw, &inner);

    var frame: [message.frameLength(8 + 2 * (16 + 20))]u8 = undefined;
    try serverFrame(&s, base | 9, 4, cw.items(), &frame);

    var out: [2]message.Incoming = undefined;
    const got = try s.receive(&frame, now, &out);
    try std.testing.expect(got.is_container);
    try std.testing.expectEqual(@as(usize, 2), got.messages.len);
    try std.testing.expectEqual(base | 1, got.messages[0].msg_id);
    try std.testing.expectEqual(base | 5, got.messages[1].msg_id);
    try std.testing.expectEqualSlices(u8, w.items(), got.messages[0].body);
    try std.testing.expectEqual(@as(usize, 2), s.pendingAckCount());
}

test "receive rejects parity, window, ordering and session violations" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 1, sprng.random());
    defer s.deinit();

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(message.pong_id);
    try w.writeLong(1);
    try w.writeLong(2);

    const now: u64 = 1_700_000_000;
    const base = @as(i64, now) << 32;
    var frame: [message.frameLength(20)]u8 = undefined;
    var out: [1]message.Incoming = undefined;

    // Server ids must be ≡ 1 or 3 (mod 4).
    try serverFrame(&s, base | 0, 0, w.items(), &frame);
    try std.testing.expectError(error.MsgIdInvalid, s.receive(&frame, now, &out));

    // Too far in the future / in the past.
    try serverFrame(&s, (base + (100 << 32)) | 1, 0, w.items(), &frame);
    try std.testing.expectError(error.MsgIdTooNew, s.receive(&frame, now, &out));
    try serverFrame(&s, (base - (400 << 32)) | 1, 0, w.items(), &frame);
    try std.testing.expectError(error.MsgIdTooOld, s.receive(&frame, now, &out));

    // First server message with a content (odd) seq_no of 3 — the counter
    // starts at 1.
    try serverFrame(&s, base | 1, 3, w.items(), &frame);
    try std.testing.expectError(error.SeqNoInvalid, s.receive(&frame, now, &out));

    // Wrong session.
    var prng = std.Random.DefaultPrng.init(3);
    var wrong: [message.frameLength(20)]u8 = undefined;
    try message.writeEncrypted(&test_key, .server_to_client, .{
        .salt = 0,
        .session_id = s.session_id + 1,
        .msg_id = base | 1,
        .seq_no = 0,
        .body = w.items(),
    }, prng.random(), &wrong);
    try std.testing.expectError(error.SessionIdMismatch, s.receive(&wrong, now, &out));

    // A failed frame must not poison the counters: the next valid one
    // still expects seq_no 0 for a service message.
    try serverFrame(&s, base | 3, 0, w.items(), &frame);
    const got = try s.receive(&frame, now, &out);
    try std.testing.expectEqual(@as(usize, 1), got.messages.len);
    try std.testing.expectEqual(@as(usize, 0), s.pendingAckCount()); // pong is technical

    // ...and afterwards ids must strictly increase.
    try serverFrame(&s, base | 3, 0, w.items(), &frame);
    try std.testing.expectError(error.MsgIdOutOfOrder, s.receive(&frame, now, &out));
}

test "bad_server_salt needs no ack and is parseable" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 1, sprng.random());
    defer s.deinit();

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(message.bad_server_salt_id);
    try w.writeLong(0x2000_0004);
    try w.writeInt(1);
    try w.writeInt(message.err_salt_invalid);
    try w.writeLong(@bitCast(@as(u64, 0xfeed_face_beef_cafe)));

    const now: u64 = 1_700_000_000;
    const base = @as(i64, now) << 32;
    var frame: [message.frameLength(28)]u8 = undefined;
    try serverFrame(&s, base | 3, 0, w.items(), &frame);

    var out: [1]message.Incoming = undefined;
    const got = try s.receive(&frame, now, &out);
    try std.testing.expectEqual(@as(usize, 0), s.pendingAckCount());

    var body = try message.parseServiceBody(std.testing.allocator, got.messages[0].body);
    defer body.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(i64, @bitCast(@as(u64, 0xfeed_face_beef_cafe))),
        body.bad_server_salt.new_server_salt,
    );
    s.setServerSalt(body.bad_server_salt.new_server_salt);

    var w2 = Writer.init(std.testing.allocator);
    defer w2.deinit();
    const resend_ping = message.Ping{ .ping_id = 1 };
    try resend_ping.serialize(&w2);
    var dst: [message.frameLength(12)]u8 = undefined;
    _ = try s.encode(now, false, w2.items(), &dst);
    const dec = try message.readEncrypted(&test_key, .client_to_server, s.session_id, &dst);
    try std.testing.expectEqual(@as(i64, @bitCast(@as(u64, 0xfeed_face_beef_cafe))), dec.salt);
}

test "flushAcks emits msgs_ack and drains the queue" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 1, sprng.random());
    defer s.deinit();

    try s.queueAck(11);
    try s.queueAck(22);
    try s.queueAck(22); // deduplicated
    try s.queueAck(33);
    try std.testing.expectEqual(@as(usize, 3), s.pendingAckCount());

    const len = s.pendingAckFrameLength();
    const dst = try std.testing.allocator.alloc(u8, len);
    defer std.testing.allocator.free(dst);
    const sent = try s.flushAcks(1_700_000_000, dst);
    try std.testing.expect(sent != null);
    try std.testing.expectEqual(@as(i32, 0), sent.?.seq_no); // acks are service messages

    const dec = try message.readEncrypted(&test_key, .client_to_server, s.session_id, dst);
    var r = Reader.init(dec.body);
    const ack = try message.MsgsAck.deserialize(std.testing.allocator, &r);
    defer std.testing.allocator.free(ack.msg_ids);
    try std.testing.expectEqualSlices(i64, &.{ 11, 22, 33 }, ack.msg_ids);

    try std.testing.expectEqual(@as(usize, 0), s.pendingAckCount());
    try std.testing.expectEqual(@as(usize, 0), s.pendingAckFrameLength());
    const again = try s.flushAcks(1_700_000_000, dst);
    try std.testing.expectEqual(@as(?message.Sent, null), again);
}

test "flushAcks groups at most 8192 ids per frame and keeps the rest queued" {
    var sprng = std.Random.DefaultPrng.init(0x5e55);
    var s = try newSession(std.testing.allocator, 1, sprng.random());
    defer s.deinit();

    // One id past the spec's grouping recommendation: the overflow must
    // stay queued for the next frame, in order.
    const total = message.max_acks_per_message + 1;
    for (0..total) |i| try s.queueAck(@intCast(i));
    try std.testing.expectEqual(total, s.pendingAckCount());

    // First flush carries exactly the maximum.
    const dst = try std.testing.allocator.alloc(u8, s.pendingAckFrameLength());
    defer std.testing.allocator.free(dst);
    const sent = (try s.flushAcks(1_700_000_000, dst)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(message.isContentRelated(sent.seq_no) == false);

    const dec = try message.readEncrypted(&test_key, .client_to_server, s.session_id, dst);
    var r = Reader.init(dec.body);
    const ack = try message.MsgsAck.deserialize(std.testing.allocator, &r);
    defer std.testing.allocator.free(ack.msg_ids);
    try std.testing.expectEqual(message.max_acks_per_message, ack.msg_ids.len);
    try std.testing.expectEqual(@as(i64, 0), ack.msg_ids[0]);
    try std.testing.expectEqual(@as(i64, @intCast(total - 2)), ack.msg_ids[ack.msg_ids.len - 1]);

    // The overflow id is still pending, and its frame is smaller.
    try std.testing.expectEqual(@as(usize, 1), s.pendingAckCount());
    const dst2 = try std.testing.allocator.alloc(u8, s.pendingAckFrameLength());
    defer std.testing.allocator.free(dst2);
    try std.testing.expect(dst2.len < dst.len);
    _ = (try s.flushAcks(1_700_000_000, dst2)) orelse return error.TestUnexpectedResult;

    const dec2 = try message.readEncrypted(&test_key, .client_to_server, s.session_id, dst2);
    var r2 = Reader.init(dec2.body);
    const ack2 = try message.MsgsAck.deserialize(std.testing.allocator, &r2);
    defer std.testing.allocator.free(ack2.msg_ids);
    try std.testing.expectEqualSlices(i64, &.{@as(i64, @intCast(total - 1))}, ack2.msg_ids);

    // Drained: the queue is reset (not offset-frozen) and dedups again.
    try std.testing.expectEqual(@as(usize, 0), s.pendingAckCount());
    try std.testing.expectEqual(@as(usize, 0), s.pendingAckFrameLength());
    try s.queueAck(1);
    try s.queueAck(1); // deduplicated against the fresh queue
    try std.testing.expectEqual(@as(usize, 1), s.pendingAckCount());
}
