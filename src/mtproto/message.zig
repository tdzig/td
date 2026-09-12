//! MTProto 2.0 encrypted-message framing: envelopes, msg_id/seq_no rules,
//! message containers, acknowledgements and the core service messages —
//! everything that travels *inside* the AES-256-IGE payload.
//!
//! Implemented per https://core.telegram.org/mtproto/description and
//! https://core.telegram.org/mtproto/service_messages:
//!
//!   Encrypted frame (both directions):
//!
//!     auth_key_id      8 bytes   SHA1(auth_key)[12..20]
//!     msg_key         16 bytes   SHA256(auth_key[88+x..] ++ data_with_padding)[8..24]
//!     encrypted_data  AES-256-IGE over data_with_padding:
//!       salt           8 bytes
//!       session_id     8 bytes
//!       msg_id         8 bytes
//!       seq_no         4 bytes
//!       length         4 bytes   = body length
//!       body          `length` bytes (one serialized TL object)
//!       padding       12..1024 random bytes; total divisible by 16
//!
//!   msg_id: monotonically increasing, ≈ unixtime · 2^32; divisible by 4
//!   for client→server (low 32 bits never empty); ≡ 1 (mod 4) for server
//!   responses, ≡ 3 for other server messages. A message is rejected when
//!   more than 30 s into the future or 300 s into the past. A container's
//!   msg_id is strictly greater than those of all nested messages.
//!
//!   seq_no = 2 · (content messages created so far) + (1 if this message
//!   is content-related else 0); only content-related messages advance the
//!   counter, and they are exactly the ones requiring acknowledgement —
//!   except technical messages (ping/pong, bad_msg_notification, gzip
//!   wrappers, containers themselves).
//!
//! The AES-IGE and msg_key math lives in `tdzig.crypto`; this module owns
//! the envelope around it. The stateful side (counters, dedup, pending
//! acks) is `Session` in session.zig; everything here is stateless and
//! composable with caller-owned buffers.

const std = @import("std");
const crypto = @import("../crypto/mod.zig");
const tl = @import("../tl/mod.zig");
const Writer = tl.Writer;
const Reader = tl.Reader;
const TlError = @import("../errors.zig").TlError;

/// salt + session_id + msg_id + seq_no + length ahead of the body inside
/// the decrypted payload.
pub const inner_header_size: usize = 32;
/// auth_key_id + msg_key ahead of the ciphertext.
pub const frame_header_size: usize = 24;

// Core service constructor ids. The authority is the vendored Telegram
// Desktop `scheme/mtproto.tl` (schema/mtproto.tl); rpc_result,
// msg_container, msg_copy and gzip_packed are marked "parsed manually"
// there, so their ids are pinned here.
pub const msg_container_id: u32 = 0x73f1f8dc;
pub const msgs_ack_id: u32 = 0x62d6b459;
pub const bad_msg_notification_id: u32 = 0xa7eff811;
pub const bad_server_salt_id: u32 = 0xedab447b;
pub const new_session_created_id: u32 = 0x9ec20908;
pub const pong_id: u32 = 0x347773c5;
pub const ping_id: u32 = 0x7abe77ec;
pub const ping_delay_disconnect_id: u32 = 0xf3427b8c;
pub const future_salt_id: u32 = 0x0949d9dc;
pub const future_salts_id: u32 = 0xae500895;
pub const get_future_salts_id: u32 = 0xb921bd04;
pub const rpc_result_id: u32 = 0xf35c6d01;
pub const rpc_error_id: u32 = 0x2144ca19;
pub const gzip_packed_id: u32 = 0x3072cfa1;

/// bad_msg_notification error codes — the numeric counterparts of the
/// checks this module and `Session` perform on received messages.
pub const err_msg_id_too_low: i32 = 16;
pub const err_msg_id_too_high: i32 = 17;
pub const err_seq_no_too_low: i32 = 18;
pub const err_seq_no_too_high: i32 = 19;
pub const err_msg_id_too_old: i32 = 20;
pub const err_salt_invalid: i32 = 48;
pub const err_container_invalid: i32 = 64;

/// A container may hold up to 1024 nested messages; acknowledgements are
/// grouped into msgs_ack messages of at most 8192 ids each.
pub const max_container_messages: usize = 1024;
pub const max_acks_per_message: usize = 8192;

pub const Error = error{
    OutOfMemory,
    /// Frame shorter than the fixed headers, or impossible length fields.
    InvalidLength,
    /// A body or length field is not a multiple of four (TL alignment).
    MessageNotAligned,
    /// Padding outside the spec range of 12..1024 bytes.
    PaddingInvalid,
    /// The frame's auth_key_id does not match ours.
    AuthKeyIdMismatch,
    /// The decrypted session_id does not match ours.
    SessionIdMismatch,
    /// Decrypted data does not match msg_key (tampering, wrong key or
    /// wrong direction).
    MessageKeyMismatch,
    /// msg_id is zero or has the wrong parity for its direction.
    MsgIdInvalid,
    /// msg_id more than 300 s in the past (bad_msg_notification code 20).
    MsgIdTooOld,
    /// msg_id more than 30 s in the future (code 17).
    MsgIdTooNew,
    /// msg_id not strictly greater than the previous one from this peer.
    MsgIdOutOfOrder,
    /// seq_no does not match the expected counter (codes 18/19).
    SeqNoInvalid,
    /// Container violations: id ordering or nesting (code 64).
    ContainerInvalid,
    /// More nested messages than the 1024 limit (or than the caller's
    /// output buffer holds).
    ContainerTooLarge,
};

/// Total encrypted-frame length for a body of `body_len` bytes.
pub fn frameLength(body_len: usize) usize {
    return frame_header_size + crypto.paddedLength(inner_header_size + body_len);
}

// ---------------------------------------------------------------- msg_id

/// Client→server ids: non-zero and divisible by four.
pub fn isValidClientMsgId(msg_id: i64) bool {
    return msg_id != 0 and @rem(msg_id, 4) == 0;
}

/// Server→client ids: ≡ 1 (mod 4) for responses, ≡ 3 for other service
/// messages; never zero.
pub fn isValidServerMsgId(msg_id: i64) bool {
    if (msg_id == 0) return false;
    const r = @rem(msg_id, 4);
    return r == 1 or r == 3;
}

/// The unix timestamp embedded in a msg_id (its high 32 bits).
pub fn msgIdUnixTime(msg_id: i64) i64 {
    return @intCast(@as(u64, @bitCast(msg_id)) >> 32);
}

/// Spec receive window: ids more than 30 s in the future or 300 s in the
/// past must be rejected. `now_seconds` is the receiver's clock.
pub fn msgIdInTimeWindow(msg_id: i64, now_seconds: i64) bool {
    const t = msgIdUnixTime(msg_id);
    return now_seconds - 300 <= t and t <= now_seconds + 30;
}

// ---------------------------------------------------------------- seq_no

/// Content-related messages have odd seq_no (2·content_count + 1) and are
/// the ones requiring acknowledgement.
pub fn isContentRelated(seq_no: i32) bool {
    return (seq_no & 1) == 1;
}

// ------------------------------------------------------------- envelopes

/// A message on its way out: the envelope fields the sender stamps.
pub const Outgoing = struct {
    salt: i64,
    session_id: i64,
    msg_id: i64,
    seq_no: i32,
    body: []const u8,
};

/// Envelope fields stamped on a successfully encoded frame.
pub const Sent = struct {
    msg_id: i64,
    seq_no: i32,
};

/// One logical message (top-level, or nested in a container). `body`
/// borrows from the frame buffer.
pub const Incoming = struct {
    msg_id: i64,
    seq_no: i32,
    body: []const u8,
};

/// A fully decrypted frame envelope. `body` borrows from the input buffer.
pub const Decrypted = struct {
    salt: i64,
    session_id: i64,
    msg_id: i64,
    seq_no: i32,
    body: []const u8,
};

/// Writes the complete encrypted frame for one message into `dst`.
/// Exactly `frameLength(body.len)` bytes are used; a different `dst.len`
/// is an error (mirroring the crypto primitives — nothing is truncated
/// silently). Padding is drawn from `random`.
pub fn writeEncrypted(
    auth_key: *const [crypto.auth_key_size]u8,
    direction: crypto.Direction,
    msg: Outgoing,
    random: std.Random,
    dst: []u8,
) Error!void {
    if (msg.body.len % 4 != 0) return error.MessageNotAligned;
    const plain_len = inner_header_size + msg.body.len;
    const total = frameLength(msg.body.len);
    if (dst.len != total) return error.InvalidLength;

    // Build data_with_padding directly at the ciphertext position; the
    // AES-IGE core encrypts in place.
    const plain = dst[frame_header_size..];
    std.mem.writeInt(i64, plain[0..8], msg.salt, .little);
    std.mem.writeInt(i64, plain[8..16], msg.session_id, .little);
    std.mem.writeInt(i64, plain[16..24], msg.msg_id, .little);
    std.mem.writeInt(i32, plain[24..28], msg.seq_no, .little);
    std.mem.writeInt(u32, plain[28..32], @intCast(msg.body.len), .little);
    @memcpy(plain[32..][0..msg.body.len], msg.body);
    random.bytes(plain[plain_len..]);

    var msg_key: [crypto.msg_key_size]u8 = undefined;
    crypto.encryptMessage(auth_key, direction, plain, plain, &msg_key) catch |e| return switch (e) {
        error.InvalidLength => error.InvalidLength,
        error.BufferTooSmall => error.InvalidLength,
        error.MessageKeyMismatch => error.MessageKeyMismatch,
        error.InvalidKeySize => unreachable, // typed [256]u8
    };
    const key_id = crypto.authKeyId(auth_key);
    @memcpy(dst[0..8], &key_id);
    @memcpy(dst[8..24], &msg_key);
}

/// Decrypts and structurally validates an encrypted frame **in place**
/// (`buf` is mutated; the returned body borrows from it). Checks: frame
/// shape, auth_key_id, msg_key (constant-time, inside the crypto layer),
/// session identity, body alignment and padding bounds. The stateful
/// rules — monotonicity, time window, seq_no counters — belong to
/// `Session` (session.zig).
///
/// `expected_session_id == 0` is the fresh-connection server role: any
/// session id is accepted, so a peer can bind to `Decrypted.session_id`
/// from the first frame it decrypts. Client sessions draw non-zero ids,
/// so 0 never names a real session.
pub fn readEncrypted(
    auth_key: *const [crypto.auth_key_size]u8,
    direction: crypto.Direction,
    expected_session_id: i64,
    buf: []u8,
) Error!Decrypted {
    if (buf.len < frame_header_size) return error.InvalidLength;
    const data_full = buf[frame_header_size..];
    // Padded transports (padded intermediate) deliver 0..15 frame-padding
    // bytes after the ciphertext. The encrypted part is the longest
    // 16-aligned prefix — the reference clients parse padded frames the
    // same way — and for exact frames this is the whole tail.
    const data = data_full[0 .. data_full.len - data_full.len % crypto.block_size];
    if (data.len < inner_header_size) return error.InvalidLength;

    const key_id = crypto.authKeyId(auth_key);
    if (!std.mem.eql(u8, buf[0..8], &key_id)) return error.AuthKeyIdMismatch;

    var msg_key: [crypto.msg_key_size]u8 = undefined;
    @memcpy(&msg_key, buf[8..24]);

    crypto.decryptMessage(auth_key, direction, &msg_key, data, data) catch |e| return switch (e) {
        error.InvalidLength => error.InvalidLength,
        error.BufferTooSmall => error.InvalidLength,
        error.MessageKeyMismatch => error.MessageKeyMismatch,
        error.InvalidKeySize => unreachable, // typed [256]u8
    };

    const salt = std.mem.readInt(i64, data[0..8], .little);
    const session_id = std.mem.readInt(i64, data[8..16], .little);
    const msg_id = std.mem.readInt(i64, data[16..24], .little);
    const seq_no = std.mem.readInt(i32, data[24..28], .little);
    const length = std.mem.readInt(u32, data[28..32], .little);

    if (length % 4 != 0) return error.MessageNotAligned;
    const body_len: usize = @intCast(length);
    if (body_len > data.len - inner_header_size) return error.InvalidLength;
    const padding = data.len - inner_header_size - body_len;
    if (padding < crypto.min_padding or padding > 1024) return error.PaddingInvalid;

    if (expected_session_id != 0 and session_id != expected_session_id) return error.SessionIdMismatch;

    return .{
        .salt = salt,
        .session_id = session_id,
        .msg_id = msg_id,
        .seq_no = seq_no,
        .body = data[inner_header_size..][0..body_len],
    };
}

// ------------------------------------------------------------- containers

/// Serialized size of a `msg_container#73f1f8dc` body holding `messages`.
pub fn containerBodyLength(messages: []const Incoming) usize {
    var len: usize = 8; // constructor id + count
    for (messages) |m| len += 16 + m.body.len;
    return len;
}

/// Writes a `msg_container#73f1f8dc` body. Inner messages are *not* boxed
/// individually: each contributes msg_id:long, seqno:int, bytes:int, then
/// its raw body. The caller stamps each inner message's id/seq_no with
/// the usual rules; the container body is four-byte aligned by
/// construction.
pub fn writeContainer(w: *Writer, messages: []const Incoming) TlError!void {
    if (messages.len > max_container_messages) return error.InvalidLength;
    try w.writeConstructorId(msg_container_id);
    try w.writeVectorLength(messages.len);
    for (messages) |m| {
        if (m.body.len % 4 != 0) return error.InvalidLength;
        try w.writeLong(m.msg_id);
        try w.writeInt(m.seq_no);
        try w.writeUInt(@intCast(m.body.len));
        try w.writeRaw(m.body);
    }
}

/// Parses a container body into `out` (borrowed bodies) and returns the
/// message count. Enforces the 1024-message limit, exact body lengths and
/// that the whole body is consumed. Id-ordering and seq_no rules are the
/// caller's (`Session`) job.
pub fn readContainer(body: []const u8, out: []Incoming) Error!usize {
    var r = Reader.init(body);
    const id = r.readConstructorId() catch return error.InvalidLength;
    if (id != msg_container_id) return error.ContainerInvalid;
    const count = r.readVectorLength() catch return error.InvalidLength;
    if (count > max_container_messages or count > out.len) return error.ContainerTooLarge;
    for (out[0..count]) |*m| {
        m.msg_id = r.readLong() catch return error.InvalidLength;
        m.seq_no = r.readInt() catch return error.InvalidLength;
        const len = r.readUInt() catch return error.InvalidLength;
        if (len % 4 != 0) return error.MessageNotAligned;
        const body_len: usize = @intCast(len);
        if (body_len > r.remaining()) return error.InvalidLength;
        m.body = r.readRaw(body_len) catch return error.InvalidLength;
    }
    if (r.remaining() != 0) return error.InvalidLength;
    return count;
}

// ------------------------------------------------------- service messages

/// `msgs_ack#62d6b459 msg_ids:Vector<long>` — receipt acknowledgement.
pub const MsgsAck = struct {
    /// Borrowed on serialize; allocated (caller-owned) on deserialize.
    msg_ids: []const i64,

    pub fn serialize(self: *const MsgsAck, w: *Writer) TlError!void {
        if (self.msg_ids.len > max_acks_per_message) return error.InvalidLength;
        try w.writeConstructorId(msgs_ack_id);
        try w.writeVectorOfLong(self.msg_ids);
    }

    pub fn deserialize(allocator: std.mem.Allocator, r: *Reader) TlError!MsgsAck {
        if ((try r.readConstructorId()) != msgs_ack_id) return error.InvalidValue;
        return .{ .msg_ids = try r.readVectorOfLong(allocator) };
    }
};

/// `ping#7abe77ec ping_id:long` (or `ping_delay_disconnect#f3427b8c`).
pub const Ping = struct {
    ping_id: i64,
    /// Set for the ping_delay_disconnect variant.
    disconnect_delay: ?i32 = null,

    pub fn serialize(self: *const Ping, w: *Writer) TlError!void {
        if (self.disconnect_delay) |delay| {
            try w.writeConstructorId(ping_delay_disconnect_id);
            try w.writeLong(self.ping_id);
            try w.writeInt(delay);
        } else {
            try w.writeConstructorId(ping_id);
            try w.writeLong(self.ping_id);
        }
    }
};

/// `bad_msg_notification#a7eff811` — a sent message violated a rule.
pub const BadNotification = struct {
    bad_msg_id: i64,
    bad_msg_seqno: i32,
    error_code: i32,
};

/// `bad_server_salt#edab447b` — re-send with the new salt.
pub const BadServerSalt = struct {
    bad_msg_id: i64,
    bad_msg_seqno: i32,
    error_code: i32,
    new_server_salt: i64,
};

/// `new_session_created#9ec20908` — first message of a server session.
pub const NewSessionCreated = struct {
    first_msg_id: i64,
    unique_id: i64,
    server_salt: i64,
};

/// `pong#347773c5 msg_id:long ping_id:long`.
pub const Pong = struct {
    msg_id: i64,
    ping_id: i64,
};

/// `future_salt#0949d9dc valid_since:int valid_until:int salt:long`.
pub const FutureSalt = struct {
    valid_since: i32,
    valid_until: i32,
    salt: i64,
};

/// `future_salts#ae500895 ... salts:vector<future_salt>` — note the
/// *bare* vector (no `vector#1cb5c415` constructor id on the wire), while
/// each future_salt element keeps its own constructor id.
pub const FutureSalts = struct {
    req_msg_id: i64,
    now: i32,
    /// Allocated with the caller's allocator.
    salts: []FutureSalt,
};

/// `rpc_result#f35c6d01 req_msg_id:long result:Object` — the response to
/// an RPC query; doubles as the acknowledgement of `req_msg_id`.
pub const RpcResult = struct {
    req_msg_id: i64,
    /// The raw serialized result object (borrows from the input). May be
    /// `rpc_error`, `gzip_packed` or any API object; the RPC layer
    /// classifies it.
    result: []const u8,
};

/// `rpc_error#2144ca19 error_code:int error_message:string`.
pub const RpcError = struct {
    error_code: i32,
    error_message: []const u8,
};

/// `gzip_packed#3072cfa1 packed_data:string`. Inflate comes with the RPC
/// layer; here the wrapper is recognized and its payload exposed.
pub const GzipPacked = struct {
    packed_data: []const u8,
};

/// Best-effort classification of a message body into the core service
/// messages. API-level bodies come back as `.unknown` with the leading
/// constructor id; allocation-requiring variants are flagged in `deinit`.
pub const ServiceBody = union(enum) {
    msgs_ack: MsgsAck,
    bad_msg_notification: BadNotification,
    bad_server_salt: BadServerSalt,
    new_session_created: NewSessionCreated,
    pong: Pong,
    future_salts: FutureSalts,
    rpc_result: RpcResult,
    gzip_packed: GzipPacked,
    unknown: struct {
        constructor_id: u32,
        body: []const u8,
    },

    /// Frees the allocated parts (`msg_ids`, `salts`); borrowed slices
    /// are left alone.
    pub fn deinit(self: *ServiceBody, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .msgs_ack => |m| allocator.free(m.msg_ids),
            .future_salts => |f| allocator.free(f.salts),
            else => {},
        }
    }
};

/// Parses one message body. Unknown (API-level) constructors are not an
/// error. All returned slices borrow from `body` except the two
/// allocation-requiring variants (see `ServiceBody.deinit`).
pub fn parseServiceBody(allocator: std.mem.Allocator, body: []const u8) TlError!ServiceBody {
    var r = Reader.init(body);
    const id = try r.readConstructorId();
    switch (id) {
        msgs_ack_id => return .{ .msgs_ack = .{
            .msg_ids = try r.readVectorOfLong(allocator),
        } },
        bad_msg_notification_id => return .{ .bad_msg_notification = .{
            .bad_msg_id = try r.readLong(),
            .bad_msg_seqno = try r.readInt(),
            .error_code = try r.readInt(),
        } },
        bad_server_salt_id => return .{ .bad_server_salt = .{
            .bad_msg_id = try r.readLong(),
            .bad_msg_seqno = try r.readInt(),
            .error_code = try r.readInt(),
            .new_server_salt = try r.readLong(),
        } },
        new_session_created_id => return .{ .new_session_created = .{
            .first_msg_id = try r.readLong(),
            .unique_id = try r.readLong(),
            .server_salt = try r.readLong(),
        } },
        pong_id => return .{ .pong = .{
            .msg_id = try r.readLong(),
            .ping_id = try r.readLong(),
        } },
        future_salts_id => {
            const req_msg_id = try r.readLong();
            const now = try r.readInt();
            const count = try r.readVectorLength();
            const salts = allocator.alloc(FutureSalt, count) catch return error.OutOfMemory;
            for (salts) |*s| {
                if ((try r.readConstructorId()) != future_salt_id) return error.InvalidValue;
                s.valid_since = try r.readInt();
                s.valid_until = try r.readInt();
                s.salt = try r.readLong();
            }
            return .{ .future_salts = .{ .req_msg_id = req_msg_id, .now = now, .salts = salts } };
        },
        rpc_result_id => {
            const req_msg_id = try r.readLong();
            return .{ .rpc_result = .{ .req_msg_id = req_msg_id, .result = r.data[r.pos..] } };
        },
        gzip_packed_id => return .{ .gzip_packed = .{
            .packed_data = try r.readString(),
        } },
        else => return .{ .unknown = .{ .constructor_id = id, .body = body } },
    }
}

// ---------------------------------------------------------------- tests

// Varied byte pattern so the auth_key windows used by the two directions
// differ in tests (same idea as the crypto-layer test key).
const test_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 73 +% 11);
    break :blk k;
};

const test_salt: i64 = 0x0011_2233_4455_6677;
const test_session: i64 = 0x7fed_cba9_8765_4321;
const test_body = [_]u8{ 0x78, 0x77, 0x6e, 0xc0, 0xde, 0xad, 0xbe, 0xef }; // any 4-aligned bytes

test "encrypted frame layout and roundtrip" {
    var prng = std.Random.DefaultPrng.init(1);

    const msg = Outgoing{
        .salt = test_salt,
        .session_id = test_session,
        .msg_id = (@as(i64, 1_700_000_000) << 32) | 4,
        .seq_no = 1,
        .body = &test_body,
    };

    var dst: [frameLength(test_body.len)]u8 = undefined;
    try writeEncrypted(&test_key, .client_to_server, msg, prng.random(), &dst);

    // Prefix: our auth_key_id, then a msg_key that is not all zeros.
    const key_id = crypto.authKeyId(&test_key);
    try std.testing.expectEqualSlices(u8, &key_id, dst[0..8]);
    try std.testing.expect(!std.mem.eql(u8, &[_]u8{0} ** 16, dst[8..24]));

    const dec = try readEncrypted(&test_key, .client_to_server, test_session, &dst);
    try std.testing.expectEqual(test_salt, dec.salt);
    try std.testing.expectEqual(test_session, dec.session_id);
    try std.testing.expectEqual(msg.msg_id, dec.msg_id);
    try std.testing.expectEqual(msg.seq_no, dec.seq_no);
    try std.testing.expectEqualSlices(u8, &test_body, dec.body);

    // Padding within the spec range and the frame divisible by 16 after
    // the 24-byte prefix.
    const padding = dst.len - frame_header_size - inner_header_size - test_body.len;
    try std.testing.expect(padding >= crypto.min_padding and padding <= 1024);
    try std.testing.expectEqual(@as(usize, 0), (dst.len - frame_header_size) % 16);

    // A peer with a different key derives a different auth_key_id, so the
    // frame is rejected before decryption — nothing of ours is readable.
    var other_key = test_key;
    other_key[0] ^= 1;
    try std.testing.expectError(
        error.AuthKeyIdMismatch,
        readEncrypted(&other_key, .client_to_server, test_session, &dst),
    );
}

test "readEncrypted rejects structural violations" {
    var prng = std.Random.DefaultPrng.init(2);
    const msg = Outgoing{
        .salt = test_salt,
        .session_id = test_session,
        .msg_id = (@as(i64, 1_700_000_000) << 32) | 8,
        .seq_no = 3,
        .body = &test_body,
    };
    var dst: [frameLength(test_body.len)]u8 = undefined;
    try writeEncrypted(&test_key, .server_to_client, msg, prng.random(), &dst);

    // readEncrypted decrypts in place and mutates the buffer — every
    // case below works on a fresh copy of the honest frame.
    var honest = dst;

    // Not an auth_key_id frame.
    var bad_id = honest;
    bad_id[0] ^= 0xff;
    try std.testing.expectError(
        error.AuthKeyIdMismatch,
        readEncrypted(&test_key, .server_to_client, test_session, &bad_id),
    );

    // Wrong direction fails msg_key verification.
    var wrong_dir = honest;
    try std.testing.expectError(
        error.MessageKeyMismatch,
        readEncrypted(&test_key, .client_to_server, test_session, &wrong_dir),
    );

    // Tampered ciphertext fails msg_key verification.
    var tampered = honest;
    tampered[tampered.len - 1] ^= 0x40;
    try std.testing.expectError(
        error.MessageKeyMismatch,
        readEncrypted(&test_key, .server_to_client, test_session, &tampered),
    );

    // Another session's frame.
    var other_session = honest;
    try std.testing.expectError(
        error.SessionIdMismatch,
        readEncrypted(&test_key, .server_to_client, test_session + 1, &other_session),
    );

    // Truncated and non-16-aligned frames. One byte short: the
    // 16-aligned truncation (padded-frame tolerance, see readEncrypted)
    // treats the missing block as part of the tail, so the shortened
    // ciphertext no longer matches msg_key. A frame shorter than the
    // fixed headers stays an InvalidLength.
    try std.testing.expectError(
        error.MessageKeyMismatch,
        readEncrypted(&test_key, .server_to_client, test_session, honest[0 .. honest.len - 1]),
    );
    try std.testing.expectError(
        error.InvalidLength,
        readEncrypted(&test_key, .server_to_client, test_session, honest[0 .. frame_header_size - 1]),
    );

    // A tampered plaintext length field (still decrypts, then fails).
    var bad_len = honest;
    // Flip a bit inside the encrypted length word (offset 24+28 in data).
    bad_len[frame_header_size + 28] ^= 0x04;
    const r = readEncrypted(&test_key, .server_to_client, test_session, &bad_len);
    try std.testing.expectError(error.MessageKeyMismatch, r);
}

test "readEncrypted tolerates transport frame padding" {
    var prng = std.Random.DefaultPrng.init(4);
    const msg = Outgoing{
        .salt = test_salt,
        .session_id = test_session,
        .msg_id = (@as(i64, 1_700_000_000) << 32) | 12,
        .seq_no = 5,
        .body = &test_body,
    };
    var dst: [frameLength(test_body.len)]u8 = undefined;
    try writeEncrypted(&test_key, .server_to_client, msg, prng.random(), &dst);

    // A padded-intermediate peer ships the frame with 0..15 extra bytes
    // of transport padding; the encrypted part is the 16-aligned prefix,
    // so every padding width decodes to the same message.
    for ([_]usize{ 0, 1, 7, 15 }) |pad| {
        var padded: [dst.len + 15]u8 = undefined;
        @memcpy(padded[0..dst.len], &dst);
        @memset(padded[dst.len..][0..pad], 0xA5);
        const dec = try readEncrypted(&test_key, .server_to_client, test_session, padded[0 .. dst.len + pad]);
        try std.testing.expectEqual(msg.msg_id, dec.msg_id);
        try std.testing.expectEqualSlices(u8, &test_body, dec.body);
    }

    // Padding beyond the 0..15 transport range corrupts the encrypted
    // part's shape (the next block is consumed as ciphertext padding) —
    // the msg_key check fails rather than silently shrinking the frame.
    var over: [dst.len + 16]u8 = undefined;
    @memcpy(over[0..dst.len], &dst);
    @memset(over[dst.len..], 0);
    try std.testing.expectError(
        error.MessageKeyMismatch,
        readEncrypted(&test_key, .server_to_client, test_session, &over),
    );
}

test "writeEncrypted validates inputs" {
    var prng = std.Random.DefaultPrng.init(3);
    var dst: [frameLength(test_body.len)]u8 = undefined;

    const good = Outgoing{
        .salt = 0,
        .session_id = test_session,
        .msg_id = 4,
        .seq_no = 0,
        .body = &test_body,
    };

    // Bodies must be four-byte aligned.
    try std.testing.expectError(
        error.MessageNotAligned,
        writeEncrypted(&test_key, .client_to_server, .{
            .salt = 0,
            .session_id = test_session,
            .msg_id = 4,
            .seq_no = 0,
            .body = test_body[0..6],
        }, prng.random(), &dst),
    );

    // dst must match frameLength exactly — no truncation, no spare room.
    try std.testing.expectError(
        error.InvalidLength,
        writeEncrypted(&test_key, .client_to_server, good, prng.random(), dst[0 .. dst.len - 16]),
    );
    var big: [frameLength(test_body.len) + 16]u8 = undefined;
    try std.testing.expectError(
        error.InvalidLength,
        writeEncrypted(&test_key, .client_to_server, good, prng.random(), &big),
    );
}

test "msg_id direction rules and time window" {
    const base = @as(i64, 1_700_000_000) << 32;

    try std.testing.expect(isValidClientMsgId(base | 4));
    try std.testing.expect(isValidClientMsgId(base | 0x1000));
    try std.testing.expect(!isValidClientMsgId(base | 1));
    try std.testing.expect(!isValidClientMsgId(base | 2));
    try std.testing.expect(!isValidClientMsgId(0));

    try std.testing.expect(isValidServerMsgId(base | 1));
    try std.testing.expect(isValidServerMsgId(base | 3));
    try std.testing.expect(!isValidServerMsgId(base | 0));
    try std.testing.expect(!isValidServerMsgId(base | 2));
    try std.testing.expect(!isValidServerMsgId(0));

    try std.testing.expectEqual(@as(i64, 1_700_000_000), msgIdUnixTime(base | 3));

    const now: i64 = 1_700_000_000;
    try std.testing.expect(msgIdInTimeWindow(base | 1, now));
    try std.testing.expect(msgIdInTimeWindow((now - 300) << 32 | 1, now));
    try std.testing.expect(msgIdInTimeWindow((now + 30) << 32 | 1, now));
    try std.testing.expect(!msgIdInTimeWindow((now - 301) << 32 | 1, now));
    try std.testing.expect(!msgIdInTimeWindow((now + 31) << 32 | 1, now));
}

test "seq_no content rule" {
    try std.testing.expect(isContentRelated(1));
    try std.testing.expect(isContentRelated(3));
    try std.testing.expect(isContentRelated(2 * 41 + 1));
    try std.testing.expect(!isContentRelated(0));
    try std.testing.expect(!isContentRelated(2));
    try std.testing.expect(!isContentRelated(2 * 41));
}

test "container roundtrip and structural limits" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const inner = [_]Incoming{
        .{ .msg_id = 0x0000_1000_0000_0004, .seq_no = 1, .body = &test_body },
        .{ .msg_id = 0x0000_1000_0000_0008, .seq_no = 3, .body = &test_body },
    };
    var w = Writer.init(arena);
    try writeContainer(&w, &inner);
    try std.testing.expectEqual(containerBodyLength(&inner), w.len());

    // Exact wire layout: ctor, count, then per message long/int/int/body.
    try std.testing.expectEqual(msg_container_id, std.mem.readInt(u32, w.items()[0..4], .little));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, w.items()[4..8], .little));
    try std.testing.expectEqual(inner[0].msg_id, std.mem.readInt(i64, w.items()[8..16], .little));

    var out: [2]Incoming = undefined;
    const count = try readContainer(w.items(), &out);
    try std.testing.expectEqual(@as(usize, 2), count);
    for (out[0..count], inner) |got, want| {
        try std.testing.expectEqual(want.msg_id, got.msg_id);
        try std.testing.expectEqual(want.seq_no, got.seq_no);
        try std.testing.expectEqualSlices(u8, want.body, got.body);
    }

    // Not a container.
    try std.testing.expectError(error.ContainerInvalid, readContainer(w.items()[4..], &out));

    // Caller buffer too small and over-limit counts.
    var small: [1]Incoming = undefined;
    try std.testing.expectError(error.ContainerTooLarge, readContainer(w.items(), &small));
    var w2 = Writer.init(arena);
    try w2.writeConstructorId(msg_container_id);
    try w2.writeUInt(max_container_messages + 1);
    var out2: [4]Incoming = undefined;
    try std.testing.expectError(error.ContainerTooLarge, readContainer(w2.items(), &out2));

    // Truncated tail.
    try std.testing.expectError(error.InvalidLength, readContainer(w.items()[0 .. w.len() - 4], &out));

    // Trailing garbage.
    var w3 = Writer.init(arena);
    try w3.writeRaw(w.items());
    try w3.writeInt(0);
    try std.testing.expectError(error.InvalidLength, readContainer(w3.items(), &out));
}

test "service messages: msgs_ack roundtrip" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    const ids = [_]i64{ 1, -2, 0x7fff_ffff_ffff_ffff };
    const ack = MsgsAck{ .msg_ids = &ids };
    try ack.serialize(&w);

    try std.testing.expectEqual(msgs_ack_id, std.mem.readInt(u32, w.items()[0..4], .little));
    // Boxed Vector<long>: the vector constructor id precedes the count.
    try std.testing.expectEqual(tl.vector_constructor_id, std.mem.readInt(u32, w.items()[4..8], .little));

    var r = Reader.init(w.items());
    const parsed = try MsgsAck.deserialize(std.testing.allocator, &r);
    defer std.testing.allocator.free(parsed.msg_ids);
    try std.testing.expectEqualSlices(i64, &ids, parsed.msg_ids);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "service messages: parse and classify bodies" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // bad_server_salt — the client re-sends bad_msg_id with the new salt.
    {
        var w = Writer.init(arena);
        try w.writeConstructorId(bad_server_salt_id);
        try w.writeLong(0x2000_0004);
        try w.writeInt(1);
        try w.writeInt(err_salt_invalid);
        try w.writeLong(@bitCast(@as(u64, 0xfeed_face_beef_cafe)));
        var body = try parseServiceBody(arena, w.items());
        defer body.deinit(arena);
        try std.testing.expectEqual(
            @as(i64, @bitCast(@as(u64, 0xfeed_face_beef_cafe))),
            body.bad_server_salt.new_server_salt,
        );
        try std.testing.expectEqual(err_salt_invalid, body.bad_server_salt.error_code);
        try std.testing.expectEqual(@as(i64, 0x2000_0004), body.bad_server_salt.bad_msg_id);
    }

    // bad_msg_notification.
    {
        var w = Writer.init(arena);
        try w.writeConstructorId(bad_msg_notification_id);
        try w.writeLong(7);
        try w.writeInt(2);
        try w.writeInt(err_msg_id_too_high);
        const body = try parseServiceBody(arena, w.items());
        try std.testing.expectEqual(err_msg_id_too_high, body.bad_msg_notification.error_code);
    }

    // new_session_created.
    {
        var w = Writer.init(arena);
        try w.writeConstructorId(new_session_created_id);
        try w.writeLong(0x1111);
        try w.writeLong(0x2222);
        try w.writeLong(0x3333);
        const body = try parseServiceBody(arena, w.items());
        try std.testing.expectEqual(@as(i64, 0x3333), body.new_session_created.server_salt);
    }

    // pong.
    {
        var w = Writer.init(arena);
        try w.writeConstructorId(pong_id);
        try w.writeLong(0x4444);
        try w.writeLong(0x5555);
        const body = try parseServiceBody(arena, w.items());
        try std.testing.expectEqual(@as(i64, 0x5555), body.pong.ping_id);
    }

    // rpc_result with an rpc_error inside.
    {
        var w = Writer.init(arena);
        try w.writeConstructorId(rpc_result_id);
        try w.writeLong(0x6666);
        try w.writeConstructorId(rpc_error_id);
        try w.writeInt(420);
        try w.writeString("FLOOD_WAIT_60");
        const body = try parseServiceBody(arena, w.items());
        try std.testing.expectEqual(@as(i64, 0x6666), body.rpc_result.req_msg_id);
        try std.testing.expectEqual(rpc_error_id, std.mem.readInt(u32, body.rpc_result.result[0..4], .little));
    }

    // gzip_packed wrapper (payload stays opaque here).
    {
        var w = Writer.init(arena);
        try w.writeConstructorId(gzip_packed_id);
        try w.writeString("deflate-me");
        const body = try parseServiceBody(arena, w.items());
        try std.testing.expectEqualStrings("deflate-me", body.gzip_packed.packed_data);
    }

    // future_salts: bare vector, boxed elements.
    {
        var w = Writer.init(arena);
        try w.writeConstructorId(future_salts_id);
        try w.writeLong(0x7777);
        try w.writeInt(1_700_000_000);
        try w.writeVectorLength(2);
        try w.writeConstructorId(future_salt_id);
        try w.writeInt(1);
        try w.writeInt(2);
        try w.writeLong(0xaaaa);
        try w.writeConstructorId(future_salt_id);
        try w.writeInt(3);
        try w.writeInt(4);
        try w.writeLong(0xbbbb);
        var body = try parseServiceBody(arena, w.items());
        defer body.deinit(arena);
        try std.testing.expectEqual(@as(i64, 0x7777), body.future_salts.req_msg_id);
        try std.testing.expectEqual(@as(usize, 2), body.future_salts.salts.len);
        try std.testing.expectEqual(@as(i64, 0xaaaa), body.future_salts.salts[0].salt);
        try std.testing.expectEqual(@as(i64, 0xbbbb), body.future_salts.salts[1].salt);
    }

    // API-level bodies classify as unknown, keeping the ctor id.
    {
        var w = Writer.init(arena);
        try w.writeConstructorId(0xb1b8cc83); // user (API schema)
        try w.writeInt(1);
        const body = try parseServiceBody(arena, w.items());
        try std.testing.expectEqual(@as(u32, 0xb1b8cc83), body.unknown.constructor_id);
        try std.testing.expectEqualSlices(u8, w.items(), body.unknown.body);
    }
}

test "ping serialization" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var w = Writer.init(arena);
    const plain = Ping{ .ping_id = 0x1234 };
    try plain.serialize(&w);
    try std.testing.expectEqual(ping_id, std.mem.readInt(u32, w.items()[0..4], .little));
    try std.testing.expectEqual(@as(i64, 0x1234), std.mem.readInt(i64, w.items()[4..12], .little));

    var w2 = Writer.init(arena);
    const delayed = Ping{ .ping_id = 0x5678, .disconnect_delay = 60 };
    try delayed.serialize(&w2);
    try std.testing.expectEqual(ping_delay_disconnect_id, std.mem.readInt(u32, w2.items()[0..4], .little));
    try std.testing.expectEqual(@as(i32, 60), std.mem.readInt(i32, w2.items()[12..16], .little));
}
