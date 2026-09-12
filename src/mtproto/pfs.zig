//! Perfect forward secrecy (https://core.telegram.org/api/pfs): the
//! temporary auth keys traffic is encrypted with, and the
//! `auth.bindTempAuthKey` binding that ties them to the permanent key.
//!
//! The protocol: alongside the permanent auth key (the handshake's
//! `p_q_inner_data_dc` result, the one that authorizes the session), the
//! client generates short-lived temporary keys (`p_q_inner_data_temp_dc`,
//! see `Handshake.runTemp`) and does *all* encryption with those. A temp
//! key is unusable until `auth.bindTempAuthKey` ties it to the permanent
//! key; the permanent key itself never encrypts a message, so leaking a
//! long-term key cannot retroactively decrypt recorded traffic.
//!
//! The binding carries its own encryption quirk: the request's
//! `encrypted_message` field is a complete **MTProto v1** packet
//! encrypted with the **permanent** key (v2 everywhere else), with the
//! customary salt/session_id slots replaced by random bytes and the
//! request's own msg_id/seq_no embedded inside. The `bindTempAuthKey`
//! request itself travels encrypted with the temporary key. Field
//! placement transcribed from TDLib master (`SessionConnection::
//! encrypted_bind`) — the reference for what production servers accept;
//! the official page alone has proven misleading for this handshake
//! before.
//!
//! No logging in this module, ever: both the permanent and the temporary
//! keys are secret material.

const std = @import("std");
const crypto = @import("../crypto/mod.zig");
const tl = @import("../tl/mod.zig");
const Writer = tl.Writer;
const Reader = tl.Reader;
const TlError = @import("../errors.zig").TlError;
const ige = @import("../crypto/aes_ige.zig");

/// `bind_auth_key_inner` — the inner binding message serialized into the
/// encrypted blob (core MTProto schema, schema/mtproto.tl).
pub const bind_auth_key_inner_id: u32 = 0x75a3f765;

/// A temporary authorization key. RAM-only by spec ("Clients should keep
/// all temporarily generated keys in RAM only") — never persisted.
pub const TempKey = struct {
    /// Secret; never logged.
    key: [256]u8,
    /// SHA1(key)[12..20] — what the server sees in the auth_key_id slot.
    id: [8]u8,
    /// The server salt derived from the temp handshake.
    server_salt: [8]u8,
    /// Unix time (server clock) the server invalidates the key. The
    /// server may also expire it earlier at any moment.
    expires_at: i32,
};

/// Lifetime requested for freshly generated temp keys. The server may
/// expire them earlier, so callers must treat `expires_at` as an upper
/// bound and rotate ahead of it (see `Client` rotation margin).
pub const default_expires_in: i32 = 24 * 60 * 60;

/// Rotation lead: when a temp key is within this many seconds of
/// `expires_at` (client clock), it is regenerated and re-bound before
/// the next request instead of being used.
pub const rotate_margin_seconds: i64 = 60;

/// The inner binding message.
pub const BindAuthKeyInner = struct {
    /// Random long; must equal the `nonce` argument of the wrapping
    /// `auth.bindTempAuthKey` request.
    nonce: i64,
    temp_auth_key_id: i64,
    perm_auth_key_id: i64,
    /// The session id of the connection the request is sent on — the
    /// server validates that the binding names the session that used it.
    temp_session_id: i64,
    expires_at: i32,

    pub fn serialize(self: *const BindAuthKeyInner, w: *Writer) TlError!void {
        try w.writeConstructorId(bind_auth_key_inner_id);
        try w.writeLong(self.nonce);
        try w.writeLong(self.temp_auth_key_id);
        try w.writeLong(self.perm_auth_key_id);
        try w.writeLong(self.temp_session_id);
        try w.writeInt(self.expires_at);
    }
};

/// Serialized size of `BindAuthKeyInner` (id + 4×long + int).
pub const bind_inner_size: usize = 4 + 4 * 8 + 4;

/// Builds the `encrypted_message` of `auth.bindTempAuthKey`: a complete
/// MTProto **v1** packet encrypted with the **permanent** key.
///
/// Layout (all integers little-endian, per TDLib `encrypted_bind`):
///
///     auth_key_id   8    SHA1(perm_key)[12..20] — names the perm key
///     msg_key      16    SHA1(salt..body)[4..20] — padding excluded
///     ciphertext (AES-256-IGE, key/iv = v1 KDF(perm_key, msg_key, x=0)):
///       salt        8    random (salt/session slots are irrelevant here)
///       session_id  8    random
///       msg_id      8    the msg_id the request itself is sent under
///       seq_no      4    0
///       msg_len     4    = bind_inner_size (40)
///       inner      40    serialized BindAuthKeyInner
///       padding   0..15  random, to a multiple of 16
///
/// The returned blob is owned by the caller. `msg_id` must be the exact
/// msg_id the `auth.bindTempAuthKey` request is sent with — reserve it
/// first (`rpc.Client.reserveMsgId`).
pub fn buildBindBlob(
    allocator: std.mem.Allocator,
    perm_key: *const [256]u8,
    inner: BindAuthKeyInner,
    msg_id: i64,
    random: std.Random,
) (error{OutOfMemory} || TlError)![]u8 {
    var w = Writer.init(allocator);
    defer w.deinit();
    try inner.serialize(&w);
    std.debug.assert(w.items().len == bind_inner_size);
    const body = w.items();

    const plain_len = 16 + 16 + bind_inner_size; // salt+session slots + msg_id+seq_no+msg_len + body
    const padded_len = plain_len + (16 - plain_len % 16) % 16;

    const blob = try allocator.alloc(u8, 24 + padded_len); // auth_key_id + msg_key + ciphertext
    errdefer allocator.free(blob);
    const plain = blob[24..];
    std.mem.writeInt(i64, plain[0..8], random.int(i64), .little); // salt slot
    std.mem.writeInt(i64, plain[8..16], random.int(i64), .little); // session slot
    std.mem.writeInt(i64, plain[16..24], msg_id, .little);
    std.mem.writeInt(i32, plain[24..28], 0, .little); // seq_no
    std.mem.writeInt(u32, plain[28..32], @intCast(bind_inner_size), .little);
    @memcpy(plain[32..][0..body.len], body);
    random.bytes(plain[plain_len..]);

    // v1 msg_key covers everything up to the body — the padding is
    // excluded (TDLib hashes header.data + data_size for version 1).
    const msg_key = crypto.computeMsgKeyV1(plain[0..plain_len]);
    const params = crypto.deriveAesParamsV1(perm_key, &msg_key, 0);
    ige.encrypt256(params.key, params.iv, plain, plain) catch unreachable; // aligned by construction

    const key_id = crypto.authKeyId(perm_key);
    @memcpy(blob[0..8], &key_id);
    @memcpy(blob[8..24], &msg_key);
    return blob;
}

/// The server-side view of a bind blob, recovered by `openBindBlob`.
pub const OpenedBind = struct {
    /// The msg_id embedded in the packet (the server compares it with
    /// the outer request's msg_id).
    msg_id: i64,
    inner: BindAuthKeyInner,
};

pub const OpenError = error{
    /// Blob shorter than any fixed header, or ciphertext not 16-aligned.
    InvalidFormat,
    /// auth_key_id does not name this permanent key.
    AuthKeyIdMismatch,
    /// Decrypted inner is not `bind_auth_key_inner`, or its length
    /// field disagrees with the fixed size.
    InvalidInner,
    /// The recomputed v1 msg_key does not match — wrong key or tampered
    /// ciphertext (what a server answers with ENCRYPTED_MESSAGE_INVALID).
    MessageKeyMismatch,
};

/// Opens a bind blob encrypted for `perm_key` (the loopback peer's job,
/// and the independent decoder for round-trip tests). Decrypts in place
/// — `blob` must be a mutable copy. Integrity: v1 verifies the msg_key
/// over `salt..body` only — the random padding is outside the hash by
/// protocol (a padding-region flip is undetectable, as on real servers).
pub fn openBindBlob(blob: []u8, perm_key: *const [256]u8) OpenError!OpenedBind {
    if (blob.len < 24 + 16) return error.InvalidFormat;
    const key_id = crypto.authKeyId(perm_key);
    if (!std.mem.eql(u8, blob[0..8], &key_id)) return error.AuthKeyIdMismatch;
    const plain = blob[24..];
    if (plain.len % 16 != 0) return error.InvalidFormat;

    var msg_key: [16]u8 = undefined;
    @memcpy(&msg_key, blob[8..24]);
    const params = crypto.deriveAesParamsV1(perm_key, &msg_key, 0);
    ige.decrypt256(params.key, params.iv, plain, plain) catch return error.InvalidFormat;

    if (plain.len < 32) return error.InvalidFormat;
    const msg_id = std.mem.readInt(i64, plain[16..24], .little);
    const seq_no = std.mem.readInt(i32, plain[24..28], .little);
    const msg_len = std.mem.readInt(u32, plain[28..32], .little);
    // The spec pins seq_no to 0 and the body to exactly one
    // bind_auth_key_inner.
    if (seq_no != 0) return error.InvalidInner;
    if (msg_len != bind_inner_size or plain.len < 32 + bind_inner_size) return error.InvalidInner;

    // v1 verification: msg_key = SHA1(salt .. end-of-body)[4..20].
    const check = crypto.computeMsgKeyV1(plain[0 .. 32 + bind_inner_size]);
    if (!std.crypto.timing_safe.eql([16]u8, check, msg_key)) return error.MessageKeyMismatch;

    var r = Reader.init(plain[32 .. 32 + bind_inner_size]);
    if ((r.readConstructorId() catch return error.InvalidInner) != bind_auth_key_inner_id) return error.InvalidInner;
    var inner: BindAuthKeyInner = undefined;
    inner.nonce = r.readLong() catch return error.InvalidInner;
    inner.temp_auth_key_id = r.readLong() catch return error.InvalidInner;
    inner.perm_auth_key_id = r.readLong() catch return error.InvalidInner;
    inner.temp_session_id = r.readLong() catch return error.InvalidInner;
    inner.expires_at = r.readInt() catch return error.InvalidInner;
    return .{ .msg_id = msg_id, .inner = inner };
}

// ---------------------------------------------------------------- tests

const test_perm_key = blk: {
    var k: [256]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 67 +% 3);
    break :blk k;
};

test "bind blob round-trips through the independent opener" {
    var prng = std.Random.DefaultPrng.init(0xb10b);

    const inner = BindAuthKeyInner{
        .nonce = 0x1122334455667788,
        .temp_auth_key_id = @bitCast(@as(u64, 0xaabbccdd11223344)),
        .perm_auth_key_id = @bitCast(@as(u64, 0xfeedface87654321)),
        .temp_session_id = 0x5555_aaaa_5555_aaaa,
        .expires_at = 1_900_000_000,
    };
    const msg_id: i64 = @bitCast(@as(u64, 1_770_000_000) << 32 | 8);

    const blob = try buildBindBlob(std.testing.allocator, &test_perm_key, inner, msg_id, prng.random());
    defer std.testing.allocator.free(blob);

    // auth_key_id names the permanent key; the ciphertext is 16-aligned.
    try std.testing.expectEqualSlices(u8, &crypto.authKeyId(&test_perm_key), blob[0..8]);
    try std.testing.expectEqual(@as(usize, 24 + 80), blob.len); // 72-byte plaintext + 8 pad

    const opened = try openBindBlob(@constCast(blob), &test_perm_key);
    try std.testing.expectEqual(msg_id, opened.msg_id);
    try std.testing.expectEqual(inner.nonce, opened.inner.nonce);
    try std.testing.expectEqual(inner.temp_auth_key_id, opened.inner.temp_auth_key_id);
    try std.testing.expectEqual(inner.perm_auth_key_id, opened.inner.perm_auth_key_id);
    try std.testing.expectEqual(inner.temp_session_id, opened.inner.temp_session_id);
    try std.testing.expectEqual(inner.expires_at, opened.inner.expires_at);
}

test "bind blob rejects a wrong permanent key and tampered ciphertext" {
    var prng = std.Random.DefaultPrng.init(0xb10c);
    var other_key = test_perm_key;
    other_key[0] ^= 1;

    const blob = try buildBindBlob(std.testing.allocator, &test_perm_key, .{
        .nonce = 1,
        .temp_auth_key_id = 2,
        .perm_auth_key_id = 3,
        .temp_session_id = 4,
        .expires_at = 5,
    }, 0x100, prng.random());
    defer std.testing.allocator.free(blob);

    // auth_key_id travels in the clear: a wrong permanent key is
    // rejected before any decryption.
    try std.testing.expectError(error.AuthKeyIdMismatch, openBindBlob(@constCast(blob), &other_key));

    // Flip one byte of the second-to-last ciphertext block: IGE garbles
    // that plaintext block (inside the hashed region) plus the final
    // block, so the recomputed msg_key no longer matches — the v1
    // counterpart of MessageKeyMismatch. Padding-region flips are the
    // one tamper v1 cannot see (the hash stops at the body).
    var tampered = std.testing.allocator.dupe(u8, blob) catch unreachable;
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 32] ^= 0x80;
    try std.testing.expectError(error.MessageKeyMismatch, openBindBlob(tampered, &test_perm_key));

    // Truncation below the fixed headers is structural.
    try std.testing.expectError(error.InvalidFormat, openBindBlob(tampered[0..30], &test_perm_key));
}

test "opened blob pins seq_no to zero" {
    var prng = std.Random.DefaultPrng.init(0xb10d);
    const blob = try buildBindBlob(std.testing.allocator, &test_perm_key, .{
        .nonce = 1,
        .temp_auth_key_id = 2,
        .perm_auth_key_id = 3,
        .temp_session_id = 4,
        .expires_at = 5,
    }, 0x200, prng.random());
    defer std.testing.allocator.free(blob);
    // seq_no is written by buildBindBlob at blob[24+16+8..]; flip it.
    const seq_off = 24 + 16 + 8;
    @memset(blob[seq_off..][0..4], 1);
    try std.testing.expectError(error.InvalidInner, openBindBlob(@constCast(blob), &test_perm_key));
}
