//! MTProto 2.0 message-key computation, AES parameter derivation and
//! message encryption/decryption primitives.
//!
//! Implemented exactly per https://core.telegram.org/mtproto/description:
//!
//!   msg_key_large = SHA256(auth_key[88+x .. 88+x+32] ++ data_with_padding)
//!   msg_key       = msg_key_large[8..24]
//!
//!   sha256_a = SHA256(msg_key ++ auth_key[x .. x+36])
//!   sha256_b = SHA256(auth_key[40+x .. 40+x+36] ++ msg_key)
//!   aes_key  = sha256_a[0..8]  ++ sha256_b[8..24] ++ sha256_a[24..32]
//!   aes_iv   = sha256_b[0..8]  ++ sha256_a[8..24] ++ sha256_b[24..32]
//!
//!   x = 0 for client→server, x = 8 for server→client
//!
//!   auth_key_id = SHA1(auth_key)[12..20]  (the 64 lower-order bits)
//!
//! Padding: random bytes, at least 12, such that the padded length is a
//! multiple of 16; padding is covered by the msg_key hash.
//!
//! All functions are allocation-free and operate on caller-owned buffers;
//! nothing is truncated silently (wrong sizes are errors).

const std = @import("std");
const ige = @import("aes_ige.zig");

pub const Sha1 = std.crypto.hash.Sha1;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

/// Authorization key length in bytes (2048 bits), as used by MTProto.
pub const auth_key_size: usize = 256;
/// msg_key length in bytes.
pub const msg_key_size: usize = 16;
/// AES block size.
pub const block_size: usize = 16;
/// Minimum random padding (spec: 12..1024 bytes).
pub const min_padding: usize = 12;

pub const Direction = enum(u8) {
    client_to_server = 0,
    server_to_client = 8,

    /// The `x` offset into auth_key used by the key/IV derivation.
    pub fn x(self: Direction) usize {
        return @intFromEnum(self);
    }
};

pub const Error = error{
    /// auth_key must be exactly 256 bytes.
    InvalidKeySize,
    /// Padded payload length is not a multiple of 16.
    InvalidLength,
    /// Destination buffer does not exactly fit the result.
    BufferTooSmall,
    /// Decrypted payload does not match the received msg_key (tampering,
    /// wrong key, or wrong direction).
    MessageKeyMismatch,
};

/// auth_key_id: the 64 lower-order bits of SHA1(auth_key).
pub fn authKeyId(auth_key: *const [auth_key_size]u8) [8]u8 {
    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(auth_key, &digest, .{});
    return digest[12..20].*;
}

/// msg_key over already-padded payload:
/// SHA256(auth_key[88+x .. 88+x+32] ++ data_with_padding)[8..24].
pub fn computeMsgKey(
    auth_key: *const [auth_key_size]u8,
    direction: Direction,
    data_with_padding: []const u8,
) Error![msg_key_size]u8 {
    if (data_with_padding.len % block_size != 0) return error.InvalidLength;
    var h = Sha256.init(.{});
    h.update(auth_key[88 + direction.x() ..][0..32]);
    h.update(data_with_padding);
    var digest: [Sha256.digest_length]u8 = undefined;
    h.final(&digest);
    return digest[8..24].*;
}

/// The AES-256 key and IGE IV derived from msg_key and auth_key.
pub const AesParams = struct {
    key: [32]u8,
    iv: [ige.iv_size]u8,
};

/// Derives the AES-256-IGE key/IV pair per the MTProto 2.0 formulas.
pub fn deriveAesParams(
    auth_key: *const [auth_key_size]u8,
    msg_key: *const [msg_key_size]u8,
    direction: Direction,
) AesParams {
    const x = direction.x();

    var buf_a: [msg_key_size + 36]u8 = undefined;
    @memcpy(buf_a[0..msg_key_size], msg_key);
    @memcpy(buf_a[msg_key_size..], auth_key[x..][0..36]);
    var sha256_a: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&buf_a, &sha256_a, .{});

    var buf_b: [36 + msg_key_size]u8 = undefined;
    @memcpy(buf_b[0..36], auth_key[40 + x ..][0..36]);
    @memcpy(buf_b[36..], msg_key);
    var sha256_b: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&buf_b, &sha256_b, .{});

    var params: AesParams = undefined;
    @memcpy(params.key[0..8], sha256_a[0..8]);
    @memcpy(params.key[8..24], sha256_b[8..24]);
    @memcpy(params.key[24..32], sha256_a[24..32]);
    @memcpy(params.iv[0..8], sha256_b[0..8]);
    @memcpy(params.iv[8..24], sha256_a[8..24]);
    @memcpy(params.iv[24..32], sha256_b[24..32]);
    return params;
}

/// Returns the padded length for a plaintext of `len` bytes: the smallest
/// multiple of 16 that is at least `len + 12` (spec: random padding of
/// 12..1024 bytes, total divisible by 16).
pub fn paddedLength(len: usize) usize {
    const target = len + min_padding;
    return target + (block_size - target % block_size) % block_size;
}

/// Copies `plaintext` into `dst` and fills the remainder with random
/// padding, returning the padded length. `dst` must be at least
/// `paddedLength(plaintext.len)` bytes; anything smaller is an error.
/// The RNG is injected so tests can be deterministic.
pub fn padMessage(
    plaintext: []const u8,
    dst: []u8,
    rng: std.Random,
) Error!usize {
    const padded = paddedLength(plaintext.len);
    if (dst.len < padded) return error.BufferTooSmall;
    @memcpy(dst[0..plaintext.len], plaintext);
    rng.bytes(dst[plaintext.len..padded]);
    return padded;
}

/// Encrypts a padded payload (MTProto 2.0, AES-256-IGE) into `dst`.
/// `msg_key_out` receives the message key. `dst.len` must equal
/// `padded.len`.
pub fn encryptMessage(
    auth_key: *const [auth_key_size]u8,
    direction: Direction,
    padded: []const u8,
    dst: []u8,
    msg_key_out: *[msg_key_size]u8,
) Error!void {
    const msg_key = try computeMsgKey(auth_key, direction, padded);
    const params = deriveAesParams(auth_key, &msg_key, direction);
    ige.encrypt256(params.key, params.iv, padded, dst) catch |e| switch (e) {
        error.InvalidLength => return error.InvalidLength,
        error.BufferSizeMismatch => return error.BufferTooSmall,
    };
    msg_key_out.* = msg_key;
}

/// Decrypts a ciphertext payload and verifies its msg_key (computed the
/// same way over the decrypted padded data). The plaintext-with-padding is
/// written to `dst`; `msg_key` is the key received alongside the message.
/// A mismatch (wrong key/direction/tampering) is `error.MessageKeyMismatch`.
/// Length rules mirror `encryptMessage`; MTProto framing (reading the real
/// payload length out of the decrypted header) belongs to the future
/// transport layer, not to these primitives.
pub fn decryptMessage(
    auth_key: *const [auth_key_size]u8,
    direction: Direction,
    msg_key: *const [msg_key_size]u8,
    ciphertext: []const u8,
    dst: []u8,
) Error!void {
    const params = deriveAesParams(auth_key, msg_key, direction);
    ige.decrypt256(params.key, params.iv, ciphertext, dst) catch |e| switch (e) {
        error.InvalidLength => return error.InvalidLength,
        error.BufferSizeMismatch => return error.BufferTooSmall,
    };
    const check = try computeMsgKey(auth_key, direction, dst);
    if (!std.crypto.timing_safe.eql([msg_key_size]u8, check, msg_key.*)) {
        return error.MessageKeyMismatch;
    }
}

/// Cryptographically secure random bytes from the OS CSPRNG.
/// Takes the `Io` instance explicitly (no hidden process-global RNG).
pub fn randomBytes(io: std.Io, buf: []u8) std.Io.RandomSecureError!void {
    return std.Io.randomSecure(io, buf);
}

// ------------------------------------------------------- MTProto v1 (PFS)
//
// The legacy v1 message encryption survives in exactly one place on the
// modern wire: the `encrypted_message` of `auth.bindTempAuthKey`
// (https://core.telegram.org/api/pfs) is a complete v1 packet encrypted
// with the *permanent* key. Formulas transcribed from TDLib master
// (td/mtproto/KDF.cpp `KDF`, td/mtproto/Transport.cpp v1 paths) — the
// reference for what production servers accept.

/// v1 msg_key over the plaintext-with-header, **excluding** the trailing
/// random padding: SHA1(data)[4..20]. TDLib hashes exactly
/// salt..body (v1 `calc_message_ack_and_key`); x/direction plays no role.
pub fn computeMsgKeyV1(data: []const u8) [msg_key_size]u8 {
    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(data, &digest, .{});
    return digest[4..20].*;
}

/// The v1 AES-256-IGE key/IV derivation. `x` offsets into auth_key; on
/// the wire this survives only as client→server traffic (the bind blob),
/// where TDLib hardcodes x = 0 for v1 in both directions — so callers
/// pass 0.
pub fn deriveAesParamsV1(
    auth_key: *const [auth_key_size]u8,
    msg_key: *const [msg_key_size]u8,
    x: usize,
) AesParams {
    var buf: [48]u8 = undefined;

    // sha1_a = SHA1(msg_key ++ auth_key[x .. x+32])
    @memcpy(buf[0..msg_key_size], msg_key);
    @memcpy(buf[msg_key_size..], auth_key[x..][0..32]);
    var sha1_a: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&buf, &sha1_a, .{});

    // sha1_b = SHA1(auth_key[x+32 .. x+48] ++ msg_key ++ auth_key[x+48 .. x+64])
    @memcpy(buf[0..16], auth_key[x + 32 ..][0..16]);
    @memcpy(buf[16..32], msg_key);
    @memcpy(buf[32..48], auth_key[x + 48 ..][0..16]);
    var sha1_b: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&buf, &sha1_b, .{});

    // sha1_c = SHA1(auth_key[64+x .. 96+x] ++ msg_key)
    @memcpy(buf[0..32], auth_key[64 + x ..][0..32]);
    @memcpy(buf[32..48], msg_key);
    var sha1_c: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&buf, &sha1_c, .{});

    // sha1_d = SHA1(msg_key ++ auth_key[96+x .. 128+x])
    @memcpy(buf[0..16], msg_key);
    @memcpy(buf[16..48], auth_key[96 + x ..][0..32]);
    var sha1_d: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&buf, &sha1_d, .{});

    var params: AesParams = undefined;
    @memcpy(params.key[0..8], sha1_a[0..8]);
    @memcpy(params.key[8..20], sha1_b[8..20]);
    @memcpy(params.key[20..32], sha1_c[4..16]);
    @memcpy(params.iv[0..12], sha1_a[8..20]);
    @memcpy(params.iv[12..20], sha1_b[0..8]);
    @memcpy(params.iv[20..24], sha1_c[16..20]);
    @memcpy(params.iv[24..32], sha1_d[0..8]);
    return params;
}

test "v1 msg_key and KDF match the TDLib formulas" {
    const payload = [_]u8{0x5a} ** 64;

    // msg_key: SHA1(plain)[4..20], independent recomputation.
    var sha1_full: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&payload, &sha1_full, .{});
    const key = computeMsgKeyV1(&payload);
    try std.testing.expectEqualSlices(u8, sha1_full[4..20], &key);

    // KDF chunks, independent recomputation (x = 0, the wire value).
    const msg_key = [_]u8{0x33} ** 16;
    const params = deriveAesParamsV1(&test_key, &msg_key, 0);

    var buf: [48]u8 = undefined;
    @memcpy(buf[0..16], &msg_key);
    @memcpy(buf[16..], test_key[0..32]);
    var a: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&buf, &a, .{});
    @memcpy(buf[0..16], test_key[32..48]);
    @memcpy(buf[16..32], &msg_key);
    @memcpy(buf[32..], test_key[48..64]);
    var b: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&buf, &b, .{});
    @memcpy(buf[0..32], test_key[64..96]);
    @memcpy(buf[32..], &msg_key);
    var c: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&buf, &c, .{});
    @memcpy(buf[0..16], &msg_key);
    @memcpy(buf[16..], test_key[96..128]);
    var d: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&buf, &d, .{});

    var expect_key: [32]u8 = undefined;
    @memcpy(expect_key[0..8], a[0..8]);
    @memcpy(expect_key[8..20], b[8..20]);
    @memcpy(expect_key[20..32], c[4..16]);
    var expect_iv: [32]u8 = undefined;
    @memcpy(expect_iv[0..12], a[8..20]);
    @memcpy(expect_iv[12..20], b[0..8]);
    @memcpy(expect_iv[20..24], c[16..20]);
    @memcpy(expect_iv[24..32], d[0..8]);
    try std.testing.expectEqualSlices(u8, &expect_key, &params.key);
    try std.testing.expectEqualSlices(u8, &expect_iv, &params.iv);

    // A nonzero x offsets every auth_key window (kept for completeness;
    // the wire always uses 0).
    const params8 = deriveAesParamsV1(&test_key, &msg_key, 8);
    try std.testing.expect(!std.mem.eql(u8, &params.key, &params8.key));
}

// ---------------------------------------------------------------- tests

// Varied byte pattern so the different auth_key windows (x=0 vs x=8) used
// by the two directions actually contain different bytes in tests.
const test_key = blk: {
    var k: [auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    break :blk k;
};

test "authKeyId is SHA1(auth_key)[12..20]" {
    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(&test_key, &digest, .{});
    const id = authKeyId(&test_key);
    try std.testing.expectEqualSlices(u8, digest[12..20], &id);
    // Different keys give different ids.
    var other = test_key;
    other[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &id, &authKeyId(&other)));
}

test "msg_key formula and direction sensitivity" {
    const payload = [_]u8{0xab} ** 48;

    const c2s = try computeMsgKey(&test_key, .client_to_server, &payload);
    const s2c = try computeMsgKey(&test_key, .server_to_client, &payload);

    // Independent recomputation straight from the spec text.
    var expect: [Sha256.digest_length]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(test_key[88..120]); // 88+x, x=0
    h.update(&payload);
    h.final(&expect);
    try std.testing.expectEqualSlices(u8, expect[8..24], &c2s);

    var expect2: [Sha256.digest_length]u8 = undefined;
    var h2 = Sha256.init(.{});
    h2.update(test_key[96..128]); // 88+8
    h2.update(&payload);
    h2.final(&expect2);
    try std.testing.expectEqualSlices(u8, expect2[8..24], &s2c);

    try std.testing.expect(!std.mem.eql(u8, &c2s, &s2c));
    try std.testing.expectError(error.InvalidLength, computeMsgKey(&test_key, .client_to_server, payload[0..20]));
}

test "aes params derivation follows the spec chunking" {
    const msg_key = [_]u8{0x11} ** 16;
    const params = deriveAesParams(&test_key, &msg_key, .client_to_server);

    // Independent recomputation.
    var buf_a: [16 + 36]u8 = undefined;
    @memcpy(buf_a[0..16], &msg_key);
    @memcpy(buf_a[16..], test_key[0..36]); // x=0
    var a: [32]u8 = undefined;
    Sha256.hash(&buf_a, &a, .{});

    var buf_b: [36 + 16]u8 = undefined;
    @memcpy(buf_b[0..36], test_key[40..76]); // 40+x, x=0
    @memcpy(buf_b[36..], &msg_key);
    var b: [32]u8 = undefined;
    Sha256.hash(&buf_b, &b, .{});

    var expect_key: [32]u8 = undefined;
    @memcpy(expect_key[0..8], a[0..8]);
    @memcpy(expect_key[8..24], b[8..24]);
    @memcpy(expect_key[24..32], a[24..32]);
    var expect_iv: [32]u8 = undefined;
    @memcpy(expect_iv[0..8], b[0..8]);
    @memcpy(expect_iv[8..24], a[8..24]);
    @memcpy(expect_iv[24..32], b[24..32]);

    try std.testing.expectEqualSlices(u8, &expect_key, &params.key);
    try std.testing.expectEqualSlices(u8, &expect_iv, &params.iv);

    // Direction changes the derived key (x=8 offsets).
    const params_s2c = deriveAesParams(&test_key, &msg_key, .server_to_client);
    try std.testing.expect(!std.mem.eql(u8, &params.key, &params_s2c.key));
}

test "padding rules" {
    try std.testing.expectEqual(@as(usize, 32), paddedLength(17)); // 17+12=29 → 32
    try std.testing.expectEqual(@as(usize, 16), paddedLength(4)); // 4+12=16
    try std.testing.expectEqual(@as(usize, 48), paddedLength(33)); // 45 → 48

    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    const message = "hello mtproto";
    var buf: [64]u8 = undefined;
    const padded = try padMessage(message, &buf, prng.random());
    try std.testing.expectEqual(paddedLength(message.len), padded);
    try std.testing.expectEqualSlices(u8, message, buf[0..message.len]);
    try std.testing.expectEqual(@as(u8, 0), buf[message.len..padded].len % 1); // padding exists
    try std.testing.expect(padded - message.len >= min_padding);

    var small: [16]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, padMessage(message, &small, prng.random()));
}

test "encrypt/decrypt message roundtrip with msg_key verification" {
    var prng = std.Random.DefaultPrng.init(7);
    const plaintext = "MTProto 2.0 payload with internal header placeholder";
    var padded_buf: [128]u8 = undefined;
    const padded_len = try padMessage(plaintext, &padded_buf, prng.random());
    const padded = padded_buf[0..padded_len];

    var msg_key: [msg_key_size]u8 = undefined;
    var ciphertext: [128]u8 = undefined;
    try encryptMessage(&test_key, .client_to_server, padded, ciphertext[0..padded_len], &msg_key);
    try std.testing.expect(!std.mem.eql(u8, padded, ciphertext[0..padded_len]));

    var decrypted: [128]u8 = undefined;
    try decryptMessage(&test_key, .client_to_server, &msg_key, ciphertext[0..padded_len], decrypted[0..padded_len]);
    try std.testing.expectEqualSlices(u8, padded, decrypted[0..padded_len]);

    // Wrong direction fails msg_key verification.
    try std.testing.expectError(
        error.MessageKeyMismatch,
        decryptMessage(&test_key, .server_to_client, &msg_key, ciphertext[0..padded_len], decrypted[0..padded_len]),
    );

    // Tampered ciphertext fails msg_key verification.
    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..padded_len], ciphertext[0..padded_len]);
    tampered[padded_len - 1] ^= 0x80;
    try std.testing.expectError(
        error.MessageKeyMismatch,
        decryptMessage(&test_key, .client_to_server, &msg_key, tampered[0..padded_len], decrypted[0..padded_len]),
    );

    // Wrong sizes are errors, not truncation.
    try std.testing.expectError(error.InvalidLength, encryptMessage(&test_key, .client_to_server, padded[0 .. padded_len - 1], ciphertext[0 .. padded_len - 1], &msg_key));
    try std.testing.expectError(error.BufferTooSmall, encryptMessage(&test_key, .client_to_server, padded, ciphertext[0 .. padded_len - 16], &msg_key));
}

test "sha1 and sha256 standard vectors" {
    // SHA-1("abc")
    var d1: [Sha1.digest_length]u8 = undefined;
    Sha1.hash("abc", &d1, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    }, &d1);

    // SHA-256("abc")
    var d2: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("abc", &d2, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    }, &d2);

    // SHA-256("")
    var d3: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("", &d3, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    }, &d3);
}
