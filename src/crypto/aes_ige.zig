//! AES-IGE (Infinite Garble Extension) block cipher mode, as required by
//! MTProto 2.0: https://core.telegram.org/mtproto/description
//!
//! The AES core comes from the Zig standard library (`std.crypto.core.aes`,
//! a well-audited implementation); only the IGE chaining — a fully specified
//! ISO mode — is implemented here:
//!
//!   encryption:  C_i = E_K(P_i  XOR C_{i-1}) XOR P_{i-1}
//!   decryption:  P_i = D_K(C_i  XOR C_{i-1}) XOR P_{i-1}
//!
//! where the 32-byte IGE initialization vector is
//!   iv[0..16]  = C_{-1}   (previous ciphertext block)
//!   iv[16..32] = P_{-1}   (previous plaintext block)
//!
//! All functions are allocation-free. Input length must be an exact
//! multiple of 16 bytes; anything else is an error — never truncated.

const std = @import("std");
const aes = std.crypto.core.aes;

pub const block_size: usize = 16;
pub const iv_size: usize = 32;

pub const Error = error{
    /// Input length is not a multiple of the 16-byte AES block size.
    InvalidLength,
    /// Destination buffer size does not exactly match the input.
    BufferSizeMismatch,
};

/// Generic single-key IGE over any AES key size (128/192/256).
fn igeEncrypt(
    comptime Aes: type,
    key: [Aes.key_bits / 8]u8,
    iv: [iv_size]u8,
    src: []const u8,
    dst: []u8,
) Error!void {
    if (src.len % block_size != 0) return error.InvalidLength;
    if (dst.len != src.len) return error.BufferSizeMismatch;

    const ctx = Aes.initEnc(key);
    var x = iv[0..block_size].*; // C_{i-1}
    var y = iv[block_size..][0..block_size].*; // P_{i-1}

    var i: usize = 0;
    while (i < src.len) : (i += block_size) {
        const in_block = src[i..][0..block_size].*; // captured before dst write (src may alias dst)
        var block: [block_size]u8 = undefined;
        for (&block, in_block, x) |*b, s, xk| b.* = s ^ xk;
        ctx.encrypt(&block, &block);
        for (&block, y) |*b, yk| b.* ^= yk;
        @memcpy(dst[i..][0..block_size], &block);
        x = block; // ciphertext just produced
        y = in_block; // plaintext just consumed
    }
}

/// IGE decryption is the algebraic inverse of encryption:
///   encryption: C_i = E(P_i  XOR C_{i-1}) XOR P_{i-1}
///   decryption: P_i = D(C_i  XOR P_{i-1}) XOR C_{i-1}
/// (note the feedback halves swap roles compared to encryption).
fn igeDecrypt(
    comptime Aes: type,
    key: [Aes.key_bits / 8]u8,
    iv: [iv_size]u8,
    src: []const u8,
    dst: []u8,
) Error!void {
    if (src.len % block_size != 0) return error.InvalidLength;
    if (dst.len != src.len) return error.BufferSizeMismatch;

    const ctx = Aes.initDec(key);
    var x = iv[0..block_size].*; // C_{i-1}
    var y = iv[block_size..][0..block_size].*; // P_{i-1}

    var i: usize = 0;
    while (i < src.len) : (i += block_size) {
        const in_block = src[i..][0..block_size].*; // captured before dst write (src may alias dst)
        var block: [block_size]u8 = undefined;
        for (&block, in_block, y) |*b, s, yk| b.* = s ^ yk;
        ctx.decrypt(&block, &block);
        for (&block, x) |*b, xk| b.* ^= xk;
        @memcpy(dst[i..][0..block_size], &block);
        x = in_block; // ciphertext just consumed
        y = block; // plaintext just produced
    }
}

/// AES-256-IGE encryption (the variant MTProto 2.0 uses).
pub fn encrypt256(key: [32]u8, iv: [iv_size]u8, src: []const u8, dst: []u8) Error!void {
    return igeEncrypt(aes.Aes256, key, iv, src, dst);
}

/// AES-256-IGE decryption.
pub fn decrypt256(key: [32]u8, iv: [iv_size]u8, src: []const u8, dst: []u8) Error!void {
    return igeDecrypt(aes.Aes256, key, iv, src, dst);
}

/// AES-128-IGE encryption (not used by MTProto; exists to validate the IGE
/// chaining against published OpenSSL known-answer vectors).
pub fn encrypt128(key: [16]u8, iv: [iv_size]u8, src: []const u8, dst: []u8) Error!void {
    return igeEncrypt(aes.Aes128, key, iv, src, dst);
}

pub fn decrypt128(key: [16]u8, iv: [iv_size]u8, src: []const u8, dst: []u8) Error!void {
    return igeDecrypt(aes.Aes128, key, iv, src, dst);
}

// ---------------------------------------------------------------- tests

test "AES-128-IGE OpenSSL vector" {
    const key = [16]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const iv = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const input = [_]u8{0} ** 32;
    const expected = [32]u8{
        0x1a, 0x85, 0x19, 0xa6, 0x55, 0x7b, 0xe6, 0x52,
        0xe9, 0xda, 0x8e, 0x43, 0xda, 0x4e, 0xf4, 0x45,
        0x3c, 0xf4, 0x56, 0xb4, 0xca, 0x48, 0x8a, 0xa3,
        0x83, 0xc7, 0x9c, 0x98, 0xb3, 0x47, 0x97, 0xcb,
    };

    var out: [32]u8 = undefined;
    try encrypt128(key, iv, &input, &out);
    try std.testing.expectEqualSlices(u8, &expected, &out);

    var back: [32]u8 = undefined;
    try decrypt128(key, iv, &out, &back);
    try std.testing.expectEqualSlices(u8, &input, &back);
}

test "AES-256-IGE roundtrip and in-place" {
    const key = [_]u8{0x5a} ** 32;
    const iv = [_]u8{ 0 } ** 32;
    const message = "MTProto 2.0 uses AES-256-IGE for the entire message payload!";
    const padded_len = message.len + (16 - message.len % 16);
    var plain: [80]u8 = .{0} ** 80;
    @memcpy(plain[0..message.len], message);

    var cipher: [80]u8 = undefined;
    try encrypt256(key, iv, plain[0..padded_len], cipher[0..padded_len]);
    try std.testing.expect(!std.mem.eql(u8, plain[0..padded_len], cipher[0..padded_len]));

    // distinct plaintexts share prefix but diverge in IGE ciphertext? IGE
    // garbles forward: a differing later block must not change earlier ones,
    // but any difference propagates into all following blocks.
    plain[40] ^= 1;
    var cipher2: [80]u8 = undefined;
    try encrypt256(key, iv, plain[0..padded_len], cipher2[0..padded_len]);
    try std.testing.expect(!std.mem.eql(u8, cipher[0..48], cipher2[0..48]));

    // in-place roundtrip
    try decrypt256(key, iv, cipher2[0..padded_len], cipher2[0..padded_len]);
    try std.testing.expectEqualSlices(u8, plain[0..padded_len], cipher2[0..padded_len]);
}

test "IGE rejects malformed lengths (no silent truncation)" {
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 32;
    var dst: [32]u8 = undefined;

    try std.testing.expectError(error.InvalidLength, encrypt256(key, iv, "15 bytes....!", dst[0..15]));
    try std.testing.expectError(error.InvalidLength, decrypt256(key, iv, "17 bytes exactly!!!", dst[0..17]));
    try std.testing.expectError(error.BufferSizeMismatch, encrypt256(key, iv, dst[0..16], dst[0..15]));
    try std.testing.expectError(error.BufferSizeMismatch, encrypt256(key, iv, dst[0..16], dst[0..32]));

    // zero blocks is a valid no-op (length is a multiple of 16)
    try encrypt256(key, iv, dst[0..0], dst[0..0]);
}
