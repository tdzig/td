//! RSA public-key operations for the MTProto handshake.
//!
//! Only the **public** operation (modular exponentiation with e = 65537 on
//! `std.math.big.int`) is implemented for encryption; there is no padding
//! oracle surface and no secret material here. Two encryption layouts are
//! supported, both from the official documentation:
//!
//!  * `classic` — data_with_hash := SHA1(data) ++ data ++ random bytes,
//!    padded to 255 bytes; the pre-1.0-compatible layout still accepted by
//!    servers (<https://core.telegram.org/mtproto/auth_key>, legacy flow).
//!  * `rsa_pad` — the current documented scheme (step 4.1): data padded to
//!    192 bytes and byte-reversed, SHA256(temp_key ++ data_with_padding)
//!    appended, AES-256-IGE encrypted with a zero IV, then prefixed with
//!    temp_key XOR SHA256(aes_encrypted); 256 bytes total.
//!
//! Fingerprints: lower 64 bits of SHA1 over the TL serialization of the
//! bare `rsa_public_key n:string e:string` type (both big-endian, length-
//! prefixed as TL strings). Servers list these values in
//! resPQ.server_public_key_fingerprints for both encryption layouts; the
//! fingerprint never depends on the mode.

const std = @import("std");
const bigint = @import("bigint.zig");
const ige = @import("../crypto/aes_ige.zig");
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// A 2048-bit RSA public key (modulus in big-endian, exponent normally 65537).
pub const PublicKey = struct {
    /// Big-endian modulus; expected 256 bytes for Telegram keys.
    n: [256]u8,
    e: u32 = 65537,

    /// Lower 64 bits of SHA1 over the TL serialization of the bare
    /// `rsa_public_key n:string e:string` type — the value servers list in
    /// resPQ.server_public_key_fingerprints (protocol description, step 2).
    /// Hashing the bare modulus instead silently mismatches every real
    /// server. Mode-independent: the encryption layout and the fingerprint
    /// are unrelated concepts.
    pub fn fingerprint(self: *const PublicKey) u64 {
        // TL long string (256-byte modulus: 0xFE + 3-byte LE length, no
        // padding) ++ TL string (3-byte exponent: length byte + bytes, no
        // padding). Both realistic sizes are word-aligned, so the wire
        // image below is exact.
        var wire: [4 + 256 + 1 + 4]u8 = undefined;
        wire[0] = 0xFE;
        std.mem.writeInt(u24, wire[1..4], self.n.len, .little);
        @memcpy(wire[4..][0..self.n.len], &self.n);
        var e_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &e_bytes, self.e, .big);
        const e_len: usize = if (self.e > 0xffffff) 4 else if (self.e > 0xffff) 3 else if (self.e > 0xff) 2 else 1;
        wire[260] = @intCast(e_len);
        @memcpy(wire[261..][0..e_len], e_bytes[4 - e_len ..]);

        var digest: [Sha1.digest_length]u8 = undefined;
        Sha1.hash(wire[0 .. 261 + e_len], &digest, .{});
        return std.mem.readInt(u64, digest[12..20], .big);
    }
};

pub const Mode = enum { classic, rsa_pad };

pub const Error = error{
    OutOfMemory,
    InvalidInput,
    /// Padded value ≥ modulus; caller must retry with fresh randomness.
    ValueTooLarge,
    /// Output buffer too small for the result.
    BufferTooSmall,
};

/// Raw RSA public operation: m^e mod n, output exactly 256 bytes BE.
fn rsaPublicOp(allocator: std.mem.Allocator, key: *const PublicKey, message: []const u8, out: *[256]u8) Error!void {
    const e = key.e;
    var e_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &e_bytes, e, .big);
    try bigint.powmod(allocator, message, &e_bytes, &key.n, out);
}

/// Classic layout: SHA1(data) ++ data ++ random padding, total 255 bytes
/// (data must be ≤ 235 bytes), then RSA.
pub fn encryptClassic(
    allocator: std.mem.Allocator,
    key: *const PublicKey,
    data: []const u8,
    random: std.Random,
    out: *[256]u8,
) Error!void {
    if (data.len > 235) return error.InvalidInput;
    var padded: [255]u8 = undefined;
    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(data, &digest, .{});
    @memcpy(padded[0..20], &digest);
    @memcpy(padded[20 .. 20 + data.len], data);
    random.bytes(padded[20 + data.len ..]);
    try rsaPublicOp(allocator, key, &padded, out);
}

/// rsa_pad layout (current official scheme, step 4.1):
///   data_with_padding  := data ++ random → exactly 192 bytes (data ≤ 144)
///   data_pad_reversed  := reverse(data_with_padding)
///   data_with_hash     := data_pad_reversed ++ SHA256(temp_key ++ data_with_padding)
///   aes_encrypted      := AES256-IGE(temp_key, iv=0, data_with_hash)  [224 bytes]
///   temp_key_xor       := temp_key XOR SHA256(aes_encrypted)
///   encrypted_data     := RSA(temp_key_xor ++ aes_encrypted)          [256 bytes]
pub fn encryptRsaPad(
    allocator: std.mem.Allocator,
    key: *const PublicKey,
    data: []const u8,
    random: std.Random,
    out: *[256]u8,
) Error!void {
    if (data.len > 144) return error.InvalidInput;

    var block: [256]u8 = undefined;
    var ok = false;
    var attempts: usize = 0;
    while (!ok) : (attempts += 1) {
        if (attempts > 16) return error.ValueTooLarge;

        var data_with_padding: [192]u8 = undefined;
        @memcpy(data_with_padding[0..data.len], data);
        random.bytes(data_with_padding[data.len..]);

        var temp_key: [32]u8 = undefined;
        random.bytes(&temp_key);

        var data_pad_reversed: [192]u8 = undefined;
        for (data_with_padding, 0..) |byte, i| {
            data_pad_reversed[192 - 1 - i] = byte;
        }

        var hash: [32]u8 = undefined;
        var h = Sha256.init(.{});
        h.update(&temp_key);
        h.update(&data_with_padding);
        h.final(&hash);

        var data_with_hash: [224]u8 = undefined;
        @memcpy(data_with_hash[0..192], &data_pad_reversed);
        @memcpy(data_with_hash[192..], &hash);

        var aes_encrypted: [224]u8 = undefined;
        ige.encrypt256(temp_key, [_]u8{0} ** 32, &data_with_hash, &aes_encrypted) catch return error.InvalidInput;

        var hash2: [32]u8 = undefined;
        Sha256.hash(&aes_encrypted, &hash2, .{});
        var temp_key_xor: [32]u8 = undefined;
        for (&temp_key_xor, temp_key, hash2) |*x, k, h2| x.* = k ^ h2;

        // key_aes_encrypted := temp_key_xor ++ aes_encrypted (the
        // temp_key half leads; a server that finds the AES ciphertext
        // first cannot recover the key and silently drops the request).
        @memcpy(block[0..32], &temp_key_xor);
        @memcpy(block[32..], &aes_encrypted);

        // Must be strictly less than the modulus.
        ok = true;
        for (block, key.n) |b, n| {
            if (b != n) {
                ok = b < n;
                break;
            }
        }
    }

    try rsaPublicOp(allocator, key, &block, out);
}

/// Decrypts a 256-byte RSA payload with a private exponent (test/loopback
/// server use only; production code never sees private keys here).
pub fn decryptForTests(
    allocator: std.mem.Allocator,
    n: *const [256]u8,
    d: []const u8,
    ciphertext: *const [256]u8,
    out: *[256]u8,
) Error!void {
    try bigint.powmod(allocator, ciphertext, d, n, out);
}

/// Strips the classic layout prefix: returns the plaintext after the
/// 20-byte SHA1, borrowing from `decrypted`. The 255-byte RSA message is
/// the last 255 bytes of the 256-byte decryption result.
pub fn stripClassicForTests(decrypted: *const [256]u8) []const u8 {
    return decrypted[21..256];
}

/// Unwraps the rsa_pad layout for the loopback server: verifies the
/// embedded hash and writes the recovered `data` (prefix of the 192-byte
/// padded block; trailing bytes are random padding) into `out`.
pub fn unwrapRsaPadForTests(decrypted: *const [256]u8, out: *[192]u8) Error!void {
    const temp_key_xor = decrypted[0..32];
    const aes_encrypted = decrypted[32..256];

    var hash: [32]u8 = undefined;
    Sha256.hash(aes_encrypted, &hash, .{});
    var temp_key: [32]u8 = undefined;
    for (&temp_key, temp_key_xor, hash) |*t, x, h| t.* = x ^ h;

    var data_with_hash: [224]u8 = undefined;
    ige.decrypt256(temp_key, [_]u8{0} ** 32, aes_encrypted, &data_with_hash) catch return error.InvalidInput;

    var data_with_padding: [192]u8 = undefined;
    for (data_with_hash[0..192], 0..) |byte, i| {
        data_with_padding[192 - 1 - i] = byte;
    }

    var check: [32]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(&temp_key);
    h.update(&data_with_padding);
    h.final(&check);
    if (!std.mem.eql(u8, &check, data_with_hash[192..])) return error.InvalidInput;

    @memcpy(out, &data_with_padding);
}

// ---------------------------------------------------------------- tests

test "classic + rsa_pad roundtrip through private op (test keypair)" {
    const testkeys = @import("testkeys.zig");
    const key = PublicKey{ .n = testkeys.modulus_be };
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var prng = std.Random.DefaultPrng.init(42);

    var cipher: [256]u8 = undefined;
    var plain: [256]u8 = undefined;

    try encryptClassic(arena, &key, "hello classic rsa", prng.random(), &cipher);
    try decryptForTests(arena, &key.n, &testkeys.d_be, &cipher, &plain);
    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash("hello classic rsa", &digest, .{});
    try std.testing.expectEqualSlices(u8, &digest, plain[1..21]);
    try std.testing.expectEqualSlices(u8, "hello classic rsa", plain[21 .. 21 + 17]);

    try encryptRsaPad(arena, &key, "hello rsa pad layout!!", prng.random(), &cipher);
    try decryptForTests(arena, &key.n, &testkeys.d_be, &cipher, &plain);

    // Unwrap rsa_pad: split, un-xor temp key, IGE-decrypt, reverse, hash check.
    const temp_key_xor = plain[0..32];
    const aes_encrypted = plain[32..256];
    var hash: [32]u8 = undefined;
    Sha256.hash(aes_encrypted, &hash, .{});
    var temp_key: [32]u8 = undefined;
    for (&temp_key, temp_key_xor, hash) |*t, x, h| t.* = x ^ h;
    var data_with_hash: [224]u8 = undefined;
    ige.decrypt256(temp_key, [_]u8{0} ** 32, aes_encrypted, &data_with_hash) catch unreachable;
    var data_with_padding: [192]u8 = undefined;
    for (data_with_hash[0..192], 0..) |byte, i| {
        data_with_padding[192 - 1 - i] = byte;
    }
    var h2 = Sha256.init(.{});
    h2.update(&temp_key);
    h2.update(&data_with_padding);
    var check: [32]u8 = undefined;
    h2.final(&check);
    try std.testing.expectEqualSlices(u8, &check, data_with_hash[192..]);
    try std.testing.expectEqualStrings("hello rsa pad layout!!", data_with_padding[0.."hello rsa pad layout!!".len]);
}
