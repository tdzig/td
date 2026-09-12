//! Inner-data protection for the MTProto handshake: temporary AES key/IV
//! derivation, SHA1+padding sealing, nonce hashes and auth-key derivatives.
//! All formulas follow https://core.telegram.org/mtproto/auth_key and are
//! validated against the official worked example
//! (https://core.telegram.org/mtproto/samples-auth_key).

const std = @import("std");
const ige = @import("../crypto/aes_ige.zig");
const Sha1 = std.crypto.hash.Sha1;

pub const Error = error{
    OutOfMemory,
    /// Sealed blob is shorter than its SHA1 prefix or not 16-byte aligned.
    InvalidFormat,
    /// SHA1 over the inner data did not match the sealed hash.
    HashMismatch,
};

/// tmp_aes_key = SHA1(new_nonce ++ server_nonce) ++ SHA1(server_nonce ++ new_nonce)[0..12]
/// tmp_aes_iv  = SHA1(server_nonce ++ new_nonce)[12..20] ++ SHA1(new_nonce ++ new_nonce) ++ new_nonce[0..4]
pub const TmpAesParams = struct { key: [32]u8, iv: [32]u8 };

pub fn tmpAesParams(new_nonce: *const [32]u8, server_nonce: *const [16]u8) TmpAesParams {
    var h1: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(new_nonce ++ server_nonce, &h1, .{});
    var h2: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(server_nonce ++ new_nonce, &h2, .{});
    var h3: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(new_nonce ++ new_nonce, &h3, .{});

    var p: TmpAesParams = undefined;
    @memcpy(p.key[0..20], &h1);
    @memcpy(p.key[20..32], h2[0..12]);
    @memcpy(p.iv[0..8], h2[12..20]);
    @memcpy(p.iv[8..28], &h3);
    @memcpy(p.iv[28..32], new_nonce[0..4]);
    return p;
}

/// data_with_hash := SHA1(data) ++ data ++ random bytes (0..15) so that the
/// total length is divisible by 16, then AES-256-IGE encrypted.
pub fn sealInner(
    allocator: std.mem.Allocator,
    params: TmpAesParams,
    data: []const u8,
    random: std.Random,
) Error![]u8 {
    const padded_len = data.len + 20;
    const total = padded_len + (16 - padded_len % 16) % 16;
    const buf = allocator.alloc(u8, total) catch return error.OutOfMemory;
    errdefer allocator.free(buf);

    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(data, &digest, .{});
    @memcpy(buf[0..20], &digest);
    @memcpy(buf[20..][0..data.len], data);
    random.bytes(buf[padded_len..]);

    const out = allocator.alloc(u8, total) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    ige.encrypt256(params.key, params.iv, buf, out) catch return error.InvalidFormat;
    allocator.free(buf);
    return out;
}

/// Decrypts a sealed inner-data blob **in place** and returns the full
/// plaintext buffer: SHA1 prefix at [0..20], payload at [20..], random
/// padding after. The hash must be verified once the payload length is
/// known (see `verifyInnerHash`).
pub fn openInnerDecrypt(params: TmpAesParams, sealed_scratch: []u8) Error![]const u8 {
    if (sealed_scratch.len < 20 or sealed_scratch.len % 16 != 0) return error.InvalidFormat;
    ige.decrypt256(params.key, params.iv, sealed_scratch, sealed_scratch) catch return error.InvalidFormat;
    return sealed_scratch;
}

/// Verifies the SHA1 prefix of a decrypted blob. `decrypted` is the full
/// plaintext-with-prefix buffer (SHA1 at [0..20], data at [20..]);
/// `data_len` is the true payload length (TL-parsed, excluding the random
/// trailing padding), since the hash covers only the payload.
pub fn verifyInnerHash(decrypted: []const u8, data_len: usize) Error!void {
    if (20 + data_len > decrypted.len) return error.InvalidFormat;
    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(decrypted[20 .. 20 + data_len], &digest, .{});
    if (!std.mem.eql(u8, &digest, decrypted[0..20])) return error.HashMismatch;
}

/// auth_key_aux_hash: the 64 higher-order bits of SHA1(auth_key).
pub fn authKeyAuxHash(auth_key: *const [256]u8) [8]u8 {
    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(auth_key, &digest, .{});
    return digest[0..8].*;
}

/// new_nonce_hashN = the 128 lower-order bits (last 16 bytes) of
/// SHA1(new_nonce ++ [N] ++ auth_key_aux_hash).
pub fn newNonceHash(new_nonce: *const [32]u8, n: u8, aux_hash: *const [8]u8) [16]u8 {
    var digest: [Sha1.digest_length]u8 = undefined;
    var h = Sha1.init(.{});
    h.update(new_nonce);
    h.update(&.{n});
    h.update(aux_hash);
    h.final(&digest);
    return digest[4..20].*;
}

/// auth_key_id: the 64 lower-order bits of SHA1(auth_key).
pub fn authKeyId(auth_key: *const [256]u8) [8]u8 {
    var digest: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(auth_key, &digest, .{});
    return digest[12..20].*;
}

/// server_salt = new_nonce[0..8] XOR server_nonce[0..8].
pub fn serverSalt(new_nonce: *const [32]u8, server_nonce: *const [16]u8) [8]u8 {
    var salt: [8]u8 = undefined;
    for (&salt, new_nonce[0..8], server_nonce[0..8]) |*s, nn, sn| s.* = nn ^ sn;
    return salt;
}

// ---------------------------------------------------------------- tests

test "tmp aes params match the official example" {
    var nonce: [16]u8 = undefined;
    var server_nonce: [16]u8 = undefined;
    var new_nonce: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&nonce, "51A1143FC7A3666BE4BE54D6890A02DC") catch unreachable;
    _ = std.fmt.hexToBytes(&server_nonce, "63248F6748214EAB8A2F4CC876E11974") catch unreachable;
    _ = std.fmt.hexToBytes(&new_nonce, "BF8CB5BD9C5B4FE7CF24D64D281F89311576D53C0DA65A83267E57315414C9A6") catch unreachable;

    const params = tmpAesParams(&new_nonce, &server_nonce);
    var want_key: [32]u8 = undefined;
    var want_iv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&want_key, "16F548177058E8D39C41CBAD4D419446BEB12EB9B8F5AD28EA824B8015F17D81") catch unreachable;
    _ = std.fmt.hexToBytes(&want_iv, "C4D14166C1378E35C698460047DBB6075441BE9984611C28837357EBBF8CB5BD") catch unreachable;
    try std.testing.expectEqualSlices(u8, &want_key, &params.key);
    try std.testing.expectEqualSlices(u8, &want_iv, &params.iv);
}

test "newNonceHash matches the official example" {
    // The example derives auth_key and new_nonce_hash1 = AA404B58DF404D8F363772B14CE5A56F.
    var new_nonce: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&new_nonce, "BF8CB5BD9C5B4FE7CF24D64D281F89311576D53C0DA65A83267E57315414C9A6") catch unreachable;
    var auth_key: [256]u8 = undefined;
    _ = std.fmt.hexToBytes(&auth_key, "8E1081A1B5CA1B399A9A9D7E08BB9A9182AB634F8C03F2A49F944E2F944A9C71EDBA61A32A70D3DADEB33752AE515B16B2D8E75039C40EBE18136775C3727372A8DF486606D671FD63842DF0A44ACC31E68B7B1EC6A731A1DC5C748F0CB46AC00FDE363F0520B51D9B59EAE519EA511A8E8591FC7010DF0B07CDBAB04013DD85172CB54555DC5C982EA0A5DCF4411E798D338B823161FD8C93100B7A426186B4C16F9113521081C8D2075872F4A0CF238034843DC01F2C26828721A2E2FFD93A9B0142B8DF6355C43D9AEF5B448F1CC0D84E0E72A7FF494D4CC3B1650050DDEC5DC321ADA68E420F45098280CEAB58A1CBFAA60FFF3218E56B4741143AC5A6F0") catch unreachable;

    const aux = authKeyAuxHash(&auth_key);
    const hash1 = newNonceHash(&new_nonce, 1, &aux);
    var want: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&want, "AA404B58DF404D8F363772B14CE5A56F") catch unreachable;
    try std.testing.expectEqualSlices(u8, &want, &hash1);

    // hash1/2/3 must all differ.
    const hash2 = newNonceHash(&new_nonce, 2, &aux);
    const hash3 = newNonceHash(&new_nonce, 3, &aux);
    try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
    try std.testing.expect(!std.mem.eql(u8, &hash2, &hash3));
}

test "sealInner/openInner roundtrip and tamper detection" {
    var prng = std.Random.DefaultPrng.init(9);
    const params = tmpAesParams(&([_]u8{1} ** 32), &([_]u8{2} ** 16));

    const payload = "inner data here";
    const sealed = try sealInner(std.testing.allocator, params, payload, prng.random());
    defer std.testing.allocator.free(sealed);
    try std.testing.expect(sealed.len % 16 == 0);

    const opened = try openInnerDecrypt(params, sealed);
    try std.testing.expectEqualStrings(payload, opened[20 .. 20 + payload.len]);
    try verifyInnerHash(opened, payload.len);

    sealed[sealed.len - 1] ^= 1;
    const opened2 = try openInnerDecrypt(params, sealed);
    try std.testing.expectError(error.HashMismatch, verifyInnerHash(opened2, payload.len));
}
