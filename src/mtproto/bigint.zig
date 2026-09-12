//! Big-integer helpers for the MTProto handshake (RSA public operation and
//! Diffie-Hellman), built on `std.math.big.int`.
//!
//! All functions take and return **big-endian byte strings** (the form MTProto
//! uses on the wire) and require explicit allocators. Output buffers are
//! zero-padded to their full length; input leading zeros are ignored.

const std = @import("std");
const big = std.math.big;
const Managed = big.int.Managed;

pub const Error = error{
    OutOfMemory,
    /// Output buffer too small for the result.
    BufferTooSmall,
    /// Empty operand where a value is required.
    InvalidInput,
};

/// Parses a big-endian byte string into a Managed value.
pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) Error!Managed {
    var m = Managed.init(allocator) catch return error.OutOfMemory;
    errdefer m.deinit();
    var start: usize = 0;
    while (start < bytes.len and bytes[start] == 0) start += 1;
    const trimmed = bytes[start..];
    if (trimmed.len == 0) return m;

    m.ensureTwosCompCapacity(trimmed.len * 8) catch return error.OutOfMemory;
    var mut = m.toMutable();
    mut.readTwosComplement(trimmed, trimmed.len * 8, .big, .unsigned);
    m.setMetadata(mut.positive, mut.len);
    return m;
}

/// Writes `value` into `out` as a big-endian byte string, zero-padded to the
/// full buffer length.
pub fn toBytes(out: []u8, value: *const Managed) Error!void {
    const bits = value.bitCountAbs();
    const needed = (bits + 7) / 8;
    if (needed > out.len) return error.BufferTooSmall;
    @memset(out, 0);
    value.toConst().writeTwosComplement(out, .big);
}

/// Modular exponentiation: out = base^exp mod modulus (all big-endian).
/// `out.len` defines the output width. Exponent bits are processed
/// MSB-first with square-and-multiply.
pub fn powmod(
    allocator: std.mem.Allocator,
    base_bytes: []const u8,
    exp_bytes: []const u8,
    modulus_bytes: []const u8,
    out: []u8,
) Error!void {
    var base = try fromBytes(allocator, base_bytes);
    defer base.deinit();
    var exp = try fromBytes(allocator, exp_bytes);
    defer exp.deinit();
    var modulus = try fromBytes(allocator, modulus_bytes);
    defer modulus.deinit();
    if (modulus.eqlZero()) return error.InvalidInput;
    if (base.toConst().orderAbs(modulus.toConst()) == .gt) {
        // reduce base first
        var q = Managed.init(allocator) catch return error.OutOfMemory;
        defer q.deinit();
        var r = Managed.init(allocator) catch return error.OutOfMemory;
        defer r.deinit();
        q.divFloor(&r, &base, &modulus) catch return error.OutOfMemory;
        base.copy(r.toConst()) catch return error.OutOfMemory;
    }

    var result = try fromBytes(allocator, &.{1});
    defer result.deinit();
    var sq = base.clone() catch return error.OutOfMemory;
    defer sq.deinit();
    var tmp = Managed.init(allocator) catch return error.OutOfMemory;
    defer tmp.deinit();
    var q = Managed.init(allocator) catch return error.OutOfMemory;
    defer q.deinit();
    var r = Managed.init(allocator) catch return error.OutOfMemory;
    defer r.deinit();

    const exp_bits = exp.bitCountAbs();
    var i: usize = exp_bits;
    while (i > 0) {
        i -= 1;
        // result = result^2 mod m
        tmp.sqr(&result) catch return error.OutOfMemory;
        q.divFloor(&r, &tmp, &modulus) catch return error.OutOfMemory;
        result.copy(r.toConst()) catch return error.OutOfMemory;

        const bit_set = blk: {
            // bit i of exp (MSB-first indexing)
            const limb_bits = @bitSizeOf(big.Limb);
            const limb_idx = i / limb_bits;
            const bit_idx: std.math.Log2Int(big.Limb) = @intCast(i % limb_bits);
            const limbs = exp.toConst().limbs;
            if (limb_idx >= limbs.len) break :blk false;
            break :blk (limbs[limb_idx] >> bit_idx) & 1 == 1;
        };
        if (bit_set) {
            tmp.mul(&result, &sq) catch return error.OutOfMemory;
            q.divFloor(&r, &tmp, &modulus) catch return error.OutOfMemory;
            result.copy(r.toConst()) catch return error.OutOfMemory;
        }
    }

    try toBytes(out, &result);
}

/// Generates a random big-endian integer of exactly `bytes.len` bytes with
/// the top two bits set (as recommended for DH private exponents).
pub fn randomDhScalar(random: std.Random, out: []u8) void {
    random.bytes(out);
    out[0] |= 0b1100_0000;
}

// ---------------------------------------------------------------- tests

test "fromBytes/toBytes roundtrip with leading zeros" {
    const bytes = [_]u8{ 0x01, 0x02, 0x03 };
    var m = try fromBytes(std.testing.allocator, &bytes);
    defer m.deinit();
    var out: [5]u8 = undefined;
    try toBytes(&out, &m);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 1, 2, 3 }, &out);

    var zero = try fromBytes(std.testing.allocator, &.{ 0, 0, 0 });
    defer zero.deinit();
    try std.testing.expect(zero.eqlZero());
}

test "powmod small known values" {
    var out: [8]u8 = undefined;
    // 2^10 mod 1000 = 24
    try powmod(std.testing.allocator, &.{2}, &.{ 0x0a }, &.{ 0x03, 0xe8 }, &out);
    try std.testing.expectEqual(@as(u8, 24), out[out.len - 1]);
}

test "powmod matches std for moderate values" {
    var out: [16]u8 = undefined;
    // 7^11 mod 13 = ?
    // 7^1=7, 7^2=49=10, 7^4=100=9, 7^8=81=3; 11=8+2+1 → 3*10*7=210 mod 13 = 210-208=2
    try powmod(std.testing.allocator, &.{7}, &.{ 0x0b }, &.{ 0x0d }, &out);
    try std.testing.expectEqual(@as(u8, 2), out[out.len - 1]);
}

test "powmod official example: g_b and auth_key (external KAT)" {
    // External KAT from https://core.telegram.org/mtproto/samples-auth_key:
    // g_b = g^b mod dh_prime and auth_key = g_a^b mod dh_prime with the
    // example's b, g_a, dh_prime and expected outputs.
    const g_a_hex = "8539DB1E497692EE8BD112463F5F26699039792151BE8B575AA56D8914EDBAA242C2A8096FFAB06211B36291FC4994CB0FDFD37389DF8886F2C6B634C0D01B1C8EBD3E9BE1F49B4A8BD33C3952EF1CEC5E9425CD9C2136CA482A521F9ACC86BEA7D8E224F3D6D78A7F734961EED863EA52EC399C58AE94B733E4CB0AFC728926FB2F457D4AB89576D8067489E323DF8702DEC6EFA2EAF1D85548748D2DFA62925920563076F143D8AE852BCAE61553371BEDA580FEBD952AC7C7C1AFBB3F15934CE815716C6C362F9382BE91DC6F964E97C1A308D63FC1E4DFB2B8395A3E7B9A996C2DD3086488EB281301BEEC1ECEDD00296D76AC7EF7B786EA82F0FA7896DB";
    const b_hex = "96E8D3D298D05AA574B92495F566D0C71C2CA5E1A1FCB18CEFF2408CC57F9E5D5EBD18F3DAFB5FA3DA41F6A73ADB14CF36642882D403A39FD640B9A3B4DEAD433DB0FFA55262EBC89A44324E6F3BEDEA1EB9CA19E465E1135B73497B8567ED842DFCC8F02EB2A8E4C8F923826CDF98D717FBF6F6D55313779163D40E3B18289A7BBCD9CC2B2280B888DCC36117E342D352BE67944CC9C723D928339877E7CB47917A582AB8DAB59A9BFFBEC88A21ECCAF93BAEF9AFB4EE3FB69FFF55A1D7EFAE03328C585E39750506D7C795E5737AFC3FF6CA79C7C205269A8BCB3F03D74DF36CE727E8E3D52663F208AE31B786EC852F1BA4C36EFEE2F8528AD1945E2C7ECF";
    const g_b_hex = "2EE7B6CC1343B2D39A1AAB034551C9912E5DEE8047C6C62FFBD42B5E1894CFCB79EFEF794135A9FAA3F32C88D5D6D19F75289A5362984AC02A53A4E49E78C07E78C35FF505BC707F7F64E9AAA4BFBD0DBB11E3CACE330048C629DB154463731A2833E11130328EDE8C1230B246D1D999A0336CAC5B32BE5780253DE10BAA6513A5A079F2B9D6A59DB7799E97915F556C89407617BE822C7F65532C8E37792442EDD83793940F5606BC1994B4964ED3458C9AD513977F217699D32368315C7BB07D99C9EE77DE069E62E4A4DFDB16F4F911AA1AEF7373A2F49185501BE684A777772BFC4BD99E38FA51014A3E059543BDCF213977FE913E8A3D881C2EB5523B04";
    const dh_prime_hex = "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B";
    const expect_hex = "8E1081A1B5CA1B399A9A9D7E08BB9A9182AB634F8C03F2A49F944E2F944A9C71EDBA61A32A70D3DADEB33752AE515B16B2D8E75039C40EBE18136775C3727372A8DF486606D671FD63842DF0A44ACC31E68B7B1EC6A731A1DC5C748F0CB46AC00FDE363F0520B51D9B59EAE519EA511A8E8591FC7010DF0B07CDBAB04013DD85172CB54555DC5C982EA0A5DCF4411E798D338B823161FD8C93100B7A426186B4C16F9113521081C8D2075872F4A0CF238034843DC01F2C26828721A2E2FFD93A9B0142B8DF6355C43D9AEF5B448F1CC0D84E0E72A7FF494D4CC3B1650050DDEC5DC321ADA68E420F45098280CEAB58A1CBFAA60FFF3218E56B4741143AC5A6F0";

    var g_a_buf = [_]u8{0} ** 256;
    var b_buf = [_]u8{0} ** 256;
    var prime_buf = [_]u8{0} ** 256;
    var expect_buf = [_]u8{0} ** 256;
    _ = std.fmt.hexToBytes(&g_a_buf, g_a_hex) catch unreachable;
    _ = std.fmt.hexToBytes(&b_buf, b_hex) catch unreachable;
    _ = std.fmt.hexToBytes(&prime_buf, dh_prime_hex) catch unreachable;
    _ = std.fmt.hexToBytes(&expect_buf, expect_hex) catch unreachable;

    // auth_key = g_a^b mod dh_prime
    var auth_key: [256]u8 = undefined;
    try powmod(std.testing.allocator, &g_a_buf, &b_buf, &prime_buf, &auth_key);
    try std.testing.expectEqualSlices(u8, &expect_buf, &auth_key);

    // g_b = 3^b mod dh_prime
    var g_b: [256]u8 = undefined;
    try powmod(std.testing.allocator, &.{3}, &b_buf, &prime_buf, &g_b);
    var g_b_expect = [_]u8{0} ** 256;
    _ = std.fmt.hexToBytes(&g_b_expect, g_b_hex) catch unreachable;
    try std.testing.expectEqualSlices(u8, &g_b_expect, &g_b);
}


fn hexRightAlign(buf: *[256]u8, hex_in: []const u8) void {
    const nibbles = hex_in.len;
    const n = (nibbles + 1) / 2;
    const out = buf[256 - n ..];
    var count: usize = 0;
    var pos = nibbles;
    var idx = n;
    while (pos > 0) {
        pos -= 1;
        const nib = std.fmt.charToDigit(hex_in[pos], 16) catch unreachable;
        if (count % 2 == 0) {
            idx -= 1;
            out[idx] = nib;
        } else {
            out[idx] |= nib << 4;
        }
        count += 1;
    }
}
