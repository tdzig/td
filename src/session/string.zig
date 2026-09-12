//! Portable session strings: the compact, copy-pasteable form of a
//! Telegram session used across the client ecosystem — one base64url
//! blob carrying the data center, application id, test-mode flag, the
//! 256-byte authorization key and the signed-in identity. No ecosystem
//! names appear anywhere in the API; this module just speaks the
//! format, reading every layout it has shipped in and writing the
//! current one.
//!
//! Layouts (all big-endian, base64url without padding):
//!
//!   * current (271 bytes):
//!     `dc[1] api_id[4] test[1] auth_key[256] user_id[8] bot[1]`
//!   * legacy 32-bit user id (263 bytes):
//!     `dc[1] test[1] auth_key[256] user_id[4] bot[1]`
//!   * legacy 64-bit user id (267 bytes):
//!     `dc[1] test[1] auth_key[256] user_id[8] bot[1]`
//!
//! The decoder dispatches by decoded payload length and additionally
//! tolerates one leading version digit and retained `=` padding — both
//! appear in strings produced by historical variants. `encode` always
//! writes the current layout.
//!
//! Secret hygiene: the authorization key is secret material. This
//! module never logs and never renders it; the string form itself is
//! the secret the caller asked for.

const std = @import("std");
const crypto = @import("../crypto/mod.zig");

pub const Error = error{
    OutOfMemory,
    /// Not base64url, not one of the three known payload layouts, or
    /// fields that could not describe a session.
    InvalidSessionString,
};

/// One decoded portable session.
pub const SessionString = struct {
    /// The data center the authorization key belongs to (1..5 in
    /// production today).
    dc_id: i32,
    /// Application id; null in the two legacy layouts, which carry
    /// none.
    api_id: ?i32,
    /// Test network?
    test_mode: bool,
    /// The 256-byte authorization key. Secret material: never logged.
    auth_key: [crypto.auth_key_size]u8,
    /// Signed-in user id (0 = the session is not signed in).
    user_id: i64,
    /// Whether the signed-in user is a bot.
    is_bot: bool,
};

/// Current layout: dc, api id, test flag, key, 64-bit user id, bot flag.
const v2_size = 271;
/// Legacy layout with a 32-bit user id and no application id.
const v1_32_size = 263;
/// Legacy layout with a 64-bit user id and no application id.
const v1_64_size = 267;

/// Decodes one portable session string. Allocation-free; the key comes
/// back by value.
pub fn parse(s: []const u8) Error!SessionString {
    var buf: [v2_size]u8 = undefined;
    var n = tryDecode(&buf, s);
    // Tolerate one leading version digit: some historical variants
    // prefixed one, and a digit is indistinguishable from payload only
    // by looking at what decodes cleanly afterwards.
    if (n == null and s.len > 0 and s[0] >= '0' and s[0] <= '9')
        n = tryDecode(&buf, s[1..]);
    const len = n orelse return error.InvalidSessionString;

    const ss: SessionString = switch (len) {
        v2_size => return .{
            .dc_id = buf[0],
            .api_id = @bitCast(std.mem.readInt(u32, buf[1..5], .big)),
            .test_mode = buf[5] != 0,
            .auth_key = buf[6..262].*,
            .user_id = @bitCast(std.mem.readInt(u64, buf[262..270], .big)),
            .is_bot = buf[270] != 0,
        },
        v1_32_size => return .{
            .dc_id = buf[0],
            .api_id = null,
            .test_mode = buf[1] != 0,
            .auth_key = buf[2..258].*,
            .user_id = std.mem.readInt(u32, buf[258..262], .big),
            .is_bot = buf[262] != 0,
        },
        v1_64_size => return .{
            .dc_id = buf[0],
            .api_id = null,
            .test_mode = buf[1] != 0,
            .auth_key = buf[2..258].*,
            .user_id = @bitCast(std.mem.readInt(u64, buf[258..266], .big)),
            .is_bot = buf[266] != 0,
        },
        else => return error.InvalidSessionString,
    };
    if (ss.dc_id < 1) return error.InvalidSessionString;
    return ss;
}

/// Encodes a session in the current layout: base64url, unpadded, owned
/// by the caller. A null `api_id` (legacy input) is written as 0.
pub fn encode(allocator: std.mem.Allocator, ss: SessionString) Error![]u8 {
    const dc = std.math.cast(u8, ss.dc_id) orelse return error.InvalidSessionString;

    var payload: [v2_size]u8 = undefined;
    payload[0] = dc;
    std.mem.writeInt(u32, payload[1..5], @bitCast(ss.api_id orelse 0), .big);
    payload[5] = @intFromBool(ss.test_mode);
    @memcpy(payload[6..262], &ss.auth_key);
    std.mem.writeInt(u64, payload[262..270], @bitCast(ss.user_id), .big);
    payload[270] = @intFromBool(ss.is_bot);

    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = allocator.alloc(u8, enc.calcSize(payload.len)) catch return error.OutOfMemory;
    _ = enc.encode(out, &payload);
    return out;
}

/// Best-effort base64url decode into `buf`; null when the input cannot
/// be one of the known layouts. Trailing `=` padding is tolerated.
fn tryDecode(buf: *[v2_size]u8, s: []const u8) ?usize {
    var body = s;
    while (body.len > 0 and body[body.len - 1] == '=') body = body[0 .. body.len - 1];
    if (body.len == 0) return null;

    const dec = std.base64.url_safe_no_pad.Decoder;
    const n = dec.calcSizeForSlice(body) catch return null;
    if (n > buf.len) return null;
    // A payload smaller than the smallest layout is not a session
    // string either; let the caller's length dispatch say so.
    dec.decode(buf[0..n], body) catch return null;
    return n;
}

// ---------------------------------------------------------------- tests
//
// Reference vectors are produced by the format's reference
// implementation (Python: `base64.urlsafe_b64encode(struct.pack(...))`)
// over a deterministic key — cross-checked bytes, not a round trip
// with our own encoder (which would pass while both sides share a
// wrong layout).

const vector_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 3 +% 7);
    break :blk k;
};

const vector_v2_user =
    "AgAAB_gABwoNEBMWGRwfIiUoKy4xNDc6PUBDRklMT1JVWFteYWRnam1wc3Z5fH-ChYiLjpGUl5qdoKOmqayvsrW4u77BxMfKzdDT1tnc3-Ll6Ovu8fT3-v0AAwYJDA8SFRgbHiEkJyotMDM2OTw_QkVIS05RVFdaXWBjZmlsb3J1eHt-gYSHio2Qk5aZnJ-ipairrrG0t7q9wMPGyczP0tXY297h5Ofq7fDz9vn8_wIFCAsOERQXGh0gIyYpLC8yNTg7PkFER0pNUFNWWVxfYmVoa25xdHd6fYCDhomMj5KVmJueoaSnqq2ws7a5vL_CxcjLztHU19rd4OPm6ezv8vX4-_4BBAAABxEYKdqHAA";
const vector_v2_bot =
    "AQAAB_gABwoNEBMWGRwfIiUoKy4xNDc6PUBDRklMT1JVWFteYWRnam1wc3Z5fH-ChYiLjpGUl5qdoKOmqayvsrW4u77BxMfKzdDT1tnc3-Ll6Ovu8fT3-v0AAwYJDA8SFRgbHiEkJyotMDM2OTw_QkVIS05RVFdaXWBjZmlsb3J1eHt-gYSHio2Qk5aZnJ-ipairrrG0t7q9wMPGyczP0tXY297h5Ofq7fDz9vn8_wIFCAsOERQXGh0gIyYpLC8yNTg7PkFER0pNUFNWWVxfYmVoa25xdHd6fYCDhomMj5KVmJueoaSnqq2ws7a5vL_CxcjLztHU19rd4OPm6ezv8vX4-_4BBAAVXAzzjv_YAQ";
const vector_v2_test =
    "BQAAQ8UBBwoNEBMWGRwfIiUoKy4xNDc6PUBDRklMT1JVWFteYWRnam1wc3Z5fH-ChYiLjpGUl5qdoKOmqayvsrW4u77BxMfKzdDT1tnc3-Ll6Ovu8fT3-v0AAwYJDA8SFRgbHiEkJyotMDM2OTw_QkVIS05RVFdaXWBjZmlsb3J1eHt-gYSHio2Qk5aZnJ-ipairrrG0t7q9wMPGyczP0tXY297h5Ofq7fDz9vn8_wIFCAsOERQXGh0gIyYpLC8yNTg7PkFER0pNUFNWWVxfYmVoa25xdHd6fYCDhomMj5KVmJueoaSnqq2ws7a5vL_CxcjLztHU19rd4OPm6ezv8vX4-_4BBAAAAAEAAAAAAA";
const vector_v1_32 =
    "BAEHCg0QExYZHB8iJSgrLjE0Nzo9QENGSUxPUlVYW15hZGdqbXBzdnl8f4KFiIuOkZSXmp2go6aprK-ytbi7vsHEx8rN0NPW2dzf4uXo6-7x9Pf6_QADBgkMDxIVGBseISQnKi0wMzY5PD9CRUhLTlFUV1pdYGNmaWxvcnV4e36BhIeKjZCTlpmcn6KlqKuusbS3ur3Aw8bJzM_S1djb3uHk5-rt8PP2-fz_AgUICw4RFBcaHSAjJiksLzI1ODs-QURHSk1QU1ZZXF9iZWhrbnF0d3p9gIOGiYyPkpWYm56hpKeqrbCztrm8v8LFyMvO0dTX2t3g4-bp7O_y9fj7_gEEB1vNFQE";
const vector_v1_64 =
    "BQAHCg0QExYZHB8iJSgrLjE0Nzo9QENGSUxPUlVYW15hZGdqbXBzdnl8f4KFiIuOkZSXmp2go6aprK-ytbi7vsHEx8rN0NPW2dzf4uXo6-7x9Pf6_QADBgkMDxIVGBseISQnKi0wMzY5PD9CRUhLTlFUV1pdYGNmaWxvcnV4e36BhIeKjZCTlpmcn6KlqKuusbS3ur3Aw8bJzM_S1djb3uHk5-rt8PP2-fz_AgUICw4RFBcaHSAjJiksLzI1ODs-QURHSk1QU1ZZXF9iZWhrbnF0d3p9gIOGiYyPkpWYm56hpKeqrbCztrm8v8LFyMvO0dTX2t3g4-bp7O_y9fj7_gEEAAAI-4_ZgosA";

test "decodes every reference vector exactly" {
    // Current layout: user session, bot session, test-network session.
    const cases = [_]struct { s: []const u8, want: SessionString }{
        .{ .s = vector_v2_user, .want = .{
            .dc_id = 2,
            .api_id = 2040,
            .test_mode = false,
            .auth_key = vector_key,
            .user_id = 7770001234567,
            .is_bot = false,
        } },
        .{ .s = vector_v2_bot, .want = .{
            .dc_id = 1,
            .api_id = 2040,
            .test_mode = false,
            .auth_key = vector_key,
            .user_id = 6012185206521816,
            .is_bot = true,
        } },
        .{ .s = vector_v2_test, .want = .{
            .dc_id = 5,
            .api_id = 17349,
            .test_mode = true,
            .auth_key = vector_key,
            .user_id = 4294967296, // needs 64 bits
            .is_bot = false,
        } },
        .{ .s = vector_v1_32, .want = .{
            .dc_id = 4,
            .api_id = null,
            .test_mode = true,
            .auth_key = vector_key,
            .user_id = 123456789,
            .is_bot = true,
        } },
        .{ .s = vector_v1_64, .want = .{
            .dc_id = 5,
            .api_id = null,
            .test_mode = false,
            .auth_key = vector_key,
            .user_id = 9876543210123,
            .is_bot = false,
        } },
    };
    for (cases) |c| {
        const got = try parse(c.s);
        try std.testing.expectEqual(c.want.dc_id, got.dc_id);
        try std.testing.expectEqual(c.want.api_id, got.api_id);
        try std.testing.expectEqual(c.want.test_mode, got.test_mode);
        try std.testing.expectEqualSlices(u8, &c.want.auth_key, &got.auth_key);
        try std.testing.expectEqual(c.want.user_id, got.user_id);
        try std.testing.expectEqual(c.want.is_bot, got.is_bot);
    }
}

test "encode reproduces the reference bytes and round-trips" {
    const src = try parse(vector_v2_user);
    const out = try encode(std.testing.allocator, src);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings(vector_v2_user, out);

    // Arbitrary values (negative user ids are legal 64-bit patterns).
    const ss = SessionString{
        .dc_id = 4,
        .api_id = 1,
        .test_mode = false,
        .auth_key = vector_key,
        .user_id = -3,
        .is_bot = true,
    };
    const enc = try encode(std.testing.allocator, ss);
    defer std.testing.allocator.free(enc);
    const back = try parse(enc);
    try std.testing.expectEqual(ss.dc_id, back.dc_id);
    try std.testing.expectEqual(ss.api_id, back.api_id);
    try std.testing.expectEqual(ss.user_id, back.user_id);
    try std.testing.expectEqual(ss.is_bot, back.is_bot);
    try std.testing.expectEqualSlices(u8, &ss.auth_key, &back.auth_key);

    // A legacy session (null api id) re-encodes in the current layout.
    const legacy = try parse(vector_v1_64);
    const upgraded = try encode(std.testing.allocator, legacy);
    defer std.testing.allocator.free(upgraded);
    const back2 = try parse(upgraded);
    try std.testing.expectEqual(@as(?i32, 0), back2.api_id);
    try std.testing.expectEqual(legacy.user_id, back2.user_id);
}

test "tolerates padding and a leading version digit, rejects garbage" {
    // Retained '=' padding.
    const padded = vector_v2_user ++ "==";
    const got = try parse(padded);
    try std.testing.expectEqual(@as(i32, 2), got.dc_id);

    // One leading version digit (historical variants).
    const prefixed = "2" ++ vector_v2_user;
    const got2 = try parse(prefixed);
    try std.testing.expectEqual(@as(i32, 2), got2.dc_id);

    // Garbage, wrong sizes, truncated payloads: all rejected.
    const bad = [_][]const u8{
        "",
        "not a session string at all",
        "abcd-efgh", // decodes, but to 7 bytes
        vector_v2_user[0 .. vector_v2_user.len - 4], // 268-byte payload
        "!!!!",
    };
    for (bad) |s| try std.testing.expectError(error.InvalidSessionString, parse(s));
}
