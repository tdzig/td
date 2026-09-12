//! Telegram cloud-password (2FA) math, per https://core.telegram.org/api/srp.
//!
//! Pure computation, no IO: the SRP client side of `auth.checkPassword`
//! and the password-hash KDF for setting a new password through
//! `account.updatePasswordSettings`. Everything here allocates through an
//! explicit allocator and never touches a client or a transport — the RPC
//! mapping lives in `flow.zig`.
//!
//! The wire roles:
//!
//!   * `Algo.init` — validates the `passwordKdfAlgo*` the server handed
//!     out: the modulus must be an odd 2048-bit **safe** prime (p and
//!     (p−1)/2 probably prime, Miller–Rabin with fixed + random bases)
//!     and the generator in 2..7 with g² mod p ≠ 1. The server picks
//!     both values, so the checks are a security boundary, not a
//!     formality: a weak modulus would let a man-in-the-middle
//!     brute-force the password from a single exchange. Validation is
//!     expensive (dozens of 2048-bit modpows) — callers keep the `Algo`
//!     and reuse it across attempts.
//!   * `Srp.init` — one login attempt: x = PH2(salt1 ∥ PH2(salt2 ∥
//!     password)), v = g^x mod p, fresh random a, A = g^a mod p,
//!     k = SHA256(p ∥ pad(g)).
//!   * `Srp.answer` — folds the server's `srp_B` in (with the
//!     specification's proof checks; on failure `error.InvalidServerProof`
//!     and the caller starts a fresh attempt — new random a — per spec)
//!     and produces the `inputCheckPasswordSRP` value: srp_id, A, M1.
//!     `A` and `M1` borrow the `Srp`; serialize the request before
//!     dropping it.
//!   * `newPasswordHash` — the KDF for *setting* a password:
//!     x = SHA256(PBKDF2-HMAC-SHA512(PH2(password), salt, 100000)),
//!     hash = g^x mod p. Extending the server's `new_algo` salt with
//!     client randomness is `Algo.withExtendedSalt` (the specification
//!     requires at least 32 fresh bytes).

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const bigint = @import("../mtproto/bigint.zig");
const Managed = std.math.big.int.Managed;
const api = @import("../api/mod.zig");

pub const Error = error{
    OutOfMemory,
    /// The `passwordKdfAlgo` failed validation (unknown algo, wrong
    /// modulus size, composite modulus, bad generator): refuse the
    /// exchange, never feed a password into it.
    InvalidAlgo,
    /// The server's `srp_B` failed the proof checks. Discard this
    /// attempt — fresh random `a`, fresh `A` — and retry; a repeated
    /// failure is a hostile server.
    InvalidServerProof,
};

/// 2048-bit values travel as 256-byte big-endian strings.
pub const group_len: usize = 256;
/// SHA-256 digest length (x, k, u, K, M1).
pub const digest_len: usize = 32;
/// PBKDF2 output length feeding the final SHA-256 when setting a
/// password (HMAC-SHA512 block-sized truncation, per the KDF name).
const pbkdf2_out_len: usize = 64;
/// Client randomness mixed into the salt when setting a new password.
pub const new_salt_random_bytes: usize = 32;

// ------------------------------------------------------------- hashing

pub fn sha256(data: []const u8) [digest_len]u8 {
    var out: [digest_len]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

/// PH1 of the specification: plain SHA-256.
pub fn ph1(data: []const u8) [digest_len]u8 {
    return sha256(data);
}

/// PH2 of the specification: SHA-256 of SHA-256.
pub fn ph2(data: []const u8) [digest_len]u8 {
    const h1 = ph1(data);
    return sha256(&h1);
}

/// The specification's Hx: SHA-256 of `data`, folded to 8 bytes by XOR
/// over the four quarters, repeated four times.
pub fn hx(data: []const u8) [digest_len]u8 {
    const h = sha256(data);
    var eighth: [8]u8 = @splat(0);
    for (0..4) |i| {
        for (0..8) |j| eighth[j] ^= h[i * 8 + j];
    }
    var out: [digest_len]u8 = undefined;
    for (0..4) |i| out[i * 8 ..][0..8].* = eighth;
    return out;
}

/// `parts` concatenated into one owned buffer.
pub fn concat(allocator: std.mem.Allocator, parts: []const []const u8) Error![]u8 {
    var len: usize = 0;
    for (parts) |p| len += p.len;
    const buf = allocator.alloc(u8, len) catch return error.OutOfMemory;
    var off: usize = 0;
    for (parts) |p| {
        @memcpy(buf[off .. off + p.len], p);
        off += p.len;
    }
    return buf;
}

/// The login KDF input: x = PH2(salt1 ∥ PH2(salt2 ∥ password)).
pub fn computeX(allocator: std.mem.Allocator, password: []const u8, salt1: []const u8, salt2: []const u8) Error![digest_len]u8 {
    const inner = concat(allocator, &.{ salt2, password }) catch return error.OutOfMemory;
    defer allocator.free(inner);
    const inner_hash = ph2(inner);
    const outer = concat(allocator, &.{ salt1, &inner_hash }) catch return error.OutOfMemory;
    defer allocator.free(outer);
    return ph2(outer);
}

/// The SRP-6a multiplier: k = SHA256(p ∥ pad(g, 256)).
pub fn computeK(g: u8, p: *const [group_len]u8) [digest_len]u8 {
    var buf: [2 * group_len]u8 = @splat(0);
    @memcpy(buf[0..group_len], p);
    buf[2 * group_len - 1] = g;
    return sha256(&buf);
}

/// g as a zero-padded 256-byte big-endian integer.
fn paddedG(g: u8) [group_len]u8 {
    var out: [group_len]u8 = @splat(0);
    out[group_len - 1] = g;
    return out;
}

// ----------------------------------------------------- byte-level math

/// Right shift by one bit of a big-endian unsigned integer.
fn shr1(buf: []u8) void {
    var carry: u8 = 0;
    for (buf) |*b| {
        const next_carry = (b.* & 1) << 7;
        b.* = (b.* >> 1) | carry;
        carry = next_carry;
    }
}

/// Whether `v` (fixed-width big-endian) equals 1.
fn isOne(v: []const u8) bool {
    for (v[0 .. v.len - 1]) |b| {
        if (b != 0) return false;
    }
    return v[v.len - 1] == 1;
}

/// Whether `v` (fixed-width big-endian) equals zero.
fn isZero(v: []const u8) bool {
    for (v) |b| {
        if (b != 0) return false;
    }
    return true;
}

/// Miller–Rabin primality: the small primes plus `rounds` random bases,
/// so an adversary cannot pick a modulus tuned to the fixed bases.
/// `n` is big-endian, at most `group_len` bytes (the SRP scale).
pub fn isProbablyPrime(
    allocator: std.mem.Allocator,
    n: []const u8,
    random: std.Random,
    rounds: usize,
) Error!bool {
    var start: usize = 0;
    while (start < n.len and n[start] == 0) start += 1;
    const m = n[start..];
    if (m.len == 0 or m.len > group_len) return false;
    if (m.len == 1) {
        return switch (m[0]) {
            2, 3, 5, 7 => true,
            0, 1, 4, 6, 8, 9 => false,
            else => @rem(m[0], 3) != 0 and @rem(m[0], 5) != 0 and @rem(m[0], 7) != 0,
        };
    }
    // Even: composite.
    if ((m[m.len - 1] & 1) == 0) return false;

    // n-1 = d·2^s, byte-level (working width: m.len, right-aligned in a
    // fixed 256-byte window so powmod output and n-1 compare directly).
    var d: [group_len]u8 = @splat(0);
    @memcpy(d[group_len - m.len ..], m);
    var idx: usize = group_len;
    while (idx > 0) {
        idx -= 1;
        if (d[idx] != 0) {
            d[idx] -= 1;
            break;
        }
        d[idx] = 0xff;
    }
    var s: usize = 0;
    while ((d[group_len - 1] & 1) == 0) {
        shr1(&d);
        s += 1;
    }

    // n-1 in the same window, for the y == n-1 comparisons.
    var nm1: [group_len]u8 = @splat(0);
    @memcpy(nm1[group_len - m.len ..], m);
    idx = group_len;
    while (idx > 0) {
        idx -= 1;
        if (nm1[idx] != 0) {
            nm1[idx] -= 1;
            break;
        }
        nm1[idx] = 0xff;
    }

    const bases = [_]u8{ 2, 3, 5, 7, 11, 13, 17, 19 };
    var y: [group_len]u8 = undefined;

    var checked: usize = 0;
    while (checked < bases.len + rounds) : (checked += 1) {
        var base: [group_len]u8 = @splat(0);
        if (checked < bases.len) {
            base[group_len - 1] = bases[checked];
        } else {
            // Random base < 2^(bits(n)-1) ≤ n: strictly inside (1, n-1).
            // (For tiny n the explicit order check below does the job.)
            const tail = base[group_len - m.len ..];
            random.bytes(tail);
            tail[0] &= 0x7f;
            if (isZero(tail) or isOne(tail) or std.mem.order(u8, tail, m) != .lt) {
                checked -= 1; // redraw
                continue;
            }
        }

        bigint.powmod(allocator, &base, &d, m, &y) catch return error.OutOfMemory;
        if (std.mem.eql(u8, &y, &nm1) or isOne(&y)) continue;

        var composite = true;
        var r: usize = 1;
        while (r < s) : (r += 1) {
            bigint.powmod(allocator, &y, &.{ 2 }, m, &y) catch return error.OutOfMemory;
            if (std.mem.eql(u8, &y, &nm1)) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

test "isProbablyPrime small values" {
    var prng = std.Random.DefaultPrng.init(1);
    const random = prng.random();
    const a = std.testing.allocator;
    try std.testing.expect(!try isProbablyPrime(a, &.{0}, random, 4));
    try std.testing.expect(!try isProbablyPrime(a, &.{1}, random, 4));
    try std.testing.expect(try isProbablyPrime(a, &.{2}, random, 4));
    try std.testing.expect(try isProbablyPrime(a, &.{3}, random, 4));
    try std.testing.expect(try isProbablyPrime(a, &.{97}, random, 4));
    try std.testing.expect(!try isProbablyPrime(a, &.{91}, random, 4)); // 7·13
    try std.testing.expect(!try isProbablyPrime(a, &.{99}, random, 4));
    // Carmichael number 561 = 3·11·17 must not fool the random bases.
    try std.testing.expect(!try isProbablyPrime(a, &.{ 0x02, 0x31 }, random, 8));
}

// ----------------------------------------------------- algo validation

/// A validated `passwordKdfAlgo` with owned salt copies. Expensive to
/// build (safe-prime checks); build once per `account.getPassword`
/// answer and reuse across attempts.
pub const Algo = struct {
    allocator: std.mem.Allocator,
    /// Generator, validated to 2..7.
    g: u8,
    /// Validated 2048-bit safe-prime modulus, big-endian.
    p: [group_len]u8,
    salt1: []u8,
    salt2: []u8,

    /// Validates the generated `account.PasswordKdfAlgo` value (the
    /// `current_algo` of `account.password`, or `new_algo` when setting
    /// a password) and copies what it needs.
    pub fn init(allocator: std.mem.Allocator, algo: api.PasswordKdfAlgo, random: std.Random) Error!Algo {
        const params = switch (algo) {
            .passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow => |a| a,
            .passwordKdfAlgoUnknown => return error.InvalidAlgo,
        };
        return initRaw(allocator, params.g, params.p, params.salt1, params.salt2, random);
    }

    /// Same validation for raw values (tests, hand-built plumbing).
    pub fn initRaw(
        allocator: std.mem.Allocator,
        g: i32,
        p_bytes: []const u8,
        salt1: []const u8,
        salt2: []const u8,
        random: std.Random,
    ) Error!Algo {
        if (g < 2 or g > 7) return error.InvalidAlgo;

        var start: usize = 0;
        while (start < p_bytes.len and p_bytes[start] == 0) start += 1;
        const p_norm = p_bytes[start..];
        // Exactly 2048 bits: 256 bytes, top bit set, odd.
        if (p_norm.len != group_len or (p_norm[0] & 0x80) == 0 or (p_norm[group_len - 1] & 1) == 0)
            return error.InvalidAlgo;

        var p: [group_len]u8 = undefined;
        @memcpy(&p, p_norm);

        // g² mod p ≠ 1 (rejects generators of small prime order).
        var g_sq: [group_len]u8 = undefined;
        const g_bytes = [1]u8{@intCast(g)};
        bigint.powmod(allocator, &g_bytes, &.{ 2 }, &p, &g_sq) catch return error.OutOfMemory;
        if (isOne(&g_sq)) return error.InvalidAlgo;

        // Safe prime: p and (p-1)/2 both probably prime.
        if (!try isProbablyPrime(allocator, &p, random, 8)) return error.InvalidAlgo;
        var half: [group_len]u8 = p;
        shr1(&half);
        if (!try isProbablyPrime(allocator, &half, random, 8)) return error.InvalidAlgo;

        const s1 = allocator.dupe(u8, salt1) catch return error.OutOfMemory;
        errdefer allocator.free(s1);
        const s2 = allocator.dupe(u8, salt2) catch return error.OutOfMemory;
        errdefer allocator.free(s2);
        return .{ .allocator = allocator, .g = @intCast(g), .p = p, .salt1 = s1, .salt2 = s2 };
    }

    pub fn deinit(self: *Algo) void {
        self.allocator.free(self.salt1);
        self.allocator.free(self.salt2);
        self.* = undefined;
    }

    /// The salt to use when setting a password: the server's `salt1`
    /// extended with client randomness (spec: at least 32 bytes). Owned
    /// by `allocator`.
    pub fn withExtendedSalt(self: *const Algo, allocator: std.mem.Allocator, random: std.Random) Error![]u8 {
        const out = allocator.alloc(u8, self.salt1.len + new_salt_random_bytes) catch return error.OutOfMemory;
        @memcpy(out[0..self.salt1.len], self.salt1);
        random.bytes(out[self.salt1.len..]);
        return out;
    }
};

// ---------------------------------------------------------- SRP client

/// One SRP login attempt. Holds the attempt's secrets; the `A` and `M1`
/// returned by `answer` borrow it — serialize the request (or finish the
/// rpc send) before `deinit`.
pub const Srp = struct {
    allocator: std.mem.Allocator,
    algo: *const Algo,
    x: [digest_len]u8,
    k: [digest_len]u8,
    v: [group_len]u8,
    a: [group_len]u8,
    A: [group_len]u8,
    m1: [digest_len]u8,

    /// Derives x, v, k and draws the fresh random `a` for this attempt.
    pub fn init(allocator: std.mem.Allocator, random: std.Random, algo: *const Algo, password: []const u8) Error!Srp {
        var self = Srp{
            .allocator = allocator,
            .algo = algo,
            .x = try computeX(allocator, password, algo.salt1, algo.salt2),
            .k = computeK(algo.g, &algo.p),
            .v = undefined,
            .a = undefined,
            .A = undefined,
            .m1 = undefined,
        };

        // v = g^x mod p
        bigint.powmod(allocator, &.{algo.g}, &self.x, &algo.p, &self.v) catch return error.OutOfMemory;

        // a = random 2048-bit, A = g^a mod p
        random.bytes(&self.a);
        self.a[0] |= 0x80; // keep it a full 2048-bit number
        bigint.powmod(allocator, &.{algo.g}, &self.a, &algo.p, &self.A) catch return error.OutOfMemory;
        return self;
    }

    pub fn deinit(self: *Srp) void {
        self.* = undefined;
    }

    /// Folds the server's `srp_B` in and produces the
    /// `inputCheckPasswordSRP` wire value. `A` points into `self.A`,
    /// `M1` into `self.m1`: both live until `deinit`.
    pub fn answer(self: *Srp, srp_id: i64, B: []const u8) Error!api.inputCheckPasswordSRP {
        const p = &self.algo.p;

        // Normalize B into a fixed-width buffer; the server sends a
        // value < p, anything else is a broken proof.
        var b_buf: [group_len]u8 = @splat(0);
        if (B.len == 0 or B.len > group_len) return error.InvalidServerProof;
        @memcpy(b_buf[group_len - B.len ..], B);
        if (std.mem.order(u8, &b_buf, p) != .lt) return error.InvalidServerProof;
        if (isZero(&b_buf) or isOne(&b_buf)) return error.InvalidServerProof;

        var b_int = bigint.fromBytes(self.allocator, &b_buf) catch return error.OutOfMemory;
        defer b_int.deinit();

        var p_int = bigint.fromBytes(self.allocator, p) catch return error.OutOfMemory;
        defer p_int.deinit();
        var k_int = bigint.fromBytes(self.allocator, &self.k) catch return error.OutOfMemory;
        defer k_int.deinit();
        var v_int = bigint.fromBytes(self.allocator, &self.v) catch return error.OutOfMemory;
        defer v_int.deinit();
        var one_int = bigint.fromBytes(self.allocator, &.{1}) catch return error.OutOfMemory;
        defer one_int.deinit();

        // t = (B - k·v) mod p
        var kv = Managed.init(self.allocator) catch return error.OutOfMemory;
        defer kv.deinit();
        kv.mul(&k_int, &v_int) catch return error.OutOfMemory;
        modReduce(&kv, &p_int) catch return error.OutOfMemory;

        var t = Managed.init(self.allocator) catch return error.OutOfMemory;
        defer t.deinit();
        t.sub(&b_int, &kv) catch return error.OutOfMemory;
        modReduce(&t, &p_int) catch return error.OutOfMemory;

        // Proof checks: t ∉ {0, 1}.
        if (t.eqlZero()) return error.InvalidServerProof;
        if (t.toConst().orderAbs(one_int.toConst()) == .eq) return error.InvalidServerProof;

        // u = SHA256(A ∥ B); exponent e = a + u·x
        const ab = concat(self.allocator, &.{ &self.A, &b_buf }) catch return error.OutOfMemory;
        defer self.allocator.free(ab);
        const u = sha256(ab);

        var u_int = bigint.fromBytes(self.allocator, &u) catch return error.OutOfMemory;
        defer u_int.deinit();
        var x_int = bigint.fromBytes(self.allocator, &self.x) catch return error.OutOfMemory;
        defer x_int.deinit();
        var a_int = bigint.fromBytes(self.allocator, &self.a) catch return error.OutOfMemory;
        defer a_int.deinit();

        var ux = Managed.init(self.allocator) catch return error.OutOfMemory;
        defer ux.deinit();
        ux.mul(&u_int, &x_int) catch return error.OutOfMemory;
        var e = Managed.init(self.allocator) catch return error.OutOfMemory;
        defer e.deinit();
        e.add(&a_int, &ux) catch return error.OutOfMemory;

        // s = t^e mod p; K = SHA256(s)
        var e_bytes: [group_len + 64]u8 = undefined;
        bigint.toBytes(&e_bytes, &e) catch return error.OutOfMemory;
        var s: [group_len]u8 = undefined;
        var t_bytes: [group_len]u8 = undefined;
        bigint.toBytes(&t_bytes, &t) catch return error.OutOfMemory;
        bigint.powmod(self.allocator, &t_bytes, &e_bytes, p, &s) catch return error.OutOfMemory;
        const k_s = sha256(&s);

        // M1 = SHA256(Hx(p) ∥ Hx(g) ∥ salt1 ∥ salt2 ∥ A ∥ B ∥ K)
        const g_padded = paddedG(self.algo.g);
        const hx_p = hx(p);
        const hx_g = hx(&g_padded);
        const m1_preimage = concat(self.allocator, &.{
            &hx_p,
            &hx_g,
            self.algo.salt1,
            self.algo.salt2,
            &self.A,
            &b_buf,
            &k_s,
        }) catch return error.OutOfMemory;
        defer self.allocator.free(m1_preimage);
        self.m1 = sha256(m1_preimage);

        return .{
            .srp_id = srp_id,
            .A = &self.A,
            .M1 = &self.m1,
        };
    }
};

fn modReduce(v: *Managed, modulus: *const Managed) Error!void {
    var q = Managed.init(v.allocator) catch return error.OutOfMemory;
    defer q.deinit();
    var r = Managed.init(v.allocator) catch return error.OutOfMemory;
    defer r.deinit();
    q.divFloor(&r, v, modulus) catch return error.OutOfMemory;
    v.copy(r.toConst()) catch return error.OutOfMemory;
}

// --------------------------------------------- setting a new password

/// The `new_password_hash` for `account.passwordInputSettings`:
/// x = SHA256(PBKDF2-HMAC-SHA512(PH2(password), salt, 100000)),
/// hash = g^x mod p. Pair the salt with `Algo.withExtendedSalt`.
pub fn newPasswordHash(
    allocator: std.mem.Allocator,
    algo: *const Algo,
    salt: []const u8,
    password: []const u8,
) Error![group_len]u8 {
    var pbkdf_out: [pbkdf2_out_len]u8 = undefined;
    const pw_hash = ph2(password);
    std.crypto.pwhash.pbkdf2(&pbkdf_out, &pw_hash, salt, 100_000, HmacSha512) catch return error.OutOfMemory;
    const x = sha256(&pbkdf_out);
    var out: [group_len]u8 = undefined;
    bigint.powmod(allocator, &.{algo.g}, &x, &algo.p, &out) catch return error.OutOfMemory;
    return out;
}

// ---------------------------------------------------------------- tests

test "hx matches the specification fold" {
    const h = sha256("td");
    var eighth: [8]u8 = @splat(0);
    for (0..4) |i| {
        for (0..8) |j| eighth[j] ^= h[i * 8 + j];
    }
    var expect: [digest_len]u8 = undefined;
    for (0..4) |i| expect[i * 8 ..][0..8].* = eighth;
    try std.testing.expectEqualSlices(u8, &expect, &hx("td"));
}

test "computeX matches the specification formula" {
    const a = std.testing.allocator;
    const x = try computeX(a, "pw", "s1", "s2");
    const inner = ph2("s2pw");
    var outer: [34]u8 = undefined;
    @memcpy(outer[0..2], "s1");
    @memcpy(outer[2..], &inner);
    const expect = ph2(&outer);
    try std.testing.expectEqualSlices(u8, &expect, &x);
}

// A known 2048-bit safe prime: the MTProto sample dh_prime
// (https://core.telegram.org/mtproto/samples-auth_key).
const test_prime_hex = "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B";

fn testPrime() [group_len]u8 {
    var p: [group_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&p, test_prime_hex) catch unreachable;
    return p;
}

test "algo validation accepts the safe prime and rejects malformed inputs" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(2);
    const random = prng.random();
    const p_buf = testPrime();

    var good = try Algo.initRaw(a, 3, &p_buf, "s1", "s2", random);
    defer good.deinit();
    try std.testing.expectEqual(@as(u8, 3), good.g);
    try std.testing.expectEqualStrings("s1", good.salt1);

    // Generator out of range.
    try std.testing.expectError(error.InvalidAlgo, Algo.initRaw(a, 1, &p_buf, "", "", random));
    try std.testing.expectError(error.InvalidAlgo, Algo.initRaw(a, 8, &p_buf, "", "", random));

    // Even modulus.
    var even = p_buf;
    even[group_len - 1] += 1;
    try std.testing.expectError(error.InvalidAlgo, Algo.initRaw(a, 3, &even, "", "", random));

    // Not 2048-bit.
    var small = p_buf;
    small[0] &= 0x7f;
    try std.testing.expectError(error.InvalidAlgo, Algo.initRaw(a, 3, &small, "", "", random));

    // Truncated modulus.
    try std.testing.expectError(error.InvalidAlgo, Algo.initRaw(a, 3, p_buf[0..128], "", "", random));
}

test "withExtendedSalt appends fresh random bytes" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(4);
    const random = prng.random();
    const p_buf = testPrime();
    var algo = try Algo.initRaw(a, 3, &p_buf, "salt-one", "s2", random);
    defer algo.deinit();

    const extended = try algo.withExtendedSalt(a, random);
    defer a.free(extended);
    try std.testing.expectEqual(algo.salt1.len + new_salt_random_bytes, extended.len);
    try std.testing.expectEqualStrings("salt-one", extended[0..algo.salt1.len]);
}

test "srp round trip against an in-test server" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(7);
    const random = prng.random();
    const p_buf = testPrime();

    var algo = try Algo.initRaw(a, 3, &p_buf, "salt-one", "salt-two", random);
    defer algo.deinit();
    const password = "hunter2";

    // ---- server side: v, b
    const server_x = try computeX(a, password, algo.salt1, algo.salt2);
    var v: [group_len]u8 = undefined;
    try bigint.powmod(a, &.{algo.g}, &server_x, &algo.p, &v);
    var b: [group_len]u8 = undefined;
    random.bytes(&b);
    b[0] |= 0x80;

    // ---- client side: A, M1
    var srp = try Srp.init(a, random, &algo, password);
    defer srp.deinit();

    // ---- server answer: B = k·v + g^b (mod p) — the SRP-6a form the
    // client's `answer` expects (it folds B - k·v back to g^b). k is the
    // public H(p)∥H(g) parameter, identical on both sides.
    var p_int = try bigint.fromBytes(a, &algo.p);
    defer p_int.deinit();
    var k_int = try bigint.fromBytes(a, &srp.k);
    defer k_int.deinit();
    var v_int = try bigint.fromBytes(a, &v);
    defer v_int.deinit();
    var gb: [group_len]u8 = undefined;
    try bigint.powmod(a, &.{algo.g}, &b, &algo.p, &gb);
    var gb_int = try bigint.fromBytes(a, &gb);
    defer gb_int.deinit();
    var kv_man = Managed.init(a) catch return error.OutOfMemory;
    defer kv_man.deinit();
    kv_man.mul(&k_int, &v_int) catch return error.OutOfMemory;
    modReduce(&kv_man, &p_int) catch return error.OutOfMemory;
    var b_man = Managed.init(a) catch return error.OutOfMemory;
    defer b_man.deinit();
    b_man.add(&kv_man, &gb_int) catch return error.OutOfMemory;
    modReduce(&b_man, &p_int) catch return error.OutOfMemory;
    var B: [group_len]u8 = undefined;
    try bigint.toBytes(&B, &b_man);

    const ans = try srp.answer(42, &B);
    try std.testing.expectEqual(@as(i64, 42), ans.srp_id);
    try std.testing.expectEqualSlices(u8, &srp.A, ans.A);
    try std.testing.expect(!isOne(&srp.A));
    try std.testing.expect(std.mem.order(u8, &srp.A, &algo.p) == .lt);

    // ---- server verifies M1: s = (A·v^u)^b mod p
    const ab = try concat(a, &.{ &srp.A, &B });
    defer a.free(ab);
    const u = sha256(ab);

    var u_int = try bigint.fromBytes(a, &u);
    defer u_int.deinit();
    var A_int = try bigint.fromBytes(a, &srp.A);
    defer A_int.deinit();

    // s = (A·v^u)^b mod p — v^u is an exponentiation, not a product.
    var vu: [group_len]u8 = undefined;
    try bigint.powmod(a, &v, &u, &algo.p, &vu);
    var vu_int = try bigint.fromBytes(a, &vu);
    defer vu_int.deinit();
    var avu = Managed.init(a) catch return error.OutOfMemory;
    defer avu.deinit();
    avu.mul(&A_int, &vu_int) catch return error.OutOfMemory;
    modReduce(&avu, &p_int) catch return error.OutOfMemory;
    var avu_buf: [group_len]u8 = undefined;
    try bigint.toBytes(&avu_buf, &avu);

    var s: [group_len]u8 = undefined;
    try bigint.powmod(a, &avu_buf, &b, &algo.p, &s);
    const K = sha256(&s);
    const g_padded = paddedG(algo.g);
    const m1_pre = try concat(a, &.{
        &hx(&algo.p),
        &hx(&g_padded),
        algo.salt1,
        algo.salt2,
        &srp.A,
        &B,
        &K,
    });
    defer a.free(m1_pre);
    const expect = sha256(m1_pre);
    try std.testing.expectEqualSlices(u8, &expect, ans.M1);
}

test "srp answer rejects broken server proofs" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(9);
    const random = prng.random();
    const p_buf = testPrime();
    var algo = try Algo.initRaw(a, 3, &p_buf, "", "", random);
    defer algo.deinit();

    var srp = try Srp.init(a, random, &algo, "pw");
    defer srp.deinit();

    var one: [group_len]u8 = @splat(0);
    one[group_len - 1] = 1;
    try std.testing.expectError(error.InvalidServerProof, srp.answer(1, &one));

    var zero: [group_len]u8 = @splat(0);
    try std.testing.expectError(error.InvalidServerProof, srp.answer(1, &zero));

    // B == p (not reduced) and B shorter than one byte.
    try std.testing.expectError(error.InvalidServerProof, srp.answer(1, &algo.p));
    try std.testing.expectError(error.InvalidServerProof, srp.answer(1, ""));

    // B that makes B - k·v ≡ 1 (mod p): craft with the client's own k, v.
    var crafted: [group_len]u8 = undefined;
    // B = 1 + k·v mod p → t = B - k·v = 1 → rejected.
    var one_int = try bigint.fromBytes(a, &.{1});
    defer one_int.deinit();
    var k_int = try bigint.fromBytes(a, &srp.k);
    defer k_int.deinit();
    var v_int = try bigint.fromBytes(a, &srp.v);
    defer v_int.deinit();
    var p_int = try bigint.fromBytes(a, &algo.p);
    defer p_int.deinit();
    var kv_man = Managed.init(a) catch return error.OutOfMemory;
    defer kv_man.deinit();
    kv_man.mul(&k_int, &v_int) catch return error.OutOfMemory;
    modReduce(&kv_man, &p_int) catch return error.OutOfMemory;
    var b_man = Managed.init(a) catch return error.OutOfMemory;
    defer b_man.deinit();
    b_man.add(&one_int, &kv_man) catch return error.OutOfMemory;
    modReduce(&b_man, &p_int) catch return error.OutOfMemory;
    try bigint.toBytes(&crafted, &b_man);
    try std.testing.expectError(error.InvalidServerProof, srp.answer(1, &crafted));
}
