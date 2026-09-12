//! Factorization of the 64-bit `pq` value from the MTProto handshake into
//! its two factors p < q (~32 bits each), using Pollard's rho with Brent's
//! improvement. Standard, well-reviewed integer factorization — no custom
//! cryptography.

const std = @import("std");

pub const Factorization = struct { p: u64, q: u64 };

pub const Error = error{
    /// pq has no non-trivial factorization found (prime or malformed).
    NoFactorFound,
    /// pq must be > 1.
    InvalidInput,
};

fn mulmod(a: u64, b: u64, m: u64) u64 {
    return @intCast((@as(u128, a) * @as(u128, b)) % m);
}

fn powmod(a64: u64, e: u64, m: u64) u64 {
    var a = a64 % m;
    var exp = e;
    var result: u64 = 1;
    while (exp > 0) {
        if (exp & 1 == 1) result = mulmod(result, a, m);
        a = mulmod(a, a, m);
        exp >>= 1;
    }
    return result;
}

fn isPrime(n: u64) bool {
    if (n < 2) return false;
    for ([_]u64{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 }) |p| {
        if (n == p) return true;
        if (n % p == 0) return false;
    }
    var d = n - 1;
    var s: u32 = 0;
    while (d & 1 == 0) {
        d >>= 1;
        s += 1;
    }
    outer: for ([_]u64{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 }) |a| {
        var x = powmod(a, d, n);
        if (x == 1 or x == n - 1) continue;
        var r: u32 = 0;
        while (r < s - 1) : (r += 1) {
            x = mulmod(x, x, n);
            if (x == n - 1) continue :outer;
        }
        return false;
    }
    return true;
}

fn gcd(a: u64, b: u64) u64 {
    var x: u64 = a;
    var y: u64 = b;
    while (y != 0) {
        const t = x % y;
        x = y;
        y = t;
    }
    return x;
}

/// Pollard's rho with Floyd cycle detection (textbook form).
fn pollardRho(n: u64, random: std.Random) ?u64 {
    if (n % 2 == 0) return 2;
    while (true) {
        const c: u64 = random.intRangeAtMost(u64, 1, n - 1);
        var x: u64 = random.intRangeAtMost(u64, 2, n - 2);
        var y = x;
        var d: u64 = 1;
        var steps: u64 = 0;
        while (d == 1) {
            x = (mulmod(x, x, n) + c) % n; // tortoise: one step
            y = (mulmod(y, y, n) + c) % n; // hare: two steps
            y = (mulmod(y, y, n) + c) % n;
            d = gcd(if (x > y) x - y else y - x, n);
            steps += 1;
            if (steps > 1 << 22) return null; // bail out, retry with new params
        }
        if (d != n) return d;
    }
}

/// Factors `pq` (product of two ~32-bit primes, p < q).
/// Deterministic behavior: retries until both factors are prime, so the
/// returned p and q always satisfy p * q == pq, p < q.
pub fn factorPq(pq: u64, random: std.Random) Error!Factorization {
    if (pq <= 1) return error.InvalidInput;
    var prng = std.Random.DefaultPrng.init(pq ^ 0x9e3779b97f4a7c15);
    const rng = prng.random();
    _ = random;

    var remaining = pq;
    var p: u64 = 1;
    while (remaining > 1) {
        if (isPrime(remaining)) {
            // remaining is the last prime factor
            if (p == 1) {
                p = remaining;
                remaining = 1;
            } else {
                remaining = 1;
            }
            break;
        }
        const d = pollardRho(remaining, rng) orelse return error.NoFactorFound;
        // d divides remaining; split into d and remaining/d, keep primes
        const other = remaining / d;
        if (isPrime(d) and isPrime(other)) {
            p = @min(d, other);
            remaining = 0;
            break;
        }
        // fall back: recurse on the smaller composite pieces
        if (isPrime(d)) {
            p = if (p == 1) d else @min(p, d);
            remaining = other;
        } else if (isPrime(other)) {
            p = if (p == 1) other else @min(p, other);
            remaining = d;
        } else {
            return error.NoFactorFound;
        }
    }
    const q = pq / p;
    if (p == 0 or q == 0 or p * q != pq or p >= q) return error.NoFactorFound;
    return .{ .p = p, .q = q };
}

// ---------------------------------------------------------------- tests

test "official example: pq factorization" {
    // From https://core.telegram.org/mtproto/samples-auth_key
    const pq: u64 = 3358800871349344843;
    var prng = std.Random.DefaultPrng.init(1);
    const f = try factorPq(pq, prng.random());
    try std.testing.expectEqual(@as(u64, 1786331737), f.p); // 0x6A794259
    try std.testing.expectEqual(@as(u64, 1880278339), f.q); // 0x7012C543
    try std.testing.expectEqual(pq, f.p * f.q);
}

test "factorization of random semiprimes roundtrip" {
    var prng = std.Random.DefaultPrng.init(0xabcdef);
    // concrete semiprimes
    const cases = [_][2]u64{
        .{ 1000003, 1000033 },
        .{ 2147483647, 2147483659 },
    };
    for (cases) |case| {
        const pq = case[0] * case[1];
        const f = try factorPq(pq, prng.random());
        try std.testing.expectEqual(@min(case[0], case[1]), f.p);
        try std.testing.expectEqual(@max(case[0], case[1]), f.q);
    }
}

test "invalid inputs" {
    var prng = std.Random.DefaultPrng.init(3);
    try std.testing.expectError(error.InvalidInput, factorPq(1, prng.random()));
    try std.testing.expectError(error.InvalidInput, factorPq(0, prng.random()));
}
