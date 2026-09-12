//! Reconnect backoff: exponential growth with full jitter.
//!
//! The n-th consecutive delay is drawn uniformly from
//! `[0, min(base·2ⁿ, max))` rather than set to the exponential value
//! itself: a fleet of clients reconnecting after the same outage spreads
//! its attempts over the whole window instead of synchronizing into a
//! new storm on the exponential curve (the "thundering herd" the
//! exponential shape alone does not prevent).
//!
//! Pure policy — no clocks, no IO, no globals. The caller sleeps with
//! whatever driver the `std.Io` provides; `connman.Manager` owns that
//! wiring.

const std = @import("std");

pub const Backoff = struct {
    /// Delay scale of the first attempt after a `reset`.
    base: std.Io.Duration,
    /// Hard ceiling for every attempt.
    max: std.Io.Duration,
    /// Draw source for the jitter; borrowed, must outlive this value.
    random: std.Random,
    /// Consecutive attempts since the last `reset`.
    attempt: u32 = 0,

    pub fn init(base: std.Io.Duration, max: std.Io.Duration, random: std.Random) Backoff {
        return .{ .base = base, .max = max, .random = random };
    }

    /// Upper bound of the current attempt's delay: base·2^attempt, capped
    /// at `max`. Overflow-safe: the doubling stops at the cap, so an
    /// `attempt` counter that has run for years cannot wrap anything.
    pub fn ceiling(self: *const Backoff) i96 {
        const max_ns: i128 = self.max.nanoseconds;
        var cur: i128 = self.base.nanoseconds;
        if (cur < 0) cur = 0;
        var doublings: u32 = 0;
        while (doublings < self.attempt and cur < max_ns) : (doublings += 1) {
            cur *= 2;
        }
        if (cur > max_ns) cur = max_ns;
        return @intCast(cur);
    }

    /// Draws the next delay and advances the attempt counter. Never
    /// returns more than `max` and never less than zero.
    pub fn next(self: *Backoff) std.Io.Duration {
        const top = self.ceiling();
        self.attempt +%= 1;
        // uintLessThan requires a positive bound; a degenerate curve
        // (zero/near-zero base or max) degenerates to an immediate retry.
        if (top <= 1) return std.Io.Duration.fromNanoseconds(top);
        const bound: u64 = if (top > std.math.maxInt(u64))
            std.math.maxInt(u64)
        else
            @intCast(top);
        const jitter = self.random.uintLessThan(u64, bound);
        return std.Io.Duration.fromNanoseconds(@intCast(jitter));
    }

    /// Returns to the base delay — call once the connection is
    /// (re-)established, so a flapping link does not inherit the depth of
    /// an outage it was not part of.
    pub fn reset(self: *Backoff) void {
        self.attempt = 0;
    }
};

// ---------------------------------------------------------------- tests

test "ceiling doubles per attempt and caps at max" {
    var prng = std.Random.DefaultPrng.init(0);
    var b = Backoff.init(
        std.Io.Duration.fromMilliseconds(10),
        std.Io.Duration.fromMilliseconds(100),
        prng.random(),
    );
    const ms: i96 = std.time.ns_per_ms;
    try std.testing.expectEqual(@as(i96, 10 * ms), b.ceiling());
    _ = b.next();
    try std.testing.expectEqual(@as(i96, 20 * ms), b.ceiling());
    _ = b.next();
    try std.testing.expectEqual(@as(i96, 40 * ms), b.ceiling());
    _ = b.next();
    try std.testing.expectEqual(@as(i96, 80 * ms), b.ceiling());
    _ = b.next();
    try std.testing.expectEqual(@as(i96, 100 * ms), b.ceiling());
    _ = b.next();
    // The cap holds no matter how long the outage lasts.
    _ = b.next();
    _ = b.next();
    try std.testing.expectEqual(@as(i96, 100 * ms), b.ceiling());
}

test "draws stay within [0, ceiling) and reset returns to base" {
    var prng = std.Random.DefaultPrng.init(0xbac0);
    var b = Backoff.init(
        std.Io.Duration.fromMilliseconds(4),
        std.Io.Duration.fromMilliseconds(64),
        prng.random(),
    );
    for (0..64) |round| {
        // Advance deep into the cap so both growing and capped attempts
        // are exercised.
        if (round > 8) b.attempt = 8;
        const top = b.ceiling();
        const d = b.next();
        try std.testing.expect(d.nanoseconds >= 0);
        try std.testing.expect(d.nanoseconds < top);
    }
    b.reset();
    try std.testing.expectEqual(@as(i96, 4 * std.time.ns_per_ms), b.ceiling());
}

test "degenerate curve yields zero delay without drawing" {
    var prng = std.Random.DefaultPrng.init(1);
    var b = Backoff.init(std.Io.Duration.zero, std.Io.Duration.fromSeconds(1), prng.random());
    try std.testing.expectEqual(@as(i96, 0), b.next().nanoseconds);
    try std.testing.expectEqual(@as(u32, 1), b.attempt);
}

test "negative base is clamped to zero" {
    var prng = std.Random.DefaultPrng.init(2);
    var b = Backoff.init(
        std.Io.Duration.fromNanoseconds(-5),
        std.Io.Duration.fromSeconds(1),
        prng.random(),
    );
    try std.testing.expectEqual(@as(i96, 0), b.ceiling());
    try std.testing.expectEqual(@as(i96, 0), b.next().nanoseconds);
}
