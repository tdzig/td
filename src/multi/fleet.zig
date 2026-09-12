//! Multi-session scheduler: fair, bounded multiplexing of pump and
//! maintenance work across a fleet of independent sessions.
//!
//! td's whole stack is single-`Io`, single-thread: one `Manager` is one
//! connection driven by explicit calls. Scaling to thousands of
//! sessions is therefore a *scheduling* problem, not a threading one,
//! and this module is the scheduler:
//!
//!     Fleet
//!       ├─ slots[N]        stable slab — one connman.Manager each
//!       ├─ pump(io, B)     one sweep: round-robin B/N per session,
//!       │                  budget-capped, resumable via the cursor
//!       └─ maintainAll(io) keep-alive across the fleet
//!
//! Every session stays fully independent — own auth key, wire session
//! id, endpoint, counters, backoff state. The fleet owns scheduling and
//! observability only: a fixed-capacity slot slab (stable addresses, so
//! a manager's client never dangles — `addSession`/`removeSession` are
//! free-list operations, never memmoves), a fairness cursor that makes
//! sweeps resumable across calls when the budget runs out mid-round,
//! and per-sweep accounting (`Sweep`: sessions visited, sessions that
//! delivered frames, frames dispatched, wall time) from which the
//! event-loop utilization numbers in the benchmark suite are derived.
//!
//! Costs that are *not* hidden: a sweep is O(live sessions) — there is
//! no readiness API under the blocking `std.Io` model, so idle sessions
//! are skipped by policy (their per-session pump returns on the
//! transport's idle `TimedOut`), not by an event reactor. What that
//! costs per sweep at each fleet size, and what share of sweep time
//! actually delivers frames, is exactly what `just bench multi`
//! measures — those numbers, not assumptions, set the recommended fleet
//! sizes and budgets documented in docs/operations.md.

const std = @import("std");
const transport = @import("../transport/mod.zig");
const crypto = @import("../crypto/mod.zig");
const connman = @import("../connman/mod.zig");

pub const Manager = connman.Manager;

pub const Error = error{
    /// Every slot is occupied; raise the fleet's capacity.
    FleetFull,
    /// The id does not name a live session.
    NoSuchSession,
    /// Slot-slab or free-list allocation failed (`init`, `removeSession`
    /// recycle).
    OutOfMemory,
};

/// Fleet-wide configuration. The endpoint and per-session options are
/// defaults — `addSessionOn` overrides the endpoint per session.
pub const Options = struct {
    /// Slot count, fixed for the fleet's lifetime. Slot addresses are
    /// stable, so this is also the bound on simultaneous sessions.
    capacity: usize,
    /// Default endpoint for `addSession`. Host bytes are borrowed (as
    /// everywhere a transport endpoint appears).
    endpoint: transport.Endpoint,
    /// Per-session manager options (timeouts, backoff, transport
    /// provider). For socket fleets keep `tcp.read_timeout` well below
    /// the budgets you pass to `pump` — it bounds the blocking read
    /// every idle session costs per sweep.
    session: connman.Options = .{},
};

/// Result of one `pump` sweep — the raw material for event-loop
/// utilization: `work_sessions / visited` is the fraction of scheduled
/// sessions that delivered traffic, `frames` the work delivered.
pub const Sweep = struct {
    /// Sessions pumped in this sweep (may be fewer than live when the
    /// budget ran out — the cursor resumes there next call).
    visited: usize,
    /// Sessions that dispatched at least one frame.
    work_sessions: usize,
    /// Frames dispatched across the sweep (rpc results, pongs, acks,
    /// updates — anything the peers sent).
    frames: usize,
    /// Wall time of the sweep.
    ns: u64,
    /// True when the budget expired before every live session was
    /// visited; the next sweep resumes from the fairness cursor.
    stopped_early: bool,
};

/// Lifetime counters of the fleet.
pub const Totals = struct {
    sweeps: u64 = 0,
    frames: u64 = 0,
    pump_errors: u64 = 0,
    sessions_added: u64 = 0,
    sessions_removed: u64 = 0,
};

const Slot = struct {
    mgr: Manager,
    /// Backs the manager's randomness (wire session ids, padding,
    /// backoff jitter). Lives beside the manager so the borrowed
    /// `Random` outlives `Manager.init`.
    prng: std.Random.DefaultPrng,
    live: bool = false,
    /// Frames the manager had dispatched at its last sweep visit — the
    /// per-session work delta.
    frames_seen: usize = 0,
    last_error: ?anyerror = null,
};

pub const Fleet = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    /// Fixed slab; slot addresses never move (managers must not move
    /// once their client exists — the client borrows slot storage).
    slots: []Slot,
    /// Free slot indices, LIFO for cache-friendly reuse.
    free: std.ArrayList(u32) = .empty,
    live: usize = 0,
    /// Round-robin fairness cursor: the slot index the next sweep
    /// starts scanning from.
    cursor: usize = 0,
    /// Fleet-wide cumulative counters. Named `totals_acc` because the
    /// `totals()` method below would collide with a field of that name.
    totals_acc: Totals = .{},
    /// Set once `deinit` has freed the slab; makes deinit idempotent.
    freed: bool = false,

    pub fn init(allocator: std.mem.Allocator, opts: Options) Error!Fleet {
        if (opts.capacity == 0) return error.FleetFull;
        const slots = allocator.alloc(Slot, opts.capacity) catch return error.OutOfMemory;
        var fleet = Fleet{
            .allocator = allocator,
            .opts = opts,
            .slots = slots,
        };
        errdefer allocator.free(slots);
        fleet.free.ensureTotalCapacity(allocator, opts.capacity) catch return error.OutOfMemory;
        // LIFO order: first addSession takes slot 0.
        var i: usize = opts.capacity;
        while (i > 0) {
            i -= 1;
            fleet.free.appendAssumeCapacity(@intCast(i));
        }
        for (slots) |*s| s.* = .{
            .mgr = undefined,
            .prng = undefined,
            .live = false,
        };
        return fleet;
    }

    /// Closes and frees every live session. Idempotent.
    pub fn deinit(self: *Fleet, io: std.Io) void {
        if (self.freed) return;
        self.freed = true;
        for (self.slots) |*s| {
            if (s.live) {
                s.mgr.deinit(io);
                s.live = false;
            }
        }
        self.free.deinit(self.allocator);
        self.allocator.free(self.slots);
        self.live = 0;
    }

    // ------------------------------------------------------- membership

    /// Adds a session over `key` at the fleet's default endpoint. The
    /// key bytes are copied (each session owns its key); the endpoint
    /// host is borrowed. Returns the session id (its slot index).
    pub fn addSession(
        self: *Fleet,
        key: *const [crypto.auth_key_size]u8,
        server_salt: i64,
    ) Error!u32 {
        return self.addSessionOn(self.opts.endpoint, key, server_salt);
    }

    /// `addSession` with an explicit endpoint.
    pub fn addSessionOn(
        self: *Fleet,
        endpoint: transport.Endpoint,
        key: *const [crypto.auth_key_size]u8,
        server_salt: i64,
    ) Error!u32 {
        const idx = self.free.pop() orelse return error.FleetFull;
        const slot = &self.slots[idx];
        // Distinct per-session randomness from (slot, generation): wire
        // session ids and backoff jitter must not correlate across
        // sessions.
        slot.prng = std.Random.DefaultPrng.init(
            0x9e37_79b9 ^ (@as(u64, idx) << 32) ^ self.totals_acc.sessions_added,
        );
        slot.mgr = Manager.init(
            self.allocator,
            endpoint,
            key,
            server_salt,
            slot.prng.random(),
            self.opts.session,
        );
        slot.live = true;
        slot.frames_seen = 0;
        slot.last_error = null;
        self.live += 1;
        self.totals_acc.sessions_added += 1;
        return idx;
    }

    /// Frees one session: graceful manager shutdown (ack drain, cancel,
    /// close, provider release) and slot recycle. The id may name an
    /// already-removed slot — removing twice is a no-op.
    pub fn removeSession(self: *Fleet, io: std.Io, id: u32) Error!void {
        if (id >= self.slots.len) return error.NoSuchSession;
        const slot = &self.slots[id];
        if (!slot.live) return error.NoSuchSession;
        slot.mgr.deinit(io);
        slot.live = false;
        self.live -= 1;
        self.totals_acc.sessions_removed += 1;
        self.free.append(self.allocator, id) catch {
            // The free-list append is the only allocation; losing it
            // would strand the slot, so treat failure as fatal for the
            // fleet's bookkeeping contract.
            @panic("td.multi: out of memory recycling a fleet slot");
        };
    }

    /// The manager behind a session id. Borrowed: any manager method
    /// may be called through it, but never move it.
    pub fn session(self: *Fleet, id: u32) Error!*Manager {
        if (id >= self.slots.len) return error.NoSuchSession;
        if (!self.slots[id].live) return error.NoSuchSession;
        return &self.slots[id].mgr;
    }

    // ------------------------------------------------------- scheduling

    /// One scheduling sweep: pumps up to `live` connected sessions
    /// round-robin from the fairness cursor, `budget/live` per session,
    /// and stops as soon as the total budget is spent (resuming from
    /// the cursor on the next call — no session is starved across
    /// sweeps). Per-session errors are recorded on the slot and counted
    /// in `Totals.pump_errors`; one dead session never aborts the sweep.
    pub fn pump(self: *Fleet, io: std.Io, budget: std.Io.Duration) Sweep {
        const t0 = std.Io.Timestamp.now(io, .awake);
        var sweep = Sweep{
            .visited = 0,
            .work_sessions = 0,
            .frames = 0,
            .ns = 0,
            .stopped_early = false,
        };
        if (self.live == 0) return sweep;

        const slice = std.Io.Duration.fromNanoseconds(
            @max(@divTrunc(budget.nanoseconds, @as(i96, @intCast(self.live))), 1),
        );

        while (sweep.visited < self.live) {
            const idx = self.nextLive() orelse break;
            const slot = &self.slots[idx];
            var frames_before: usize = 0;
            if (slot.mgr.client) |*c| frames_before = c.frames_seen;

            slot.mgr.pump(io, slice) catch |e| {
                slot.last_error = e;
                self.totals_acc.pump_errors += 1;
            };

            var frames_after: usize = frames_before;
            if (slot.mgr.client) |*c| frames_after = c.frames_seen;
            if (frames_after > frames_before) {
                sweep.work_sessions += 1;
                sweep.frames += frames_after - frames_before;
                slot.last_error = null;
            }
            slot.frames_seen = frames_after;
            sweep.visited += 1;

            if (sweep.visited < self.live and
                t0.durationTo(std.Io.Timestamp.now(io, .awake)).nanoseconds >= budget.nanoseconds)
            {
                sweep.stopped_early = true;
                break;
            }
        }

        sweep.ns = @intCast(t0.durationTo(std.Io.Timestamp.now(io, .awake)).nanoseconds);
        self.totals_acc.sweeps += 1;
        self.totals_acc.frames += sweep.frames;
        return sweep;
    }

    /// Keep-alive across the fleet: `Manager.maintain` per live session
    /// (ping when due, reconnect when silent). Returns how many
    /// sessions were visited. Per-session errors are recorded, not
    /// surfaced — one unreachable session must not skip the rest.
    pub fn maintainAll(self: *Fleet, io: std.Io) usize {
        var visited: usize = 0;
        var i: usize = 0;
        while (i < self.live) : (i += 1) {
            const idx = self.nextLive() orelse break;
            const slot = &self.slots[idx];
            slot.mgr.maintain(io) catch |e| {
                slot.last_error = e;
                self.totals_acc.pump_errors += 1;
            };
            visited += 1;
        }
        return visited;
    }

    /// Next live slot at or after `cursor` (wrapping), advancing the
    /// cursor past it. Null when no session is live.
    fn nextLive(self: *Fleet) ?u32 {
        if (self.live == 0) return null;
        var i: usize = self.cursor;
        var scanned: usize = 0;
        while (scanned < self.slots.len) : ({
            i = (i + 1) % self.slots.len;
            scanned += 1;
        }) {
            if (self.slots[i].live) {
                self.cursor = (i + 1) % self.slots.len;
                return @intCast(i);
            }
        }
        return null;
    }

    // ----------------------------------------------------- observability

    /// Fleet-wide totals (sweeps, frames, errors, membership churn).
    pub fn totals(self: *const Fleet) Totals {
        return self.totals_acc;
    }

    /// How many sessions currently believe they are connected.
    pub fn connectedCount(self: *const Fleet) usize {
        var n: usize = 0;
        for (self.slots) |*s| {
            if (s.live and s.mgr.client != null and s.mgr.client.?.isConnected()) n += 1;
        }
        return n;
    }
};

// ---------------------------------------------------------------- tests

const test_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 53 +% 17);
    break :blk k;
};

test "membership: add fills slots LIFO, remove recycles, bounds are errors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fleet = try Fleet.init(std.testing.allocator, .{
        .capacity = 2,
        .endpoint = .{ .host = "loopback", .port = 0 },
    });
    defer fleet.deinit(io);

    const a = try fleet.addSession(&test_key, 1);
    const b = try fleet.addSession(&test_key, 2);
    try std.testing.expectEqual(@as(u32, 0), a);
    try std.testing.expectEqual(@as(u32, 1), b);
    try std.testing.expectEqual(@as(usize, 2), fleet.live);
    try std.testing.expectError(error.FleetFull, fleet.addSession(&test_key, 3));

    _ = try fleet.session(a); // resolves
    try std.testing.expectError(error.NoSuchSession, fleet.session(9));

    try fleet.removeSession(io, a);
    try std.testing.expectError(error.NoSuchSession, fleet.session(a));
    try std.testing.expectEqual(@as(usize, 1), fleet.live);

    // Recycle: the freed slot is handed out again.
    const c = try fleet.addSession(&test_key, 3);
    try std.testing.expectEqual(a, c);
    try std.testing.expectError(error.NoSuchSession, fleet.removeSession(io, 42));
}

test "pump sweeps every live session and records per-session errors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fleet = try Fleet.init(std.testing.allocator, .{
        .capacity = 4,
        .endpoint = .{ .host = "loopback", .port = 0 },
        // Never-connected managers fail their one connect attempt
        // immediately (no DNS, no retry sleeps) — exactly what this
        // test wants the sweep to record and survive.
        .session = .{
            .max_connect_attempts = 1,
            .backoff_base = std.Io.Duration.fromMilliseconds(1),
            .backoff_max = std.Io.Duration.fromMilliseconds(1),
        },
    });
    defer fleet.deinit(io);

    _ = try fleet.addSession(&test_key, 1);
    _ = try fleet.addSession(&test_key, 2);
    _ = try fleet.addSession(&test_key, 3);

    const sweep = fleet.pump(io, std.Io.Duration.fromMilliseconds(5));
    try std.testing.expectEqual(@as(usize, 3), sweep.visited);
    try std.testing.expect(!sweep.stopped_early);
    try std.testing.expect(fleet.totals_acc.pump_errors > 0); // cannot reach "loopback"
    try std.testing.expectEqual(@as(u64, 1), fleet.totals_acc.sweeps);

    // Removing one session mid-fleet keeps the sweep visiting the rest.
    try fleet.removeSession(io, 1);
    const sweep2 = fleet.pump(io, std.Io.Duration.fromMilliseconds(5));
    try std.testing.expectEqual(@as(usize, 2), sweep2.visited);

    // An empty fleet sweeps to a zeroed result.
    try fleet.removeSession(io, 0);
    try fleet.removeSession(io, 2);
    const sweep3 = fleet.pump(io, std.Io.Duration.fromMilliseconds(5));
    try std.testing.expectEqual(@as(usize, 0), sweep3.visited);
    try std.testing.expectEqual(@as(usize, 0), sweep3.frames);
}
