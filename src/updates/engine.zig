//! The updates engine: consumes decoded `api.Updates` values, keeps the
//! common state (`pts`/`qts`/`date`/`seq`), orders and dedupes the
//! stream, and delivers application events.
//!
//! Two operations, strictly separated so neither can corrupt the other:
//!
//!   * `handle` — pure, synchronous, allocation-free: one decoded
//!     `Updates` value in, an `Outcome` out, events delivered inline to
//!     the handler. Gaps are *recorded* (`needs_difference`), never
//!     healed here.
//!   * `reconcile` — the healing pass: seeds a pristine state from
//!     `updates.getState`, otherwise runs the `updates.getDifference`
//!     slice loop until the server reports a final state, delivering
//!     everything the client missed along the way. Called by the pump
//!     loop *after* `pump` returns — never from inside the updates hook,
//!     which would re-enter the client's read loop (see `fetch.hook`).
//!
//! Ordering rules (see `state.zig` for the verdicts): containers are
//! judged by `seq` first — stale ones are dropped whole, ahead-of-state
//! ones are gaps; inside a live container each update is checked against
//! its own counter, so an `updatesCombined` overlap delivers only the
//! genuinely new parts. The short-message variants carry their own
//! `pts` and flow through the same pts rules. Everything recovered by a
//! difference is delivered unconditionally: the server starts strictly
//! after the state the request carried, so it is new by construction.

const std = @import("std");
const api = @import("../api/mod.zig");
const rpc = @import("../rpc/mod.zig");
const state_mod = @import("state.zig");
const classify_mod = @import("classify.zig");

pub const State = state_mod.State;

/// One application-visible event. All pointers borrow from the
/// `Updates` value (or fetched difference) currently being processed
/// and are valid only for the duration of the handler call.
pub const Event = union(enum) {
    /// A sequenced or unsequenced update, delivered in stream order,
    /// exactly once.
    update: *const api.Update,
    /// `updateShortMessage` — private-chat message shortcut.
    short_message: *const api.updateShortMessage,
    /// `updateShortChatMessage` — small-group message shortcut.
    short_chat_message: *const api.updateShortChatMessage,
    /// `updateShortSentMessage` — the echo of a sent message.
    short_sent_message: *const api.updateShortSentMessage,
    /// A message recovered through `updates.getDifference` — the same
    /// shape `updateNewMessage` would have carried.
    new_message: *const api.Message,
    /// An encrypted message recovered through `updates.getDifference`.
    encrypted_message: *const api.EncryptedMessage,
};

/// Application callback. Runs synchronously inside `handle`; it must
/// not run long, retain event pointers, or perform RPCs on the same
/// client (queue work instead).
pub const Handler = struct {
    ctx: *anyopaque,
    notify: *const fn (ctx: *anyopaque, event: Event) void,
};

/// Typed RPC responses owned transiently by the engine (allocated by
/// the fetcher with the engine's allocator; `dropResponse` disposes).
pub const DifferenceResponse = rpc.Response(api.updates.Difference);
pub const StateResponse = rpc.Response(api.updates.state);

/// The engine's window onto the network: `updates.getDifference` and
/// `updates.getState`, type-erased so the engine never touches a
/// client directly. Implementations allocate the response with the
/// engine's allocator; the engine deinits and destroys it after use
/// (see `fetch.RpcFetcher` for the rpc.Client implementation).
pub const Fetcher = struct {
    ctx: *anyopaque,
    getDifference: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        req: api.updates.getDifference,
    ) anyerror!*DifferenceResponse,
    getState: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
    ) anyerror!*StateResponse,
};

pub const Options = struct {
    /// Bound on getDifference rounds in one `reconcile`; a server that
    /// keeps producing intermediate states past this count is treated
    /// as a protocol malfunction (`error.SliceLimit`), not a loop.
    max_difference_slices: usize = 100,
};

/// Which counter violation produced a gap.
pub const GapKind = enum {
    /// Container `seq` skips ahead (or `updatesTooLong`).
    seq,
    /// A pts-bearing update is beyond the next position.
    pts,
    /// A qts-bearing update is beyond the next position.
    qts,
    /// `updatesTooLong` or `differenceTooLong`: state unusably old.
    too_long,
};

/// What one `handle` (or a whole reconcile, read off `Stats`) did.
pub const Outcome = struct {
    /// Events delivered to the handler.
    delivered: usize = 0,
    /// Wholly stale input; nothing was new.
    duplicate: bool = false,
    /// A gap was detected. Healed already only if `healed` is set;
    /// otherwise `needs_difference` is set for the next `reconcile`.
    gap: ?GapKind = null,
    healed: bool = false,
    /// Pristine state was seeded from `updates.getState`.
    resynced: bool = false,
    /// `differenceTooLong`: pts was reset; the application must
    /// refetch message history itself.
    too_long: bool = false,
};

/// Lifetime counters, mirroring `connman.Health` in spirit.
pub const Stats = struct {
    updates_seen: usize = 0,
    events_delivered: usize = 0,
    duplicates_skipped: usize = 0,
    /// Raw bodies the hook could not decode as `api.Updates`.
    undecodable_bodies: usize = 0,
    difference_rounds: usize = 0,
    gaps_healed: usize = 0,
    /// getState seeds and differenceTooLong resets.
    resyncs: usize = 0,
};

pub const Error = error{
    OutOfMemory,
    SliceLimit,
    FetchFailed,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    /// The common update state. Zeroed means "never initialized";
    /// `reconcile` then seeds it with `updates.getState`.
    state: State = .{},
    handler: ?Handler = null,
    fetcher: ?Fetcher = null,
    opts: Options = .{},
    stats: Stats = .{},

    /// A gap was seen and `reconcile` has not caught up for it yet.
    needs_difference: bool = false,
    /// The raw error of the last failed fetch, for diagnostics.
    last_fetch_error: ?anyerror = null,

    pub fn init(allocator: std.mem.Allocator) Engine {
        return .{ .allocator = allocator };
    }

    // ------------------------------------------------------------ ingest

    /// Processes one decoded `Updates` value: orders, dedupes, delivers.
    /// Pure — no allocation, no IO. Event pointers borrow from `u` for
    /// the duration of the call.
    pub fn handle(self: *Engine, u: *const api.Updates) Outcome {
        self.stats.updates_seen += 1;
        return switch (u.*) {
            .updatesTooLong => blk: {
                self.needs_difference = true;
                break :blk Outcome{ .gap = .too_long };
            },
            .updates_ => |*v|
                self.applyContainer(v.date, state_mod.seqVerdict(self.state.seq, v.seq), v.seq, v.updates),
            .updatesCombined => |*v|
                self.applyContainer(v.date, state_mod.seqStartVerdict(self.state.seq, v.seq_start, v.seq), v.seq, v.updates),
            .updateShort => |*v| blk: {
                self.state.mergeDate(v.date);
                break :blk self.deliverSingle(&v.update);
            },
            .updateShortMessage => |*v|
                self.deliverPtsEvent(v.pts, v.pts_count, v.date, .{ .short_message = v }),
            .updateShortChatMessage => |*v|
                self.deliverPtsEvent(v.pts, v.pts_count, v.date, .{ .short_chat_message = v }),
            .updateShortSentMessage => |*v|
                self.deliverPtsEvent(v.pts, v.pts_count, v.date, .{ .short_sent_message = v }),
        };
    }

    // ------------------------------------------------------------ heal

    /// Heals a recorded gap: a pristine state is seeded with
    /// `updates.getState`, anything else runs the getDifference slice
    /// loop until a final state. No-op when nothing is pending or no
    /// fetcher is attached (the flag stays set for the caller).
    pub fn reconcile(self: *Engine, io: std.Io) Error!void {
        if (!self.needs_difference) return;
        const f = self.fetcher orelse return;
        self.needs_difference = false;
        if (self.state.isPristine()) {
            try self.fetchState(io, f);
            return;
        }
        try self.fetchDifference(io, f);
    }

    fn fetchState(self: *Engine, io: std.Io, f: Fetcher) Error!void {
        const res = f.getState(f.ctx, self.allocator, io) catch |e| {
            self.fetchFailed(e);
            return error.FetchFailed;
        };
        defer self.dropResponse(res);
        const s = res.value;
        self.state = .{
            .pts = s.pts,
            .qts = s.qts,
            .seq = s.seq,
            .unread_count = s.unread_count,
        };
        self.state.mergeDate(s.date);
        self.stats.resyncs += 1;
    }

    fn fetchDifference(self: *Engine, io: std.Io, f: Fetcher) Error!void {
        var rounds: usize = 0;
        while (true) {
            rounds += 1;
            if (rounds > self.opts.max_difference_slices) {
                // Leave the flag set: a later reconcile may get further.
                self.needs_difference = true;
                return error.SliceLimit;
            }
            const req = api.updates.getDifference{
                .pts = self.state.pts,
                .date = self.state.date,
                .qts = self.state.qts,
            };
            const res = f.getDifference(f.ctx, self.allocator, io, req) catch |e| {
                self.fetchFailed(e);
                return error.FetchFailed;
            };
            defer self.dropResponse(res);
            self.stats.difference_rounds += 1;
            switch (res.value) {
                .differenceEmpty => |d| {
                    self.state.mergeDate(d.date);
                    if (d.seq != 0) self.state.seq = d.seq;
                    self.stats.gaps_healed += 1;
                    return;
                },
                .differenceTooLong => |d| {
                    // Local state is unusably old; the server hands back
                    // only a fresh pts. The engine stays current from
                    // here; the application must refetch history itself.
                    self.state.pts = d.pts;
                    self.stats.resyncs += 1;
                    return;
                },
                .difference => |d| {
                    self.applyDifference(d.new_messages, d.new_encrypted_messages, d.other_updates);
                    self.adoptState(d.state);
                    self.stats.gaps_healed += 1;
                    return;
                },
                .differenceSlice => |d| {
                    self.applyDifference(d.new_messages, d.new_encrypted_messages, d.other_updates);
                    self.adoptState(d.intermediate_state);
                },
            }
        }
    }

    // --------------------------------------------------------- internals

    /// One update wrapped in a dated container (`updateShort`).
    fn deliverSingle(self: *Engine, u: *const api.Update) Outcome {
        return switch (classify_mod.classify(u)) {
            .none => blk: {
                self.deliver(.{ .update = u });
                break :blk .{ .delivered = 1 };
            },
            .pts => |p| self.deliverPtsEvent(p.pts, p.count, 0, .{ .update = u }),
            .qts => |q| self.deliverQtsEvent(q, .{ .update = u }),
        };
    }

    /// A pts-sequenced event (the short-message family and pts-bearing
    /// updates delivered alone): apply → advance and deliver; skip →
    /// duplicate; gap → recorded, nothing delivered.
    fn deliverPtsEvent(self: *Engine, pts: i32, count: i32, date: i32, ev: Event) Outcome {
        // A pristine engine adopts the first pts it sees (see handle).
        const verdict: state_mod.PtsVerdict = if (self.state.isPristine())
            .apply
        else
            state_mod.ptsVerdict(self.state.pts, pts, count);
        switch (verdict) {
            .apply => {
                self.state.pts = pts;
                if (date != 0) self.state.mergeDate(date);
                self.deliver(ev);
                return .{ .delivered = 1 };
            },
            .skip => {
                self.stats.duplicates_skipped += 1;
                return .{ .duplicate = true };
            },
            .gap => {
                self.needs_difference = true;
                return .{ .gap = .pts };
            },
        }
    }

    fn deliverQtsEvent(self: *Engine, qts: i32, ev: Event) Outcome {
        const verdict: state_mod.PtsVerdict = if (self.state.isPristine())
            .apply
        else
            state_mod.qtsVerdict(self.state.qts, qts);
        switch (verdict) {
            .apply => {
                self.state.qts = qts;
                self.deliver(ev);
                return .{ .delivered = 1 };
            },
            .skip => {
                self.stats.duplicates_skipped += 1;
                return .{ .duplicate = true };
            },
            .gap => {
                self.needs_difference = true;
                return .{ .gap = .qts };
            },
        }
    }

    /// A live (seq-checked) container: every update is judged by its own
    /// counter, so overlapping `updatesCombined` batches deliver only
    /// their new parts. A hole inside the container records a gap but
    /// does not stop delivery: the remaining updates are independently
    /// verifiable by their own counters, and the heal will refill the
    /// hole.
    fn applyContainer(
        self: *Engine,
        date: i32,
        verdict: state_mod.SeqVerdict,
        seq: i32,
        updates: []const api.Update,
    ) Outcome {
        switch (verdict) {
            .duplicate => {
                self.stats.duplicates_skipped += updates.len;
                return .{ .duplicate = true };
            },
            .gap => {
                self.needs_difference = true;
                return .{ .gap = .seq };
            },
            .apply => {},
        }
        const before = self.stats.events_delivered;
        var gap: ?GapKind = null;
        for (updates) |*u| {
            switch (classify_mod.classify(u)) {
                .none => self.deliver(.{ .update = u }),
                .pts => |p| switch (state_mod.ptsVerdict(self.state.pts, p.pts, p.count)) {
                    .apply => {
                        self.state.pts = p.pts;
                        self.deliver(.{ .update = u });
                    },
                    .skip => self.stats.duplicates_skipped += 1,
                    .gap => {
                        self.needs_difference = true;
                        if (gap == null) gap = .pts;
                    },
                },
                .qts => |q| switch (state_mod.qtsVerdict(self.state.qts, q)) {
                    .apply => {
                        self.state.qts = q;
                        self.deliver(.{ .update = u });
                    },
                    .skip => self.stats.duplicates_skipped += 1,
                    .gap => {
                        self.needs_difference = true;
                        if (gap == null) gap = .qts;
                    },
                },
            }
        }
        self.state.mergeDate(date);
        self.state.seq = seq;
        return .{
            .delivered = self.stats.events_delivered - before,
            .gap = gap,
        };
    }

    /// Everything inside a difference is new by construction: deliver
    /// unconditionally, messages first (they are the oldest facts the
    /// server had), then the auxiliary updates.
    fn applyDifference(
        self: *Engine,
        messages: []const api.Message,
        encrypted: []const api.EncryptedMessage,
        others: []const api.Update,
    ) void {
        for (messages) |*m| self.deliver(.{ .new_message = m });
        for (encrypted) |*e| self.deliver(.{ .encrypted_message = e });
        for (others) |*u| self.deliver(.{ .update = u });
    }

    /// Adopts a server-authoritative state (a difference's final or
    /// intermediate state); date only moves forward.
    fn adoptState(self: *Engine, s: api.updates.State) void {
        switch (s) {
            .state => |inner| {
                self.state = .{
                    .pts = inner.pts,
                    .qts = inner.qts,
                    .seq = inner.seq,
                    .unread_count = inner.unread_count,
                };
                self.state.mergeDate(inner.date);
            },
        }
    }

    fn deliver(self: *Engine, ev: Event) void {
        if (self.handler) |h| h.notify(h.ctx, ev);
        self.stats.events_delivered += 1;
    }

    fn dropResponse(self: *Engine, res: anytype) void {
        res.deinit();
        self.allocator.destroy(res);
    }

    fn fetchFailed(self: *Engine, e: anyerror) void {
        self.last_fetch_error = e;
        self.needs_difference = true;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

const Recorder = struct {
    tags: std.ArrayList([]const u8) = .empty,

    fn notify(ctx: *anyopaque, ev: Event) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        const t: []const u8 = switch (ev) {
            .update => |u| @tagName(u.*),
            .short_message => "short_message",
            .short_chat_message => "short_chat_message",
            .short_sent_message => "short_sent_message",
            .new_message => "new_message",
            .encrypted_message => "encrypted_message",
        };
        self.tags.append(testing.allocator, t) catch @panic("oom");
    }

    fn handler(self: *Recorder) Handler {
        return .{ .ctx = self, .notify = &notify };
    }
};

test "handle is a no-op sink without a handler and still tracks state" {
    var e = Engine.init(testing.allocator);
    const u = api.Updates{ .updates_ = .{
        .updates = &.{},
        .users = &.{},
        .chats = &.{},
        .date = 100,
        .seq = 1,
    } };
    const out = e.handle(&u);
    try testing.expectEqual(@as(usize, 0), out.delivered);
    try testing.expectEqual(@as(i32, 1), e.state.seq);
    try testing.expectEqual(@as(i32, 100), e.state.date);
    try testing.expect(!e.needs_difference);
}

test "updatesTooLong records a too_long gap" {
    var e = Engine.init(testing.allocator);
    const u = api.Updates{ .updatesTooLong = .{} };
    const out = e.handle(&u);
    try testing.expectEqual(GapKind.too_long, out.gap.?);
    try testing.expect(e.needs_difference);
    // Without a fetcher, reconcile is a no-op and the flag persists.
    try e.reconcile(undefined);
    try testing.expect(e.needs_difference);
}
