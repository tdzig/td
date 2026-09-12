//! Update state and ordering verdicts — the pure heart of the updates
//! system, no IO and no generated types.
//!
//! Telegram sequences every update stream with four counters, carried by
//! `updates.State`:
//!
//!   * `pts` — the common "operation" sequence for message-history
//!     updates; each pts-bearing update advances it by its `pts_count`,
//!     so `update.pts == local.pts + pts_count` must hold for the update
//!     to be exactly the next one.
//!   * `qts` — the secret-chat sequence; strictly +1 per update.
//!   * `date` — wall-clock marker of the last processed event; only ever
//!     moves forward (feeds `updates.getDifference`).
//!   * `seq` — the update-sequence number of `updates`/`updatesCombined`
//!     containers; `seq == local.seq + 1` means in order.
//!
//! A violation of any of these is a *gap*: the client missed something,
//! and the only correct recovery is `updates.getDifference` (or a full
//! `updates.getState` resync when the local state was never initialized).
//! Every predicate here returns a verdict instead of mutating, so the
//! engine can decide, log and test each outcome.

const std = @import("std");

/// The four sequencing counters plus the unread badge carried by
/// `updates.state`. Defaults describe a state that was never
/// initialized (`isPristine`): the engine then seeds itself from
/// `updates.getState` instead of trying to heal a gap.
pub const State = struct {
    pts: i32 = 0,
    qts: i32 = 0,
    date: i32 = 0,
    seq: i32 = 0,
    unread_count: i32 = 0,

    /// True while no real state has been adopted or applied yet. A
    /// pristine state cannot meaningfully "gap": there is nothing to
    /// reconcile against, only to initialize.
    pub fn isPristine(self: State) bool {
        return self.pts == 0 and self.qts == 0 and self.date == 0 and self.seq == 0;
    }

    /// Moves `date` forward, never backward.
    pub fn mergeDate(self: *State, date: i32) void {
        if (date > self.date) self.date = date;
    }
};

/// What the engine should do with a pts- or qts-sequenced update.
pub const PtsVerdict = enum {
    /// Exactly the next update (or a tolerated slight overlap): apply
    /// it and advance `pts`/`qts`.
    apply,
    /// Already reflected in the local state (duplicate or stale):
    /// drop it silently.
    skip,
    /// Beyond the next position: a gap — recovery is getDifference.
    gap,
};

/// Verdict for a pts-bearing update. `pts_count <= 0` is clamped to 1
/// (the convention for updates that move `pts` without a count field).
pub fn ptsVerdict(local_pts: i32, pts: i32, pts_count: i32) PtsVerdict {
    const count: i32 = if (pts_count > 0) pts_count else 1;
    if (pts <= local_pts) return .skip;
    if (pts - count <= local_pts) return .apply;
    return .gap;
}

/// Verdict for a qts-bearing update (strictly one event per qts).
pub fn qtsVerdict(local_qts: i32, qts: i32) PtsVerdict {
    return ptsVerdict(local_qts, qts, 1);
}

/// What the engine should do with a whole `updates`/`updatesCombined`
/// container, judged by its `seq` fields alone.
pub const SeqVerdict = enum {
    /// The container is in order: apply it, then set `seq`.
    apply,
    /// Older than the local state: nothing in it can be new.
    duplicate,
    /// It skips ahead: a gap — recovery is getDifference.
    gap,
};

/// Verdict for a plain `updates` container (one `seq`).
///
/// `seq == 0` means the server did not sequence this container; it is
/// always accepted and delivered as-is.
pub fn seqVerdict(local_seq: i32, seq: i32) SeqVerdict {
    if (seq == 0) return .apply;
    if (seq == local_seq + 1) return .apply;
    if (seq <= local_seq) return .duplicate;
    return .gap;
}

/// Verdict for an `updatesCombined` container, which covers the
/// sequence range `seq_start..seq`.
///
/// The normal case is `seq_start == local.seq + 1`. A batch that starts
/// in the past but reaches past the local state is an overlapping
/// retransmission: it is accepted, and per-update pts/qts dedup filters
/// out the parts already applied. Anything wholly in the past is a
/// duplicate; anything wholly ahead is a gap.
pub fn seqStartVerdict(local_seq: i32, seq_start: i32, seq: i32) SeqVerdict {
    if (seq_start == 0) return .apply;
    if (seq_start == local_seq + 1 and seq >= seq_start) return .apply;
    if (seq_start <= local_seq and seq > local_seq) return .apply;
    // The batch starts ahead of the local state: updates in between are
    // missing, whatever the (possibly inconsistent) end claims.
    if (seq_start > local_seq) return .gap;
    if (seq <= local_seq) return .duplicate;
    return .gap;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "isPristine only for the all-zero state" {
    const zero: State = .{};
    const pts: State = .{ .pts = 1 };
    const qts: State = .{ .qts = 1 };
    const date: State = .{ .date = 1 };
    const seq: State = .{ .seq = 1 };
    try testing.expect(zero.isPristine());
    try testing.expect(!pts.isPristine());
    try testing.expect(!qts.isPristine());
    try testing.expect(!date.isPristine());
    try testing.expect(!seq.isPristine());
}

test "ptsVerdict: exact next applies, overlap applies, past skips, ahead gaps" {
    // Exactly the next position.
    try testing.expectEqual(PtsVerdict.apply, ptsVerdict(10, 12, 2));
    // Single-step update (count 1).
    try testing.expectEqual(PtsVerdict.apply, ptsVerdict(10, 11, 1));
    // Clamped count: a pts without a usable count moves one position.
    try testing.expectEqual(PtsVerdict.apply, ptsVerdict(10, 11, 0));
    // Slight overlap: partially known but still new — apply.
    try testing.expectEqual(PtsVerdict.apply, ptsVerdict(10, 12, 3));
    // Already applied or older — skip.
    try testing.expectEqual(PtsVerdict.skip, ptsVerdict(10, 10, 1));
    try testing.expectEqual(PtsVerdict.skip, ptsVerdict(10, 7, 3));
    // Skips ahead — gap.
    try testing.expectEqual(PtsVerdict.gap, ptsVerdict(10, 13, 1));
    try testing.expectEqual(PtsVerdict.gap, ptsVerdict(10, 20, 2));
}

test "qtsVerdict is strict +1" {
    try testing.expectEqual(PtsVerdict.apply, qtsVerdict(5, 6));
    try testing.expectEqual(PtsVerdict.skip, qtsVerdict(5, 5));
    try testing.expectEqual(PtsVerdict.skip, qtsVerdict(5, 4));
    try testing.expectEqual(PtsVerdict.gap, qtsVerdict(5, 7));
}

test "seqVerdict for plain updates containers" {
    try testing.expectEqual(SeqVerdict.apply, seqVerdict(4, 5));
    try testing.expectEqual(SeqVerdict.apply, seqVerdict(4, 0));
    try testing.expectEqual(SeqVerdict.duplicate, seqVerdict(4, 4));
    try testing.expectEqual(SeqVerdict.duplicate, seqVerdict(4, 2));
    try testing.expectEqual(SeqVerdict.gap, seqVerdict(4, 6));
}

test "seqStartVerdict for updatesCombined containers" {
    // Normal contiguous batch.
    try testing.expectEqual(SeqVerdict.apply, seqStartVerdict(4, 5, 6));
    try testing.expectEqual(SeqVerdict.apply, seqStartVerdict(4, 5, 5));
    // Unsequenced batch.
    try testing.expectEqual(SeqVerdict.apply, seqStartVerdict(4, 0, 0));
    // Overlapping retransmission: starts in the past, reaches ahead.
    try testing.expectEqual(SeqVerdict.apply, seqStartVerdict(6, 4, 8));
    // Wholly in the past.
    try testing.expectEqual(SeqVerdict.duplicate, seqStartVerdict(6, 4, 6));
    try testing.expectEqual(SeqVerdict.duplicate, seqStartVerdict(6, 2, 5));
    // Wholly ahead.
    try testing.expectEqual(SeqVerdict.gap, seqStartVerdict(4, 7, 9));
    try testing.expectEqual(SeqVerdict.gap, seqStartVerdict(4, 5, 3));
}

test "mergeDate moves forward only" {
    var st: State = .{};
    st.mergeDate(100);
    try testing.expectEqual(@as(i32, 100), st.date);
    // Equal and older dates never regress the marker.
    st.mergeDate(100);
    try testing.expectEqual(@as(i32, 100), st.date);
    st.mergeDate(50);
    try testing.expectEqual(@as(i32, 100), st.date);
    st.mergeDate(101);
    try testing.expectEqual(@as(i32, 101), st.date);
    // Only the all-zero state is pristine; a real date is state.
    try testing.expect(!st.isPristine());
}

test "verdict edge cases: clamped counts and inconsistent container ranges" {
    // Negative pts_count is clamped to 1, same as zero.
    try testing.expectEqual(PtsVerdict.apply, ptsVerdict(10, 11, -5));
    try testing.expectEqual(PtsVerdict.skip, ptsVerdict(10, 10, -1));
    try testing.expectEqual(PtsVerdict.gap, ptsVerdict(10, 12, -1));

    // updatesCombined claiming a range that ends before it starts: the
    // start decides — ahead of the local state is a gap.
    try testing.expectEqual(SeqVerdict.gap, seqStartVerdict(4, 7, 5));
    // ...and wholly below the local state is a duplicate.
    try testing.expectEqual(SeqVerdict.duplicate, seqStartVerdict(6, 2, 1));
}
