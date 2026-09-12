//! Structured client storage: what a logged-in client remembers between
//! runs, kept in one place behind one interface.
//!
//! Three kinds of data, one small surface:
//!
//!   * the **session record** — which DC the authorization key belongs
//!     to, the API id, the test/production flag, the secret auth key
//!     itself, the signed-in user id and bot flag, and a touched-on
//!     timestamp;
//!   * the **peer cache** — users/chats/channels keyed by id, with the
//!     access hash needed to reference them and optional username /
//!     phone-number lookups (usernames expire after
//!     `username_ttl_seconds`; a stale entry answers "miss" rather than
//!     serving a handle that may have moved);
//!   * **update state** — per-entity `pts`/`qts`/`date`/`seq` counters
//!     a `getDifference` loop continues from.
//!
//! `MemoryStorage` (`td.storage.memory`) holds these as plain struct
//! members, for in-process use and tests. `Storage` is the type-erased
//! interface backends satisfy (in the style of `session.Store`);
//! `conformance` runs the identical behavioral suite against any
//! implementation.
//!
//! Secret hygiene: the auth key is data, never diagnostics. This module
//! has no logging, `SessionRecord` renders only through its redacted
//! `format`, and error paths carry no field values.

const std = @import("std");

pub const memory = @import("memory.zig");

pub const MemoryStorage = memory.MemoryStorage;

test {
    _ = @import("memory.zig");
}

/// Storage-layer failures, kept intentionally coarse: implementation
/// specifics all surface as `StorageFailed`. No message text embeds
/// stored values.
pub const Error = error{
    OutOfMemory,
    /// The backing storage failed.
    StorageFailed,
};

/// The DC a fresh session record points at before the first
/// authorization (the same default the ecosystem's session files use).
pub const default_dc_id: i32 = 2;

/// How long a cached username→peer binding is trusted. Telegram
/// usernames can be reassigned, so older lookups answer "miss" and the
/// caller resolves them from the server again.
pub const username_ttl_seconds: i64 = 8 * 60 * 60;

/// Session identity and authorization material: the single row of the
/// `sessions` table.
pub const SessionRecord = struct {
    /// Data center the auth key belongs to (and the client works on).
    dc_id: i32 = default_dc_id,
    /// API id the client authenticates as; null until first use.
    api_id: ?i32 = null,
    /// Test vs production network — auth keys are network-specific.
    test_mode: bool = false,
    /// The 256-byte authorization key. **Secret**: never logged, never
    /// formatted. Null until the key handshake has been persisted.
    auth_key: ?[]const u8 = null,
    /// Unix time the record was last written (0 = never).
    date: i64 = 0,
    /// Signed-in user; null while nobody is signed in.
    user_id: ?i64 = null,
    /// Bot flag of the signed-in user.
    is_bot: ?bool = null,

    /// Frees owned field memory (the auth key copy). The record's
    /// slices are owned by whoever produced it — `Storage` getters
    /// return records the caller must `deinit`.
    pub fn deinit(self: *SessionRecord, allocator: std.mem.Allocator) void {
        if (self.auth_key) |k| allocator.free(k);
        self.auth_key = null;
    }

    /// Field-wise equality including the auth-key bytes.
    pub fn eql(self: SessionRecord, other: SessionRecord) bool {
        if (self.dc_id != other.dc_id or self.test_mode != other.test_mode) return false;
        if (self.date != other.date) return false;
        if (!optEq(i32, self.api_id, other.api_id)) return false;
        if (!optEq(i64, self.user_id, other.user_id)) return false;
        if (!optEq(bool, self.is_bot, other.is_bot)) return false;
        return optBytesEq(self.auth_key, other.auth_key);
    }

    /// Redacted rendering (the `{f}` path): the auth key never appears.
    pub fn describe(self: SessionRecord, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print(
            "storage.SessionRecord{{dc_id={d}, api_id={s}, test_mode={}, auth_key={s}, date={d}, user_id={s}, is_bot={s}}}",
            .{
                self.dc_id,
                optScalar(i32, self.api_id),
                self.test_mode,
                if (self.auth_key != null) "<redacted>" else "null",
                self.date,
                optScalar(i64, self.user_id),
                optScalar(bool, self.is_bot),
            },
        );
    }

    /// Makes the redacted `describe` reachable through `{f}`. Default
    /// `{}`/`{any}` would dump the raw fields — never use them here.
    pub fn format(self: SessionRecord, w: *std.Io.Writer) std.Io.Writer.Error!void {
        return self.describe(w);
    }
};

/// Peer kind, stored as the ecosystem's small integer codes.
pub const PeerType = enum(i64) {
    user = 0,
    chat = 1,
    channel = 2,
};

/// One cached peer: the `peers` table row.
pub const Peer = struct {
    id: i64,
    /// Required to build most references to the peer; optional because
    /// some updates legitimately carry none.
    access_hash: ?i64 = null,
    type: PeerType,
    /// Lowercased handle, when the peer has one.
    username: ?[]const u8 = null,
    /// Digits with a leading `+`, when the peer is a contact.
    phone_number: ?[]const u8 = null,
    /// Unix time this entry was written (drives username expiry).
    last_update_on: i64 = 0,

    pub fn deinit(self: *Peer, allocator: std.mem.Allocator) void {
        if (self.username) |u| allocator.free(u);
        if (self.phone_number) |p| allocator.free(p);
        self.username = null;
        self.phone_number = null;
    }

    pub fn eql(self: Peer, other: Peer) bool {
        if (self.id != other.id or self.type != other.type) return false;
        if (self.last_update_on != other.last_update_on) return false;
        if (!optEq(i64, self.access_hash, other.access_hash)) return false;
        if (!optBytesEq(self.username, other.username)) return false;
        return optBytesEq(self.phone_number, other.phone_number);
    }
};

/// Per-entity update counters: the `update_state` table row. A
/// `getDifference` loop continues from these; null means "unknown /
/// start over" for that counter.
pub const UpdateStateRow = struct {
    /// Entity the counters belong to (0 = the account-global row).
    id: i32 = 0,
    pts: ?i64 = null,
    qts: ?i64 = null,
    date: ?i64 = null,
    seq: ?i64 = null,

    pub fn eql(self: UpdateStateRow, other: UpdateStateRow) bool {
        return self.id == other.id and
            optEq(i64, self.pts, other.pts) and
            optEq(i64, self.qts, other.qts) and
            optEq(i64, self.date, other.date) and
            optEq(i64, self.seq, other.seq);
    }
};

/// Type-erased storage interface, in the style of `session.Store`.
/// Implementations own their backing (file, connection, heap); this
/// interface only moves values.
///
/// Ownership: getter results are allocated with the caller's allocator
/// and released with the record's `deinit`; setters copy their inputs,
/// so callers keep ownership of what they pass.
pub const Storage = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getSession: *const fn (ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator) Error!SessionRecord,
        setSession: *const fn (ctx: *anyopaque, io: std.Io, record: SessionRecord) Error!void,
        updatePeers: *const fn (ctx: *anyopaque, io: std.Io, peers: []const Peer, now: i64) Error!void,
        getPeerById: *const fn (ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator, id: i64) Error!?Peer,
        getPeerByUsername: *const fn (ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator, username: []const u8, now: i64) Error!?Peer,
        getPeerByPhoneNumber: *const fn (ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator, phone_number: []const u8) Error!?Peer,
        getUpdateState: *const fn (ctx: *anyopaque, io: std.Io, id: i32) Error!?UpdateStateRow,
        setUpdateState: *const fn (ctx: *anyopaque, io: std.Io, row: UpdateStateRow) Error!void,
        deleteUpdateState: *const fn (ctx: *anyopaque, io: std.Io, id: i32) Error!void,
    };

    /// The session record. A fresh store answers with the default
    /// record (dc 2, no key, no user) — never a missing table.
    pub fn getSession(self: Storage, io: std.Io, allocator: std.mem.Allocator) Error!SessionRecord {
        return self.vtable.getSession(self.ctx, io, allocator);
    }

    /// Replaces the record wholesale (the table holds exactly one row).
    /// `record.date` is stored verbatim — stamp it with the caller's
    /// clock if a touched-on time is wanted.
    pub fn setSession(self: Storage, io: std.Io, record: SessionRecord) Error!void {
        return self.vtable.setSession(self.ctx, io, record);
    }

    /// Inserts or replaces the given peers, stamping each row's
    /// `last_update_on` with `now` (the clock is the caller's, so tests
    /// stay deterministic).
    pub fn updatePeers(self: Storage, io: std.Io, peers: []const Peer, now: i64) Error!void {
        return self.vtable.updatePeers(self.ctx, io, peers, now);
    }

    pub fn getPeerById(self: Storage, io: std.Io, allocator: std.mem.Allocator, id: i64) Error!?Peer {
        return self.vtable.getPeerById(self.ctx, io, allocator, id);
    }

    /// Resolves a peer by handle. Misses (null) when the entry is older
    /// than `username_ttl_seconds` — the handle may have been reassigned.
    pub fn getPeerByUsername(self: Storage, io: std.Io, allocator: std.mem.Allocator, username: []const u8, now: i64) Error!?Peer {
        return self.vtable.getPeerByUsername(self.ctx, io, allocator, username, now);
    }

    pub fn getPeerByPhoneNumber(self: Storage, io: std.Io, allocator: std.mem.Allocator, phone_number: []const u8) Error!?Peer {
        return self.vtable.getPeerByPhoneNumber(self.ctx, io, allocator, phone_number);
    }

    pub fn getUpdateState(self: Storage, io: std.Io, id: i32) Error!?UpdateStateRow {
        return self.vtable.getUpdateState(self.ctx, io, id);
    }

    /// Inserts or replaces the row for `row.id`. All-null counters are
    /// stored as nulls (present row, unknown values).
    pub fn setUpdateState(self: Storage, io: std.Io, row: UpdateStateRow) Error!void {
        return self.vtable.setUpdateState(self.ctx, io, row);
    }

    /// Drops the row for `id`; dropping nothing is not an error.
    pub fn deleteUpdateState(self: Storage, io: std.Io, id: i32) Error!void {
        return self.vtable.deleteUpdateState(self.ctx, io, id);
    }
};

// -------------------------------------------------------------- helpers

fn optEq(comptime T: type, a: ?T, b: ?T) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return a.? == b.?;
}

fn optBytesEq(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

fn optScalar(comptime T: type, v: ?T) []const u8 {
    return if (v) |x| switch (T) {
        bool => if (x) "true" else "false",
        else => "<set>",
    } else "null";
}

// ---------------------------------------------------------------- tests
//
// One behavioral suite, run against every backend through the
// type-erased interface (each backend's own file adds the
// backend-specific tests: persistence, permissions, migration, ...).

pub fn conformance(s: Storage, io: std.Io) !void {
    const alloc = std.testing.allocator;

    // -- fresh store: the default record -----------------------------
    var fresh = try s.getSession(io, alloc);
    defer fresh.deinit(alloc);
    try std.testing.expectEqual(default_dc_id, fresh.dc_id);
    try std.testing.expect(fresh.api_id == null);
    try std.testing.expectEqual(false, fresh.test_mode);
    try std.testing.expect(fresh.auth_key == null);
    try std.testing.expectEqual(@as(i64, 0), fresh.date);
    try std.testing.expect(fresh.user_id == null);
    try std.testing.expect(fresh.is_bot == null);

    // -- full session roundtrip ---------------------------------------
    var key: [256]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @truncate(i *% 89 +% 11);
    try s.setSession(io, .{
        .dc_id = 4,
        .api_id = 20350,
        .test_mode = true,
        .auth_key = &key,
        .date = 1_760_000_000,
        .user_id = 1_234_567_890_123,
        .is_bot = false,
    });
    var back = try s.getSession(io, alloc);
    defer back.deinit(alloc);
    try std.testing.expectEqual(@as(i32, 4), back.dc_id);
    try std.testing.expectEqual(@as(?i32, 20350), back.api_id);
    try std.testing.expectEqual(true, back.test_mode);
    try std.testing.expectEqual(@as(i64, 1_760_000_000), back.date);
    try std.testing.expectEqual(@as(?i64, 1_234_567_890_123), back.user_id);
    try std.testing.expectEqual(@as(?bool, false), back.is_bot);
    try std.testing.expectEqualSlices(u8, &key, back.auth_key.?);

    // Replace with a sparse record: nulls must overwrite, not linger.
    try s.setSession(io, .{ .dc_id = 2, .date = 42, .is_bot = true });
    var sparse = try s.getSession(io, alloc);
    defer sparse.deinit(alloc);
    try std.testing.expect(sparse.api_id == null);
    try std.testing.expect(sparse.auth_key == null);
    try std.testing.expect(sparse.user_id == null);
    try std.testing.expectEqual(@as(?bool, true), sparse.is_bot);
    try std.testing.expectEqual(@as(i64, 42), sparse.date);

    // -- peers ---------------------------------------------------------
    const now: i64 = 1_000_000;
    const hostile = "u'; DROP TABLE peers; --";
    try s.updatePeers(io, &.{
        .{ .id = 100, .type = .user, .access_hash = 0xdead_beef, .username = "liber", .phone_number = "+15550100" },
        .{ .id = -100_200_300, .type = .channel, .access_hash = 7 },
        .{ .id = 300, .type = .user, .username = hostile },
    }, now);

    var by_id = (try s.getPeerById(io, alloc, 100)) orelse return error.TestUnexpectedResult;
    defer by_id.deinit(alloc);
    try std.testing.expect(by_id.eql(.{
        .id = 100,
        .type = .user,
        .access_hash = 0xdead_beef,
        .username = "liber",
        .phone_number = "+15550100",
        .last_update_on = now,
    }));

    var by_name = (try s.getPeerByUsername(io, alloc, "liber", now)) orelse return error.TestUnexpectedResult;
    defer by_name.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 100), by_name.id);
    var by_phone = (try s.getPeerByPhoneNumber(io, alloc, "+15550100")) orelse return error.TestUnexpectedResult;
    defer by_phone.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 100), by_phone.id);

    // Hostile-looking strings are plain data: they roundtrip whole
    // and never damage the backing store.
    var evil = (try s.getPeerByUsername(io, alloc, hostile, now)) orelse return error.TestUnexpectedResult;
    defer evil.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 300), evil.id);
    try std.testing.expectEqualStrings(hostile, evil.username.?);
    var probe = (try s.getPeerById(io, alloc, 100)) orelse return error.TestUnexpectedResult;
    defer probe.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 100), probe.id);

    // Misses answer null, not errors.
    try std.testing.expectEqual(@as(?Peer, null), try s.getPeerById(io, alloc, 999));
    try std.testing.expectEqual(@as(?Peer, null), try s.getPeerByUsername(io, alloc, "nobody", now));
    try std.testing.expectEqual(@as(?Peer, null), try s.getPeerByPhoneNumber(io, alloc, "+1999"));

    // Replacing a peer by id keeps exactly one row for it.
    try s.updatePeers(io, &.{
        .{ .id = 100, .type = .user, .username = "renamed" },
    }, now + 5);
    try std.testing.expectEqual(@as(?Peer, null), try s.getPeerByUsername(io, alloc, "liber", now + 5));
    var renamed = (try s.getPeerByUsername(io, alloc, "renamed", now + 5)) orelse return error.TestUnexpectedResult;
    defer renamed.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 100), renamed.id);
    try std.testing.expect(renamed.access_hash == null);

    // A username older than the TTL answers miss; the id lookup
    // (never expires) still finds the peer. The newest stamp among the
    // peers above is `now + 5` (the rename), so expire past that.
    const stale_now = now + 5 + username_ttl_seconds + 1;
    try std.testing.expectEqual(@as(?Peer, null), try s.getPeerByUsername(io, alloc, "renamed", stale_now));
    try std.testing.expectEqual(@as(?Peer, null), try s.getPeerByUsername(io, alloc, hostile, stale_now));
    var still = (try s.getPeerById(io, alloc, 300)) orelse return error.TestUnexpectedResult;
    defer still.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 300), still.id);

    // -- update state ---------------------------------------------------
    try s.setUpdateState(io, .{ .id = 0, .pts = 17, .qts = 4, .date = 1_700_000_123, .seq = 9 });
    var st0 = (try s.getUpdateState(io, 0)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(st0.eql(.{ .id = 0, .pts = 17, .qts = 4, .date = 1_700_000_123, .seq = 9 }));

    try s.setUpdateState(io, .{ .id = 0, .pts = 18, .qts = 5 });
    const st0b = (try s.getUpdateState(io, 0)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(st0b.eql(.{ .id = 0, .pts = 18, .qts = 5, .date = null, .seq = null }));

    // All-null counters: the row exists with unknown values.
    try s.setUpdateState(io, .{ .id = 7 });
    const st7 = (try s.getUpdateState(io, 7)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(st7.eql(.{ .id = 7 }));

    try s.deleteUpdateState(io, 0);
    try std.testing.expectEqual(@as(?UpdateStateRow, null), try s.getUpdateState(io, 0));
    try s.deleteUpdateState(io, 0); // deleting nothing is fine
    try std.testing.expect((try s.getUpdateState(io, 7)) != null);
}

test "SessionRecord redacted rendering never contains the auth key" {
    var key: [256]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @truncate(i *% 37 +% 1);

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const rec = SessionRecord{ .dc_id = 5, .auth_key = &key, .user_id = 42, .is_bot = true };
    try rec.format(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "<redacted>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, key[0..16]) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "dc_id=5") != null);
}
