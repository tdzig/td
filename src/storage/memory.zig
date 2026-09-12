//! In-memory structured storage: the storage-module data as plain
//! fields — nothing touches a file, nothing survives the process.
//!
//! The fields, exactly:
//!
//!   * `session` — `SessionRecord`: `dc_id`, `api_id`, `test_mode`,
//!     `auth_key` (secret), `date`, `user_id`, `is_bot`. Starts at the
//!     default record (dc 2, no key, no user, date 0).
//!   * `peers` — id → `Peer` (access hash, type, username, phone
//!     number, last-update stamp), with the same username TTL as any
//!     file backend would have.
//!   * `update_states` — entity id → `UpdateStateRow` (`pts`, `qts`,
//!     `date`, `seq`).
//!
//! Use it for in-process reconnects, examples and as the test double
//! behind the `Storage` interface. It is a full `Storage` peer,
//! verified by the same conformance suite. Username lookups scan
//! linearly: a peer cache is small.
//!
//! Secret hygiene: the auth key sits in `session.auth_key` and is never
//! rendered (`SessionRecord` formats only through its redacted form).
//! This module has no logging.

const std = @import("std");
const mod = @import("mod.zig");

const Error = mod.Error;
const SessionRecord = mod.SessionRecord;
const Peer = mod.Peer;
const UpdateStateRow = mod.UpdateStateRow;
const Storage = mod.Storage;

pub const MemoryStorage = struct {
    allocator: std.mem.Allocator,
    /// The session record (see module docs for the field list). Owned:
    /// `setSession` copies into it, `getSession` copies out of it.
    session: SessionRecord = .{},
    /// Peer cache, keyed by peer id. Values own their strings.
    peers: std.AutoHashMapUnmanaged(i64, Peer) = .empty,
    /// Per-entity update counters, keyed by entity id.
    update_states: std.AutoHashMapUnmanaged(i32, UpdateStateRow) = .empty,

    pub fn init(allocator: std.mem.Allocator) MemoryStorage {
        return .{ .allocator = allocator };
    }

    /// Frees the session record, every peer and both maps.
    pub fn deinit(self: *MemoryStorage) void {
        self.session.deinit(self.allocator);
        var it = self.peers.valueIterator();
        while (it.next()) |p| p.deinit(self.allocator);
        self.peers.deinit(self.allocator);
        self.update_states.deinit(self.allocator);
    }

    pub fn storage(self: *MemoryStorage) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable = Storage.VTable{
        .getSession = getSessionImpl,
        .setSession = setSessionImpl,
        .updatePeers = updatePeersImpl,
        .getPeerById = getPeerByIdImpl,
        .getPeerByUsername = getPeerByUsernameImpl,
        .getPeerByPhoneNumber = getPeerByPhoneImpl,
        .getUpdateState = getUpdateStateImpl,
        .setUpdateState = setUpdateStateImpl,
        .deleteUpdateState = deleteUpdateStateImpl,
    };

    fn getSessionImpl(ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator) Error!SessionRecord {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        var rec = SessionRecord{
            .dc_id = self.session.dc_id,
            .api_id = self.session.api_id,
            .test_mode = self.session.test_mode,
            .date = self.session.date,
            .user_id = self.session.user_id,
            .is_bot = self.session.is_bot,
        };
        if (self.session.auth_key) |k| {
            rec.auth_key = allocator.dupe(u8, k) catch return error.OutOfMemory;
        }
        return rec;
    }

    fn setSessionImpl(ctx: *anyopaque, io: std.Io, record: SessionRecord) Error!void {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        var owned = SessionRecord{
            .dc_id = record.dc_id,
            .api_id = record.api_id,
            .test_mode = record.test_mode,
            .date = record.date,
            .user_id = record.user_id,
            .is_bot = record.is_bot,
        };
        if (record.auth_key) |k| {
            owned.auth_key = self.allocator.dupe(u8, k) catch return error.OutOfMemory;
        }
        self.session.deinit(self.allocator);
        self.session = owned;
    }

    fn updatePeersImpl(ctx: *anyopaque, io: std.Io, peers: []const Peer, now: i64) Error!void {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        for (peers) |p| {
            var owned = Peer{
                .id = p.id,
                .access_hash = p.access_hash,
                .type = p.type,
                .last_update_on = now,
            };
            if (p.username) |u| {
                owned.username = self.allocator.dupe(u8, u) catch return error.OutOfMemory;
            }
            if (p.phone_number) |ph| {
                owned.phone_number = self.allocator.dupe(u8, ph) catch {
                    if (owned.username) |u| self.allocator.free(u);
                    return error.OutOfMemory;
                };
            }
            const gop = self.peers.getOrPut(self.allocator, p.id) catch {
                owned.deinit(self.allocator);
                return error.OutOfMemory;
            };
            if (gop.found_existing) gop.value_ptr.deinit(self.allocator);
            gop.value_ptr.* = owned;
        }
    }

    /// Copies a stored peer out under the caller's allocator.
    fn copyPeer(self: *MemoryStorage, p: *const Peer, allocator: std.mem.Allocator) Error!?Peer {
        _ = self;
        var out = Peer{
            .id = p.id,
            .access_hash = p.access_hash,
            .type = p.type,
            .last_update_on = p.last_update_on,
        };
        if (p.username) |u| {
            out.username = allocator.dupe(u8, u) catch return error.OutOfMemory;
        }
        if (p.phone_number) |ph| {
            out.phone_number = allocator.dupe(u8, ph) catch {
                if (out.username) |u| allocator.free(u);
                return error.OutOfMemory;
            };
        }
        return out;
    }

    fn getPeerByIdImpl(ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator, id: i64) Error!?Peer {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        const p = self.peers.get(id) orelse return null;
        return self.copyPeer(&p, allocator);
    }

    fn getPeerByUsernameImpl(ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator, username: []const u8, now: i64) Error!?Peer {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        // Linear scan: the memory peer set is small by construction.
        var it = self.peers.valueIterator();
        while (it.next()) |p| {
            const u = p.username orelse continue;
            if (!std.mem.eql(u8, u, username)) continue;
            if (p.last_update_on <= now - mod.username_ttl_seconds) return null; // stale
            return self.copyPeer(p, allocator);
        }
        return null;
    }

    fn getPeerByPhoneImpl(ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator, phone_number: []const u8) Error!?Peer {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        var it = self.peers.valueIterator();
        while (it.next()) |p| {
            const ph = p.phone_number orelse continue;
            if (std.mem.eql(u8, ph, phone_number)) return self.copyPeer(p, allocator);
        }
        return null;
    }

    fn getUpdateStateImpl(ctx: *anyopaque, io: std.Io, id: i32) Error!?UpdateStateRow {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        return self.update_states.get(id);
    }

    fn setUpdateStateImpl(ctx: *anyopaque, io: std.Io, row: UpdateStateRow) Error!void {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        const gop = self.update_states.getOrPut(self.allocator, row.id) catch return error.OutOfMemory;
        gop.value_ptr.* = row;
    }

    fn deleteUpdateStateImpl(ctx: *anyopaque, io: std.Io, id: i32) Error!void {
        _ = io;
        const self: *MemoryStorage = @ptrCast(@alignCast(ctx));
        _ = self.update_states.remove(id);
    }
};

// ---------------------------------------------------------------- tests

test "memory storage: full conformance suite" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var mem = MemoryStorage.init(std.testing.allocator);
    defer mem.deinit();
    try mod.conformance(mem.storage(), io);
}

test "memory storage: fields are the documented struct members" {
    // The point of this backend: the data is directly reachable as
    // fields (and the interface view agrees with them).
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var mem = MemoryStorage.init(std.testing.allocator);
    defer mem.deinit();

    try std.testing.expectEqual(mod.default_dc_id, mem.session.dc_id);
    try std.testing.expect(mem.session.api_id == null);
    try std.testing.expect(mem.session.auth_key == null);
    try std.testing.expect(mem.session.user_id == null);
    try std.testing.expect(mem.peers.count() == 0);
    try std.testing.expect(mem.update_states.count() == 0);

    var key: [256]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @truncate(i *% 3 +% 1);
    try mem.storage().setSession(io, .{ .dc_id = 5, .api_id = 9, .auth_key = &key, .user_id = 3, .is_bot = true });
    try mem.storage().updatePeers(io, &.{.{ .id = 1, .type = .user, .username = "a" }}, 10);
    try mem.storage().setUpdateState(io, .{ .id = 2, .pts = 3 });

    try std.testing.expectEqual(@as(i32, 5), mem.session.dc_id);
    try std.testing.expectEqual(@as(?i32, 9), mem.session.api_id);
    try std.testing.expectEqualSlices(u8, &key, mem.session.auth_key.?);
    try std.testing.expectEqual(@as(?i64, 3), mem.session.user_id);
    try std.testing.expectEqual(@as(?bool, true), mem.session.is_bot);
    try std.testing.expectEqual(@as(i64, 10), mem.peers.get(1).?.last_update_on);
    try std.testing.expectEqual(@as(?i64, 3), mem.update_states.get(2).?.pts);
}
