//! Session storage: the interface between serialized session bytes and
//! wherever a caller wants to keep them.
//!
//! `Store` is a small type-erased interface (in the style of
//! `handshake.Transport`): `load` returns the stored bytes (null when
//! nothing is stored), `save` atomically replaces them, `remove` drops
//! them. Implementations ship with tdzig:
//!
//!   * `MemoryStore` — in-process bytes; the session lives and dies with
//!     the program (reconnects within one run skip re-authorization).
//!   * `FileStore` (see `file.zig`) — one file per session, written
//!     atomically with owner-only permissions.
//!
//! The store layer deliberately knows nothing about the content: it
//! moves opaque bytes. Parsing, validation and redaction live in
//! `state.zig`, so secret material never appears in error paths or
//! logs here (this module has no logging at all).

const std = @import("std");
const state = @import("state.zig");

pub const Error = error{
    OutOfMemory,
    /// The backing storage failed (I/O error, unwritable path, ...).
    /// Implementation-specific causes are mapped here.
    StorageFailed,
};

pub const LoadStateError = Error || state.DeserializeError;

pub const Store = struct {
    ctx: *anyopaque,
    loadFn: *const fn (ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator) Error!?[]u8,
    saveFn: *const fn (ctx: *anyopaque, io: std.Io, bytes: []const u8) Error!void,
    removeFn: *const fn (ctx: *anyopaque, io: std.Io) Error!void,

    /// Reads the stored bytes; null when nothing is stored. The returned
    /// slice is owned by the caller (allocated from `allocator`).
    pub fn load(self: Store, io: std.Io, allocator: std.mem.Allocator) Error!?[]u8 {
        return self.loadFn(self.ctx, io, allocator);
    }

    /// Stores `bytes`, replacing any previous content atomically where
    /// the implementation can.
    pub fn save(self: Store, io: std.Io, bytes: []const u8) Error!void {
        return self.saveFn(self.ctx, io, bytes);
    }

    /// Drops the stored bytes; removing nothing is not an error.
    pub fn remove(self: Store, io: std.Io) Error!void {
        return self.removeFn(self.ctx, io);
    }

    /// Serializes `st` and stores it.
    pub fn saveState(self: Store, io: std.Io, st: state.State) Error!void {
        var buf: [state.serialized_size]u8 = undefined;
        st.serialize(&buf);
        return self.save(io, &buf);
    }

    /// Loads and parses a stored session; null when nothing is stored.
    /// Byte-level failures surface as `Error.StorageFailed`, content
    /// failures (magic/version/checksum/...) as `state.DeserializeError`.
    pub fn loadState(self: Store, io: std.Io, allocator: std.mem.Allocator) LoadStateError!?state.State {
        const bytes = (try self.load(io, allocator)) orelse return null;
        defer allocator.free(bytes);
        return try state.State.deserialize(bytes);
    }
};

/// In-memory storage: one owned byte blob, replaced on every save.
pub const MemoryStore = struct {
    allocator: std.mem.Allocator,
    bytes: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator) MemoryStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MemoryStore) void {
        if (self.bytes) |b| self.allocator.free(b);
        self.bytes = null;
    }

    pub fn store(self: *MemoryStore) Store {
        return .{
            .ctx = self,
            .loadFn = loadImpl,
            .saveFn = saveImpl,
            .removeFn = removeImpl,
        };
    }

    fn loadImpl(ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator) Error!?[]u8 {
        _ = io;
        const self: *MemoryStore = @ptrCast(@alignCast(ctx));
        const b = self.bytes orelse return null;
        return allocator.dupe(u8, b) catch return error.OutOfMemory;
    }

    fn saveImpl(ctx: *anyopaque, io: std.Io, bytes: []const u8) Error!void {
        _ = io;
        const self: *MemoryStore = @ptrCast(@alignCast(ctx));
        const copy = self.allocator.dupe(u8, bytes) catch return error.OutOfMemory;
        if (self.bytes) |old| self.allocator.free(old);
        self.bytes = copy;
    }

    fn removeImpl(ctx: *anyopaque, io: std.Io) Error!void {
        _ = io;
        const self: *MemoryStore = @ptrCast(@alignCast(ctx));
        if (self.bytes) |old| self.allocator.free(old);
        self.bytes = null;
    }
};

// ---------------------------------------------------------------- tests

const crypto = @import("../crypto/mod.zig");
const mtproto = @import("../mtproto/mod.zig");

fn sampleState() state.State {
    var key: mtproto.AuthKey = undefined;
    for (&key.key, 0..) |*b, i| b.* = @truncate(i *% 97 +% 5);
    key.id = crypto.authKeyId(&key.key);
    for (&key.aux_hash, 0..) |*b, i| b.* = @truncate(i +% 1);
    for (&key.server_salt, 0..) |*b, i| b.* = @truncate(i *% 3);
    return .{
        .environment = .production,
        .dc = 2,
        .auth_key = key,
        .session_id = 7,
        .last_msg_id = @as(i64, 1) << 32,
        .content_count = 1,
        .remote_content_count = 1,
    };
}

test "memory store: empty load, save/load roundtrip, remove" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var mem = MemoryStore.init(std.testing.allocator);
    defer mem.deinit();
    const s = mem.store();

    try std.testing.expectEqual(@as(?[]u8, null), try s.load(io, std.testing.allocator));

    const st = sampleState();
    try s.saveState(io, st);

    // loadState parses back the same state.
    const back = (try s.loadState(io, std.testing.allocator)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(st.dc, back.dc);
    try std.testing.expectEqual(st.session_id, back.session_id);
    try std.testing.expectEqualSlices(u8, &st.auth_key.key, &back.auth_key.key);

    // Saved bytes are copied: mutating a loaded copy leaves the store
    // intact.
    if (try s.load(io, std.testing.allocator)) |bytes| {
        defer std.testing.allocator.free(bytes);
        @memset(bytes, 0);
    }
    const again = (try s.loadState(io, std.testing.allocator)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &st.auth_key.key, &again.auth_key.key);

    // Save replaces wholesale; remove drops everything (idempotently).
    var st2 = st;
    st2.session_id = 9;
    try s.saveState(io, st2);
    const third = (try s.loadState(io, std.testing.allocator)).?;
    try std.testing.expectEqual(@as(i64, 9), third.session_id);

    try s.remove(io);
    try s.remove(io); // removing nothing is fine
    try std.testing.expectEqual(@as(?[]u8, null), try s.load(io, std.testing.allocator));
    try std.testing.expect((try s.loadState(io, std.testing.allocator)) == null);
}
