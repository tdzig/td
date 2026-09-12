//! File-backed session storage.
//!
//! One file per session (the serialized fixed-size form of a
//! `state.State`), written **atomically**: the bytes go to a sibling
//! `<path>.tmp` first and are renamed over the target only after the
//! write succeeded — a crash mid-save never destroys the previous
//! session. Both the temp file and (through the rename) the final file
//! are created with owner-only permissions (0600): the auth key inside
//! is long-lived secret material.
//!
//! `path` is interpreted relative to the process working directory (the
//! same convention as `tdzig-keygen`'s `--out`); the parent directory
//! must already exist. Secret material never appears in error paths or
//! logs — this module has no logging at all.

const std = @import("std");
const store_mod = @import("store.zig");
const state = @import("state.zig");

const Store = store_mod.Store;
const Error = store_mod.Error;

/// Owner-read/write only; the stored auth key is a long-lived secret.
const file_mode: std.posix.mode_t = 0o600;

/// Sessions are exactly `state.serialized_size` bytes; anything larger
/// than this bound is not ours and is refused without being buffered.
const max_file_size: usize = 4096;

const tmp_suffix = ".tmp";

pub const FileStore = struct {
    allocator: std.mem.Allocator,
    /// Owned. Relative to the working directory (or absolute where the
    /// platform `Dir` API accepts it).
    path: []u8,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) Error!FileStore {
        const owned = allocator.dupe(u8, path) catch return error.OutOfMemory;
        return .{ .allocator = allocator, .path = owned };
    }

    pub fn deinit(self: *FileStore) void {
        self.allocator.free(self.path);
    }

    pub fn store(self: *FileStore) Store {
        return .{
            .ctx = self,
            .loadFn = loadImpl,
            .saveFn = saveImpl,
            .removeFn = removeImpl,
        };
    }

    fn loadImpl(ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator) Error!?[]u8 {
        const self: *FileStore = @ptrCast(@alignCast(ctx));
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, self.path, allocator, .limited(max_file_size)) catch |e| switch (e) {
            error.FileNotFound => return null,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.StorageFailed,
        };
        return bytes;
    }

    fn saveImpl(ctx: *anyopaque, io: std.Io, bytes: []const u8) Error!void {
        const self: *FileStore = @ptrCast(@alignCast(ctx));
        const cwd = std.Io.Dir.cwd();

        const tmp = self.allocator.alloc(u8, self.path.len + tmp_suffix.len) catch return error.OutOfMemory;
        defer self.allocator.free(tmp);
        @memcpy(tmp[0..self.path.len], self.path);
        @memcpy(tmp[self.path.len..], tmp_suffix);

        // A stale temp file from a crashed save could predate the
        // owner-only permissions; drop it so the fresh one is created
        // with 0600.
        cwd.deleteFile(io, tmp) catch {};
        cwd.writeFile(io, .{
            .sub_path = tmp,
            .data = bytes,
            .flags = .{ .permissions = std.Io.File.Permissions.fromMode(file_mode) },
        }) catch {
            cwd.deleteFile(io, tmp) catch {};
            return error.StorageFailed;
        };
        cwd.rename(tmp, cwd, self.path, io) catch {
            cwd.deleteFile(io, tmp) catch {};
            return error.StorageFailed;
        };
    }

    fn removeImpl(ctx: *anyopaque, io: std.Io) Error!void {
        const self: *FileStore = @ptrCast(@alignCast(ctx));
        std.Io.Dir.cwd().deleteFile(io, self.path) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return error.StorageFailed,
        };
    }
};

// ---------------------------------------------------------------- tests

const crypto = @import("../crypto/mod.zig");
const mtproto = @import("../mtproto/mod.zig");

fn sampleState() state.State {
    var key: mtproto.AuthKey = undefined;
    for (&key.key, 0..) |*b, i| b.* = @truncate(i *% 71 +% 9);
    key.id = crypto.authKeyId(&key.key);
    for (&key.aux_hash, 0..) |*b, i| b.* = @truncate(i *% 5 +% 2);
    for (&key.server_salt, 0..) |*b, i| b.* = @truncate(i *% 17 +% 4);
    return .{
        .environment = .production,
        .dc = 5,
        .auth_key = key,
        .session_id = 0x1234,
        .last_msg_id = (@as(i64, 1_700_000_000) << 32) | 8,
        .content_count = 2,
        .remote_content_count = 1,
    };
}

/// The FileStore resolves paths against the working directory;
/// `testing.tmpDir` creates its directory under `.zig-cache/tmp/`, so a
/// cwd-relative path to the temp file can be reconstructed from the
/// returned `sub_path`.
fn tempPath(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/{s}", .{ &tmp.sub_path, name });
}

test "file store: save/load roundtrip, atomic replace, remove" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try tempPath(std.testing.allocator, &tmp, "session.bin");
    defer std.testing.allocator.free(path);

    var fs = try FileStore.init(std.testing.allocator, path);
    defer fs.deinit();
    const s = fs.store();

    try std.testing.expectEqual(@as(?[]u8, null), try s.load(io, std.testing.allocator));

    const st = sampleState();
    try s.saveState(io, st);
    const back = (try s.loadState(io, std.testing.allocator)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(st.dc, back.dc);
    try std.testing.expectEqual(st.session_id, back.session_id);
    try std.testing.expectEqualSlices(u8, &st.auth_key.key, &back.auth_key.key);
    try std.testing.expectEqualSlices(u8, &st.auth_key.server_salt, &back.auth_key.server_salt);

    // Exactly one file exists — the atomic save left no temp behind.
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.openFile(io, "session.bin.tmp", .{}),
    );
    const written = try tmp.dir.readFileAlloc(io, "session.bin", std.testing.allocator, .limited(max_file_size));
    defer std.testing.allocator.free(written);
    try std.testing.expectEqual(@as(usize, state.serialized_size), written.len);

    // Saving over an existing session replaces it wholesale.
    var st2 = st;
    st2.session_id = 0x5678;
    try s.saveState(io, st2);
    const back2 = (try s.loadState(io, std.testing.allocator)).?;
    try std.testing.expectEqual(@as(i64, 0x5678), back2.session_id);

    try s.remove(io);
    try std.testing.expectEqual(@as(?[]u8, null), try s.load(io, std.testing.allocator));
    try s.remove(io); // removing nothing is fine
}

test "file store: garbage and truncated files fail content validation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try tempPath(std.testing.allocator, &tmp, "garbage.bin");
    defer std.testing.allocator.free(path);
    var fs = try FileStore.init(std.testing.allocator, path);
    defer fs.deinit();
    const s = fs.store();

    try tmp.dir.writeFile(io, .{ .sub_path = "garbage.bin", .data = "not a session at all" });
    try std.testing.expectError(error.BadMagic, s.loadState(io, std.testing.allocator));

    try tmp.dir.writeFile(io, .{ .sub_path = "garbage.bin", .data = "TDZS" });
    try std.testing.expectError(error.InvalidLength, s.loadState(io, std.testing.allocator));

    // A full-size file with the right magic but a broken body.
    const st = sampleState();
    var buf: [state.serialized_size]u8 = undefined;
    st.serialize(&buf);
    buf[100] ^= 0xff;
    try tmp.dir.writeFile(io, .{ .sub_path = "garbage.bin", .data = &buf });
    try std.testing.expectError(error.ChecksumMismatch, s.loadState(io, std.testing.allocator));
}

test "file store: the session file is owner-only (0600)" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tempPath(std.testing.allocator, &tmp, "perms.bin");
    defer std.testing.allocator.free(path);

    var fs = try FileStore.init(std.testing.allocator, path);
    defer fs.deinit();
    const s = fs.store();
    try s.saveState(io, sampleState());

    // The persisted secret sits in this file: only the owner may read or
    // write it. Compare the permission bits — st.permissions may carry
    // file-type bits on top.
    const cwd = std.Io.Dir.cwd();
    {
        const f = try cwd.openFile(io, path, .{});
        defer f.close(io);
        const st = try f.stat(io);
        try std.testing.expectEqual(file_mode, @as(std.posix.mode_t, @intCast(@intFromEnum(st.permissions) & 0o777)));
    }

    // An atomic replace must not loosen the mode: the replacement file
    // (and not just the first save) is 0600.
    try cwd.setFilePermissions(io, path, std.Io.File.Permissions.fromMode(0o644), .{});
    try s.saveState(io, sampleState());
    {
        const f = try cwd.openFile(io, path, .{});
        defer f.close(io);
        const st = try f.stat(io);
        try std.testing.expectEqual(file_mode, @as(std.posix.mode_t, @intCast(@intFromEnum(st.permissions) & 0o777)));
    }
}
