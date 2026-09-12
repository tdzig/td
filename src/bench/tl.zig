//! TL serialization and deserialization benchmarks.
//!
//! Covers the generated-API paths on realistic shapes — a
//! vector-of-unions request (`users.getUsers`), a field-rich request
//! with a flags word and a recursive peer (`messages.sendMessage`), a
//! full user object, a scalar status struct (`updates.state`), a string
//! field (`photoSize`), and the raw writer/reader primitives — plus the
//! RPC result-decode layer (`decodeResult` of `Vector<Bool>`).
//!
//! Every serialize benchmark reports its wire size, ns/op and the
//! allocations per op (fresh `Writer` per op, so buffer growth is
//! included); deserialization runs on a per-op arena, which is how the
//! RPC layer hands out decoded `Response` values.

const std = @import("std");
const td = @import("td");
const common = @import("common.zig");

const api = td.api;
const Writer = td.tl.Writer;
const Reader = td.tl.Reader;

const bool_true_wire: [4]u8 = .{ 0xb5, 0x75, 0x72, 0x99 };

pub fn run(gpa: std.mem.Allocator, io: std.Io) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Fixtures (built once; benchmarks only measure the ser/de paths).
    var users8: [8]api.InputUser = undefined;
    fillUsers(&users8);
    var users64: [64]api.InputUser = undefined;
    fillUsers(&users64);

    const req8 = api.users.getUsers{ .id = try arena.dupe(api.InputUser, &users8) };
    const req64 = api.users.getUsers{ .id = try arena.dupe(api.InputUser, &users64) };

    const peer = try arena.create(api.InputPeer);
    peer.* = .{ .inputPeerUser = .{ .user_id = 100, .access_hash = 200 } };
    const send_req = api.messages.sendMessage{
        .silent = true,
        .peer = peer,
        .message = "hello from td — the benchmark message body, long enough to exercise the length-prefixed string encoding",
        .random_id = 0x1122_3344_5566_7788,
    };

    const user_obj = api.User{ .user = .{
        .id = 777,
        .access_hash = 0x1234_5678_9abc,
        .first_name = "Alice",
        .last_name = "Liddell",
        .username = "alice",
        .phone = "15551234567",
    } };
    const state_obj = api.updates.state{
        .pts = 4242,
        .qts = 7,
        .date = 1_700_000_000,
        .seq = 11,
        .unread_count = 3,
    };
    const photo_obj = api.PhotoSize{ .photoSize = .{
        .type_ = "x",
        .w = 800,
        .h = 600,
        .size = 12345,
    } };

    var ints: [64]i32 = undefined;
    for (&ints, 0..) |*v, i| v.* = @intCast(i *% 1_000_003);

    var iw = Writer.init(arena);
    try iw.writeVectorOfInt(&ints);
    const wire_ints = try arena.dupe(u8, iw.items());
    iw.deinit();

    // vector<Bool> result body for the RPC decode layer.
    var vw = Writer.init(arena);
    try vw.writeConstructorId(td.tl.vector_constructor_id);
    try vw.writeVectorLength(64);
    for (0..64) |_| try vw.writeRaw(&bool_true_wire);
    const wire_bools = try arena.dupe(u8, vw.items());
    vw.deinit();

    std.debug.print("\n-- TL serialization --\n", .{});
    try benchSerialize(io, gpa, "serialize users.getUsers (8 ids)", req8, 20_000);
    try benchSerialize(io, gpa, "serialize users.getUsers (64 ids)", req64, 5_000);
    try benchSerialize(io, gpa, "serialize messages.sendMessage", send_req, 50_000);
    try benchSerialize(io, gpa, "serialize user", user_obj, 100_000);
    try benchSerialize(io, gpa, "serialize updates.state", state_obj, 200_000);
    try benchSerialize(io, gpa, "serialize photoSize", photo_obj, 100_000);
    try benchWriterVectorOfInt(io, gpa, "writer primitives: vector<int>[64]", &ints, 100_000);

    std.debug.print("\n-- TL deserialization --\n", .{});
    try benchDeserializeInputUsers(io, gpa, "deserialize getUsers vector (8 ids)", req8, 20_000);
    try benchDeserializeInputUsers(io, gpa, "deserialize getUsers vector (64 ids)", req64, 5_000);
    try benchDeserializeUser(io, gpa, "deserialize user", user_obj, 50_000);
    try benchDeserializeState(io, gpa, "deserialize updates.state", state_obj, 200_000);
    try benchDeserializePhotoSize(io, gpa, "deserialize photoSize", photo_obj, 100_000);
    try benchDeserializeBool(io, gpa, "deserialize Bool", 200_000);
    try benchReaderVectorOfInt(io, gpa, "reader primitives: vector<int>[64]", wire_ints, 50_000);
    try benchDecodeResult(io, gpa, "rpc decodeResult: Vector<Bool>[64]", wire_bools, 10_000);
}

fn fillUsers(arr: []api.InputUser) void {
    for (arr, 0..) |*u, i| {
        u.* = .{ .inputUser = .{
            .user_id = @intCast(i + 1),
            .access_hash = @intCast(0xdead_beef_0000 + i),
        } };
    }
}

/// Serializes once (for wire sizes / golden check by the caller) and
/// benchmarks fresh-writer serialization with allocation counts.
fn benchSerialize(io: std.Io, gpa: std.mem.Allocator, label: []const u8, req: anytype, iters: usize) !void {
    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var wire_len: usize = 0;
    {
        var w = Writer.init(a);
        defer w.deinit();
        try req.serialize(&w);
        wire_len = w.len();
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        var w = Writer.init(a);
        defer w.deinit();
        try req.serialize(&w);
    }
    const total = t.ns();
    common.reportLine(label, wire_len, total, iters);
    common.reportAllocs(label, iters, &c);
}

fn benchWriterVectorOfInt(io: std.Io, gpa: std.mem.Allocator, label: []const u8, ints: *const [64]i32, iters: usize) !void {
    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var wire_len: usize = 0;
    {
        var w = Writer.init(a);
        defer w.deinit();
        try w.writeVectorOfInt(ints);
        wire_len = w.len();
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        var w = Writer.init(a);
        defer w.deinit();
        try w.writeVectorOfInt(ints);
    }
    const total = t.ns();
    common.reportLine(label, wire_len, total, iters);
    common.reportAllocs(label, iters, &c);
}

fn benchReaderVectorOfInt(io: std.Io, gpa: std.mem.Allocator, label: []const u8, wire: []const u8, iters: usize) !void {
    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    {
        var r = Reader.init(wire);
        const v = try r.readVectorOfInt(a);
        common.keep(@intCast(v.len));
        a.free(v);
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        var r = Reader.init(wire);
        const v = try r.readVectorOfInt(a);
        common.keep(@intCast(v[0]));
        a.free(v);
    }
    const total = t.ns();
    common.reportLine(label, wire.len, total, iters);
    common.reportAllocs(label, iters, &c);
}

/// Deserializes the `Vector<InputUser>` payload of a serialized
/// `users.getUsers` request (fn id skipped, vector header parsed — the
/// exact shape the RPC result decoder drives generated deserialize with).
fn benchDeserializeInputUsers(io: std.Io, gpa: std.mem.Allocator, label: []const u8, req: anytype, iters: usize) !void {
    // Serialize once; the wire copy outlives every benchmark iteration.
    const wire = try serializeOnce(gpa, req);
    defer gpa.free(wire);

    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var dec = std.heap.ArenaAllocator.init(a);
    defer dec.deinit();

    {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(wire[4..]);
        common.keep(try r.readUInt()); // vector constructor id
        const n = try r.readVectorLength();
        const da = dec.allocator();
        for (0..n) |_| {
            const u = try api.InputUser.deserialize(da, &r);
            common.keep(@bitCast(u.inputUser.user_id));
        }
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(wire[4..]);
        common.keep(try r.readUInt());
        const n = try r.readVectorLength();
        const da = dec.allocator();
        for (0..n) |_| {
            const u = try api.InputUser.deserialize(da, &r);
            common.keep(@bitCast(u.inputUser.user_id));
        }
    }
    const total = t.ns();
    common.reportLine(label, wire.len, total, iters);
    common.reportAllocs(label, iters, &c);
}

fn benchDeserializeUser(io: std.Io, gpa: std.mem.Allocator, label: []const u8, user_obj: api.User, iters: usize) !void {
    const wire = try serializeOnce(gpa, user_obj);
    defer gpa.free(wire);

    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var dec = std.heap.ArenaAllocator.init(a);
    defer dec.deinit();

    {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(wire);
        const u = try api.User.deserialize(dec.allocator(), &r);
        if (u != .user) return error.UnexpectedTag;
        common.keep(@intCast(u.user.id));
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(wire);
        const u = try api.User.deserialize(dec.allocator(), &r);
        common.keep(@intCast(u.user.id));
    }
    const total = t.ns();
    common.reportLine(label, wire.len, total, iters);
    common.reportAllocs(label, iters, &c);
}

fn benchDeserializeState(io: std.Io, gpa: std.mem.Allocator, label: []const u8, state_obj: api.updates.state, iters: usize) !void {
    const wire = try serializeOnce(gpa, state_obj);
    defer gpa.free(wire);

    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var dec = std.heap.ArenaAllocator.init(a);
    defer dec.deinit();

    {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(wire);
        const v = try api.updates.state.deserialize(dec.allocator(), &r);
        common.keep(@as(u32, @bitCast(v.pts)));
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(wire);
        const v = try api.updates.state.deserialize(dec.allocator(), &r);
        common.keep(@as(u32, @bitCast(v.pts)));
    }
    const total = t.ns();
    common.reportLine(label, wire.len, total, iters);
    common.reportAllocs(label, iters, &c);
}

fn benchDeserializePhotoSize(io: std.Io, gpa: std.mem.Allocator, label: []const u8, photo_obj: api.PhotoSize, iters: usize) !void {
    const wire = try serializeOnce(gpa, photo_obj);
    defer gpa.free(wire);

    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var dec = std.heap.ArenaAllocator.init(a);
    defer dec.deinit();

    {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(wire);
        const v = try api.PhotoSize.deserialize(dec.allocator(), &r);
        switch (v) {
            .photoSize => |p| common.keep(@intCast(@as(u32, @bitCast(p.w)))),
            else => return error.UnexpectedTag,
        }
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(wire);
        const v = try api.PhotoSize.deserialize(dec.allocator(), &r);
        switch (v) {
            .photoSize => |p| common.keep(@intCast(@as(u32, @bitCast(p.w)))),
            else => return error.UnexpectedTag,
        }
    }
    const total = t.ns();
    common.reportLine(label, wire.len, total, iters);
    common.reportAllocs(label, iters, &c);
}

/// Serializes `obj` once and returns a caller-owned wire copy.
fn serializeOnce(gpa: std.mem.Allocator, obj: anytype) ![]u8 {
    var sw = Writer.init(gpa);
    defer sw.deinit();
    try obj.serialize(&sw);
    return gpa.dupe(u8, sw.items());
}

fn benchDeserializeBool(io: std.Io, gpa: std.mem.Allocator, label: []const u8, iters: usize) !void {
    const wire: [4]u8 = bool_true_wire;
    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var dec = std.heap.ArenaAllocator.init(a);
    defer dec.deinit();

    {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(&wire);
        const b = try api.Bool.deserialize(dec.allocator(), &r);
        common.keep(@intFromBool(b == .boolTrue));
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        _ = dec.reset(.retain_capacity);
        var r = Reader.init(&wire);
        const b = try api.Bool.deserialize(dec.allocator(), &r);
        common.keep(@intFromBool(b == .boolTrue));
    }
    const total = t.ns();
    common.reportLine(label, wire.len, total, iters);
    common.reportAllocs(label, iters, &c);
}

/// RPC result-decode layer: `decodeResult([]api.Bool, arena, bytes)` on a
/// fresh arena per op — the exact shape of `Client.wait`'s `Response(T)`.
fn benchDecodeResult(io: std.Io, gpa: std.mem.Allocator, label: []const u8, wire: []const u8, iters: usize) !void {
    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    {
        var dec = std.heap.ArenaAllocator.init(a);
        defer dec.deinit();
        const v = try td.rpc.decodeResult([]api.Bool, dec.allocator(), wire);
        common.keep(@intCast(v.len));
    }
    c.reset();
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        var dec = std.heap.ArenaAllocator.init(a);
        defer dec.deinit();
        const v = try td.rpc.decodeResult([]api.Bool, dec.allocator(), wire);
        common.keep(@intCast(v.len));
    }
    const total = t.ns();
    common.reportLine(label, wire.len, total, iters);
    common.reportAllocs(label, iters, &c);
}
