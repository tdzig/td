//! Runtime tests against the committed generated Telegram API
//! (`src/api/mod.zig` = `td.api`). These exercise real API shapes:
//! unions, vectors of unions, namespaced function requests, and the
//! recursive `InputPeer` type (pointer-boxed by the generator).
//!
//! Wire layouts verified here can be cross-checked against the schema lines:
//!   inputPeerUser#dde8a54c user_id:long access_hash:long = InputPeer;
//!   inputPeerUserFromMessage#a87b0a1c peer:InputPeer msg_id:int user_id:long = InputPeer;
//!   inputUser#f21158c6 user_id:long access_hash:long = InputUser;
//!   users.getUsers#d91a548 id:Vector<InputUser> = Vector<User>;
//!   photoSize#75c78e60 type:string w:int h:int size:int = PhotoSize;

const std = @import("std");
const td = @import("td");
const api = td.api;

test "api: Bool union roundtrip" {
    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try (api.Bool{ .boolTrue = .{} }).serialize(&w);
    try (api.Bool{ .boolFalse = .{} }).serialize(&w);

    var r = td.tl.Reader.init(w.items());
    const a = try api.Bool.deserialize(std.testing.allocator, &r);
    const b = try api.Bool.deserialize(std.testing.allocator, &r);
    try std.testing.expect(a == .boolTrue);
    try std.testing.expect(b == .boolFalse);
}

test "api: photoSize roundtrip (escaped field name)" {
    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    const original = api.PhotoSize{ .photoSize = .{
        .type_ = "x",
        .w = 800,
        .h = 600,
        .size = 12345,
    } };
    try original.serialize(&w);

    var r = td.tl.Reader.init(w.items());
    const decoded = try api.PhotoSize.deserialize(std.testing.allocator, &r);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
    switch (decoded) {
        .photoSize => |p| {
            try std.testing.expectEqual(@as(u32, 0x75c78e60), api.photoSize.constructor_id);
            try std.testing.expectEqualStrings("x", p.type_);
            try std.testing.expectEqual(@as(i32, 800), p.w);
            try std.testing.expectEqual(@as(i32, 600), p.h);
            try std.testing.expectEqual(@as(i32, 12345), p.size);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "api: users.getUsers request with vector of unions" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const req = api.users.getUsers{
        .id = try arena.dupe(api.InputUser, &.{
            .{ .inputUser = .{ .user_id = 1, .access_hash = 0xdeadbeef } },
            .{ .inputUser = .{ .user_id = 2, .access_hash = 0xcafebabe } },
        }),
    };

    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try req.serialize(&w);

    // Wire: fn id + vector id + count + 2 * (ctor id + long + long)
    try std.testing.expectEqual(@as(usize, 4 + 4 + 4 + 2 * 20), w.len());

    var r = td.tl.Reader.init(w.items());
    try std.testing.expectEqual(api.users.getUsers.constructor_id, try r.readConstructorId());
    try std.testing.expectEqual(td.tl.vector_constructor_id, try r.readUInt());
    try std.testing.expectEqual(@as(u32, 2), try r.readVectorLength());
    const first = try api.InputUser.deserialize(arena, &r);
    const second = try api.InputUser.deserialize(arena, &r);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
    try std.testing.expectEqual(@as(i64, 1), first.inputUser.user_id);
    try std.testing.expectEqual(@as(i64, 0xdeadbeef), first.inputUser.access_hash);
    try std.testing.expectEqual(@as(i64, 2), second.inputUser.user_id);
}

test "api: recursive InputPeer roundtrip (pointer-boxed field)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const inner = try arena.create(api.InputPeer);
    inner.* = .{ .inputPeerUser = .{ .user_id = 42, .access_hash = 7 } };

    const original = api.InputPeer{ .inputPeerUserFromMessage = .{
        .peer = inner,
        .msg_id = 1234,
        .user_id = 42,
    } };

    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try original.serialize(&w);

    var r = td.tl.Reader.init(w.items());
    const decoded = try api.InputPeer.deserialize(arena, &r);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
    switch (decoded) {
        .inputPeerUserFromMessage => |v| {
            try std.testing.expectEqual(@as(i32, 1234), v.msg_id);
            try std.testing.expectEqual(@as(i64, 42), v.user_id);
            // The recursive field is heap-boxed by generated deserialize.
            try std.testing.expect(v.peer.*.inputPeerUser.user_id == 42);
            try std.testing.expectEqual(@as(i64, 7), v.peer.*.inputPeerUser.access_hash);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "api: messages.sendMessage request serialization" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const peer = try arena.create(api.InputPeer);
    peer.* = .{ .inputPeerUser = .{ .user_id = 100, .access_hash = 200 } };

    const req = api.messages.sendMessage{
        .silent = true, // flags.5
        .peer = peer, // recursive type: field is *InputPeer
        .reply_to = null,
        .message = "hello from td",
        .random_id = 0x1122334455667788,
        .reply_markup = null,
        .entities = null,
        .schedule_date = null,
        .schedule_repeat_period = null,
        .send_as = null,
        .quick_reply_shortcut = null,
        .effect = null,
        .allow_paid_stars = null,
        .suggested_post = null,
        .rich_message = null,
    };

    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try req.serialize(&w);

    var r = td.tl.Reader.init(w.items());
    try std.testing.expectEqual(@as(u32, 0xfef48f62), try r.readConstructorId());
    const flags = try r.readUInt();
    try std.testing.expectEqual(@as(u32, 1 << 5), flags); // only silent set
    // peer union: inputPeerUser#dde8a54c + two longs
    try std.testing.expectEqual(@as(u32, 0xdde8a54c), try r.readConstructorId());
    try std.testing.expectEqual(@as(i64, 100), try r.readLong());
    try std.testing.expectEqual(@as(i64, 200), try r.readLong());
    try std.testing.expectEqualStrings("hello from td", try r.readString());
    try std.testing.expectEqual(@as(i64, 0x1122334455667788), try r.readLong());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "api: namespace and type surface is present" {
    // Constructors, functions, namespaces and unions all hang off td.api.
    try std.testing.expectEqual(@as(u32, 0xfef48f62), api.messages.sendMessage.constructor_id);
    try std.testing.expectEqual(@as(u32, 0xb1b8cc83), api.user.constructor_id); // current layer
    _ = api.users.getUsers;
    _ = api.InputPeer;
    _ = api.InputUser;
    _ = api.Updates;
    _ = api.User;
    _ = api.contacts.contacts_;
}
