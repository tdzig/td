//! Compilation + serialization roundtrip tests for generated code.
//! Imports the committed golden output (`golden/expected_sample.zig`);
//! merely compiling this file proves the generated code is valid Zig, and
//! the tests below exercise ids, serialization and deserialization.

const std = @import("std");
const td = @import("td");
const gen = @import("golden/expected_sample.zig");

test "constructor ids preserved exactly" {
    try std.testing.expectEqual(@as(u32, 0xbc799737), gen.boolFalse.constructor_id);
    try std.testing.expectEqual(@as(u32, 0x997275b5), gen.boolTrue.constructor_id);
    try std.testing.expectEqual(@as(u32, 0xd10d979a), gen.user.constructor_id);
    try std.testing.expectEqual(@as(u32, 0x0d91a548), gen.users.getUsers.constructor_id);
}

test "bool union roundtrip" {
    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();

    const yes = gen.Bool{ .boolTrue = .{} };
    try yes.serialize(&w);
    const no: gen.Bool = .{ .boolFalse = .{} };
    try no.serialize(&w);

    var r = td.tl.Reader.init(w.items());
    const a = try gen.Bool.deserialize(std.testing.allocator, &r);
    const b = try gen.Bool.deserialize(std.testing.allocator, &r);
    try std.testing.expect(std.meta.eql(a, yes));
    try std.testing.expect(std.meta.eql(b, no));
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "user roundtrip with optionals set" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const tags: [][]i32 = try arena.alloc([]i32, 2);
    tags[0] = try arena.dupe(i32, &.{ 1, -2147483648 });
    tags[1] = try arena.dupe(i32, &.{2147483647});

    const value = gen.user{
        .self = true,
        .id = std.math.maxInt(i64),
        .first_name = "td",
        .last_name = null,
        .photo = .{ .userProfilePhoto = .{
            .has_video = true,
            .photo_id = 42,
            .stripped_thumb = "\x01\x02\x03",
            .dc_id = 2,
        } },
        .tags = tags,
    };
    const original = gen.User{ .user = value };

    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try original.serialize(&w);

    var r = td.tl.Reader.init(w.items());
    const decoded = try gen.User.deserialize(arena, &r);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
    switch (decoded) {
        .user => |u| {
            try std.testing.expect(u.self);
            try std.testing.expectEqual(value.id, u.id);
            try std.testing.expectEqualStrings(value.first_name.?, u.first_name.?);
            try std.testing.expect(u.last_name == null);
            try std.testing.expectEqual(@as(usize, 2), u.tags.len);
            try std.testing.expectEqualSlices(i32, tags[0], u.tags[0]);
            try std.testing.expectEqualSlices(i32, tags[1], u.tags[1]);
            switch (u.photo.?) {
                .userProfilePhoto => |p| {
                    try std.testing.expect(p.has_video);
                    try std.testing.expectEqual(@as(i64, 42), p.photo_id);
                    try std.testing.expectEqualStrings("\x01\x02\x03", p.stripped_thumb.?);
                    try std.testing.expectEqual(@as(i32, 2), p.dc_id);
                },
            }
        },
    }
}

test "user roundtrip with all optionals cleared" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    const original = gen.User{ .user = .{
        .self = false,
        .id = 1,
        .first_name = null,
        .last_name = null,
        .photo = null,
        .tags = &.{},
    } };

    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try original.serialize(&w);
    // ctor id (4) + flags word (4) + id (8) + empty vector (8)
    try std.testing.expectEqual(@as(usize, 24), w.len());

    var r = td.tl.Reader.init(w.items());
    const decoded = try gen.User.deserialize(arena_state.allocator(), &r);
    switch (decoded) {
        .user => |u| {
            try std.testing.expect(!u.self);
            try std.testing.expect(u.first_name == null);
            try std.testing.expect(u.photo == null);
            try std.testing.expectEqual(@as(usize, 0), u.tags.len);
        },
    }
}

test "unknown constructor id is rejected" {
    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(0xdeadbeef);
    var r = td.tl.Reader.init(w.items());
    try std.testing.expectError(error.InvalidValue, gen.Bool.deserialize(std.testing.allocator, &r));
}

test "function request serialization" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    const req = gen.users.getUsers{ .id = try arena_state.allocator().dupe(i32, &.{ 1, 2, 3 }) };
    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try req.serialize(&w);

    // function id + vector id + count + 3 ints
    try std.testing.expectEqual(@as(usize, 4 + 4 + 4 + 12), w.len());
    var r = td.tl.Reader.init(w.items());
    try std.testing.expectEqual(gen.users.getUsers.constructor_id, try r.readConstructorId());
    try std.testing.expectEqual(td.tl.vector_constructor_id, try r.readUInt());
    try std.testing.expectEqual(@as(u32, 3), try r.readVectorLength());
}

test "keyword parameter names are escaped" {
    // `type` from photoSize and `long` from geoPoint must be escaped.
    var photo = gen.photoSize{ .type_ = "m", .w = 1, .h = 1, .size = 7 };
    _ = &photo;
    var geo = gen.geoPoint{ .long_ = 1.5, .lat = -2.5 };
    _ = &geo;
}
