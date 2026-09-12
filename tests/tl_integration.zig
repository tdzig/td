//! Integration tests: real fragments of the Telegram TL schema
//! (https://core.telegram.org/schema) parsed through the public API,
//! plus a writer→reader round-trip over a full message-shaped payload.

const std = @import("std");
const td = @import("td");

const sample =
    \\// fragment of the Telegram TL schema
    \\user#d10d979a flags:# id:long access_hash:flags.0?long
    \\    first_name:flags.1?string last_name:flags.2?string
    \\    username:flags.3?string = User;
    \\users.getUsers#d91a548 id:Vector<InputUser> = users.Users;
;

test "parse realistic schema fragment" {
    var schema = try td.tl.parseSchema(std.testing.allocator, sample);
    defer schema.deinit();

    try std.testing.expectEqual(@as(usize, 2), schema.constructors.len);

    const user = schema.findByName("user").?;
    try std.testing.expectEqual(@as(u32, 0xd10d979a), user.id);
    try std.testing.expectEqual(@as(usize, 6), user.params.len);
    try std.testing.expect(user.params[0].isFlagsField());
    // username:flags.3?string
    const username = user.params[5];
    try std.testing.expectEqualStrings("username", username.name);
    try std.testing.expectEqualStrings("flags", username.flags_field.?);
    try std.testing.expectEqual(@as(?u6, 3), username.flag_index);

    const rpc = schema.findByName("users.getUsers").?;
    try std.testing.expectEqual(@as(u32, 0x0d91a548), rpc.id);
    try std.testing.expectEqualStrings("users.Users", rpc.result_type.name);
    try std.testing.expectEqualStrings("InputUser", rpc.params[0].type_expr.arg.?.name);
    try std.testing.expectEqual(rpc, schema.findById(0x0d91a548).?);
}

test "message-shaped writer/reader roundtrip" {
    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();

    // Emits a user-shaped payload: id:long, flags-bits-in-bools, names.
    try w.writeConstructorId(0xd10d979a);
    try w.writeLong(1234567890);
    try w.writeBool(true); // flags.1 → first_name present
    try w.writeBool(false); // flags.2 → last_name absent
    try w.writeString("zig");

    var r = td.tl.Reader.init(w.items());
    try std.testing.expectEqual(@as(u32, 0xd10d979a), try r.readConstructorId());
    try std.testing.expectEqual(@as(i64, 1234567890), try r.readLong());
    try std.testing.expectEqual(true, try r.readBool());
    try std.testing.expectEqual(false, try r.readBool());
    try std.testing.expectEqualStrings("zig", try r.readString());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "int128/int256 roundtrip" {
    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();

    var mid: [16]u8 = undefined;
    for (&mid, 0..) |*b, i| b.* = @intCast(i);
    var big: [32]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @intCast(255 - i);

    try w.writeInt128(mid);
    try w.writeInt256(big);

    var r = td.tl.Reader.init(w.items());
    try std.testing.expectEqual(mid, try r.readInt128());
    try std.testing.expectEqual(big, try r.readInt256());
}

test "vector of strings roundtrip and ownership" {
    var w = td.tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeVectorOfString(&.{ "alpha", "", "gamma" });

    var r = td.tl.Reader.init(w.items());
    const v = try r.readVectorOfString(std.testing.allocator);
    defer std.testing.allocator.free(v);
    try std.testing.expectEqual(@as(usize, 3), v.len);
    try std.testing.expectEqualStrings("alpha", v[0]);
    try std.testing.expectEqual(@as(usize, 0), v[1].len);
    try std.testing.expectEqualStrings("gamma", v[2]);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "schema strings borrow from source" {
    // The AST borrows from `src`; verify no copies were made by checking
    // pointer identity with a slice of the same source text.
    var schema = try td.tl.parseSchema(std.testing.allocator, sample);
    defer schema.deinit();
    const user = schema.findByName("user").?;
    const offset = std.mem.indexOf(u8, sample, "user#").?;
    try std.testing.expectEqual(sample[offset .. offset + 4].ptr, user.name.ptr);
}
