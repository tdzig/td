//! Small demo binary: parses an embedded sample of the Telegram TL schema
//! and exercises the TL binary writer/reader round-trip.

const std = @import("std");
const td = @import("td");

const sample_schema =
    \\// Sample of Telegram TL schema (https://core.telegram.org/schema)
    \\user#d10d979a flags:# id:long access_hash:flags.0?long
    \\    first_name:flags.1?string last_name:flags.2?string = User;
    \\users.getUsers#d91a548 id:Vector<InputUser> = users.Users;
;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var schema = try td.tl.parseSchema(allocator, sample_schema);
    defer schema.deinit();

    std.debug.print("parsed {d} constructors from sample schema:\n", .{schema.constructors.len});
    for (schema.constructors) |c| {
        std.debug.print("  {s}# {x:0>8} ({d} params) = {s}\n", .{ c.name, c.id, c.params.len, c.result_type.name });
    }

    var writer = td.tl.Writer.init(allocator);
    defer writer.deinit();
    try writer.writeInt(123);
    try writer.writeString("td");
    try writer.writeVectorOfInt(&.{ 1, 2, 3 });

    var reader = td.tl.Reader.init(writer.items());
    const n = try reader.readInt();
    const s = try reader.readString();
    const v = try reader.readVectorOfInt(allocator);
    defer allocator.free(v);

    std.debug.print("roundtrip: int={d} string=\"{s}\" vector_len={d}\n", .{ n, s, v.len });
}
