//! Compatibility test against the complete official Telegram API schema.
//!
//! `schema/api.tl` is the schema text used by Telegram's own
//! desktop client (Telegram Desktop, `mtproto/scheme/api.tl`) — the same
//! schema published at https://core.telegram.org/schema. Only the schema
//! text is used; no client code.

const std = @import("std");
const td = @import("td");

const api_tl = @import("schema").api_tl;

test "official schema parses completely" {
    var schema = try td.tl.parseSchema(std.testing.allocator, api_tl);
    defer schema.deinit();

    // The schema file has one declaration per line; every non-comment,
    // non-marker line must have parsed.
    var decl_lines: usize = 0;
    var it = std.mem.splitScalar(u8, api_tl, '\n');
    while (it.next()) |line| {
        const t = std.mem.trim(u8, line, " \t\r");
        if (t.len > 0 and !std.mem.startsWith(u8, t, "//") and
            !std.mem.startsWith(u8, t, "---functions---"))
        {
            decl_lines += 1;
        }
    }
    try std.testing.expectEqual(decl_lines, schema.total());
    try std.testing.expect(schema.constructors.len > 1000);
    try std.testing.expect(schema.functions.len > 500);
}

test "official schema spot checks" {
    var schema = try td.tl.parseSchema(std.testing.allocator, api_tl);
    defer schema.deinit();

    // Types section (ids from the current schema layer)
    const user = schema.findByName("user").?;
    try std.testing.expectEqual(@as(u32, 0xb1b8cc83), user.id);
    try std.testing.expect(user.params[0].isFlagsField());
    // The current layer has a second natural field `flags2:#`, declared
    // after the optional fields of the first one.
    var has_flags2 = false;
    for (user.params) |p| {
        if (std.mem.eql(u8, p.name, "flags2")) has_flags2 = p.isFlagsField();
    }
    try std.testing.expect(has_flags2);

    const vector = schema.findByName("vector").?;
    try std.testing.expectEqual(@as(u32, 0x1cb5c415), vector.id);
    try std.testing.expect(vector.params[0].is_type_var);
    try std.testing.expectEqualStrings("t", vector.params[0].name);
    try std.testing.expect(vector.params[1].isFlagsField()); // anonymous '#'
    try std.testing.expect(vector.params[2].iterative);
    try std.testing.expectEqualStrings("t", vector.result_type.var_args[0].name);

    // Functions section
    const get_users = schema.findByName("users.getUsers").?;
    try std.testing.expectEqual(@as(u32, 0x0d91a548), get_users.id);
    try std.testing.expectEqualStrings("InputUser", get_users.params[0].type_expr.arg.?.name);

    const invoke = schema.findByName("invokeAfterMsg").?;
    try std.testing.expect(invoke.params[0].is_type_var);
    try std.testing.expect(invoke.params[2].type_expr.bang);

    // ids resolve from both sections
    try std.testing.expectEqual(user, schema.findById(0xb1b8cc83).?);
    try std.testing.expectEqual(get_users, schema.findById(0x0d91a548).?);
}

test "official schema passes validation" {
    var schema = try td.tl.parseSchema(std.testing.allocator, api_tl);
    defer schema.deinit();

    var issues: std.ArrayList(td.tl.validate.Issue) = .empty;
    defer issues.deinit(std.testing.allocator);
    try std.testing.expect(td.tl.validate.validate(std.testing.allocator, &schema, &issues));
    for (issues.items) |issue| {
        std.debug.print("issue: {s} {s} {s}\n", .{ @tagName(issue.kind), issue.constructor, issue.detail });
    }
    try std.testing.expectEqual(@as(usize, 0), issues.items.len);
}
