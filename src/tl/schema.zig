//! Parsed TL schema with explicit ownership.
//!
//! Ownership rules:
//!  * All name/type strings inside the AST **borrow from the schema source
//!    text** passed to `parse` — the caller must keep that buffer alive for
//!    as long as the `Schema` lives.
//!  * The `Schema` owns an arena backing every AST allocation. One
//!    `deinit()` frees everything.
//!
//! Schema files (Telegram's official `api.tl`) split declarations with a
//! `---functions---` section marker: everything before it is type
//! constructors, everything after is RPC functions. Both are represented by
//! the same `Constructor` AST; the split is preserved positionally.

const std = @import("std");
const ast = @import("types.zig");
const Parser = @import("parser.zig").Parser;
const err = @import("../errors.zig");
const ParseError = err.ParseError;

pub const functions_marker = "---functions---";
/// Core-schema files alternate sections (`---types---` after a
/// `---functions---` block); everything after it is a type constructor
/// again. api.tl has no `---types---` marker.
pub const types_marker = "---types---";

pub const Schema = struct {
    arena: std.heap.ArenaAllocator,
    /// Type constructors (before `---functions---`).
    constructors: []ast.Constructor = &.{},
    /// RPC functions (after `---functions---`); empty when the schema has
    /// no functions section.
    functions: []ast.Constructor = &.{},
    /// The schema's API layer, from a `// LAYER <n>` comment. Official
    /// schemas carry it at the end of the file; the position is not
    /// significant. null when the schema declares none.
    layer: ?i32 = null,

    pub fn deinit(self: *Schema) void {
        self.arena.deinit();
        self.constructors = &.{};
        self.functions = &.{};
    }

    /// Total number of declarations (constructors + functions).
    pub fn total(self: *const Schema) usize {
        return self.constructors.len + self.functions.len;
    }

    /// Finds a declaration by its exact unsigned 32-bit wire id
    /// (searches constructors and functions).
    pub fn findById(self: *const Schema, id: u32) ?*const ast.Constructor {
        for (self.constructors) |*c| {
            if (c.id == id) return c;
        }
        for (self.functions) |*c| {
            if (c.id == id) return c;
        }
        return null;
    }

    /// Finds a declaration by full (possibly namespaced) name.
    pub fn findByName(self: *const Schema, name: []const u8) ?*const ast.Constructor {
        for (self.constructors) |*c| {
            if (std.mem.eql(u8, c.name, name)) return c;
        }
        for (self.functions) |*c| {
            if (std.mem.eql(u8, c.name, name)) return c;
        }
        return null;
    }
};

/// Parses a complete TL schema. On error all intermediate allocations are
/// freed; `parser.last_diagnostic` describes the failure.
pub fn parse(allocator: std.mem.Allocator, src: []const u8) ParseError!Schema {
    var parser = Parser.init(src);
    return parseWith(allocator, &parser);
}

/// Like `parse`, but keeps the parser around so callers can read
/// `parser.last_diagnostic` after an error.
pub fn parseWith(allocator: std.mem.Allocator, parser: *Parser) ParseError!Schema {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var constructors: std.ArrayList(ast.Constructor) = .empty;
    errdefer constructors.deinit(a);
    var functions: std.ArrayList(ast.Constructor) = .empty;
    errdefer functions.deinit(a);

    var seen_marker = false;

    while (true) {
        try parser.skipTrivia();
        if (parser.peek() == null) break;

        if (std.mem.startsWith(u8, parser.src[parser.pos..], functions_marker)) {
            for (0..functions_marker.len) |_| _ = parser.advance();
            seen_marker = true;
            continue;
        }
        if (std.mem.startsWith(u8, parser.src[parser.pos..], types_marker)) {
            for (0..types_marker.len) |_| _ = parser.advance();
            seen_marker = false;
            continue;
        }
        const c = try parser.constructor(a);
        // Declarations after the `---functions---` marker are RPC functions.
        const target = if (seen_marker) &functions else &constructors;
        target.append(a, c) catch return error.OutOfMemory;
    }
    return .{
        .arena = arena,
        .constructors = constructors.toOwnedSlice(a) catch return error.OutOfMemory,
        .functions = functions.toOwnedSlice(a) catch return error.OutOfMemory,
        .layer = parseLayer(parser.src),
    };
}

/// Scans the source for a `// LAYER <n>` comment; the first
/// well-formed one wins, anywhere in the file. Comments are trivia to
/// the grammar, so a malformed or absent marker simply yields null.
fn parseLayer(src: []const u8) ?i32 {
    var rest = src;
    while (std.mem.indexOf(u8, rest, "//")) |idx| {
        const after = rest[idx + 2 ..];
        const line_end = std.mem.indexOfAny(u8, after, "\r\n") orelse after.len;
        var it = std.mem.tokenizeAny(u8, after[0..line_end], " \t");
        if (it.next()) |kw| {
            if (std.mem.eql(u8, kw, "LAYER")) {
                const num = it.next() orelse return null;
                return std.fmt.parseInt(i32, num, 10) catch null;
            }
        }
        rest = after;
    }
    return null;
}

// ---------------------------------------------------------------- tests

test "parse multi-constructor schema" {
    const src =
        \\user#d10d979a flags:# first_name:flags.1?string = User;
        \\users.getUsers#d91a548 id:Vector<InputUser> = users.Users;
    ;
    var schema = parse(std.testing.allocator, src) catch |e| {
        std.debug.print("parse failed: {s}\n", .{@errorName(e)});
        return e;
    };
    defer schema.deinit();

    try std.testing.expectEqual(@as(usize, 2), schema.constructors.len);
    try std.testing.expectEqual(@as(usize, 0), schema.functions.len);
    const user = schema.findByName("user").?;
    try std.testing.expectEqual(@as(u32, 0xd10d979a), user.id);
    try std.testing.expectEqual(user, schema.findById(0xd10d979a).?);
    try std.testing.expect(schema.findById(0xdeadbeef) == null);

    const rpc = schema.findByName("users.getUsers").?;
    try std.testing.expectEqualStrings("users.Users", rpc.result_type.name);
    try std.testing.expectEqualStrings("InputUser", rpc.params[0].type_expr.arg.?.name);
}

test "functions section splits declarations" {
    const src =
        \\boolTrue#997275b5 = Bool;
        \\---functions---
        \\users.getUsers#d91a548 id:Vector<InputUser> = users.Users;
        \\users.getFullUser#cae9dd57 id:InputUser = users.UserFull;
    ;
    var schema = try parse(std.testing.allocator, src);
    defer schema.deinit();

    try std.testing.expectEqual(@as(usize, 1), schema.constructors.len);
    try std.testing.expectEqual(@as(usize, 2), schema.functions.len);
    try std.testing.expectEqualStrings("boolTrue", schema.constructors[0].name);
    try std.testing.expectEqualStrings("users.getUsers", schema.functions[0].name);
    try std.testing.expectEqualStrings("users.getFullUser", schema.functions[1].name);
    try std.testing.expectEqual(@as(usize, 3), schema.total());
}

test "parse error mid-schema frees partial results" {
    const src =
        \\good#1 a:int = Good;
        \\bad#zzz b:int = Bad;
    ;
    var parser = Parser.init(src);
    try std.testing.expectError(error.InvalidConstructorId, parseWith(std.testing.allocator, &parser));
    try std.testing.expect(parser.last_diagnostic.line > 0);
}

test "empty schema" {
    var schema = try parse(std.testing.allocator, "// only a comment\n");
    defer schema.deinit();
    try std.testing.expectEqual(@as(usize, 0), schema.total());
}

test "layer marker is picked up wherever it sits" {
    // Official position: end of file.
    var s = try parse(std.testing.allocator,
        \\boolTrue#997275b5 = Bool;
        \\
        \\// LAYER 229
    );
    defer s.deinit();
    try std.testing.expectEqual(@as(?i32, 229), s.layer);

    // Anywhere else works too; the first well-formed marker wins.
    var s2 = try parse(std.testing.allocator,
        \\// LAYER 181
        \\boolTrue#997275b5 = Bool;
        \\// LAYER 229
    );
    defer s2.deinit();
    try std.testing.expectEqual(@as(?i32, 181), s2.layer);

    // Absent, malformed, or non-layer comments yield null.
    for ([_][]const u8{
        "boolTrue#997275b5 = Bool;",
        "// LAYER\nboolTrue#997275b5 = Bool;",
        "// LAYER 20x9\nboolTrue#997275b5 = Bool;",
        "// layers have layers\nboolTrue#997275b5 = Bool;",
    }) |src| {
        var s3 = try parse(std.testing.allocator, src);
        defer s3.deinit();
        try std.testing.expectEqual(@as(?i32, null), s3.layer);
    }
}
