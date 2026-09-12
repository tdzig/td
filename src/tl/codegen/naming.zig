//! Type mapping and identifier naming for the TL → Zig code generator.
//!
//! Pure functions, no state: TL type names → Zig type expressions,
//! TL identifiers → escaped Zig identifiers. Kept separate from emission
//! (emit.zig) so the mapping policy can evolve independently.

const std = @import("std");
const ast = @import("../types.zig");

/// Zig keywords that can plausibly appear as TL parameter names
/// (TL names are lowercase, so only lowercase keywords matter).
const keywords = std.StaticStringMap(void).initComptime(.{
    .{"align"},      .{"and"},     .{"asm"},       .{"break"},   .{"callconv"},
    .{"catch"},      .{"comptime"}, .{"const"},    .{"continue"}, .{"defer"},
    .{"else"},       .{"enum"},    .{"error"},     .{"export"},  .{"extern"},
    .{"fn"},         .{"for"},     .{"if"},        .{"inline"},  .{"noalias"},
    .{"noinline"},   .{"or"},      .{"orelse"},    .{"packed"},  .{"pub"},
    .{"return"},     .{"struct"},  .{"suspend"},   .{"switch"},  .{"test"},
    .{"threadlocal"}, .{"try"},    .{"union"},     .{"unreachable"}, .{"var"},
    .{"volatile"},   .{"while"},   .{"usingnamespace"}, .{"anytype"}, .{"anyframe"},
    // primitives that cannot be used as identifiers
    .{"type"},       .{"void"},    .{"usize"},     .{"isize"},   .{"u32"},
    .{"u64"},        .{"i32"},     .{"i64"},       .{"f64"},     .{"bool"},
    .{"long"},       .{"int"},     .{"true"},      .{"false"},   .{"null"},
    .{"undefined"},  .{"comptime_float"}, .{"comptime_int"}, .{"noreturn"},
});

/// Escapes a TL identifier into a valid, distinct Zig identifier.
/// Borrows `name` when no escape is needed; otherwise allocates from
/// `allocator` (name ++ "_").
pub fn ident(allocator: std.mem.Allocator, name: []const u8) std.mem.Allocator.Error![]const u8 {
    if (keywords.get(name) == null) return name;
    var buf = try std.ArrayList(u8).initCapacity(allocator, name.len + 1);
    buf.appendSlice(allocator, name) catch unreachable;
    buf.append(allocator, '_') catch unreachable;
    return buf.toOwnedSlice(allocator);
}

/// Primitive TL types that map to builtin Zig types.
/// `true` maps to bool (only meaningful inside optional fields).
pub fn scalarZigType(name: []const u8) ?[]const u8 {
    return std.StaticStringMap([]const u8).initComptime(.{
        .{ "int", "i32" },
        .{ "long", "i64" },
        .{ "double", "f64" },
        .{ "string", "[]const u8" },
        .{ "bytes", "[]const u8" },
        .{ "int128", "[16]u8" },
        .{ "int256", "[32]u8" },
        .{ "Bool", "bool" },
        .{ "true", "bool" },
        .{ "#", "u32" },
    }).get(name);
}

/// True for types whose serialization needs a per-element `for` loop
/// (`Vector<...>` and the core schema's bare `vector<...>`).
pub fn isVector(expr: *const ast.TypeExpr) bool {
    return (std.mem.eql(u8, expr.name, "Vector") or std.mem.eql(u8, expr.name, "vector")) and expr.arg != null;
}

/// True for the core schema's lowercase `vector<...>`: written without
/// the `vector#1cb5c415` constructor id (count-prefixed bare vector),
/// while its elements stay boxed — each keeps its own constructor id
/// (production-verified by td's hand-parsed `future_salts`).
pub fn isBareVector(expr: *const ast.TypeExpr) bool {
    return std.mem.eql(u8, expr.name, "vector") and expr.arg != null;
}

/// True when the expression references a generic type variable (`X`/`!X`):
/// generated code represents these as opaque, pre-serialized TL bytes.
pub fn isTypeVarRef(expr: *const ast.TypeExpr) bool {
    if (expr.var_args.len > 0) return true;
    if (expr.arg) |a| return isTypeVarRef(a);
    return scalarZigType(expr.name) == null and !isQualified(expr.name) and
        !std.mem.eql(u8, expr.name, "Vector") and expr.name.len == 1;
}

fn isQualified(name: []const u8) bool {
    return std.mem.indexOfScalar(u8, name, '.') != null;
}

/// Maps a TL type expression to a Zig type expression (allocated from
/// `allocator`). Named combinator types keep their TL path (`users.Users`),
/// which matches the nested namespace structs the emitter generates.
pub fn zigType(allocator: std.mem.Allocator, expr: *const ast.TypeExpr) std.mem.Allocator.Error![]const u8 {
    if (isVector(expr)) return zigSlice(allocator, expr.arg.?);
    if (isTypeVarRef(expr)) return "[]const u8";
    if (scalarZigType(expr.name)) |s| return s;
    return expr.name; // named (possibly namespaced) combinator type
}

fn zigSlice(allocator: std.mem.Allocator, elem: *const ast.TypeExpr) std.mem.Allocator.Error![]const u8 {
    const inner = try zigType(allocator, elem);
    const out = try allocator.alloc(u8, inner.len + 2);
    out[0] = '[';
    out[1] = ']';
    @memcpy(out[2..], inner);
    return out;
}

/// True when the combinator is generic (binds `{X:Type}`, has an iterative
/// `[ t ]` body, or mentions a type variable anywhere in its signature).
/// Generic combinators (`vector`, `invokeWithLayer` wrappers) are not
/// emitted as structs; `Vector<T>` is mapped to native slices and wrapper
/// functions are left to the future RPC layer.
pub fn isGeneric(c: *const ast.Constructor) bool {
    if (c.result_type.var_args.len > 0) return true;
    for (c.params) |p| {
        if (p.is_type_var or p.iterative) return true;
        if (exprMentionsVar(&p.type_expr)) return true;
    }
    return exprMentionsVar(&c.result_type);
}

fn exprMentionsVar(expr: *const ast.TypeExpr) bool {
    if (expr.bang) return true;
    if (expr.var_args.len > 0) return true;
    if (expr.arg) |a| {
        if (exprMentionsVar(a)) return true;
    }
    // A bare single-letter, non-primitive name inside an angle argument is
    // a variable reference (`Vector<X>` in a wrapper signature).
    if (isVector(expr) and expr.arg != null and
        scalarZigType(expr.arg.?.name) == null and !isQualified(expr.arg.?.name) and
        expr.arg.?.name.len == 1 and !std.mem.eql(u8, expr.arg.?.name, "Vector"))
    {
        return true;
    }
    return false;
}

/// Namespace prefix of a dot-separated name ("" when top-level).
pub fn namespaceOf(name: []const u8) []const u8 {
    const i = std.mem.indexOfScalar(u8, name, '.') orelse return "";
    return name[0..i];
}

/// Last path segment of a dot-separated name.
pub fn lastSegment(name: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, name, '.') orelse return name;
    return name[i + 1 ..];
}

// ---------------------------------------------------------------- tests

test "ident escaping" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expectEqualStrings("flags", try ident(a, "flags"));
    try std.testing.expectEqualStrings("long_", try ident(a, "long"));
    try std.testing.expectEqualStrings("type_", try ident(a, "type"));
}

test "scalar type mapping" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expectEqualStrings("i64", try zigType(a, &.{ .name = "long" }));
    try std.testing.expectEqualStrings("[]const u8", try zigType(a, &.{ .name = "string" }));
    const vec = ast.TypeExpr{ .name = "Vector", .arg = &.{ .name = "int" } };
    try std.testing.expectEqualStrings("[]i32", try zigType(a, &vec));
    const nested = ast.TypeExpr{ .name = "Vector", .arg = &vec };
    try std.testing.expectEqualStrings("[][]i32", try zigType(a, &nested));
    try std.testing.expectEqualStrings("users.User", try zigType(a, &.{ .name = "users.User" }));
}

test "namespace helpers" {
    try std.testing.expectEqualStrings("users", namespaceOf("users.getUsers"));
    try std.testing.expectEqualStrings("", namespaceOf("user"));
    try std.testing.expectEqualStrings("getUsers", lastSegment("users.getUsers"));
    try std.testing.expectEqualStrings("user", lastSegment("user"));
}

test "generic detection" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const parse = @import("../parser.zig").Parser.init;

    var p1 = parse("foo#1 a:int = Foo;");
    const simple = try p1.constructor(a);
    try std.testing.expect(!isGeneric(&simple));

    var p2 = parse("vector#1cb5c415 {t:Type} # [ t ] = Vector t;");
    const vector = try p2.constructor(a);
    try std.testing.expect(isGeneric(&vector));

    var p3 = parse("invokeAfterMsg#cb9f372d {X:Type} msg_id:long query:!X = X;");
    const wrapper = try p3.constructor(a);
    try std.testing.expect(isGeneric(&wrapper));
}
