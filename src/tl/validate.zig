//! Semantic validation of a parsed TL schema.
//!
//! Runs after parsing and before any (future) code generation:
//!     TL schema → lexer/parser → AST → **validation** → code generator
//!
//! Checks performed:
//!  * constructor ids are globally unique across constructors and functions
//!    (ids are CRC-like wire identifiers; duplicates would be ambiguous)
//!  * constructor full names are globally unique
//!  * every type-variable reference resolves to a `{X:Type}` parameter of
//!    the same combinator (a bare single-letter name used as a type is
//!    treated as a variable reference, matching TL convention — concrete
//!    types in Telegram's schema are always longer)
//!
//! Flag-field references (`flags.N?T`) are validated during parsing
//! (see `parser.zig checkFlagsRef`) because they are local to one
//! declaration; this module covers schema-wide invariants.

const std = @import("std");
const ast = @import("types.zig");
const Schema = @import("schema.zig").Schema;

pub const IssueKind = enum {
    duplicate_id,
    duplicate_name,
    unknown_type_var,
};

pub const Issue = struct {
    kind: IssueKind,
    /// Full name of the offending declaration (borrows from schema source).
    constructor: []const u8,
    /// The duplicated/unresolved identifier (borrows from schema source).
    detail: []const u8,
};

const Ctx = struct {
    allocator: std.mem.Allocator,
    issues: *std.ArrayList(Issue),
    valid: bool = true,

    fn report(self: *Ctx, kind: IssueKind, constructor: []const u8, detail: []const u8) void {
        self.issues.append(self.allocator, .{
            .kind = kind,
            .constructor = constructor,
            .detail = detail,
        }) catch return; // allocation failure: drop the report, stay valid=false
        self.valid = false;
    }
};

/// Appends every issue found to `issues` (caller-owned list, freed with the
/// same allocator). Returns true when the schema is valid.
pub fn validate(allocator: std.mem.Allocator, schema: *const Schema, issues: *std.ArrayList(Issue)) bool {
    var ctx = Ctx{ .allocator = allocator, .issues = issues };
    var ids = std.AutoHashMap(u32, []const u8).init(allocator);
    defer ids.deinit();
    var names = std.StringHashMap([]const u8).init(allocator);
    defer names.deinit();

    for ([_][]const ast.Constructor{ schema.constructors, schema.functions }) |decls| {
        for (decls) |*c| {
            checkDuplicate(&ids, c.id, c, &ctx, .duplicate_id);
            checkDuplicate(&names, c.name, c, &ctx, .duplicate_name);
            checkTypeVars(c, &ctx);
        }
    }
    return ctx.valid;
}

fn checkDuplicate(map: anytype, key: anytype, c: *const ast.Constructor, ctx: *Ctx, kind: IssueKind) void {
    const gop = map.getOrPut(key) catch return; // allocation failure: skip check
    if (gop.found_existing) {
        ctx.report(kind, c.name, gop.value_ptr.*);
    } else {
        gop.value_ptr.* = c.name;
    }
}

/// True when a name should be treated as a type-variable reference:
/// a single letter (concrete type names in Telegram's schema are longer).
fn looksLikeTypeVar(name: []const u8) bool {
    return name.len == 1 and std.ascii.isAlphabetic(name[0]);
}

fn checkTypeVars(c: *const ast.Constructor, ctx: *Ctx) void {
    for (c.params) |p| {
        if (!p.is_type_var) checkExpr(c, &p.type_expr, ctx);
    }
    checkExpr(c, &c.result_type, ctx);
}

fn declaredVar(c: *const ast.Constructor, name: []const u8) bool {
    for (c.params) |p| {
        if (p.is_type_var and std.mem.eql(u8, p.name, name)) return true;
    }
    return false;
}

fn checkExpr(c: *const ast.Constructor, expr: *const ast.TypeExpr, ctx: *Ctx) void {
    if (looksLikeTypeVar(expr.name) and !declaredVar(c, expr.name)) {
        ctx.report(.unknown_type_var, c.name, expr.name);
    }
    if (expr.arg) |child| checkExpr(c, child, ctx);
    for (expr.var_args) |child| checkExpr(c, child, ctx);
}

// ---------------------------------------------------------------- tests

fn expectIssues(src: []const u8, want_kinds: []const IssueKind) !void {
    var schema = try @import("schema.zig").parse(std.testing.allocator, src);
    defer schema.deinit();

    var issues: std.ArrayList(Issue) = .empty;
    defer issues.deinit(std.testing.allocator);
    const ok = validate(std.testing.allocator, &schema, &issues);
    try std.testing.expectEqual(@as(usize, want_kinds.len), issues.items.len);
    for (issues.items, want_kinds) |got, want| try std.testing.expectEqual(want, got.kind);
    try std.testing.expect(ok == (want_kinds.len == 0));
}

test "valid schema produces no issues" {
    try expectIssues("foo#1 a:int = Foo; bar#2 b:Vector<int> = Bar;", &.{});
}

test "generic schema produces no issues" {
    try expectIssues(
        "vector#1cb5c415 {t:Type} # [ t ] = Vector t;\n" ++
            "invokeAfterMsg#cb9f372d {X:Type} msg_id:long query:!X = X;",
        &.{},
    );
}

test "duplicate id" {
    try expectIssues("foo#1 a:int = Foo; bar#1 b:int = Bar;", &.{.duplicate_id});
}

test "duplicate name" {
    try expectIssues("foo#1 a:int = Foo; foo#2 b:int = Bar;", &.{.duplicate_name});
}

test "undeclared type variable reference" {
    try expectIssues("foo#1 {X:Type} q:!Y = X;", &.{.unknown_type_var});
}

test "undeclared type variable in result" {
    try expectIssues("foo#1 a:int = Z;", &.{.unknown_type_var});
}
