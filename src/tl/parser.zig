//! TL schema lexer + recursive-descent parser producing the AST in `types.zig`.
//!
//! Grammar (practical TL as used by Telegram's official schema files,
//! see https://core.telegram.org/mtproto/TL):
//!
//!   schema       := { combinator | sectionMarker } EOF
//!   sectionMarker:= '---functions---'          (handled by schema.zig)
//!   combinator   := fullName '#' hexId arg* '=' typeExpr ';'
//!   arg          := '{' ident ':' typeRef '}'   // generic type parameter
//!                 | '[' typeExpr+ ']'           // iterative body
//!                 | '#'                         // anonymous natural arg
//!                 | (ident | '#') ':' typeExpr
//!   paramType    := [flagsRef '?'] typeExpr
//!   flagsRef     := ident '.' bit
//!   typeExpr     := ['!'] ['%'] qualifiedName [ '<' typeExpr '>' | typeVar+ ]
//!
//! Supported: namespaces, primitive/qualified types, nested vectors,
//! `flags.N?T` optional fields, `%BareType`, `!X` expression references,
//! `{X:Type}` generic parameters, `[ t ]` iterative bodies, trailing
//! type-variable arguments (`Vector t`), `//` and `/* */` comments,
//! multiline definitions and arbitrary whitespace.
//!
//! Not supported (rejected with explicit errors, never mis-parsed):
//!   * a `{X:...}` binding whose constraint is not `Type` or a declared var
//!   * more than 8 type parameters per combinator (real schemas use <= 1)

const std = @import("std");
const ast = @import("types.zig");
const err = @import("../errors.zig");
const ParseError = err.ParseError;

/// Type-variable names bound for the combinator currently being parsed.
/// Small fixed capacity: real schemas bind at most one or two.
const TypeVars = struct {
    names: [8][]const u8 = undefined,
    len: usize = 0,

    fn push(self: *TypeVars, name: []const u8) ParseError!void {
        if (self.len == self.names.len) return error.UnsupportedSyntax;
        self.names[self.len] = name;
        self.len += 1;
    }

    fn contains(self: *const TypeVars, name: []const u8) bool {
        for (self.names[0..self.len]) |n| {
            if (std.mem.eql(u8, n, name)) return true;
        }
        return false;
    }
};

pub const Parser = struct {
    src: []const u8,
    pos: usize = 0,
    line: usize = 1,
    col: usize = 1,
    /// Context for the most recent error returned by `parseSchema`.
    last_diagnostic: err.Diagnostic = .{},

    pub fn init(src: []const u8) Parser {
        return .{ .src = src };
    }

    fn fail(self: *Parser, message: []const u8) ParseError {
        self.last_diagnostic = .{ .line = self.line, .column = self.col, .message = message };
        return error.InvalidSchema;
    }

    fn failUnsupported(self: *Parser, message: []const u8) ParseError {
        self.last_diagnostic = .{ .line = self.line, .column = self.col, .message = message };
        return error.UnsupportedSyntax;
    }

    pub fn peek(self: *const Parser) ?u8 {
        if (self.pos >= self.src.len) return null;
        return self.src[self.pos];
    }

    pub fn advance(self: *Parser) ?u8 {
        const c = self.peek() orelse return null;
        self.pos += 1;
        if (c == '\n') {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        return c;
    }

    fn skip(self: *Parser, c: u8) bool {
        if (self.peek() == c) {
            _ = self.advance();
            return true;
        }
        return false;
    }

    fn expect(self: *Parser, comptime c: u8) ParseError!void {
        if (!self.skip(c)) return self.fail("expected '" ++ [1]u8{c} ++ "'");
    }

    fn isIdentChar(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '_' or c == '.';
    }

    pub fn skipTrivia(self: *Parser) ParseError!void {
        while (self.peek()) |c| {
            if (std.ascii.isWhitespace(c)) {
                _ = self.advance();
            } else if (c == '/' and self.pos + 1 < self.src.len and self.src[self.pos + 1] == '/') {
                while (self.peek()) |lc| {
                    if (lc == '\n') break;
                    _ = self.advance();
                }
            } else if (c == '/' and self.pos + 1 < self.src.len and self.src[self.pos + 1] == '*') {
                _ = self.advance();
                _ = self.advance();
                var closed = false;
                while (self.advance()) |bc| {
                    if (bc == '*' and self.peek() == '/') {
                        _ = self.advance();
                        closed = true;
                        break;
                    }
                }
                if (!closed) return self.fail("unterminated block comment");
            } else {
                return;
            }
        }
    }

    /// Reads an identifier possibly containing '.' namespace separators.
    /// The returned slice borrows from the source text.
    fn ident(self: *Parser) ParseError![]const u8 {
        const start = self.pos;
        while (self.peek()) |c| {
            if (!isIdentChar(c)) break;
            _ = self.advance();
        }
        if (self.pos == start) return self.fail("expected identifier");
        return self.src[start..self.pos];
    }

    /// Parses a type reference. `vars` holds the generic type parameters
    /// bound by the enclosing combinator; trailing bare identifiers are only
    /// consumed as arguments when they name a bound variable (this is how
    /// `Vector t` is distinguished from the next parameter).
    fn typeExpr(self: *Parser, allocator: std.mem.Allocator, vars: *const TypeVars) ParseError!ast.TypeExpr {
        var expr = ast.TypeExpr{ .name = "" };
        if (self.skip('!')) {
            expr.bang = true;
        } else if (self.skip('%')) {
            expr.bare = true;
        }
        expr.name = try self.ident();

        if (self.skip('<')) {
            const child = allocator.create(ast.TypeExpr) catch return error.OutOfMemory;
            child.* = try self.typeExpr(allocator, vars);
            expr.arg = child;
            try self.expect('>');
        } else {
            // Trailing type-variable arguments: `Vector t`.
            var args: std.ArrayList(*const ast.TypeExpr) = .empty;
            while (true) {
                const save = self.*;
                try self.skipTrivia();
                const start = self.pos;
                if (self.peek() == null or !isIdentChar(self.peek().?) or self.peek().? == '.') {
                    self.* = save;
                    break;
                }
                while (self.peek()) |c| {
                    if (!isIdentChar(c)) break;
                    _ = self.advance();
                }
                const name = self.src[start..self.pos];
                if (vars.contains(name)) {
                    const child = allocator.create(ast.TypeExpr) catch return error.OutOfMemory;
                    child.* = .{ .name = name };
                    args.append(allocator, child) catch return error.OutOfMemory;
                } else {
                    self.* = save;
                    break;
                }
            }
            if (args.items.len > 0) {
                expr.var_args = args.toOwnedSlice(allocator) catch return error.OutOfMemory;
            } else {
                args.deinit(allocator);
            }
        }
        return expr;
    }

    /// Parses one `name:type` parameter, including `flags.N?T` optionals and
    /// the natural-number type written as `#` (e.g. `flags:#`).
    fn param(self: *Parser, allocator: std.mem.Allocator, vars: *const TypeVars) ParseError!ast.Param {
        const name = try self.ident();
        try self.expect(':');

        if (self.skip('#')) {
            return .{ .name = name, .type_expr = .{ .name = "#" } };
        }

        // Optional field: flags_field.bit?T
        if (try self.tryFlagsRef()) |ref| {
            return .{
                .name = name,
                .type_expr = try self.typeExpr(allocator, vars),
                .flags_field = ref.field,
                .flag_index = ref.index,
            };
        }
        return .{ .name = name, .type_expr = try self.typeExpr(allocator, vars) };
    }

    const FlagsRef = struct { field: []const u8, index: u6 };

    /// Attempts `name.N?` at the cursor; on success consumes up to and
    /// including '?'. Returns null (cursor untouched) if not present.
    /// The field name here must not contain '.' (unlike a plain ident, so
    /// that `flags.0?long` is not swallowed as one identifier).
    fn tryFlagsRef(self: *Parser) ParseError!?FlagsRef {
        const save = self.*;

        const field: ?[]const u8 = blk: {
            if (self.peek() != null and isIdentChar(self.peek().?) and self.peek().? != '.') {
                const start = self.pos;
                while (self.peek()) |c| {
                    if (!isIdentChar(c) or c == '.') break;
                    _ = self.advance();
                }
                break :blk self.src[start..self.pos];
            }
            break :blk null;
        };
        if (field == null or self.peek() != '.') {
            self.* = save;
            return null;
        }
        _ = self.advance(); // '.'
        const digit_start = self.pos;
        while (self.peek()) |c| {
            if (!std.ascii.isDigit(c)) break;
            _ = self.advance();
        }
        if (self.pos == digit_start or self.pos - digit_start > 2) {
            self.* = save;
            return null;
        }
        const index = std.fmt.parseInt(u6, self.src[digit_start..self.pos], 10) catch {
            self.* = save;
            return null;
        };
        if (self.peek() != '?') {
            self.* = save;
            return null;
        }
        _ = self.advance(); // '?'
        return .{ .field = field.?, .index = index };
    }

    /// Parses one combinator declaration. Strings borrow from `p.src`.
    /// Leading trivia/comments are skipped.
    ///
    /// The `#hex` id is optional in the core-MTProto dialect
    /// (`tlsBlockDomain = TlBlock;`, `int ? = Int;`,
    /// `vector {t:Type} # [ t ] = Vector t;`); when absent the id is the
    /// crc32 of the declaration's canonical serialization string, the same
    /// rule Telegram Desktop's scheme generator (desktop-app/lib_tl) uses.
    pub fn constructor(self: *Parser, allocator: std.mem.Allocator) ParseError!ast.Constructor {
        try self.skipTrivia();
        const decl_start = self.pos;
        const name = try self.ident();

        var explicit_id: ?u32 = null;
        if (self.peek() == '#') {
            _ = self.advance();
            const hex_start = self.pos;
            while (self.peek()) |c| {
                if (!std.ascii.isHex(c)) break;
                _ = self.advance();
            }
            const hex = self.src[hex_start..self.pos];
            if (hex.len == 0 or hex.len > 8) {
                self.last_diagnostic = .{ .line = self.line, .column = self.col, .message = "constructor id must be 1..8 hex digits" };
                return error.InvalidConstructorId;
            }
            explicit_id = std.fmt.parseInt(u32, hex, 16) catch {
                self.last_diagnostic = .{ .line = self.line, .column = self.col, .message = "constructor id out of u32 range" };
                return error.InvalidConstructorId;
            };
        }
        // No `#id`: the core-MTProto dialect writes plain constructors
        // (`tlsBlockString data:string = TlsBlock;`) whose id is computed
        // from the canonical serialization string after the `;`.

        var vars = TypeVars{};
        var core_bare = false;
        var params: std.ArrayList(ast.Param) = .empty;
        errdefer params.deinit(allocator);

        while (true) {
            try self.skipTrivia();
            const c = self.peek() orelse return self.fail("unexpected end of schema: expected '='");
            if (c == '=') break;

            switch (c) {
                // Core bare marker: `int ? = Int;`
                '?' => {
                    _ = self.advance();
                    core_bare = true;
                },
                // Generic type parameter: {X:Type}
                '{' => {
                    _ = self.advance();
                    const var_name = try self.ident();
                    try self.expect(':');
                    const constraint = try self.ident();
                    try self.expect('}');
                    if (!std.mem.eql(u8, constraint, "Type") and !vars.contains(constraint)) {
                        return self.fail("type parameter constraint must be 'Type' or a declared type variable");
                    }
                    try vars.push(var_name);
                    params.append(allocator, .{
                        .name = var_name,
                        .type_expr = .{ .name = constraint },
                        .is_type_var = true,
                    }) catch return error.OutOfMemory;
                },
                // Iterative body: [ t ], with the `N*[ t ]` repetition
                // form used by the core schema (`int128 4*[ int ]`).
                '[', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' => {
                    // `N*[ t ]` repetition form (int128 4*[ int ]): consume
                    // the count and its `*`, then the bracket itself.
                    while (std.ascii.isDigit(self.peek() orelse 0)) _ = self.advance();
                    _ = self.skip('*');
                    if (!self.skip('[')) return self.fail("expected '[' after repetition count");
                    while (true) {
                        try self.skipTrivia();
                        if (self.skip(']')) break;
                        if (self.peek() == null) return self.fail("unexpected end of schema inside '[...]'");
                        if (self.peek().? == '=') return self.fail("expected ']' before '='");
                        const e = try self.typeExpr(allocator, &vars);
                        params.append(allocator, .{
                            .name = "",
                            .type_expr = e,
                            .iterative = true,
                        }) catch return error.OutOfMemory;
                    }
                },
                // Anonymous natural argument (as in `vector#1cb5c415 {t:Type} # [ t ]`).
                '#' => {
                    _ = self.advance();
                    try self.skipTrivia();
                    if (self.peek() == ':') return self.failUnsupported("'#' is not a valid parameter name here");
                    params.append(allocator, .{
                        .name = "#",
                        .type_expr = .{ .name = "#" },
                    }) catch return error.OutOfMemory;
                },
                '!' => return self.failUnsupported("unexpected '!' at argument position"),
                else => {
                    const p = try self.param(allocator, &vars);
                    if (p.flag_index != null) try self.checkFlagsRef(params.items, p);
                    params.append(allocator, p) catch return error.OutOfMemory;
                },
            }
        }
        try self.expect('=');
        try self.skipTrivia();
        const result = try self.typeExpr(allocator, &vars);
        try self.skipTrivia();
        try self.expect(';');

        const id = explicit_id orelse canonicalId(allocator, self.src[decl_start..self.pos]);

        return .{
            .id = id,
            .name = name,
            .params = params.toOwnedSlice(allocator) catch return error.OutOfMemory,
            .result_type = result,
            .core_bare = core_bare,
        };
    }

    /// A `flags.N?T` field must reference an earlier `flags:#` parameter,
    /// where N names a valid bit (0..31).
    fn checkFlagsRef(self: *Parser, params: []const ast.Param, p: ast.Param) ParseError!void {
        if (p.flag_index.? > 31) return self.fail("flag bit index must be 0..31");
        for (params) |q| {
            if (q.isFlagsField() and std.mem.eql(u8, q.name, p.flags_field.?)) return;
        }
        return self.fail("optional field references unknown flags field");
    }
};

/// CRC32 of a declaration's canonical serialization string — the wire id
/// Telegram's own scheme generator (desktop-app/lib_tl `generate_tl.py`)
/// computes for constructors written without an explicit `#id`
/// (`tlsBlockDomain = TlBlock;`, the core `int ? = Int;`,
/// `vector {t:Type} # [ t ] = Vector t;`).
///
/// Canonical form, in order: name and parameters as written with all
/// whitespace collapsed; `flags.N?true` arguments dropped (they encode as
/// flag bits only); `<`/`>` angle brackets replaced by spaces;
/// `bytes` aliased to `string`; `{x:Type}` braces stripped; single
/// spaces; no trailing `;`.
fn canonicalId(allocator: std.mem.Allocator, raw: []const u8) u32 {
    // Up to the terminating `;`, with whitespace runs collapsed to one space.
    const end = std.mem.indexOfScalar(u8, raw, ';') orelse raw.len;
    var line: std.ArrayList(u8) = .empty;
    var prev_ws = true; // trims the leading edge too
    for (raw[0..end]) |c| {
        if (std.ascii.isWhitespace(c)) {
            prev_ws = true;
            continue;
        }
        if (prev_ws and line.items.len > 0) line.append(allocator, ' ') catch unreachable;
        line.append(allocator, c) catch unreachable;
        prev_ws = false;
    }

    // Drop `name:flags.N?true` arguments, token-wise.
    var args: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, line.items, ' ');
    while (it.next()) |tok| {
        if (isTrueFlagArg(tok)) continue;
        if (args.items.len > 0) args.append(allocator, ' ') catch unreachable;
        args.appendSlice(allocator, tok) catch unreachable;
    }

    // Angle brackets become spaces; collapse the doubles that creates.
    for (args.items) |*c| {
        if (c.* == '<' or c.* == '>') c.* = ' ';
    }
    const collapsed_len = std.mem.replacementSize(u8, args.items, "  ", " ");
    const out = allocator.alloc(u8, collapsed_len) catch unreachable;
    _ = std.mem.replace(u8, args.items, "  ", " ", out);
    var s = std.mem.trim(u8, out[0..collapsed_len], " ");

    // `bytes` is serialized exactly like `string`.
    var aliased: std.ArrayList(u8) = .empty;
    aliased.appendSlice(allocator, s) catch unreachable;
    inline for (.{ ":bytes ", "?bytes " }) |pat| {
        const rep = comptime pat[0 .. pat.len - "bytes ".len] ++ "string ";
        const needed = std.mem.replacementSize(u8, aliased.items, pat, rep);
        const tmp = allocator.alloc(u8, needed) catch unreachable;
        _ = std.mem.replace(u8, aliased.items, pat, rep, tmp);
        aliased.clearRetainingCapacity();
        aliased.appendSlice(allocator, tmp) catch unreachable;
    }
    s = aliased.items;

    // Braces around generic parameter bindings are dropped.
    var final: std.ArrayList(u8) = .empty;
    for (s) |c| {
        if (c == '{' or c == '}') continue;
        final.append(allocator, c) catch unreachable;
    }
    return std.hash.crc.Crc32.hash(final.items);
}

/// True for the token form `name:flags.N?true` (historically `flags2.N`):
/// an argument that encodes as a flag bit only and is omitted from the
/// canonical serialization string.
fn isTrueFlagArg(tok: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, tok, ':') orelse return false;
    var t = tok[colon + 1 ..];
    if (!std.mem.startsWith(u8, t, "flags")) return false;
    t = t["flags".len..];
    if (std.mem.startsWith(u8, t, "2")) t = t[1..];
    if (!std.mem.startsWith(u8, t, ".")) return false;
    t = t[1..];
    var rest = t;
    while (rest.len > 0 and std.ascii.isDigit(rest[0])) rest = rest[1..];
    if (rest.len == t.len) return false; // no flag index digits
    return std.mem.eql(u8, rest, "?true");
}

// ---------------------------------------------------------------- tests

fn expectSingle(src: []const u8, id: u32, name: []const u8, params: []const ast.Param, result: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init(src);
    const got = try p.constructor(arena.allocator());
    try std.testing.expectEqual(id, got.id);
    try std.testing.expectEqualStrings(name, got.name);
    try std.testing.expectEqualStrings(result, got.result_type.name);
    try std.testing.expectEqual(params.len, got.params.len);
    for (params, got.params) |w, g| {
        try std.testing.expectEqualStrings(w.name, g.name);
        try std.testing.expectEqualStrings(w.type_expr.name, g.type_expr.name);
        try std.testing.expectEqual(w.flag_index, g.flag_index);
        try std.testing.expectEqual(w.is_type_var, g.is_type_var);
        try std.testing.expectEqual(w.iterative, g.iterative);
    }
}

test "simple constructor" {
    try expectSingle("foo#12345678 id:int = Foo;", 0x12345678, "foo", &.{
        .{ .name = "id", .type_expr = .{ .name = "int" } },
    }, "Foo");
}

test "zero-parameter constructor" {
    try expectSingle("boolFalse#bc799737 = Bool;", 0xbc799737, "boolFalse", &.{}, "Bool");
}

test "vector param and namespaced result" {
    try expectSingle("users.getUsers#d91a548 id:Vector<InputUser> = users.Users;", 0x0d91a548, "users.getUsers", &.{
        .{ .name = "id", .type_expr = .{ .name = "Vector", .arg = &.{ .name = "InputUser" } } },
    }, "users.Users");
}

test "nested vector generics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init("foo#1 x:Vector<Vector<PhotoSize>> = Foo;");
    const c = try p.constructor(arena.allocator());
    const outer = c.params[0].type_expr;
    try std.testing.expectEqualStrings("Vector", outer.name);
    try std.testing.expectEqualStrings("Vector", outer.arg.?.name);
    try std.testing.expectEqualStrings("PhotoSize", outer.arg.?.arg.?.name);
}

test "flags field and optional params" {
    try expectSingle("user#d10d979a flags:# first_name:flags.1?string = User;", 0xd10d979a, "user", &.{
        .{ .name = "flags", .type_expr = .{ .name = "#" } },
        .{ .name = "first_name", .type_expr = .{ .name = "string" }, .flags_field = "flags", .flag_index = 1 },
    }, "User");
}

test "full user example" {
    const src =
        \\user#d10d979a flags:# id:long access_hash:flags.0?long
        \\    first_name:flags.1?string last_name:flags.2?string = User;
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init(src);
    const c = try p.constructor(arena.allocator());
    try std.testing.expectEqual(@as(usize, 5), c.params.len);
    try std.testing.expect(c.params[0].isFlagsField());
    try std.testing.expectEqualStrings("access_hash", c.params[2].name);
    try std.testing.expectEqual(@as(?u6, 0), c.params[2].flag_index);
}

test "generic combinator: vector builtin" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init("vector#1cb5c415 {t:Type} # [ t ] = Vector t;");
    const c = try p.constructor(arena.allocator());
    try std.testing.expectEqual(@as(u32, 0x1cb5c415), c.id);
    try std.testing.expectEqual(@as(usize, 3), c.params.len);

    const tv = c.params[0];
    try std.testing.expect(tv.is_type_var);
    try std.testing.expectEqualStrings("t", tv.name);
    try std.testing.expectEqualStrings("Type", tv.type_expr.name);

    const nat = c.params[1];
    try std.testing.expectEqualStrings("#", nat.name);
    try std.testing.expect(nat.isFlagsField()); // natural type, same representation

    const it = c.params[2];
    try std.testing.expect(it.iterative);
    try std.testing.expectEqualStrings("t", it.type_expr.name);

    try std.testing.expectEqualStrings("Vector", c.result_type.name);
    try std.testing.expectEqual(@as(usize, 1), c.result_type.var_args.len);
    try std.testing.expectEqualStrings("t", c.result_type.var_args[0].name);
}

test "generic wrapper with bang type" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init("invokeAfterMsg#cb9f372d {X:Type} msg_id:long query:!X = X;");
    const c = try p.constructor(arena.allocator());
    try std.testing.expect(c.params[0].is_type_var);
    try std.testing.expectEqualStrings("msg_id", c.params[1].name);
    const q = c.params[2];
    try std.testing.expect(q.type_expr.bang);
    try std.testing.expectEqualStrings("X", q.type_expr.name);
    try std.testing.expectEqualStrings("X", c.result_type.name);
}

test "comments are skipped" {
    const src =
        "// leading comment\n" ++
        "foo#1 a:int = Foo; // trailing\n" ++
        "/* block\n comment */ bar#2 b:long = Bar;\n";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init(src);
    const first = try p.constructor(arena.allocator());
    try std.testing.expectEqualStrings("foo", first.name);
    const second = try p.constructor(arena.allocator());
    try std.testing.expectEqualStrings("bar", second.name);
}

test "invalid constructor id" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init("foo#zzz a:int = Foo;");
    try std.testing.expectError(error.InvalidConstructorId, p.constructor(arena.allocator()));
    var p2 = Parser.init("foo#123456789 a:int = Foo;");
    try std.testing.expectError(error.InvalidConstructorId, p2.constructor(arena.allocator()));
    var p3 = Parser.init("foo# a:int = Foo;");
    try std.testing.expectError(error.InvalidConstructorId, p3.constructor(arena.allocator()));
}

test "malformed schemas" {
    const cases = [_][]const u8{
        // Note: `foo a:int = Foo;` (missing '#') is *not* malformed — the
        // core-MTProto dialect writes id-less constructors and the id is
        // computed from the canonical string (see the core-dialect tests).
        "foo#1 int = Foo;", // missing ':'
        "foo#1 a:int Foo;", // missing '='
        "foo#1 a:int = Foo", // missing ';'
        "foo#1 a:flags.3?int = Foo;", // flags.3 not defined
        "foo#1 flags:# a:other.0?int = Foo;", // other is not a flags field
        "", // empty
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for (cases) |src| {
        var p = Parser.init(src);
        try std.testing.expectError(error.InvalidSchema, p.constructor(arena.allocator()));
    }
}

test "malformed generic syntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cases = [_]struct { src: []const u8, e: anyerror }{
        .{ .src = "foo#1 {X:int} q:!X = X;", .e = error.InvalidSchema }, // constraint must be Type
        .{ .src = "foo#1 {X:Type q:!X = X;", .e = error.InvalidSchema }, // unterminated '{'
        .{ .src = "foo#1 {X:Type} q:!X = X", .e = error.InvalidSchema }, // missing ';'
        .{ .src = "foo#1 {X:Type} [ X = X;", .e = error.InvalidSchema }, // unterminated '['
    };
    for (cases) |case| {
        var p = Parser.init(case.src);
        try std.testing.expectError(case.e, p.constructor(arena.allocator()));
    }
}

test "too many type variables is unsupported, not mis-parsed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = Parser.init("foo#1 {A:Type} {B:Type} {C:Type} {D:Type} {E:Type} {F:Type} {G:Type} {H:Type} {I:Type} q:!I = I;");
    try std.testing.expectError(error.UnsupportedSyntax, p.constructor(arena.allocator()));
}

test "constructor ids of one to eight hex digits parse exactly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // One digit: ids are u32 values, not fixed-width bit patterns.
    var p = Parser.init("a#0 = A;");
    try std.testing.expectEqual(@as(u32, 0), (try p.constructor(arena.allocator())).id);

    // Eight digits: the full u32 range, wire-exact.
    var p2 = Parser.init("max#ffffffff = Max;");
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), (try p2.constructor(arena.allocator())).id);

    // Case-insensitive hex, as real schema files mix it.
    var p3 = Parser.init("up#DEADBEEF = Up;");
    try std.testing.expectEqual(@as(u32, 0xdead_beef), (try p3.constructor(arena.allocator())).id);

    // Leading zeros count toward the eight-digit budget.
    var p4 = Parser.init("pad#0000002a = Pad;");
    try std.testing.expectEqual(@as(u32, 42), (try p4.constructor(arena.allocator())).id);

    // A ninth digit is a constructor-id error, never a silent truncation.
    var p5 = Parser.init("big#0ffffffff = Big;");
    try std.testing.expectError(error.InvalidConstructorId, p5.constructor(arena.allocator()));
}

test "core dialect: missing id computed from the canonical string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Ground-truth constants: `int` is TDLib's published magic; the
    // `tlsBlock*` and `vector` values were cross-checked against
    // Telegram Desktop's scheme generator.
    const cases = [_]struct { src: []const u8, id: u32 }{
        .{ .src = "int ? = Int;", .id = 0xa8509bda },
        .{ .src = "long ? = Long;", .id = 0x22076cba },
        .{ .src = "tlsBlockDomain = TlsBlock;", .id = 0x10e8636f },
        .{ .src = "tlsBlockPadding = TlsBlock;", .id = 0xa4357218 },
        .{ .src = "tlsBlockString data:string = TlsBlock;", .id = 0x4218a164 },
        .{ .src = "tlsBlockScope entries:Vector<TlsBlock> = TlsBlock;", .id = 0xe725d44f },
        .{ .src = "inputPhoto id:long access_hash:long file_reference:bytes = InputPhoto;", .id = 0x3bb3b94a },
        .{ .src = "vector {t:Type} # [ t ] = Vector t;", .id = 0x1cb5c415 },
    };
    for (cases) |case| {
        var p = Parser.init(case.src);
        const c = try p.constructor(arena.allocator());
        try std.testing.expectEqual(case.id, c.id);
    }
}

test "core dialect: bare marker, repetition body, explicit ids win" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // `?` marks a core bare type: not emittable.
    var p = Parser.init("int ? = Int;");
    const core = try p.constructor(arena.allocator());
    try std.testing.expect(core.core_bare);

    // `N*[ t ]` repetition body parses like an iterative body.
    var p2 = Parser.init("int128 4*[ int ] = Int128;");
    const int128_decl = try p2.constructor(arena.allocator());
    try std.testing.expectEqual(@as(usize, 1), int128_decl.params.len);
    try std.testing.expect(int128_decl.params[0].iterative);
    try std.testing.expectEqual(@as(u32, 0x84ccf7b7), int128_decl.id);

    // Explicit ids are taken verbatim even when they disagree with the
    // canonical computation (the schema is the wire authority).
    var p3 = Parser.init("weird#00000001 a:int = Weird;");
    try std.testing.expectEqual(@as(u32, 1), (try p3.constructor(arena.allocator())).id);
}
