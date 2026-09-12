//! AST for TL schema definitions.
//!
//! Pipeline: schema text → lexer/parser (`parser.zig`) → these AST nodes →
//! validation (`validate.zig`) → (future) Zig code generator. The AST
//! deliberately mirrors TL syntax so the generator, not the parser, decides
//! how types map to Zig.
//!
//! All string fields are **borrows** into the schema source text; the owning
//! `Schema` (see `schema.zig`) only allocates the node arrays themselves
//! (through its arena).

/// A reference to a TL type.
///
/// Covers: `int`, `User`, `users.User`, `Vector<int>` (`arg`), `Vector t`
/// (`var_args`), `%BareType` (`bare`), and expression references `!X`
/// (`bang`, used by generic wrappers such as `invokeAfterMsg`).
pub const TypeExpr = struct {
    /// Full (possibly namespaced) type name as written, e.g. `"users.User"`,
    /// or a type-variable name such as `"X"`.
    name: []const u8,
    /// Angle-bracket generic argument, the `int` in `Vector<int>`.
    /// At most one nesting level appears per application; deeper nesting
    /// (`Vector<Vector<int>>`) is represented via `arg.arg`.
    arg: ?*const TypeExpr = null,
    /// Trailing type-variable arguments, the `t` in `Vector t`
    /// (only used by generic combinators such as `vector#1cb5c415`).
    var_args: []const *const TypeExpr = &.{},
    /// True when the type was written with the `%` bare-type marker.
    bare: bool = false,
    /// True when the type was written with the `!` expression marker
    /// (a combinator application reference), e.g. `query:!X`.
    bang: bool = false,
};

/// One argument of a combinator declaration.
pub const Param = struct {
    /// Field name, `"#"` for the natural-number flags field and for the
    /// anonymous natural argument of `vector#1cb5c415`, or `""` for the
    /// anonymous arguments of an iterative `[ ... ]` body.
    name: []const u8,
    type_expr: TypeExpr,

    /// For optional fields `flags.N?T`: the name of the referenced flags
    /// parameter and the 0-based bit index within it.
    flags_field: ?[]const u8 = null,
    flag_index: ?u6 = null,

    /// Declared inside `{X:Type}` — a generic type parameter of this
    /// combinator (e.g. the `X` of `invokeAfterMsg`).
    is_type_var: bool = false,
    /// Part of an iterative `[ ... ]` argument body (e.g. the `[ t ]` of
    /// `vector#1cb5c415`). Iterative params are anonymous.
    iterative: bool = false,

    pub fn isFlagsField(self: Param) bool {
        return std.mem.eql(u8, self.type_expr.name, "#");
    }
};

/// A single combinator declaration:
/// `name#id args* = ResultType;`
///
/// Covers both type constructors and (after the `---functions---` marker
/// in a schema file) RPC functions; the distinction is positional and is
/// recorded by `Schema` splitting the declarations into two slices.
pub const Constructor = struct {
    /// Constructor id exactly as in the schema, preserved as an unsigned
    /// 32-bit value (the value that goes on the wire). For declarations
    /// written without an explicit `#id` this is the crc32 of the
    /// canonical serialization string (see `parser.zig canonicalId`).
    id: u32,
    /// Full (possibly namespaced) constructor name, e.g. `"users.getUsers"`.
    name: []const u8,
    params: []Param,
    result_type: TypeExpr,
    /// True for core bare type declarations (`int ? = Int;`) — placeholders
    /// for the built-in primitives, never emitted as structs or unions.
    core_bare: bool = false,
};

const std = @import("std");

test "param flags helpers" {
    const p = Param{ .name = "first_name", .type_expr = .{ .name = "string" }, .flags_field = "flags", .flag_index = 1 };
    try std.testing.expect(!p.isFlagsField());
    const flags = Param{ .name = "flags", .type_expr = .{ .name = "#" } };
    try std.testing.expect(flags.isFlagsField());
}
