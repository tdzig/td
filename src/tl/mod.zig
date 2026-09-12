//! Public TL subsystem: binary reader/writer primitives, the schema AST,
//! the TL schema parser, and schema validation.

pub const Writer = @import("writer.zig").Writer;
pub const Reader = @import("reader.zig").Reader;
pub const Constructor = @import("types.zig").Constructor;
pub const Param = @import("types.zig").Param;
pub const TypeExpr = @import("types.zig").TypeExpr;
pub const Schema = @import("schema.zig").Schema;
pub const Parser = @import("parser.zig").Parser;
pub const validate = @import("validate.zig");

/// Well-known constructor ids used by the binary layer.
pub const vector_constructor_id: u32 = 0x1cb5c415;
pub const bool_true_id: u32 = 0x997275b5;
pub const bool_false_id: u32 = 0xbc799737;

/// Parse a TL schema into an owned `Schema` (strings borrow from `src`).
pub const parseSchema = @import("schema.zig").parse;

/// TL → Zig code generator (AST → generated Zig source).
pub const codegen = @import("codegen/mod.zig");

test {
    _ = @import("writer.zig");
    _ = @import("reader.zig");
    _ = @import("parser.zig");
    _ = @import("schema.zig");
    _ = @import("types.zig");
    _ = @import("validate.zig");
    _ = @import("codegen/mod.zig");
    _ = @import("codegen/naming.zig");
    _ = @import("codegen/emit.zig");
}
