//! TL → Zig code generator: AST → generated Zig source.
//!
//! Pipeline position:
//!     TL schema → lexer/parser → AST → validation → **code generation**
//!
//! `generate` is deterministic: the same validated schema and options always
//! produce byte-identical output. The returned source is allocated from the
//! caller's allocator and owned by the caller.

const std = @import("std");
const Schema = @import("../schema.zig").Schema;
const validate = @import("../validate.zig");
pub const naming = @import("naming.zig");
pub const emit = @import("emit.zig");

pub const Options = emit.Options;
pub const Emitter = emit.Emitter;
pub const OutputFile = emit.OutputFile;

pub const Error = error{
    OutOfMemory,
    /// The schema failed semantic validation; codegen refuses to run.
    InvalidSchema,
};

/// Runs semantic validation, reporting the first issues to
/// `diagnostics_out` (if non-null) as human-readable lines.
/// Returns true when the schema is valid.
fn checkValid(
    allocator: std.mem.Allocator,
    schema: *const Schema,
    diagnostics_out: ?*std.ArrayList(u8),
) Error!bool {
    var issues: std.ArrayList(validate.Issue) = .empty;
    defer issues.deinit(allocator);
    if (validate.validate(allocator, schema, &issues)) return true;
    if (diagnostics_out) |dst| {
        for (issues.items) |issue| {
            const msg = std.fmt.allocPrint(allocator, "{s}: {s} ({s})\n", .{ @tagName(issue.kind), issue.constructor, issue.detail }) catch return error.OutOfMemory;
            defer allocator.free(msg);
            dst.appendSlice(allocator, msg) catch return error.OutOfMemory;
        }
    }
    return false;
}

/// Validates `schema`, then generates Zig source for it.
/// On validation failure the first issues are written to `diagnostics_out`
/// (if non-null) as human-readable lines.
pub fn generate(
    allocator: std.mem.Allocator,
    schema: *const Schema,
    opts: Options,
    diagnostics_out: ?*std.ArrayList(u8),
) Error![]u8 {
    if (!try checkValid(allocator, schema, diagnostics_out)) return error.InvalidSchema;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var emitter = Emitter{
        .allocator = arena.allocator(),
        .opts = opts,
        .schema = schema,
    };
    const src = emitter.emit() catch return error.OutOfMemory;
    const owned = allocator.dupe(u8, src) catch return error.OutOfMemory;
    return owned;
}

/// Split-mode variant of `generate`: validates `schema`, then emits the
/// tree layout — the entry module (`opts.root_name`, default `mod.zig`)
/// re-exporting every declaration with the single-file surface,
/// `types/<group>.zig` files (result-type unions together with their
/// constructors, grouped by TL namespace and, for the root namespace,
/// thematically), `functions/<namespace>.zig` files, the two index
/// modules, and `registry.zig` (wire-id table). File names are relative
/// to the output root (`types/users.zig`). The caller owns the returned
/// slice and each file's `name`/`src` buffers; free them with
/// `allocator`.
pub fn generateMulti(
    allocator: std.mem.Allocator,
    schema: *const Schema,
    opts: Options,
    diagnostics_out: ?*std.ArrayList(u8),
) Error![]OutputFile {
    if (!try checkValid(allocator, schema, diagnostics_out)) return error.InvalidSchema;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var emitter = Emitter{
        .allocator = arena.allocator(),
        .opts = opts,
        .schema = schema,
    };
    const files = emitter.emitSplit() catch return error.OutOfMemory;

    const owned = allocator.alloc(OutputFile, files.len) catch return error.OutOfMemory;
    var filled: usize = 0;
    errdefer {
        for (owned[0..filled]) |f| {
            allocator.free(f.name);
            allocator.free(f.src);
        }
        allocator.free(owned);
    }
    for (files, 0..) |f, i| {
        owned[i] = .{
            .name = allocator.dupe(u8, f.name) catch return error.OutOfMemory,
            .src = allocator.dupe(u8, f.src) catch return error.OutOfMemory,
        };
        filled = i + 1;
    }
    return owned;
}

// ---------------------------------------------------------------- tests

test "generate refuses invalid schema" {
    var schema = try @import("../schema.zig").parse(std.testing.allocator, "foo#1 a:int = Foo; foo#2 b:int = Bar;");
    defer schema.deinit();
    try std.testing.expectError(error.InvalidSchema, generate(std.testing.allocator, &schema, .{}, null));
}

test "generated output is deterministic" {
    const src =
        \\boolFalse#bc799737 = Bool;
        \\boolTrue#997275b5 = Bool;
    ;
    var schema = try @import("../schema.zig").parse(std.testing.allocator, src);
    defer schema.deinit();

    const a = try generate(std.testing.allocator, &schema, .{}, null);
    defer std.testing.allocator.free(a);
    const b = try generate(std.testing.allocator, &schema, .{}, null);
    defer std.testing.allocator.free(b);
    try std.testing.expectEqualStrings(a, b);
}

const split_sample_tl =
    \\boolFalse#bc799737 = Bool;
    \\boolTrue#997275b5 = Bool;
    \\user#d10d979a flags:# first_name:flags.1?string = User;
    \\users.userFull#3ad1960b flags:# user:User = users.UserFull;
    \\---functions---
    \\users.getUsers#d91a548 id:Vector<User> = users.UserFull;
;

test "split: tree layout — entry module, types/, functions/, registry" {
    var schema = try @import("../schema.zig").parse(std.testing.allocator, split_sample_tl);
    defer schema.deinit();

    const files = try generateMulti(std.testing.allocator, &schema, .{
        .source_name = "split.tl",
    }, null);
    defer {
        for (files) |f| {
            std.testing.allocator.free(f.name);
            std.testing.allocator.free(f.src);
        }
        std.testing.allocator.free(files);
    }

    // Entry module, types index, the two type groups (the root-namespace
    // `User` theme and the `users` namespace merge into one file), the
    // functions index, the users function file, and the registry.
    try std.testing.expectEqual(@as(usize, 7), files.len);
    try std.testing.expectEqualStrings("mod.zig", files[0].name);
    try std.testing.expectEqualStrings("types/mod.zig", files[1].name);
    try std.testing.expectEqualStrings("types/common.zig", files[2].name);
    try std.testing.expectEqualStrings("types/users.zig", files[3].name);
    try std.testing.expectEqualStrings("functions/mod.zig", files[4].name);
    try std.testing.expectEqualStrings("functions/users.zig", files[5].name);
    try std.testing.expectEqualStrings("registry.zig", files[6].name);

    // The entry module re-exports everything flat — same paths as the
    // single-file layout — and no declaration bodies live here.
    const root = files[0].src;
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const registry = @import(\"registry.zig\");") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const types = @import(\"types/mod.zig\");") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const functions = @import(\"functions/mod.zig\");") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const boolFalse = @import(\"types/common.zig\").boolFalse;") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const Bool = @import(\"types/common.zig\").Bool;") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const user = @import(\"types/users.zig\").user;") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const User = @import(\"types/users.zig\").User;") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const users = struct {") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const userFull = @import(\"types/users.zig\").userFull;") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const getUsers = @import(\"functions/users.zig\").getUsers;") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const UserFull = @import(\"types/users.zig\").UserFull;") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const user = struct {") == null);

    // Type files keep unions together with the constructors they dispatch
    // to; cross-file references route through the entry module (`api`).
    const common = files[2].src;
    try std.testing.expect(std.mem.indexOf(u8, common, "const api = @import(\"../mod.zig\");") != null);
    try std.testing.expect(std.mem.indexOf(u8, common, "pub const boolFalse = struct {") != null);
    try std.testing.expect(std.mem.indexOf(u8, common, "boolFalse: api.boolFalse,") != null);

    const users_types = files[3].src;
    try std.testing.expect(std.mem.indexOf(u8, users_types, "pub const user = struct {") != null);
    try std.testing.expect(std.mem.indexOf(u8, users_types, "user: api.User,") != null);
    try std.testing.expect(std.mem.indexOf(u8, users_types, "userFull: api.users.userFull,") != null);

    // Function file: fields and the typed RPC `Result` decl route through
    // the entry module as well.
    const users_fns = files[5].src;
    try std.testing.expect(std.mem.indexOf(u8, users_fns, "const api = @import(\"../mod.zig\");") != null);
    try std.testing.expect(std.mem.indexOf(u8, users_fns, "id: []api.User,") != null);
    try std.testing.expect(std.mem.indexOf(u8, users_fns, "pub const Result = api.users.UserFull;") != null);

    // Registry entries are sorted by wire id (0x0d91a548 < 0x3ad1960b <
    // 0x997275b5 < 0xbc799737 < 0xd10d979a).
    const reg = files[6].src;
    const a = std.mem.indexOf(u8, reg, "0x0d91a548").?;
    const b = std.mem.indexOf(u8, reg, "0x3ad1960b").?;
    const c = std.mem.indexOf(u8, reg, "0x997275b5").?;
    const d = std.mem.indexOf(u8, reg, "0xbc799737").?;
    const e = std.mem.indexOf(u8, reg, "0xd10d979a").?;
    try std.testing.expect(a < b and b < c and c < d and d < e);
}

test "split: deterministic output" {
    var schema = try @import("../schema.zig").parse(std.testing.allocator, split_sample_tl);
    defer schema.deinit();

    const a = try generateMulti(std.testing.allocator, &schema, .{
        .source_name = "split.tl",
    }, null);
    defer {
        for (a) |f| {
            std.testing.allocator.free(f.name);
            std.testing.allocator.free(f.src);
        }
        std.testing.allocator.free(a);
    }
    const b = try generateMulti(std.testing.allocator, &schema, .{
        .source_name = "split.tl",
    }, null);
    defer {
        for (b) |f| {
            std.testing.allocator.free(f.name);
            std.testing.allocator.free(f.src);
        }
        std.testing.allocator.free(b);
    }

    try std.testing.expectEqual(a.len, b.len);
    for (a, b) |fa, fb| {
        try std.testing.expectEqualStrings(fa.name, fb.name);
        try std.testing.expectEqualStrings(fa.src, fb.src);
    }
}

test "split: themed files rename colliding last segments deterministically" {
    const src =
        \\photo#fb0aaf7e = Photo;
        \\media.photo#3a2ce4e8 = media.Photo;
    ;
    var schema = try @import("../schema.zig").parse(std.testing.allocator, src);
    defer schema.deinit();

    const files = try generateMulti(std.testing.allocator, &schema, .{
        .source_name = "split.tl",
    }, null);
    defer {
        for (files) |f| {
            std.testing.allocator.free(f.name);
            std.testing.allocator.free(f.src);
        }
        std.testing.allocator.free(files);
    }

    // The root `Photo` theme and the `media` namespace share one group
    // file, so both constructors (and both unions) land in
    // types/media.zig. First-seen keeps its name; the later declaration
    // gets a `_` suffix — while every re-export in the entry module keeps
    // the original surface name and aliases the renamed declaration.
    var media_src: ?[]const u8 = null;
    var root_src: ?[]const u8 = null;
    for (files) |f| {
        if (std.mem.eql(u8, f.name, "types/media.zig")) media_src = f.src;
        if (std.mem.eql(u8, f.name, "mod.zig")) root_src = f.src;
    }
    const media = media_src orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, media, "pub const photo = struct {") != null);
    try std.testing.expect(std.mem.indexOf(u8, media, "pub const photo_ = struct {") != null);
    try std.testing.expect(std.mem.indexOf(u8, media, "pub const Photo = union(enum) {") != null);
    try std.testing.expect(std.mem.indexOf(u8, media, "pub const Photo_ = union(enum) {") != null);

    const root = root_src orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const photo = @import(\"types/media.zig\").photo;") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const media = struct {") != null);
    try std.testing.expect(std.mem.indexOf(u8, root, "pub const photo = @import(\"types/media.zig\").photo_;") != null);
}
