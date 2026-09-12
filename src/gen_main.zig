//! td-gen: TL schema → Zig source code generator CLI.
//!
//! Usage: td-gen <schema.tl> <output.zig> [--module <name>] [--self-test]
//!       td-gen <schema.tl> <output-dir> --split [--module <name>] [--self-test]
//!
//! Reads the schema file, parses and validates it, then writes generated
//! Zig source to the output path. Exits non-zero with a diagnostic on
//! parse or validation failure.
//!
//! The generator is self-hosting: it imports only the `tl` subsystem
//! (parser + codegen), never the generated API itself, so `zig build gen`
//! works even when `src/api/` is missing or stale — that is how `just api`
//! bootstraps a full regeneration.
//!
//! `--split` treats the output path as a directory (created if missing)
//! and writes the tree layout: the entry module (`mod.zig`, which
//! re-exports every declaration so `td.api` paths are unchanged),
//! `registry.zig` (a sorted wire-id → name table), and the content in
//! two subdirectories — `types/<group>.zig` (result-type unions with
//! their constructors, grouped by TL namespace and, for the root
//! namespace, thematically) and `functions/<namespace>.zig` (the request
//! structs). Subdirectories are created automatically.

const std = @import("std");
const tl = @import("tl/mod.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // program name

    var input_path: ?[]const u8 = null;
    var output_path: []const u8 = "-";
    var module_name: []const u8 = "td";
    var self_test = false;
    var split = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--module")) {
            module_name = args.next() orelse return usage();
        } else if (std.mem.eql(u8, arg, "--self-test")) {
            self_test = true;
        } else if (std.mem.eql(u8, arg, "--split")) {
            split = true;
        } else if (input_path == null) {
            input_path = arg;
        } else if (std.mem.eql(u8, output_path, "-")) {
            output_path = arg;
        } else return usage();
    }
    if (input_path == null) return usage();

    const src = try std.Io.Dir.cwd().readFileAlloc(init.io, input_path.?, allocator, .limited(64 << 20));
    defer allocator.free(src);

    var schema = tl.parseSchema(allocator, src) catch |e| {
        std.debug.print("error: parse failed: {s}\n", .{@errorName(e)});
        return e;
    };
    defer schema.deinit();

    const opts = tl.codegen.Options{
        .module_name = module_name,
        .source_name = std.fs.path.basename(input_path.?),
        .self_test = self_test,
    };

    if (split) {
        var diagnostics: std.ArrayList(u8) = .empty;
        defer diagnostics.deinit(allocator);
        const files = tl.codegen.generateMulti(allocator, &schema, opts, &diagnostics) catch |e| {
            std.debug.print("error: codegen failed: {s} (schema failed validation?)\n", .{@errorName(e)});
            if (diagnostics.items.len > 0) std.debug.print("{s}", .{diagnostics.items});
            return e;
        };
        defer {
            for (files) |f| {
                allocator.free(f.name);
                allocator.free(f.src);
            }
            allocator.free(files);
        }
        // The output directory and any subdirectories the layout uses
        // (types/, functions/) are created automatically.
        try std.Io.Dir.cwd().createDirPath(init.io, output_path);
        for (files) |f| {
            const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ output_path, f.name });
            defer allocator.free(path);
            if (std.fs.path.dirname(path)) |dir| try std.Io.Dir.cwd().createDirPath(init.io, dir);
            try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = f.src });
            std.debug.print("wrote {s} ({d} bytes)\n", .{ path, f.src.len });
        }
        return;
    }

    var diagnostics: std.ArrayList(u8) = .empty;
    defer diagnostics.deinit(allocator);
    const generated = tl.codegen.generate(allocator, &schema, opts, &diagnostics) catch |e| {
        std.debug.print("error: codegen failed: {s} (schema failed validation?)\n", .{@errorName(e)});
        if (diagnostics.items.len > 0) std.debug.print("{s}", .{diagnostics.items});
        return e;
    };
    defer allocator.free(generated);

    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = output_path, .data = generated });
}

fn usage() error{Usage} {
    std.debug.print(
        "usage: td-gen <schema.tl> <output.zig> [--module <name>] [--self-test]\n" ++
            "       td-gen <schema.tl> <output-dir> --split [--module <name>] [--self-test]\n" ++
            "  --split writes the tree layout into <output-dir> (created if missing):\n" ++
            "    mod.zig               entry module: re-exports every declaration\n" ++
            "    types/mod.zig         index of the types/ files\n" ++
            "    types/<group>.zig     result-type unions + constructors, grouped\n" ++
            "                          by namespace and, at the root, by theme\n" ++
            "    functions/mod.zig     index of the functions/ files\n" ++
            "    functions/<ns>.zig    request structs per TL namespace\n" ++
            "    registry.zig          sorted wire-id -> name table\n",
        .{},
    );
    return error.Usage;
}
