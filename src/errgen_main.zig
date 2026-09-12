//! td-errgen: Telegram RPC error catalogs (TSV) → Zig source generator
//! CLI.
//!
//! Usage: td-errgen [--check] [--source-name <label>] <output.zig> <errors.tsv> [<errors.tsv> ...]
//!
//! Reads every TSV (in the order given — the first file wins for
//! duplicated ids), merges and sorts them, and writes the generated
//! catalog module. With `--check` the regenerated output is compared
//! against the existing file instead of written; on drift the first
//! divergence is printed and the process exits non-zero (the drift
//! guard for the committed `src/rpc/errors_gen.zig`, which CI cannot
//! check without a git repository).
//!
//! Self-hosting like td-gen: imports only `std` (via `src/errgen.zig`),
//! never the td module, so `zig build errgen` works even when the
//! generated catalog is missing or stale — that is how `just errors`
//! bootstraps a full regeneration.

const std = @import("std");
const errgen = @import("errgen.zig");

pub fn main(init: std.process.Init) !void {
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var args = try init.minimal.args.iterateAllocator(arena);
    defer args.deinit();
    _ = args.next(); // program name

    var check = false;
    var source_name: []const u8 = "rpc_errors/*.tsv";
    var output_path: ?[]const u8 = null;
    var input_paths: std.ArrayList([]const u8) = .empty;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--check")) {
            check = true;
        } else if (std.mem.eql(u8, arg, "--source-name")) {
            source_name = args.next() orelse return usage();
        } else if (output_path == null) {
            output_path = arg;
        } else try input_paths.append(arena, arg);
    }
    if (output_path == null or input_paths.items.len == 0) return usage();

    var sources: std.ArrayList(errgen.Source) = .empty;
    for (input_paths.items) |p| {
        const text = try std.Io.Dir.cwd().readFileAlloc(init.io, p, arena, .limited(64 << 20));
        try sources.append(arena, .{ .name = std.fs.path.basename(p), .text = text });
    }

    const generated = try errgen.generate(arena, sources.items, .{ .source_name = source_name });

    if (check) {
        const existing = try std.Io.Dir.cwd().readFileAlloc(init.io, output_path.?, arena, .limited(64 << 20));
        if (!std.mem.eql(u8, generated, existing)) {
            const n = @min(generated.len, existing.len);
            var i: usize = 0;
            while (i < n and generated[i] == existing[i]) i += 1;
            const start = i - @min(i, 200);
            std.debug.print("drift at byte {d} (regenerated {d} bytes, file has {d} bytes)\n", .{ i, generated.len, existing.len });
            std.debug.print("--- regenerated ---\n{s}\n", .{generated[start..@min(i + 400, generated.len)]});
            std.debug.print("--- committed ---\n{s}\n", .{existing[start..@min(i + 400, existing.len)]});
            std.process.exit(1);
        }
        std.debug.print("ok: {s} up to date ({d} bytes)\n", .{ output_path.?, generated.len });
        return;
    }

    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = output_path.?, .data = generated });
    std.debug.print("wrote {s} ({d} bytes)\n", .{ output_path.?, generated.len });
}

fn usage() error{Usage} {
    std.debug.print(
        "usage: td-errgen [--check] [--source-name <label>] <output.zig> <errors.tsv> [<errors.tsv> ...]\n" ++
            "  merges the TSV catalogs (first file wins for duplicated ids) and writes\n" ++
            "  the generated error-catalog module. --check compares against <output.zig>\n" ++
            "  instead of writing it and exits non-zero on drift.\n",
        .{},
    );
    return error.Usage;
}
