//! Golden test for the error-catalog generator: the generator's output
//! for `golden/sample_errors.tsv` must byte-for-byte match the
//! committed `golden/expected_errors_gen.zig`, proving determinism and
//! reproducibility. The committed catalog itself
//! (src/rpc/errors_gen.zig) is exercised by `tests/rpc_errors.zig`.

const std = @import("std");
const td = @import("td");

const sample_tsv = @embedFile("golden/sample_errors.tsv");
const expected_zig = @embedFile("golden/expected_errors_gen.zig");

test "golden: error-catalog generator output matches committed file" {
    const generated = try td.errgen.generate(std.testing.allocator, &.{
        .{ .name = "sample_errors.tsv", .text = sample_tsv },
    }, .{ .source_name = "sample_errors.tsv" });
    defer std.testing.allocator.free(generated);

    if (!std.mem.eql(u8, generated, expected_zig)) {
        // Print the first divergence to make failures debuggable.
        const n = @min(generated.len, expected_zig.len);
        var i: usize = 0;
        while (i < n and generated[i] == expected_zig[i]) i += 1;
        const start = i - @min(i, 200);
        std.debug.print("golden mismatch at byte {d} (generated {d} bytes, expected {d} bytes)\n", .{ i, generated.len, expected_zig.len });
        std.debug.print("--- generated ---\n{s}\n", .{generated[start..@min(i + 400, generated.len)]});
        std.debug.print("--- expected ---\n{s}\n", .{expected_zig[start..@min(i + 400, expected_zig.len)]});
        return error.TestUnexpectedResult;
    }
}
