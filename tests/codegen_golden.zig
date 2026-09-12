//! Golden test for the TL code generator: the generator's output for
//! `golden/sample.tl` must byte-for-byte match the committed
//! `golden/expected_sample.zig`, proving determinism and reproducibility.
//! The committed file is also compiled and round-tripped by
//! `tests/generated_roundtrip.zig`.

const std = @import("std");
const td = @import("td");

const sample_tl = @embedFile("golden/sample.tl");
const expected_zig = @embedFile("golden/expected_sample.zig");

test "golden: generator output matches committed file" {
    var schema = try td.tl.parseSchema(std.testing.allocator, sample_tl);
    defer schema.deinit();

    const generated = try td.tl.codegen.generate(std.testing.allocator, &schema, .{
        .module_name = "td",
        .source_name = "sample.tl",
    }, null);
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

test "golden: sample schema validates cleanly" {
    var schema = try td.tl.parseSchema(std.testing.allocator, sample_tl);
    defer schema.deinit();
    var issues: std.ArrayList(td.tl.validate.Issue) = .empty;
    defer issues.deinit(std.testing.allocator);
    try std.testing.expect(td.tl.validate.validate(std.testing.allocator, &schema, &issues));
}
