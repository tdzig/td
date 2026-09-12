//! Shared benchmark helpers: the wall-clock stopwatch, one-line result
//! reporting, and the allocation-counting allocator used to measure
//! allocations per operation.
//!
//! Every benchmark follows the same protocol: warm-up (allocator and
//! branch-predictor state reach steady state), reset the counters, time
//! the measured loop once, and report total_ns / iterations. Reports are
//! a single line per benchmark so runs are diffable.

const std = @import("std");

/// Varied-byte test authorization key. Identical bytes across the
/// per-direction msg_key windows ([88..120] vs [96..128]) would make the
/// two crypto directions degenerate (see the Step-5 test gotcha).
pub const auth_key: [256]u8 = blk: {
    var k: [256]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 73 +% 11);
    break :blk k;
};

/// The server salt every benchmark session starts with.
pub const test_salt: i64 = 0x51a1;

/// Wall-clock stopwatch over the `Io` awake clock.
pub const Timer = struct {
    io: std.Io,
    start: std.Io.Timestamp,

    pub fn begin(io: std.Io) Timer {
        return .{ .io = io, .start = std.Io.Timestamp.now(io, .awake) };
    }

    pub fn ns(self: Timer) u64 {
        return @intCast(self.start.durationTo(std.Io.Timestamp.now(self.io, .awake)).nanoseconds);
    }
};

/// One line per benchmark: label, per-op time and ops/s. `bytes` is the
/// logical payload per op (0 hides the MiB/s column).
pub fn reportLine(label: []const u8, bytes: usize, total_ns: u64, ops: usize) void {
    const per = @as(f64, @floatFromInt(total_ns)) / @as(f64, @floatFromInt(ops));
    const ops_s = @as(f64, @floatFromInt(ops)) / (@as(f64, @floatFromInt(total_ns)) / 1e9);
    if (bytes == 0) {
        std.debug.print("{s:<48} {d:>10.1} ns/op {d:>12.0} ops/s\n", .{ label, per, ops_s });
    } else {
        const mib_s = @as(f64, @floatFromInt(bytes)) / (@as(f64, @floatFromInt(total_ns)) / 1e9) / (1024 * 1024);
        std.debug.print("{s:<48} {d:>10.1} ns/op {d:>12.0} ops/s {d:>9.1} MiB/s\n", .{ label, per, ops_s, mib_s });
    }
}

/// One line for an allocation profile: allocations and bytes per op as
/// observed through a `CountingAllocator`.
pub fn reportAllocs(label: []const u8, ops: usize, c: *const CountingAllocator) void {
    const n: f64 = @floatFromInt(ops);
    std.debug.print("{s:<48} {d:>18.2} allocs/op {d:>10.1} B alloc'd/op ({d} allocs, {d} frees)\n", .{
        label,
        @as(f64, @floatFromInt(c.allocs)) / n,
        @as(f64, @floatFromInt(c.bytes_allocated)) / n,
        c.allocs,
        c.frees,
    });
}

/// Allocator wrapper that counts every interface call passing through,
/// so hot paths can be profiled for allocation counts (the cheapest
/// reliable optimization signal) without changing their behavior.
pub const CountingAllocator = struct {
    child: std.mem.Allocator,
    allocs: usize = 0,
    frees: usize = 0,
    resizes: usize = 0,
    remaps: usize = 0,
    bytes_allocated: usize = 0,
    bytes_freed: usize = 0,

    fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const p = self.child.rawAlloc(len, alignment, ret_addr);
        if (p != null) {
            self.allocs += 1;
            self.bytes_allocated += len;
        }
        return p;
    }

    fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ok = self.child.rawResize(memory, alignment, new_len, ret_addr);
        if (ok) self.resizes += 1;
        return ok;
    }

    fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const p = self.child.rawRemap(memory, alignment, new_len, ret_addr);
        if (p != null) self.remaps += 1;
        return p;
    }

    fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ret_addr);
        self.frees += 1;
        self.bytes_freed += memory.len;
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = allocFn,
        .resize = resizeFn,
        .remap = remapFn,
        .free = freeFn,
    };

    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn reset(self: *CountingAllocator) void {
        self.* = .{ .child = self.child };
    }
};

/// Accumulator the benchmarks store results into; without it a
/// ReleaseFast build may fold the entire measured loop away.
pub var sink: u64 = 0;

pub fn keep(value: u64) void {
    sink +%= value;
}
