//! td benchmark suite.
//!
//! Run with `just bench` (or `zig build bench`); a substring filter
//! selects sections: `./zig-out/bin/td-bench tl` runs only the TL
//! section. Sections:
//!
//!   crypto — raw primitives: SHA-256/SHA-1, AES-256-IGE, msg_key,
//!            key/IV derivation (1 MiB buffers);
//!   tl     — generated-API serialization/deserialization and the RPC
//!            result-decode layer, with allocation counts;
//!   frame  — message construction (Session.encode / encodeContainer),
//!            frame decrypt and Session.receive validation, with
//!            allocation counts;
//!   net    — request/response dispatch (transport isolated), pipelining
//!            depth, raw TCP-full socket echo, full-stack loopback
//!            roundtrip, multi-lane concurrent requests;
//!   multi  — fleet scaling: memory/session and construction cost at
//!            100 / 1 000 / 5 000 / 10 000 sessions, sequential and
//!            pipelined roundtrips with latency percentiles, event-loop
//!            sweep utilization, real-socket anchor at 100;
//!   alloc  — memcpy calibration curve and allocator throughput.
//!
//! Methodology: each benchmark warms up, then times one measured loop
//! and reports ns/op plus ops/s (and MiB/s where a byte count applies).
//! Allocation counts come from a counting allocator threaded under the
//! measured path. The td module is compiled at ReleaseFast for this
//! binary regardless of the build's default optimize mode — benchmarks
//! must measure optimized library code.

const std = @import("std");
const td = @import("td");
const common = @import("bench/common.zig");
const bench_tl = @import("bench/tl.zig");
const bench_frame = @import("bench/frame.zig");
const bench_net = @import("bench/net.zig");
const bench_multi = @import("bench/multi.zig");

const Section = struct {
    name: []const u8,
    run: *const fn (std.mem.Allocator, std.Io) anyerror!void,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.next(); // program name
    const filter: ?[]const u8 = args.next();

    const sections = [_]Section{
        .{ .name = "crypto", .run = runCrypto },
        .{ .name = "tl", .run = bench_tl.run },
        .{ .name = "frame", .run = bench_frame.run },
        .{ .name = "net", .run = bench_net.run },
        .{ .name = "multi", .run = bench_multi.run },
        .{ .name = "alloc", .run = runAlloc },
    };

    var failures: usize = 0;
    for (sections) |s| {
        if (filter) |f| {
            if (std.mem.indexOf(u8, s.name, f) == null) continue;
        }
        s.run(gpa, io) catch |e| {
            failures += 1;
            std.debug.print("section '{s}' FAILED: {s}\n", .{ s.name, @errorName(e) });
        };
    }
    if (failures > 0) return error.BenchFailed;
}

// ------------------------------------------------------------ crypto

const crypto_size = 1 << 20;

var crypto_buf: [crypto_size]u8 = undefined;
var crypto_out: [crypto_size]u8 = undefined;
var crypto_digest: [32]u8 = undefined;
var crypto_msg_key: [16]u8 = undefined;
var crypto_params: td.crypto.AesParams = undefined;

fn report(label: []const u8, bytes: usize, ns: u64) void {
    const mbps = @as(f64, @floatFromInt(bytes)) / (@as(f64, @floatFromInt(ns)) / 1e9) / (1024 * 1024);
    std.debug.print("{s:<48} {d:>10} ns   {d:>8.1} MiB/s\n", .{ label, ns, mbps });
}

fn runCrypto(gpa: std.mem.Allocator, io: std.Io) !void {
    _ = gpa;
    const Timestamp = std.Io.Timestamp;

    try td.crypto.randomBytes(io, &crypto_buf);
    const auth_key = &common.auth_key;

    std.debug.print("\n-- crypto primitives ({d} KiB buffer, hardware AES: {s}) --\n", .{
        crypto_size / 1024,
        if (std.crypto.core.aes.has_hardware_support) "yes" else "no (software)",
    });

    const key = [_]u8{1} ** 32;
    const iv = [_]u8{2} ** 32;
    try td.crypto.aes_ige.encrypt256(key, iv, &crypto_buf, &crypto_out); // warm-up

    {
        const t = Timestamp.now(io, .awake);
        for (0..32) |_| td.crypto.Sha256.hash(&crypto_buf, &crypto_digest, .{});
        report("SHA-256 x32", 32 * crypto_size, @intCast(t.durationTo(Timestamp.now(io, .awake)).nanoseconds));
    }
    {
        var d1: [20]u8 = undefined;
        const t = Timestamp.now(io, .awake);
        for (0..32) |_| td.crypto.Sha1.hash(&crypto_buf, &d1, .{});
        report("SHA-1 x32", 32 * crypto_size, @intCast(t.durationTo(Timestamp.now(io, .awake)).nanoseconds));
    }
    {
        const t = Timestamp.now(io, .awake);
        try td.crypto.aes_ige.encrypt256(key, iv, &crypto_buf, &crypto_out);
        report("AES-256-IGE encrypt x1", crypto_size, @intCast(t.durationTo(Timestamp.now(io, .awake)).nanoseconds));
    }
    {
        const t = Timestamp.now(io, .awake);
        try td.crypto.aes_ige.decrypt256(key, iv, &crypto_out, &crypto_buf);
        report("AES-256-IGE decrypt x1", crypto_size, @intCast(t.durationTo(Timestamp.now(io, .awake)).nanoseconds));
    }
    {
        const t = Timestamp.now(io, .awake);
        for (0..1000) |_| crypto_msg_key = try td.crypto.computeMsgKey(auth_key, .client_to_server, &crypto_buf);
        report("msg_key x1000", 1000 * crypto_size, @intCast(t.durationTo(Timestamp.now(io, .awake)).nanoseconds));
    }
    {
        const t = Timestamp.now(io, .awake);
        for (0..1000) |_| crypto_params = td.crypto.deriveAesParams(auth_key, &crypto_msg_key, .client_to_server);
        const ns: u64 = @intCast(t.durationTo(Timestamp.now(io, .awake)).nanoseconds);
        std.debug.print("{s:<48} {d:>10} ns/op\n", .{"key/IV derivation", ns / 1000});
    }
}

// ------------------------------------------------- memory + allocator

fn runAlloc(gpa: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n-- memory copies (memcpy calibration) --\n", .{});
    const mem_benches = [_]struct { sz: usize, label: []const u8, iters: usize }{
        .{ .sz = 64, .label = "memcpy 64 B", .iters = 1_000_000 },
        .{ .sz = 4096, .label = "memcpy 4 KiB", .iters = 100_000 },
        .{ .sz = 64 * 1024, .label = "memcpy 64 KiB", .iters = 20_000 },
        .{ .sz = 1024 * 1024, .label = "memcpy 1 MiB", .iters = 2_000 },
    };
    for (mem_benches) |b| {
        const src = try gpa.alloc(u8, b.sz);
        defer gpa.free(src);
        const dst = try gpa.alloc(u8, b.sz);
        defer gpa.free(dst);
        for (src, 0..) |*p, i| p.* = @truncate(i *% 251 +% 13);
        for (0..100) |_| @memcpy(dst, src); // warm-up
        const t = common.Timer.begin(io);
        for (0..b.iters) |_| @memcpy(dst, src);
        const total = t.ns();
        common.keep(dst[0]);
        common.reportLine(b.label, b.sz * b.iters, total, b.iters);
    }

    std.debug.print("\n-- allocator throughput --\n", .{});
    {
        const iters = 1_000_000;
        const t = common.Timer.begin(io);
        for (0..iters) |_| {
            const p = try gpa.alloc(u8, 64);
            gpa.free(p);
        }
        common.reportLine("gpa alloc+free 64 B", 64, t.ns(), iters);
    }
    {
        const iters = 20_000;
        const t = common.Timer.begin(io);
        for (0..iters) |_| {
            const p = try gpa.alloc(u8, 1024 * 1024);
            p[0] = 1; // touch a page
            gpa.free(p);
        }
        common.reportLine("gpa alloc+free 1 MiB", 1024 * 1024, t.ns(), iters);
    }
    {
        // Arena reset cost — the pattern the RPC response path relies on.
        const iters = 100_000;
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const t = common.Timer.begin(io);
        for (0..iters) |_| {
            _ = arena_state.reset(.retain_capacity);
            const p = try arena_state.allocator().alloc(u8, 512);
            common.keep(p.len);
        }
        common.reportLine("arena reset + alloc 512 B", 512, t.ns(), iters);
    }
}
