//! Multi-session benchmarks: what N simultaneous sessions cost.
//!
//! Two peer backends, stated plainly:
//!
//! - **in-memory fleet** (`td.multi`): N managers over `Registry` links
//!   — a real MTProto peer embedded behind each transport, no threads,
//!   no sockets. Server-side crypto and validation run inline on the
//!   same thread, so request rates here *include* the peer's work (a
//!   conservative view of client-only throughput). This backend is how
//!   fleet sizes 100 / 1 000 / 5 000 / 10 000 are measured at all.
//! - **real-socket fleet** (N=100 anchor): N TCP-full connections to
//!   threaded loopback echo peers, client driven round-robin on the
//!   main thread. Anchors the in-memory numbers against kernel and
//!   scheduling costs; per-socket latency here includes thread
//!   hand-off.
//!
//! Metrics per the multi-session milestone: memory per session (live
//! bytes through a counting allocator), CPU per session (wall time of
//! the single driving thread — this stack is single-threaded by
//! design), requests/sec, latency p50/p95/p99, connection count,
//! allocations, and event-loop utilization (share of sweep visits that
//! delivered frames, and frames per sweep).
//!
//! Reading the numbers: per-session memory is dominated by the RPC
//! client's fixed receive slots (`max_container_messages`), so it is
//! flat in fleet size; scheduler cost per sweep is O(live sessions).
//! Both claims are checked by the rows below every run — they are the
//! output, not the input.

const std = @import("std");
const td = @import("td");
const common = @import("common.zig");

const multi = td.multi;
const message = td.mtproto.message;
const net = std.Io.net;
const tcp_full = td.transport.tcp_full;

const query_ctor_id: u32 = 0x0d91a548;
const query_body: [8]u8 = blk: {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], query_ctor_id, .little);
    std.mem.writeInt(u32, b[4..8], 7, .little);
    break :blk b;
};

const fleet_sizes = [_]usize{ 100, 1_000, 5_000, 10_000 };

/// Rounds of round-trips per session in the sequential/pipelined runs.
const rounds_per_session = 3;

fn percentile(samples: []u64, pct: u64) u64 {
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    const idx = samples.len * pct / 100;
    return samples[@min(idx, samples.len - 1)];
}

fn printLatency(label: []const u8, samples: []u64, total_ns: u64) void {
    const p50 = percentile(samples, 50);
    const p95 = percentile(samples, 95);
    const p99 = percentile(samples, 99);
    const per = @as(f64, @floatFromInt(total_ns)) / @as(f64, @floatFromInt(samples.len));
    std.debug.print("{s:<44} p50 {d:>7.1}µs  p95 {d:>7.1}µs  p99 {d:>7.1}µs  ({d:.1}µs/req mean)\n", .{
        label,
        @as(f64, @floatFromInt(p50)) / 1e3,
        @as(f64, @floatFromInt(p95)) / 1e3,
        @as(f64, @floatFromInt(p99)) / 1e3,
        per / 1e3,
    });
}

fn printThroughput(label: []const u8, requests: usize, total_ns: u64) void {
    const reqs_s = @as(f64, @floatFromInt(requests)) / (@as(f64, @floatFromInt(total_ns)) / 1e9);
    std.debug.print("{s:<44} {d:>10.0} req/s  ({d} requests, {d} ms)\n", .{
        label,
        reqs_s,
        requests,
        total_ns / std.time.ns_per_ms,
    });
}

// ---------------------------------------------------------------- peer

/// The embedded peer's reply policy: rpc_result{bool_true} for the
/// benchmark query, silence otherwise (pings are not exercised here).
const BenchResponder = struct {
    fn onBody(_: *anyopaque, _: *multi.Link, dec: *const message.Decrypted, arena: std.mem.Allocator) ?multi.Reply {
        if (dec.body.len < 4) return null;
        const ctor = std.mem.readInt(u32, dec.body[0..4], .little);
        var w = td.tl.Writer.init(arena);
        if (ctor == query_ctor_id) {
            w.writeConstructorId(message.rpc_result_id) catch return null;
            w.writeLong(dec.msg_id) catch return null;
            w.writeUInt(0x997275b5) catch return null; // bool_true
            return .{ .body = w.items(), .content_related = true };
        }
        return null;
    }

    fn responder() multi.Responder {
        return .{ .ctx = undefined, .onBody = onBody };
    }
};

/// One fleet at size `n`: registry + links + fleet of connected
/// sessions. All allocation flows through the caller's allocator (the
/// benchmark passes a counting allocator when it wants memory figures).
const FleetRig = struct {
    registry: multi.Registry,
    fleet: multi.Fleet,

    /// In-place construction: the transport provider captures
    /// `&self.registry`, so the rig lives at a stable address from
    /// here on (the same immovability rule a Manager's client imposes).
    fn setup(
        self: *FleetRig,
        gpa: std.mem.Allocator,
        io: std.Io,
        n: usize,
        key: *const [256]u8,
    ) !void {
        self.registry = multi.Registry.init(gpa);
        errdefer self.registry.deinit();
        for (0..n) |_| _ = try self.registry.addLink(key, common.test_salt);
        for (self.registry.links.items) |l| l.responder = BenchResponder.responder();

        self.fleet = try multi.Fleet.init(gpa, .{
            .capacity = n,
            .endpoint = .{ .host = "loopback", .port = 0 },
            .session = .{
                .transport_provider = self.registry.provider(),
                .ping_interval = std.Io.Duration.fromSeconds(3600),
                .max_connect_attempts = 2,
                .backoff_base = std.Io.Duration.fromMilliseconds(1),
                .backoff_max = std.Io.Duration.fromMilliseconds(5),
            },
        });
        errdefer self.fleet.deinit(io);
        for (0..n) |i| {
            const id = try self.fleet.addSessionOn(.{ .host = "loopback", .port = @intCast(i) }, key, common.test_salt);
            try (try self.fleet.session(id)).ensureConnected(io);
        }
    }

    fn teardown(self: *FleetRig, io: std.Io) void {
        // Fleet deinit shuts every manager down gracefully (ack drain,
        // cancel-all, close, provider release); the registry then frees
        // the links. Pending requests that never completed are freed by
        // the managers' cancel-all.
        self.fleet.deinit(io);
        self.registry.deinit();
    }
};

// ------------------------------------------------------------- sections

fn buildAndMemory(gpa: std.mem.Allocator, io: std.Io, key: *const [256]u8) !void {
    std.debug.print("\n-- fleet build: memory and construction cost --\n", .{});
    std.debug.print("  sizeof: Manager={d} B  rpc.Client={d} B  mtproto.Session={d} B  rx slots/session={d} B\n", .{
        @sizeOf(td.connman.Manager),
        @sizeOf(td.rpc.Client),
        @sizeOf(td.mtproto.Session),
        @sizeOf(message.Incoming) * message.max_container_messages,
    });

    var lbl: [48]u8 = undefined;
    for (fleet_sizes) |n| {
        var c = common.CountingAllocator{ .child = gpa };
        const a = c.allocator();

        var rig: FleetRig = undefined;
        const t = common.Timer.begin(io);
        try rig.setup(a, io, n, key);
        defer rig.teardown(io);
        const build_ns = t.ns();

        const live = c.bytes_allocated - c.bytes_freed;
        const per_session = live / n;
        const connected = rig.fleet.connectedCount();
        const label = try std.fmt.bufPrint(&lbl, "build {d} sessions", .{n});
        std.debug.print("{s:<44} {d:>6.0} ns/session  {d:>7.1} KiB/session  ({d} connected, {d} MiB live)\n", .{
            label,
            @as(f64, @floatFromInt(build_ns)) / @as(f64, @floatFromInt(n)),
            @as(f64, @floatFromInt(per_session)) / 1024.0,
            connected,
            live / (1024 * 1024),
        });
        common.keep(build_ns);
    }
}

fn sequentialRoundtrips(gpa: std.mem.Allocator, io: std.Io, key: *const [256]u8) !void {
    std.debug.print("\n-- sequential roundtrips (round-robin over sessions, in-memory peer) --\n", .{});

    var lbl: [48]u8 = undefined;
    for (fleet_sizes) |n| {
        var c = common.CountingAllocator{ .child = gpa };
        const a = c.allocator();
        var rig: FleetRig = undefined;
        try rig.setup(a, io, n, key);
        defer rig.teardown(io);

        const samples = try gpa.alloc(u64, n * rounds_per_session);
        defer gpa.free(samples);
        c.reset();

        // Warm-up: one round, untimed.
        for (0..n) |i| {
            const mgr = try rig.fleet.session(@intCast(i));
            const bytes = try mgr.invokeRaw(io, &query_body);
            mgr.allocator.free(bytes);
        }

        var t = common.Timer.begin(io);
        var k: usize = 0;
        for (0..rounds_per_session) |_| {
            for (0..n) |i| {
                const mgr = try rig.fleet.session(@intCast(i));
                var lat = common.Timer.begin(io);
                const bytes = try mgr.invokeRaw(io, &query_body);
                samples[k] = lat.ns();
                k += 1;
                mgr.allocator.free(bytes);
            }
        }
        const total = t.ns();

        const requests = n * rounds_per_session;
        printThroughput(try std.fmt.bufPrint(&lbl, "fleet {d}: sequential", .{n}), requests, total);
        printLatency(try std.fmt.bufPrint(&lbl, "fleet {d}: latency", .{n}), samples, total);
        const per_session_ns = @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(n));
        std.debug.print("{s:<44} {d:>10.0} ns/session over the run ({d:.2} allocs/req)\n", .{
            try std.fmt.bufPrint(&lbl, "fleet {d}: cost", .{n}),
            per_session_ns,
            @as(f64, @floatFromInt(c.allocs)) / @as(f64, @floatFromInt(requests)),
        });
    }
}

fn pipelinedRoundtrips(gpa: std.mem.Allocator, io: std.Io, key: *const [256]u8) !void {
    std.debug.print("\n-- pipelined across sessions (all outstanding, then drained) --\n", .{});

    var lbl: [48]u8 = undefined;
    for (fleet_sizes) |n| {
        var rig: FleetRig = undefined;
        try rig.setup(gpa, io, n, key);
        defer rig.teardown(io);

        const handles = try gpa.alloc(td.rpc.RawHandle, n);
        defer gpa.free(handles);
        const samples = try gpa.alloc(u64, n);
        defer gpa.free(samples);

        // Warm-up: one full round, untimed.
        for (0..n) |i| {
            const mgr = try rig.fleet.session(@intCast(i));
            handles[i] = try mgr.sendRaw(io, &query_body);
        }
        for (0..n) |i| {
            const mgr = try rig.fleet.session(@intCast(i));
            const bytes = try mgr.waitRaw(io, handles[i]);
            mgr.allocator.free(bytes);
        }

        var t = common.Timer.begin(io);
        for (0..n) |i| {
            const mgr = try rig.fleet.session(@intCast(i));
            handles[i] = try mgr.sendRaw(io, &query_body);
        }
        for (0..n) |i| {
            const mgr = try rig.fleet.session(@intCast(i));
            var lat = common.Timer.begin(io);
            const bytes = try mgr.waitRaw(io, handles[i]);
            samples[i] = lat.ns();
            mgr.allocator.free(bytes);
        }
        const total = t.ns();

        printThroughput(
            try std.fmt.bufPrint(&lbl, "fleet {d}: pipelined depth {d}", .{ n, n }),
            n,
            total,
        );
        printLatency(
            try std.fmt.bufPrint(&lbl, "fleet {d}: pipelined latency", .{n}),
            samples,
            total,
        );
    }
}

fn sweepUtilization(gpa: std.mem.Allocator, io: std.Io, key: *const [256]u8) !void {
    std.debug.print("\n-- event-loop sweeps (idle vs. loaded; in-memory peer) --\n", .{});

    var lbl: [48]u8 = undefined;
    for (fleet_sizes) |n| {
        var rig: FleetRig = undefined;
        try rig.setup(gpa, io, n, key);
        defer rig.teardown(io);

        // Idle sweeps: connected sessions, nothing in flight — the pure
        // O(N) scheduling cost (in-memory peers return idle reads
        // instantly; real sockets additionally pay their read_timeout
        // per idle visit, see the net section).
        const sweeps = 10;
        var idle_ns: u64 = 0;
        for (0..sweeps) |_| {
            const s = rig.fleet.pump(io, std.Io.Duration.fromMilliseconds(1));
            idle_ns += s.ns;
        }
        std.debug.print("{s:<44} {d:>8.1} ns/sweep  {d:>6.1} ns/session-sweep (idle)\n", .{
            try std.fmt.bufPrint(&lbl, "fleet {d}: idle sweep", .{n}),
            @as(f64, @floatFromInt(idle_ns)) / sweeps,
            @as(f64, @floatFromInt(idle_ns)) / sweeps / @as(f64, @floatFromInt(n)),
        });

        // Loaded sweeps: requests in flight on every session; one sweep
        // should deliver most frames (utilization ≈ 100%). Leftover
        // waiting requests are freed by teardown's cancel-all.
        for (0..n) |i| {
            const mgr = try rig.fleet.session(@intCast(i));
            _ = try mgr.sendRaw(io, &query_body);
        }
        const s = rig.fleet.pump(io, std.Io.Duration.fromMilliseconds(10));
        const utilization = @as(f64, @floatFromInt(s.work_sessions)) / @as(f64, @floatFromInt(@max(s.visited, 1)));
        std.debug.print("{s:<44} visited {d:>5}  frames {d:>5}  work {d:>5}  utilization {d:>5.1}%\n", .{
            try std.fmt.bufPrint(&lbl, "fleet {d}: loaded sweep", .{n}),
            s.visited,
            s.frames,
            s.work_sessions,
            utilization * 100.0,
        });
    }
}

// --------------------------------------------------- real-socket anchor

const SockEchoCtx = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    listener: *net.Server,
    session_id: i64,
    prng_state: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0xabc),
    next_low: u32 = 1,
    content: u32 = 0,
    out_seq: u32 = 0,
    buf: [4096]u8 = undefined,

    fn reply(self: *SockEchoCtx, stream: *net.Stream, body: []const u8, content_related: bool) !void {
        const flen = message.frameLength(body.len);
        if (flen > self.buf.len) return error.FrameTooLarge;
        const seq: i32 = @intCast(2 * self.content + @as(u32, if (content_related) 1 else 0));
        if (content_related) self.content += 1;
        const s = @divTrunc(std.Io.Timestamp.now(self.io, .real).nanoseconds, std.time.ns_per_s);
        const id = (@as(i64, @intCast(s)) << 32) | self.next_low;
        self.next_low +%= 4;
        message.writeEncrypted(&common.auth_key, .server_to_client, .{
            .salt = common.test_salt,
            .session_id = self.session_id,
            .msg_id = id,
            .seq_no = seq,
            .body = body,
        }, self.prng_state.random(), self.buf[0..flen]) catch return;
        const h = tcp_full.Codec.header(flen, self.out_seq);
        var tr: [4]u8 = undefined;
        std.mem.writeInt(u32, &tr, tcp_full.Codec.checksum(&h, self.buf[0..flen]), .little);
        try writeAllRaw(self.io, stream, &h);
        try writeAllRaw(self.io, stream, self.buf[0..flen]);
        try writeAllRaw(self.io, stream, &tr);
        self.out_seq +%= 1;
    }
};

fn writeAllRaw(io: std.Io, stream: *net.Stream, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, &.{bytes[sent..]}, 1);
        sent += n;
    }
}

fn readExactRaw(io: std.Io, stream: *net.Stream, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        var iovec = [1][]u8{buf[got..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &iovec);
        if (n == 0) return error.EndOfStream;
        got += n;
    }
}

fn sockEchoMain(ctx: *SockEchoCtx) void {
    var stream = ctx.listener.accept(ctx.io) catch return;
    defer stream.close(ctx.io);
    while (true) {
        var hdr: [8]u8 = undefined;
        readExactRaw(ctx.io, &stream, &hdr) catch return;
        const parsed = tcp_full.Codec.parseHeader(&hdr);
        if (parsed.length < tcp_full.frame_overhead) return;
        const plen = parsed.length - tcp_full.frame_overhead;
        if (plen > ctx.buf.len) return;
        readExactRaw(ctx.io, &stream, ctx.buf[0..plen]) catch return;
        var trailer: [4]u8 = undefined;
        readExactRaw(ctx.io, &stream, &trailer) catch return;
        if (tcp_full.Codec.checksum(&hdr, ctx.buf[0..plen]) != std.mem.readInt(u32, &trailer, .little))
            return;

        const dec = message.readEncrypted(&common.auth_key, .client_to_server, ctx.session_id, ctx.buf[0..plen]) catch return;
        if (dec.body.len < 4) continue;
        const ctor = std.mem.readInt(u32, dec.body[0..4], .little);
        if (ctor == query_ctor_id) {
            var w = td.tl.Writer.init(ctx.gpa);
            defer w.deinit();
            w.writeConstructorId(message.rpc_result_id) catch return;
            w.writeLong(dec.msg_id) catch return;
            w.writeUInt(0x997275b5) catch return;
            ctx.reply(&stream, w.items(), true) catch return;
        }
        // everything else drains silently
    }
}

const SockLane = struct {
    listener: net.Server,
    tcp: td.transport.TcpFull,
    client: td.rpc.Client,
    prng_state: std.Random.DefaultPrng,
    echo: SockEchoCtx,
};

fn socketAnchor(gpa: std.mem.Allocator, io: std.Io, n: usize) !void {
    std.debug.print("\n-- real-socket anchor: {d} TCP-full connections, threaded echo peers --\n", .{n});

    var lbl: [48]u8 = undefined;
    const lanes = try gpa.alloc(SockLane, n);
    defer gpa.free(lanes);
    var built: usize = 0;
    errdefer for (0..built) |i| {
        lanes[i].client.deinit();
        lanes[i].tcp.close(io);
        lanes[i].listener.deinit(io);
    };

    for (0..n) |i| {
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        lanes[i].listener = try addr.listen(io, .{ .reuse_address = true });
        const port = lanes[i].listener.socket.address.getPort();
        lanes[i].tcp = td.transport.TcpFull.init(.{ .host = "127.0.0.1", .port = port }, .{
            .read_timeout = std.Io.Duration.fromSeconds(5),
            .write_timeout = std.Io.Duration.fromSeconds(5),
        });
        try lanes[i].tcp.connect(io);
        lanes[i].prng_state = std.Random.DefaultPrng.init(900 + i);
        lanes[i].client = try td.rpc.Client.init(
            gpa,
            lanes[i].tcp.transport(),
            &common.auth_key,
            common.test_salt,
            lanes[i].prng_state.random(),
            .{},
        );
        lanes[i].echo = .{
            .io = io,
            .gpa = gpa,
            .listener = &lanes[i].listener,
            .session_id = lanes[i].client.session.session_id,
        };
        built = i + 1;
    }

    const threads = try gpa.alloc(std.Thread, n);
    defer gpa.free(threads);
    for (0..n) |i| threads[i] = try std.Thread.spawn(.{}, sockEchoMain, .{&lanes[i].echo});

    // Warm-up round, untimed.
    for (0..n) |i| {
        const bytes = try lanes[i].client.invokeRaw(io, &query_body);
        gpa.free(bytes);
    }

    const requests = n * rounds_per_session;
    const samples = try gpa.alloc(u64, requests);
    defer gpa.free(samples);
    var t = common.Timer.begin(io);
    var k: usize = 0;
    for (0..rounds_per_session) |_| {
        for (0..n) |i| {
            var lat = common.Timer.begin(io);
            const bytes = try lanes[i].client.invokeRaw(io, &query_body);
            samples[k] = lat.ns();
            k += 1;
            gpa.free(bytes);
        }
    }
    const total = t.ns();

    printThroughput(try std.fmt.bufPrint(&lbl, "sockets {d}: sequential", .{n}), requests, total);
    printLatency(try std.fmt.bufPrint(&lbl, "sockets {d}: latency", .{n}), samples, total);

    for (0..n) |i| lanes[i].tcp.close(io); // FIN → echo threads exit
    for (0..n) |i| threads[i].join();
    for (0..n) |i| {
        lanes[i].client.deinit();
        lanes[i].listener.deinit(io);
    }
}

// ---------------------------------------------------------------- run

pub fn run(gpa: std.mem.Allocator, io: std.Io) !void {
    try buildAndMemory(gpa, io, &common.auth_key);
    try sequentialRoundtrips(gpa, io, &common.auth_key);
    try pipelinedRoundtrips(gpa, io, &common.auth_key);
    try sweepUtilization(gpa, io, &common.auth_key);
    try socketAnchor(gpa, io, 100);
}
