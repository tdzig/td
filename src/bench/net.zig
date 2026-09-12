//! Network-path benchmarks: request dispatch, response dispatch, socket
//! read/write, full-stack round trips and concurrent requests.
//!
//! Layers are measured in isolation first, then composed:
//!
//! - **send path** — `sendRaw` against a discard transport: session
//!   encode + pending-table enqueue, no socket;
//! - **request+response dispatch** — `sendRaw` + `waitRaw` against a
//!   scripted transport that serves pre-built encrypted `rpc_result`
//!   frames: read, decrypt, validate, service dispatch, completion and
//!   ack flush, still with no socket. Variants: 4 B result, 1 KiB
//!   result, and a gzip_packed 1 KiB result;
//! - **pipelining** — the same scripted path at depths 1/8/64;
//! - **socket read/write** — raw TCP-full frames bounced off a threaded
//!   loopback echo server (no MTProto), 64 B / 16 KiB / 256 KiB;
//! - **full-stack roundtrip** — `invokeRaw` against a threaded MTProto
//!   echo peer (server decrypts, answers rpc_result/pong);
//! - **concurrent lanes** — 4 threads, each on its own connection and
//!   echo peer, aggregate throughput.
//!
//! Server-side work (frame building, echo threads) is intentionally
//! naive; it stands between the client ops only as a real peer would.

const std = @import("std");
const td = @import("td");
const common = @import("common.zig");

const net = std.Io.net;
const message = td.mtproto.message;
const Writer = td.tl.Writer;
const TcpFull = td.transport.TcpFull;
const tcp_full = td.transport.tcp_full;
const Client = td.rpc.Client;
/// `RawHandle` is a module-level decl in rpc/client.zig (not a `Client`
/// member) — same for `Handle(T)`.
const RawHandle = td.rpc.RawHandle;

const query_ctor_id: u32 = 0x0d91a548;
const query_body: [8]u8 = blk: {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], query_ctor_id, .little);
    std.mem.writeInt(u32, b[4..8], 7, .little);
    break :blk b;
};

const bool_true_wire: [4]u8 = .{ 0xb5, 0x75, 0x72, 0x99 };

fn fillPattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
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

fn writeAllRaw(io: std.Io, stream: *net.Stream, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, &.{bytes[sent..]}, 1);
        sent += n;
    }
}

// ------------------------------------------------------- test doubles

/// Discards every frame: isolates the pure send path (session encode +
/// pending-table enqueue) from any socket.
const NullTransport = struct {
    bytes_written: u64 = 0,

    fn connectT(_: *anyopaque, _: std.Io) td.transport.Error!void {}
    fn closeT(_: *anyopaque, _: std.Io) void {}
    fn writeT(ctx: *anyopaque, _: std.Io, payload: []const u8) td.transport.Error!void {
        const self: *NullTransport = @ptrCast(@alignCast(ctx));
        self.bytes_written += payload.len;
    }
    fn readT(_: *anyopaque, _: std.Io, _: std.mem.Allocator) td.transport.Error![]u8 {
        return error.TimedOut;
    }
    fn isConnectedT(_: *anyopaque) bool {
        return true;
    }

    const vtable = td.transport.Transport.VTable{
        .connect = connectT,
        .close = closeT,
        .write = writeT,
        .read = readT,
        .isConnected = isConnectedT,
    };

    fn transport(self: *NullTransport) td.transport.Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

/// Serves pre-built encrypted frames from a queue: isolates the receive
/// path (frame read, session decrypt/validate, service dispatch,
/// completion, ack flush) from any socket.
const ScriptedTransport = struct {
    allocator: std.mem.Allocator,
    frames: std.ArrayList([]const u8) = .empty,
    idx: usize = 0,
    bytes_written: u64 = 0,

    fn deinit(self: *ScriptedTransport) void {
        for (self.frames.items) |f| self.allocator.free(f);
        self.frames.deinit(self.allocator);
    }

    fn push(self: *ScriptedTransport, frame: []const u8) !void {
        try self.frames.append(self.allocator, try self.allocator.dupe(u8, frame));
    }

    fn connectT(_: *anyopaque, _: std.Io) td.transport.Error!void {}
    fn closeT(_: *anyopaque, _: std.Io) void {}
    fn writeT(ctx: *anyopaque, _: std.Io, payload: []const u8) td.transport.Error!void {
        const self: *ScriptedTransport = @ptrCast(@alignCast(ctx));
        self.bytes_written += payload.len;
    }
    fn readT(ctx: *anyopaque, _: std.Io, allocator: std.mem.Allocator) td.transport.Error![]u8 {
        const self: *ScriptedTransport = @ptrCast(@alignCast(ctx));
        if (self.idx >= self.frames.items.len) return error.TimedOut;
        const f = self.frames.items[self.idx];
        self.idx += 1;
        return allocator.dupe(u8, f) catch return error.OutOfMemory;
    }
    fn isConnectedT(_: *anyopaque) bool {
        return true;
    }

    const vtable = td.transport.Transport.VTable{
        .connect = connectT,
        .close = closeT,
        .write = writeT,
        .read = readT,
        .isConnected = isConnectedT,
    };

    fn transport(self: *ScriptedTransport) td.transport.Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

/// Builds spec-correct encrypted server frames carrying one
/// rpc_result{result} each (ids off the real clock, content seq counter).
const ServerPeer = struct {
    prng_state: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0xabc),
    next_low: u32 = 1,
    content: u32 = 0,

    fn buildRpcResult(
        self: *ServerPeer,
        gpa: std.mem.Allocator,
        io: std.Io,
        session_id: i64,
        req_msg_id: i64,
        result: []const u8,
    ) ![]u8 {
        var w = Writer.init(gpa);
        defer w.deinit();
        try w.writeConstructorId(message.rpc_result_id);
        try w.writeLong(req_msg_id);
        try w.writeRaw(result);

        const frame = try gpa.alloc(u8, message.frameLength(w.len()));
        errdefer gpa.free(frame);
        const s = @divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s);
        const id = (@as(i64, @intCast(s)) << 32) | self.next_low;
        self.next_low += 4;
        const seq: i32 = @intCast(2 * self.content + 1);
        self.content += 1;
        try message.writeEncrypted(&common.auth_key, .server_to_client, .{
            .salt = common.test_salt,
            .session_id = session_id,
            .msg_id = id,
            .seq_no = seq,
            .body = w.items(),
        }, self.prng_state.random(), frame);
        return frame;
    }
};

const DispatchParts = struct {
    client: *Client,
    peer: *ServerPeer,
    scripted: *ScriptedTransport,
    gpa: std.mem.Allocator,
    io: std.Io,
    result: []const u8,
};

fn oneDispatch(p: DispatchParts) !void {
    const h = try p.client.sendRaw(p.io, &query_body);
    const req_id = p.client.pending.items[p.client.pending.items.len - 1].req_msg_id;
    const frame = try p.peer.buildRpcResult(p.gpa, p.io, p.client.session.session_id, req_id, p.result);
    defer p.gpa.free(frame);
    try p.scripted.push(frame);
    const bytes = try p.client.waitRaw(p.io, h);
    p.gpa.free(bytes);
}

fn oneDispatchTimed(p: DispatchParts) !u64 {
    const h = try p.client.sendRaw(p.io, &query_body);
    const req_id = p.client.pending.items[p.client.pending.items.len - 1].req_msg_id;
    const frame = try p.peer.buildRpcResult(p.gpa, p.io, p.client.session.session_id, req_id, p.result);
    defer p.gpa.free(frame);
    try p.scripted.push(frame);
    var t = common.Timer.begin(p.io);
    const bytes = try p.client.waitRaw(p.io, h);
    const ns = t.ns();
    p.gpa.free(bytes);
    return ns;
}

// ----------------------------------------------------------- benches

fn benchSendPath(gpa: std.mem.Allocator, io: std.Io) !void {
    var null_tr = NullTransport{};
    var prng_state = std.Random.DefaultPrng.init(5);
    var client = try Client.init(gpa, null_tr.transport(), &common.auth_key, common.test_salt, prng_state.random(), .{});
    defer client.deinit();

    for (0..1_000) |_| _ = try client.sendRaw(io, &query_body);
    const t = common.Timer.begin(io);
    for (0..50_000) |_| {
        const h = try client.sendRaw(io, &query_body);
        common.keep(h.id);
    }
    common.reportLine("rpc.sendRaw (null transport)", query_body.len, t.ns(), 50_000);
}

fn benchDispatch(gpa: std.mem.Allocator, io: std.Io, label: []const u8, result: []const u8, iters: usize) !void {
    var peer = ServerPeer{};
    var scripted = ScriptedTransport{ .allocator = gpa };
    defer scripted.deinit();
    var prng_state = std.Random.DefaultPrng.init(11);
    var client = try Client.init(gpa, scripted.transport(), &common.auth_key, common.test_salt, prng_state.random(), .{});
    defer client.deinit();

    const p = DispatchParts{
        .client = &client,
        .peer = &peer,
        .scripted = &scripted,
        .gpa = gpa,
        .io = io,
        .result = result,
    };
    for (0..200) |_| try oneDispatch(p);
    var total: u64 = 0;
    for (0..iters) |_| total += try oneDispatchTimed(p);
    common.reportLine(label, result.len, total, iters);
}

fn dispatchAllocs(gpa: std.mem.Allocator, io: std.Io, label: []const u8, result: []const u8) !void {
    var c = common.CountingAllocator{ .child = gpa };
    const a = c.allocator();
    var peer = ServerPeer{};
    var scripted = ScriptedTransport{ .allocator = a };
    defer scripted.deinit();
    var prng_state = std.Random.DefaultPrng.init(11);
    var client = try Client.init(a, scripted.transport(), &common.auth_key, common.test_salt, prng_state.random(), .{});
    defer client.deinit();

    const p = DispatchParts{
        .client = &client,
        .peer = &peer,
        .scripted = &scripted,
        .gpa = a,
        .io = io,
        .result = result,
    };
    for (0..50) |_| try oneDispatch(p);
    c.reset();
    for (0..500) |_| try oneDispatch(p);
    common.reportAllocs(label, 500, &c);
}

fn runBatch(p: *const DispatchParts, handles: []RawHandle, depth: usize) !void {
    for (0..depth) |i| {
        handles[i] = try p.client.sendRaw(p.io, &query_body);
        const req_id = p.client.pending.items[p.client.pending.items.len - 1].req_msg_id;
        const frame = try p.peer.buildRpcResult(p.gpa, p.io, p.client.session.session_id, req_id, p.result);
        defer p.gpa.free(frame);
        try p.scripted.push(frame);
    }
    for (0..depth) |i| {
        const bytes = try p.client.waitRaw(p.io, handles[i]);
        p.gpa.free(bytes);
    }
}

fn benchPipelined(gpa: std.mem.Allocator, io: std.Io, depth: usize, label: []const u8, iters: usize) !void {
    var peer = ServerPeer{};
    var scripted = ScriptedTransport{ .allocator = gpa };
    defer scripted.deinit();
    var prng_state = std.Random.DefaultPrng.init(13);
    var client = try Client.init(gpa, scripted.transport(), &common.auth_key, common.test_salt, prng_state.random(), .{});
    defer client.deinit();

    const p = DispatchParts{
        .client = &client,
        .peer = &peer,
        .scripted = &scripted,
        .gpa = gpa,
        .io = io,
        .result = &bool_true_wire,
    };
    var handles: [64]RawHandle = undefined;
    const batches = iters / depth;
    for (0..3) |_| try runBatch(&p, &handles, depth);
    const t = common.Timer.begin(io);
    for (0..batches) |_| try runBatch(&p, &handles, depth);
    common.reportLine(label, query_body.len, t.ns(), batches * depth);
}

// ------------------------------------------------ raw socket echo

const RawEchoCtx = struct {
    io: std.Io,
    listener: *net.Server,
    buf: []u8,
};

fn rawEchoMain(ctx: *RawEchoCtx) void {
    var stream = ctx.listener.accept(ctx.io) catch return;
    defer stream.close(ctx.io);
    var seq: u32 = 0;
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
        const out_h = tcp_full.Codec.header(plen, seq);
        var out_tr: [4]u8 = undefined;
        std.mem.writeInt(u32, &out_tr, tcp_full.Codec.checksum(&out_h, ctx.buf[0..plen]), .little);
        // One segment: header + payload + trailer (three writes stall on
        // Nagle + delayed ACK in this request/response exchange).
        std.mem.copyBackwards(u8, ctx.buf[8..][0..plen], ctx.buf[0..plen]);
        @memcpy(ctx.buf[0..8], &out_h);
        @memcpy(ctx.buf[8 + plen ..][0..4], &out_tr);
        writeAllRaw(ctx.io, &stream, ctx.buf[0 .. plen + tcp_full.frame_overhead]) catch return;
        seq +%= 1;
    }
}

fn benchRawSocket(gpa: std.mem.Allocator, io: std.Io, label: []const u8, payload_len: usize, iters: usize) !void {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const echo_buf = try gpa.alloc(u8, payload_len + 16);
    defer gpa.free(echo_buf);
    var ctx = RawEchoCtx{ .io = io, .listener = &server, .buf = echo_buf };
    const th = try std.Thread.spawn(.{}, rawEchoMain, .{&ctx});

    var tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = port }, .{
        .read_timeout = std.Io.Duration.fromSeconds(5),
        .write_timeout = std.Io.Duration.fromSeconds(5),
    });
    try tcp.connect(io);

    const payload = try gpa.alloc(u8, payload_len);
    defer gpa.free(payload);
    fillPattern(payload);

    for (0..100) |_| {
        try tcp.write(io, payload);
        const got = try tcp.read(io, gpa);
        gpa.free(got);
    }
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        try tcp.write(io, payload);
        const got = try tcp.read(io, gpa);
        gpa.free(got);
    }
    const total = t.ns();
    common.reportLine(label, payload_len, total, iters);

    tcp.close(io); // FIN unblocks the echo thread
    th.join();
}

// ------------------------------------------------- MTProto echo peer

const EchoCtx = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    listener: *net.Server,
    session_id: i64,
    prng_state: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0xabc),
    next_low: u32 = 1,
    content: u32 = 0,
    out_seq: u32 = 0,
    buf: [4096]u8 = undefined,
    /// Header + frame + trailer in one segment (three writes interact
    /// with Nagle + delayed ACK into ~40 ms ping-pong stalls).
    out: [4096 + 12]u8 = undefined,

    fn reply(self: *EchoCtx, stream: *net.Stream, body: []const u8, content_related: bool) void {
        const flen = message.frameLength(body.len);
        if (flen > self.buf.len) return;
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
        const total = 8 + flen + 4;
        @memcpy(self.out[0..8], &h);
        @memcpy(self.out[8..][0..flen], self.buf[0..flen]);
        @memcpy(self.out[8 + flen ..][0..4], &tr);
        writeAllRaw(self.io, stream, self.out[0..total]) catch return;
        self.out_seq +%= 1;
    }
};

fn mtprotoEchoMain(ctx: *EchoCtx) void {
    var stream = ctx.listener.accept(ctx.io) catch return;
    defer stream.close(ctx.io);
    var w = Writer.init(ctx.gpa);
    defer w.deinit();

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
            w.buf.clearRetainingCapacity();
            w.writeConstructorId(message.rpc_result_id) catch return;
            w.writeLong(dec.msg_id) catch return;
            w.writeRaw(&bool_true_wire) catch return;
            ctx.reply(&stream, w.items(), true);
        } else if (ctor == message.ping_id) {
            if (dec.body.len < 12) continue;
            w.buf.clearRetainingCapacity();
            w.writeConstructorId(message.pong_id) catch return;
            w.writeLong(dec.msg_id) catch return;
            w.writeLong(std.mem.readInt(i64, dec.body[4..12], .little)) catch return;
            ctx.reply(&stream, w.items(), false);
        }
        // everything else (msgs_ack, ...) drains silently
    }
}

fn benchRtt(gpa: std.mem.Allocator, io: std.Io, label: []const u8, iters: usize) !void {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    var tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = port }, .{
        .read_timeout = std.Io.Duration.fromSeconds(5),
        .write_timeout = std.Io.Duration.fromSeconds(5),
    });
    try tcp.connect(io);

    var prng_state = std.Random.DefaultPrng.init(42);
    var client = try Client.init(gpa, tcp.transport(), &common.auth_key, common.test_salt, prng_state.random(), .{});
    defer client.deinit();

    var echo_ctx = EchoCtx{
        .io = io,
        .gpa = gpa,
        .listener = &server,
        .session_id = client.session.session_id,
    };
    const echo_th = try std.Thread.spawn(.{}, mtprotoEchoMain, .{&echo_ctx});

    for (0..200) |_| {
        const bytes = try client.invokeRaw(io, &query_body);
        gpa.free(bytes);
    }
    const t = common.Timer.begin(io);
    for (0..iters) |_| {
        const bytes = try client.invokeRaw(io, &query_body);
        gpa.free(bytes);
    }
    common.reportLine(label, query_body.len, t.ns(), iters);

    tcp.close(io); // FIN unblocks the echo thread
    echo_th.join();
}

// ------------------------------------------------- concurrent lanes

const WorkerCtx = struct {
    io: std.Io,
    client: *Client,
    iters: usize,
    ns: u64 = 0,
    err: ?anyerror = null,
};

fn workerMain(ctx: *WorkerCtx) void {
    var t = common.Timer.begin(ctx.io);
    for (0..ctx.iters) |_| {
        const bytes = ctx.client.invokeRaw(ctx.io, &query_body) catch |e| {
            ctx.err = e;
            return;
        };
        ctx.client.allocator.free(bytes);
    }
    ctx.ns = t.ns();
}

const max_lanes = 8;

const Lane = struct {
    listener: net.Server,
    tcp: TcpFull,
    client: Client,
    /// Lives in the Lane so the session's borrowed Random outlives
    /// Client.init (a stack local here would dangle).
    prng_state: std.Random.DefaultPrng,
    echo: EchoCtx,
    worker: WorkerCtx = undefined,
};

fn benchLanes(gpa: std.mem.Allocator, io: std.Io, label: []const u8, lane_count: usize, iters: usize) !void {
    std.debug.assert(lane_count <= max_lanes);
    var lanes: [max_lanes]Lane = undefined;
    var built: usize = 0;
    errdefer {
        for (0..built) |i| {
            lanes[i].client.deinit();
            lanes[i].tcp.close(io);
            lanes[i].listener.deinit(io);
        }
    }

    for (0..lane_count) |i| {
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        lanes[i].listener = try addr.listen(io, .{ .reuse_address = true });
        const port = lanes[i].listener.socket.address.getPort();
        lanes[i].tcp = TcpFull.init(.{ .host = "127.0.0.1", .port = port }, .{
            .read_timeout = std.Io.Duration.fromSeconds(5),
            .write_timeout = std.Io.Duration.fromSeconds(5),
        });
        try lanes[i].tcp.connect(io);
        lanes[i].prng_state = std.Random.DefaultPrng.init(100 + i);
        lanes[i].client = try Client.init(
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

    var echo_threads: [max_lanes]std.Thread = undefined;
    var worker_threads: [max_lanes]std.Thread = undefined;
    for (0..lane_count) |i|
        echo_threads[i] = try std.Thread.spawn(.{}, mtprotoEchoMain, .{&lanes[i].echo});
    var wall = common.Timer.begin(io);
    for (0..lane_count) |i| {
        lanes[i].worker = .{ .io = io, .client = &lanes[i].client, .iters = iters };
        worker_threads[i] = try std.Thread.spawn(.{}, workerMain, .{&lanes[i].worker});
    }

    var total_worker_ns: u64 = 0;
    var failed: ?anyerror = null;
    for (0..lane_count) |i| {
        worker_threads[i].join();
        total_worker_ns += lanes[i].worker.ns;
        if (lanes[i].worker.err) |e| failed = e;
    }
    const wall_ns = wall.ns();

    for (0..lane_count) |i| lanes[i].tcp.close(io); // FIN → echo threads exit
    for (0..lane_count) |i| echo_threads[i].join();
    for (0..lane_count) |i| {
        lanes[i].client.deinit();
        lanes[i].listener.deinit(io);
    }
    built = 0; // normal-path teardown done; errdefer must not repeat it

    common.reportLine(label, query_body.len, wall_ns, lane_count * iters);
    std.debug.print("  ({d} lanes; sum of per-lane times {d} ms vs {d} ms wall)\n", .{
        lane_count,
        total_worker_ns / std.time.ns_per_ms,
        wall_ns / std.time.ns_per_ms,
    });
    if (failed) |e| return e;
}

// --------------------------------------------------------------- run

pub fn run(gpa: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n-- request dispatch (transport isolated) --\n", .{});
    try benchSendPath(gpa, io);

    var payload_1k: [1020]u8 = undefined;
    fillPattern(&payload_1k);
    // A realistic 1 KiB result: a known constructor id followed by
    // payload bytes (completeRpc classifies a result by its constructor;
    // an id no schema knows would travel the updates path instead).
    const result_1k = try gpa.alloc(u8, 1024);
    defer gpa.free(result_1k);
    @memcpy(result_1k[0..4], &bool_true_wire);
    @memcpy(result_1k[4..], &payload_1k);
    const gz = try td.rpc.decode.buildGzipStored(gpa, &payload_1k);
    defer gpa.free(gz);
    var gw = Writer.init(gpa);
    defer gw.deinit();
    try gw.writeConstructorId(message.gzip_packed_id);
    try gw.writeBytes(gz);
    const gzip_result = try gpa.dupe(u8, gw.items());
    defer gpa.free(gzip_result);

    try benchDispatch(gpa, io, "dispatch req+resp 4 B result", &bool_true_wire, 20_000);
    try benchDispatch(gpa, io, "dispatch req+resp 1 KiB result", result_1k, 10_000);
    try benchDispatch(gpa, io, "dispatch req+resp gzip(1 KiB)", gzip_result, 5_000);
    try dispatchAllocs(gpa, io, "dispatch req+resp 4 B result", &bool_true_wire);
    try dispatchAllocs(gpa, io, "dispatch req+resp gzip(1 KiB)", gzip_result);

    std.debug.print("\n-- pipelining (scripted transport) --\n", .{});
    try benchPipelined(gpa, io, 1, "pipeline depth 1", 20_000);
    try benchPipelined(gpa, io, 8, "pipeline depth 8", 24_000);
    try benchPipelined(gpa, io, 64, "pipeline depth 64", 64_000);

    std.debug.print("\n-- socket read/write (raw TCP-full loopback echo) --\n", .{});
    try benchRawSocket(gpa, io, "TcpFull roundtrip 64 B", 64, 20_000);
    try benchRawSocket(gpa, io, "TcpFull roundtrip 16 KiB", 16 * 1024, 5_000);
    try benchRawSocket(gpa, io, "TcpFull roundtrip 256 KiB", 256 * 1024, 300);

    std.debug.print("\n-- full-stack roundtrip (loopback MTProto peer) --\n", .{});
    try benchRtt(gpa, io, "invokeRaw roundtrip (loopback)", 5_000);

    std.debug.print("\n-- concurrent requests (thread per connection) --\n", .{});
    try benchLanes(gpa, io, "4 lanes × 1000 invokeRaw", 4, 1_000);
}
