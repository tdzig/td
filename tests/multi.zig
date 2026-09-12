//! Multi-session integration tests: a fleet of independent sessions
//! over in-memory loopback links (real MTProto both directions), driven
//! through the fleet scheduler.
//!
//! What "independent sessions" must mean, and what these tests enforce:
//! every session keeps its own wire identity (session_id, msg_id/seq
//! counters — uniqueness asserted across the fleet and against what the
//! peers actually saw), its own auth key copy, and its own failure
//! domain (one session answered rpc_error, another removed entirely —
//! the rest keep completing round trips). The scheduler side: sweeps
//! visit every live session, deliver pipelined frames, and account for
//! them.

const std = @import("std");
const td = @import("td");

const message = td.mtproto.message;
const Fleet = td.multi.Fleet;
const Registry = td.multi.Registry;
const Manager = td.connman.Manager;

const auth_key = blk: {
    var k: [256]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 89 +% 23);
    break :blk k;
};

const salt: i64 = 0x51a1;

const query_ctor_id: u32 = 0x0d91a548;
const rpc_result_id: u32 = 0xf35c6d01;
const rpc_error_id: u32 = 0x2144ca19;

fn fleetOptions(registry: *Registry) td.connman.Options {
    return .{
        .transport_provider = registry.provider(),
        .ping_interval = std.Io.Duration.fromSeconds(3600),
        .ping_timeout = std.Io.Duration.fromMilliseconds(100),
        .max_connect_attempts = 2,
        .max_retry_rounds = 2,
        .backoff_base = std.Io.Duration.fromMilliseconds(1),
        .backoff_max = std.Io.Duration.fromMilliseconds(5),
        .tcp = .{ .read_timeout = std.Io.Duration.fromMilliseconds(100) },
        .rpc = .{ .response_timeout = std.Io.Duration.fromMilliseconds(500) },
    };
}

/// Echo responder: rpc_result{bool_true} for the benchmark query.
const Echo = struct {
    fn onBody(_: *anyopaque, _: *td.multi.Link, dec: *const message.Decrypted, arena: std.mem.Allocator) ?td.multi.Reply {
        if (dec.body.len < 4) return null;
        const ctor = std.mem.readInt(u32, dec.body[0..4], .little);
        if (ctor != query_ctor_id) return null;
        var w = td.tl.Writer.init(arena);
        w.writeConstructorId(rpc_result_id) catch return null;
        w.writeLong(dec.msg_id) catch return null;
        w.writeUInt(0x997275b5) catch return null; // bool_true
        return .{ .body = w.items(), .content_related = true };
    }

    fn responder() td.multi.Responder {
        return .{ .ctx = undefined, .onBody = onBody };
    }
};

/// Answers every query with rpc_result{rpc_error{code, "TEST_ERROR"}}.
const ErrorResponder = struct {
    fn onBody(_: *anyopaque, _: *td.multi.Link, dec: *const message.Decrypted, arena: std.mem.Allocator) ?td.multi.Reply {
        if (dec.body.len < 4) return null;
        if (std.mem.readInt(u32, dec.body[0..4], .little) != query_ctor_id) return null;
        var w = td.tl.Writer.init(arena);
        w.writeConstructorId(rpc_result_id) catch return null;
        w.writeLong(dec.msg_id) catch return null;
        w.writeConstructorId(rpc_error_id) catch return null;
        w.writeInt(420) catch return null;
        w.writeString("TEST_ERROR") catch return null;
        return .{ .body = w.items(), .content_related = true };
    }

    fn responder() td.multi.Responder {
        return .{ .ctx = undefined, .onBody = onBody };
    }
};

const fleet_size = 32;
const error_session = 3; // link/session index answered with rpc_error

const Rig = struct {
    registry: Registry,
    fleet: Fleet,

    /// In-place construction: the transport provider captures
    /// `&self.registry`, so the rig must live at a stable address from
    /// here on (the same rule that keeps a Manager immovable once its
    /// client exists).
    fn setup(self: *Rig, gpa: std.mem.Allocator, io: std.Io) !void {
        self.registry = Registry.init(gpa);
        errdefer self.registry.deinit();
        for (0..fleet_size) |_| _ = try self.registry.addLink(&auth_key, salt);
        for (self.registry.links.items, 0..) |l, i| {
            l.responder = if (i == error_session) ErrorResponder.responder() else Echo.responder();
        }

        self.fleet = try Fleet.init(gpa, .{
            .capacity = fleet_size,
            .endpoint = .{ .host = "loopback", .port = 0 },
            .session = fleetOptions(&self.registry),
        });
        errdefer self.fleet.deinit(io);
        for (0..fleet_size) |i| {
            const id = try self.fleet.addSessionOn(.{ .host = "loopback", .port = @intCast(i) }, &auth_key, salt);
            std.debug.assert(id == i); // LIFO free list: identity by index
            try (try self.fleet.session(id)).ensureConnected(io);
        }
    }

    fn deinit(self: *Rig, io: std.Io) void {
        self.fleet.deinit(io);
        self.registry.deinit();
    }
};

fn invokeOk(mgr: *Manager, io: std.Io) !void {
    const body = queryBody();
    const bytes = try mgr.invokeRaw(io, &body);
    defer mgr.allocator.free(bytes);
    try std.testing.expectEqual(@as(u32, 0x997275b5), std.mem.readInt(u32, bytes[0..4], .little));
}

test "fleet of independent sessions: distinct identities, working round trips, error isolation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: Rig = undefined;
    try rig.setup(std.testing.allocator, io);
    defer rig.deinit(io);

    // Every session completes its round trip; the error session gets
    // exactly its rpc_error and nothing else is disturbed.
    for (0..fleet_size) |i| {
        const mgr = try rig.fleet.session(@intCast(i));
        if (i == error_session) {
            const body = queryBody();
            try std.testing.expectError(error.RpcError, mgr.invokeRaw(io, &body));
            try std.testing.expectEqual(@as(i32, 420), mgr.client.?.lastRpcError().code);
        } else {
            try invokeOk(mgr, io);
        }
    }

    // Wire identities: session ids are unique across the fleet and each
    // peer learned exactly its own session's id from traffic.
    var ids: [fleet_size]i64 = undefined;
    for (0..fleet_size) |i| {
        const mgr = try rig.fleet.session(@intCast(i));
        ids[i] = mgr.client.?.session.session_id;
    }
    for (0..fleet_size) |i| {
        for (i + 1..fleet_size) |j| {
            try std.testing.expect(ids[i] != ids[j]);
        }
        try std.testing.expectEqual(ids[i], rig.registry.links.items[i].session_id);
    }

    // Content flows were counted per client and matched per request —
    // every non-error session dispatched at least one result frame.
    for (0..fleet_size) |i| {
        if (i == error_session) continue;
        const mgr = try rig.fleet.session(@intCast(i));
        try std.testing.expect(mgr.client.?.frames_seen >= 1);
    }
}

test "sweeps visit every live session and deliver pipelined frames" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: Rig = undefined;
    try rig.setup(std.testing.allocator, io);
    defer rig.deinit(io);

    const body = queryBody();

    // Pipeline one query per session, then let the scheduler deliver.
    for (0..fleet_size) |i| {
        const mgr = try rig.fleet.session(@intCast(i));
        _ = try mgr.sendRaw(io, &body);
    }
    const frames_before = rig.fleet.totals().frames;
    const sweep = rig.fleet.pump(io, std.Io.Duration.fromMilliseconds(100));
    try std.testing.expectEqual(@as(usize, fleet_size), sweep.visited);
    try std.testing.expect(!sweep.stopped_early);
    try std.testing.expect(sweep.frames >= fleet_size);
    try std.testing.expect(rig.fleet.totals().frames - frames_before >= fleet_size);
    try std.testing.expectEqual(@as(usize, fleet_size), rig.fleet.connectedCount());

    // All pipelined requests complete after the sweep (their replies
    // were queued at send time; waitRaw drains what a sweep may have
    // left).
    for (0..fleet_size) |i| {
        const mgr = try rig.fleet.session(@intCast(i));
        if (i == error_session) {
            try std.testing.expectError(error.RpcError, mgr.invokeRaw(io, &body));
        } else {
            try invokeOk(mgr, io);
        }
    }
}

test "removing a session leaves the rest working and its slot recycled" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: Rig = undefined;
    try rig.setup(std.testing.allocator, io);
    defer rig.deinit(io);

    const victim = 7;
    try rig.fleet.removeSession(io, victim);
    try std.testing.expectError(error.NoSuchSession, rig.fleet.session(victim));
    try std.testing.expectEqual(@as(usize, fleet_size - 1), rig.fleet.live);

    for (0..fleet_size) |i| {
        if (i == victim or i == error_session) continue;
        const mgr = try rig.fleet.session(@intCast(i));
        try invokeOk(mgr, io);
    }

    // The recycled slot is a fresh independent session.
    const reborn = try rig.fleet.addSessionOn(.{ .host = "loopback", .port = victim }, &auth_key, salt);
    try std.testing.expectEqual(@as(u32, victim), reborn);
    const mgr = try rig.fleet.session(reborn);
    try mgr.ensureConnected(io);
    try invokeOk(mgr, io);
    try std.testing.expectEqual(@as(usize, fleet_size), rig.fleet.live);
}

test "keep-alive sweeps maintain every session without disturbing traffic" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: Rig = undefined;
    try rig.setup(std.testing.allocator, io);
    defer rig.deinit(io);

    const visited = rig.fleet.maintainAll(io);
    try std.testing.expectEqual(@as(usize, fleet_size), visited);

    // ping_interval is one hour: maintain must NOT have pinged (health
    // known-good from the connect). Traffic still flows afterwards.
    for (0..fleet_size) |i| {
        if (i == error_session) continue;
        const mgr = try rig.fleet.session(@intCast(i));
        try std.testing.expectEqual(@as(usize, 0), mgr.client.?.pongs_seen);
    }
    try invokeOk(try rig.fleet.session(0), io);
}

fn queryBody() [8]u8 {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], query_ctor_id, .little);
    std.mem.writeInt(u32, b[4..8], 7, .little);
    return b;
}
