//! In-memory loopback transport: one `Link` per session, with a real
//! MTProto peer living on the other side of the vtable — decryption,
//! envelope validation and reply construction included, only the socket
//! replaced by a queue.
//!
//! A `Link` implements `transport.Transport` for the client half. The
//! server half is embedded: `write` hands the client's encrypted frame
//! to the `Responder` (which decrypts it with `message.readEncrypted`
//! and produces a reply body), the reply is encrypted back and queued,
//! and the next `read` pops it. One `write` is one encrypted frame —
//! exactly how `rpc.Client` uses a transport (requests and ack flushes
//! each travel as a single frame).
//!
//! This is the peer the multi-session benchmarks and tests run against:
//! like a threaded loopback echo server it exercises the whole stack
//! (session encode/decode, msg_id/seq rules, rpc matching both ways),
//! but it needs no threads and no file descriptors, so a fleet of ten
//! thousand sessions costs memory and CPU rather than kernel resources.
//! Real-socket behavior — blocking reads, read_timeout waits, kernel
//! buffers — is measured separately by the `net` benchmark section and
//! the socket-backed integration tests.
//!
//! Wire identity: the peer learns the client's `session_id` from the
//! first frame it decrypts, so a link binds to a session by traffic,
//! not configuration — the same information a real server gets. Like a
//! real server, session state survives a reconnect: when the client
//! continues the same `session_id` (restored counters), the peer keeps
//! its outgoing seq counter, and when a frame arrives under a new id
//! (`Session.reset` after a reconnect), the peer rebinds and starts
//! over. Every other rule is enforced for real: wrong salt, wrong
//! msg_id parity, bad padding or a tampered frame fails the peer
//! exactly as it would fail a server.
//!
//! Not a protocol shortcut: the responder callback decides what the
//! peer answers (echo, rpc_error, silence); the transport layer itself
//! never skips a check.

const std = @import("std");
const transport = @import("../transport/mod.zig");
const crypto = @import("../crypto/mod.zig");
const message = @import("../mtproto/message.zig");
const connman = @import("../connman/mod.zig");

pub const Error = transport.Error;

/// What the peer answers to one decrypted client message. `body` is the
/// TL reply (already serialized by the responder); it is copied into the
/// outgoing frame before the callee's arena goes away.
pub const Reply = struct {
    body: []const u8,
    /// Whether the reply is content-related (odd seq_no, needs an ack).
    /// rpc results are; pongs and acks are not.
    content_related: bool,
};

/// Policy hook: receives one decrypted client message and either answers
/// (`Reply`, allocated from the provided arena) or stays silent (null —
/// the message is drained, like a msgs_ack on a real server). Runs from
/// inside the client's `write`: it must not re-enter the client.
pub const Responder = struct {
    ctx: *anyopaque,
    onBody: *const fn (ctx: *anyopaque, link: *Link, dec: *const message.Decrypted, arena: std.mem.Allocator) ?Reply,
};

/// One in-memory connection: client-side transport + embedded MTProto
/// peer. Create with `init`, hand `transport()` to an `rpc.Client` (or
/// a `connman.Manager` through a provider), and set `responder` before
/// the first frame. The link must not move while a client holds the
/// transport (the vtable points at it).
pub const Link = struct {
    allocator: std.mem.Allocator,
    /// Secret key shared with the client; borrowed, must outlive the
    /// link. Never logged.
    auth_key: *const [crypto.auth_key_size]u8,
    /// The server salt both sides use. The client adopts corrections on
    /// its own; a link used across a real salt rotation belongs behind a
    /// responder that keeps this in sync.
    salt: i64,
    /// The peer's reply policy (set before the first frame flows).
    responder: ?Responder = null,
    /// Backs reply-body construction on the peer side; reset per frame.
    scratch: std.heap.ArenaAllocator,

    connected: bool = false,
    /// Encrypted server→client frames awaiting the client's `read`.
    rx: std.ArrayList([]u8) = .empty,
    /// Frames the peer has decrypted since `connect` (answered or
    /// dropped — the count of client frames seen).
    frames_seen: usize = 0,

    // Peer wire state, learned/advanced per frame.
    session_id: i64 = 0,
    prng_state: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0x7ee),
    next_low: u32 = 1,
    content: u32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        auth_key: *const [crypto.auth_key_size]u8,
        salt: i64,
    ) Link {
        return .{
            .allocator = allocator,
            .auth_key = auth_key,
            .salt = salt,
            .scratch = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Link) void {
        self.clearRx();
        self.rx.deinit(self.allocator);
        self.scratch.deinit();
    }

    fn clearRx(self: *Link) void {
        for (self.rx.items) |f| self.allocator.free(f);
        self.rx.clearRetainingCapacity();
    }

    /// Client-side transport handle. The link must stay put while the
    /// handle is in use. The return type is an inline import — this
    /// method's name shadows the file-scope `transport` import inside
    /// the container.
    pub fn transport(self: *Link) @import("../transport/mod.zig").Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// Number of frames currently queued for the client.
    pub fn pendingReplies(self: *const Link) usize {
        return self.rx.items.len;
    }

    // -------------------------------------------------- server-side wire

    /// Server ids from the real clock: ≡ 1 (mod 4) so the client's
    /// response-parity check passes; the clock keeps the ids inside the
    /// client's receive window without configuration.
    fn nextMsgId(self: *Link, io: std.Io) i64 {
        const s = @divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s);
        const id = (@as(i64, @intCast(s)) << 32) | self.next_low;
        self.next_low +%= 4;
        return id;
    }

    fn encryptReply(self: *Link, io: std.Io, body: []const u8, content_related: bool) Error![]u8 {
        const frame = self.allocator.alloc(u8, message.frameLength(body.len)) catch
            return error.OutOfMemory;
        errdefer self.allocator.free(frame);
        const seq: i32 = @intCast(2 * self.content + @as(u32, if (content_related) 1 else 0));
        if (content_related) self.content += 1;
        message.writeEncrypted(self.auth_key, .server_to_client, .{
            .salt = self.salt,
            .session_id = self.session_id,
            .msg_id = self.nextMsgId(io),
            .seq_no = seq,
            .body = body,
        }, self.prng_state.random(), frame) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidFrame,
        };
        return frame;
    }

    /// Server half of one client frame: decrypt, validate, answer. Any
    /// protocol violation drops the frame exactly like a real server
    /// would drop the connection for it — here the link just stays
    /// silent (the client sees an idle read, which is what a silent
    /// peer is).
    fn serveFrame(self: *Link, io: std.Io, payload: []const u8) void {
        _ = self.scratch.reset(.retain_capacity);
        const arena = self.scratch.allocator();

        // readEncrypted validates in place — work on a copy so the
        // caller's tx buffer is never mutated.
        const buf = self.allocator.dupe(u8, payload) catch return;
        defer self.allocator.free(buf);

        // Decrypt with no session expectation — like a real server,
        // which keys session state by id and accepts whichever session
        // a frame names — then decide locally whether this continues
        // the known session or starts a new one.
        const dec = message.readEncrypted(self.auth_key, .client_to_server, 0, buf) catch return;
        if (dec.session_id != self.session_id) {
            self.session_id = dec.session_id;
            self.content = 0;
        }
        self.frames_seen += 1;

        const responder = self.responder orelse return;
        const reply = responder.onBody(responder.ctx, self, &dec, arena) orelse return;
        const frame = self.encryptReply(io, reply.body, reply.content_related) catch return;
        self.rx.append(self.allocator, frame) catch {
            self.allocator.free(frame);
        };
    }

    // ---------------------------------------------------- vtable plumbing

    fn connectT(ctx: *anyopaque, _: std.Io) @import("../transport/mod.zig").Error!void {
        const self: *Link = @ptrCast(@alignCast(ctx));
        if (self.connected) return error.AlreadyConnected;
        // Fresh connection, remembered session: like a real server, the
        // peer keeps the session state it learned (session id, outgoing
        // seq counter) and rebinds only when a frame arrives under a
        // different id. Replies the old connection never delivered are
        // dropped — the client re-requests what still matters.
        self.clearRx();
        self.connected = true;
    }

    fn closeT(ctx: *anyopaque, _: std.Io) void {
        const self: *Link = @ptrCast(@alignCast(ctx));
        self.connected = false;
        self.clearRx();
    }

    fn writeT(ctx: *anyopaque, io: std.Io, payload: []const u8) @import("../transport/mod.zig").Error!void {
        const self: *Link = @ptrCast(@alignCast(ctx));
        if (!self.connected) return error.NotConnected;
        self.serveFrame(io, payload);
    }

    fn readT(ctx: *anyopaque, _: std.Io, allocator: std.mem.Allocator) @import("../transport/mod.zig").Error![]u8 {
        const self: *Link = @ptrCast(@alignCast(ctx));
        if (!self.connected) return error.NotConnected;
        if (self.rx.items.len == 0) {
            // Idle: no data, and nothing will arrive until the client
            // writes again. `error.TimedOut` before any frame byte is
            // the transport contract for "connection still usable".
            return error.TimedOut;
        }
        const frame = self.rx.orderedRemove(0);
        defer self.allocator.free(frame);
        return allocator.dupe(u8, frame) catch return error.OutOfMemory;
    }

    fn isConnectedT(ctx: *anyopaque) bool {
        const self: *Link = @ptrCast(@alignCast(ctx));
        return self.connected;
    }

    const vtable = @import("../transport/mod.zig").Transport.VTable{
        .connect = connectT,
        .close = closeT,
        .write = writeT,
        .read = readT,
        .isConnected = isConnectedT,
    };
};

/// Transport provider over a set of links: `acquire` resolves an
/// endpoint whose port is the link's registry index. This is the seam
/// `connman.Options.transport_provider` plugs into — a fleet of
/// managers runs on registry links with no sockets at all.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    links: std.ArrayList(*Link) = .empty,

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Registry) void {
        for (self.links.items) |l| {
            l.deinit();
            self.allocator.destroy(l);
        }
        self.links.deinit(self.allocator);
    }

    /// Creates a link and registers it; the link's index is the port
    /// value that resolves back to it through `provider()`.
    pub fn addLink(
        self: *Registry,
        auth_key: *const [crypto.auth_key_size]u8,
        salt: i64,
    ) Error!*Link {
        const l = try self.allocator.create(Link);
        errdefer self.allocator.destroy(l);
        l.* = Link.init(self.allocator, auth_key, salt);
        errdefer l.deinit();
        try self.links.append(self.allocator, l);
        return l;
    }

    /// The `connman.TransportProvider` for this registry.
    pub fn provider(self: *Registry) connman.TransportProvider {
        return .{ .ctx = self, .acquire = acquireT, .release = releaseT };
    }

    fn acquireT(ctx: *anyopaque, _: std.Io, endpoint: transport.Endpoint) transport.Error!transport.Transport {
        const self: *Registry = @ptrCast(@alignCast(ctx));
        if (endpoint.port >= self.links.items.len) return error.ConnectFailed;
        return self.links.items[endpoint.port].transport();
    }

    fn releaseT(_: *anyopaque, _: std.Io, _: transport.Transport) void {
        // Links live in the registry for the registry's lifetime; a
        // manager returning one is a no-op. A real pool would recycle
        // here.
    }
};

// ---------------------------------------------------------------- tests

const tl = @import("../tl/mod.zig");
const mtproto = @import("../mtproto/mod.zig");

const test_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 41 +% 9);
    break :blk k;
};

const test_salt: i64 = 0x71aa;

// A minimal content-related client query, shaped like bench/net's.
const query_ctor_id: u32 = 0x0d91a548;
const ping_ctor_id: u32 = 0x7abe77ec;
const pong_ctor_id: u32 = 0x347773c5;
const rpc_result_id: u32 = 0xf35c6d01;

const EchoResponder = struct {
    fn onBody(_: *anyopaque, _: *Link, dec: *const message.Decrypted, arena: std.mem.Allocator) ?Reply {
        if (dec.body.len < 4) return null;
        const ctor = std.mem.readInt(u32, dec.body[0..4], .little);
        var w = tl.Writer.init(arena);
        if (ctor == query_ctor_id) {
            // rpc_result{req_msg_id, bool_true}
            w.writeConstructorId(rpc_result_id) catch return null;
            w.writeLong(dec.msg_id) catch return null;
            w.writeUInt(0x997275b5) catch return null;
            return .{ .body = w.items(), .content_related = true };
        }
        if (ctor == ping_ctor_id) {
            w.writeConstructorId(pong_ctor_id) catch return null;
            w.writeLong(dec.msg_id) catch return null;
            if (dec.body.len < 12) return null;
            w.writeLong(std.mem.readInt(i64, dec.body[4..12], .little)) catch return null;
            return .{ .body = w.items(), .content_related = false };
        }
        return null; // msgs_ack and everything else drains silently
    }

    fn responder() Responder {
        return .{ .ctx = undefined, .onBody = onBody };
    }
};

test "link round-trips an encrypted frame through the embedded peer" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var link = Link.init(std.testing.allocator, &test_key, test_salt);
    defer link.deinit();
    link.responder = EchoResponder.responder();

    var t = link.transport();
    try t.connect(io);
    var prng_state = std.Random.DefaultPrng.init(3);
    var session = try mtproto.Session.init(std.testing.allocator, &test_key, test_salt, prng_state.random());
    defer session.deinit();

    var w = tl.Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(query_ctor_id);
    try w.writeInt(7);
    const body = w.items();

    const frame = try std.testing.allocator.alloc(u8, message.frameLength(body.len));
    defer std.testing.allocator.free(frame);
    const sent = try session.encode(1_700_000_000, true, body, frame);
    try t.write(io, frame);
    try std.testing.expectEqual(@as(usize, 1), link.pendingReplies());

    const got = try t.read(io, std.testing.allocator);
    defer std.testing.allocator.free(got);
    var out: [1]message.Incoming = undefined;
    const now: u64 = @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
    const recvd = try session.receive(got, now, &out);
    try std.testing.expectEqual(@as(usize, 1), recvd.messages.len);
    try std.testing.expectEqual(rpc_result_id, std.mem.readInt(u32, recvd.messages[0].body[0..4], .little));
    try std.testing.expectEqual(sent.msg_id, std.mem.readInt(i64, recvd.messages[0].body[4..12], .little));
}

test "tampered frame gets no reply (peer enforces msg_key)" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var link = Link.init(std.testing.allocator, &test_key, test_salt);
    defer link.deinit();
    link.responder = EchoResponder.responder();

    var t = link.transport();
    try t.connect(io);

    var frame: [message.frameLength(8)]u8 = undefined;
    for (&frame, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
    try t.write(io, &frame);
    // Garbage never decrypts: the peer stays silent.
    try std.testing.expectEqual(@as(usize, 0), link.pendingReplies());
    // The connection itself is still usable (idle read = TimedOut).
    try std.testing.expectError(error.TimedOut, t.read(io, std.testing.allocator));
}

test "registry resolves endpoints by port" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    _ = try registry.addLink(&test_key, test_salt);
    _ = try registry.addLink(&test_key, test_salt);
    try std.testing.expectEqual(@as(usize, 2), registry.links.items.len);

    const p = registry.provider();
    const t1 = try p.acquire(p.ctx, io, .{ .host = "loopback", .port = 1 });
    try t1.connect(io);
    try std.testing.expect(t1.isConnected());
    try std.testing.expectError(error.AlreadyConnected, t1.connect(io));

    // An out-of-range port is a connect failure, not a crash.
    try std.testing.expectError(error.ConnectFailed, p.acquire(p.ctx, io, .{ .host = "loopback", .port = 9 }));

    // The provider hands the manager a disconnected transport on every
    // acquire of the same endpoint (close in between).
    t1.close(io);
    const t2 = try p.acquire(p.ctx, io, .{ .host = "loopback", .port = 1 });
    try std.testing.expect(!t2.isConnected());
    p.release(p.ctx, io, t2);
}
