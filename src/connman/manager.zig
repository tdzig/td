//! Connection manager: one owner for the whole life of an MTProto
//! connection — establishment, loss detection, reconnection with backoff,
//! request recovery, health checks and graceful shutdown — so the layers
//! below stay single-connection and the layers above can just call.
//!
//!     connman.Manager
//!       ├─ transport.Dialer    (TCP framing of the configured mode —
//!       │                       socket lifecycle, owned)
//!       └─ rpc.Client          (encrypted session + pending table)
//!
//! State machine (all state lives in the instance; no globals):
//!
//!     idle ──▶ connecting ──ok──▶ connected ──loss──▶ backing_off
//!               │  ▲                                      │
//!               └──┘──────────── retry ◀─────────────────┘
//!
//!     every state ──close──▶ closed (terminal)
//!
//! A reconnection cycle waits out an exponential, fully-jittered backoff
//! (`Backoff`), re-establishes the TCP transport, resets the wire session
//! (fresh session_id, zeroed counters — the authorization key survives)
//! and re-sends every request the dead connection never answered
//! (`rpc.Client.recoverFailed`). "Never answered" is the protocol
//! boundary: only requests failed with a connection-level error — no
//! `rpc_error` ever arrived — are re-sent, which is exactly the case
//! MTProto permits. Because recovery happens under the same handle,
//! `send` before a drop completes through `wait` after the reconnect.
//!
//! Concurrency model, like everywhere in tdzig: single `std.Io`, single
//! thread, `io` passed per call. There is no background loop —
//! maintenance happens inside the operations themselves: `call`/`wait`
//! run their retry rounds, `pump` is the read loop, `maintain` the
//! health check (ping / ping_delay_disconnect). A manager must not be
//! copied once a client exists (the client borrows the internal
//! transport storage); use it through a pointer, as every method does.
//!
//! Not wired into `dc.DataCenters` yet: a manager fixes one endpoint and
//! one authorization key. Migration and key export/import across DCs
//! compose on top and are a later milestone.

const std = @import("std");
const crypto = @import("../crypto/mod.zig");
const transport = @import("../transport/mod.zig");
const rpc = @import("../rpc/mod.zig");
const backoff_mod = @import("backoff.zig");

pub const Backoff = backoff_mod.Backoff;

pub const Error = rpc.Error || error{
    /// `close` was called; the manager no longer operates.
    Closed,
    /// The endpoint could not be reached within the connect budget (or
    /// a mid-operation loss exceeded the retry rounds).
    CannotConnect,
};

/// Connection lifecycle states, surfaced through `Manager.state` and
/// `Health.state`.
pub const State = enum {
    /// Created, never connected.
    idle,
    /// A connection attempt is in progress.
    connecting,
    /// Established and believed healthy.
    connected,
    /// Waiting out the backoff delay before the next attempt.
    backing_off,
    /// Gracefully shut down; terminal. `deinit` still applies.
    closed,
};

/// Observability snapshot; read `Manager.health` directly.
pub const Health = struct {
    state: State = .idle,
    /// Successful establishments so far (the first connect is 1).
    generation: u64 = 0,
    /// Re-establishments after a loss (generation 2 and up).
    reconnects: u64 = 0,
    /// Failed connect attempts in a row (0 while connected).
    consecutive_failures: u32 = 0,
    /// Requests re-sent by recovery across the manager's life.
    recovered_requests: u64 = 0,
    /// Last error seen by any operation (connect, traffic, health).
    last_error: ?anyerror = null,
    /// Awake-clock timestamp of the last known-good moment: the last
    /// successful connect, completed health check or completed pump.
    last_ok_ns: ?i96 = null,
};

pub const Options = struct {
    /// Connect attempts per `ensureConnected` before `error.CannotConnect`.
    max_connect_attempts: u32 = 3,
    /// Reconnect+recovery rounds one operation tolerates before its
    /// connection-level error is surfaced as `error.CannotConnect`.
    max_retry_rounds: u32 = 3,
    /// Backoff curve (exponential with full jitter between the two).
    backoff_base: std.Io.Duration = std.Io.Duration.fromMilliseconds(250),
    backoff_max: std.Io.Duration = std.Io.Duration.fromSeconds(30),
    /// Health cadence: `maintain` pings when at least this much time
    /// passed since the last known-good moment. A large value (say, one
    /// hour) disables proactive checks while keeping them available.
    ping_interval: std.Io.Duration = std.Io.Duration.fromSeconds(60),
    /// Bound on one health-check round trip.
    ping_timeout: std.Io.Duration = std.Io.Duration.fromSeconds(10),
    /// Seconds between pings the server tolerates before dropping the
    /// connection (`ping_delay_disconnect`). The standard keep-alive
    /// contract; null sends plain pings.
    ping_disconnect_delay: ?i32 = 75,
    /// TCP transport options — the shared knob for every framing
    /// (`transport.TransportMode`): payload cap and the three timeouts.
    /// `verify_sequence` applies to the full mode only. The default
    /// `read_timeout` bounds every blocking read so `pump` budgets and
    /// health checks stay responsive; an idle read returning
    /// `error.TimedOut` leaves the connection usable. Keep it below
    /// `rpc.response_timeout` when wait loops must observe their own
    /// deadline.
    tcp: transport.tcp_full.Options = .{
        .read_timeout = std.Io.Duration.fromSeconds(30),
    },
    /// Which TCP framing the default (provider-less) path dials — see
    /// `transport.TransportMode`. Abridged is the lightest framing and
    /// the library default. Provider-acquired transports ignore this.
    transport: transport.TransportMode = .abridged,
    /// RPC client options (response deadlines, gzip bomb guard).
    rpc: rpc.Options = .{},
    /// When set, connection implementations come from this provider
    /// instead of a `TcpFull` dialed at `endpoint` — in-memory links,
    /// pooled or proxied transports. The provider (and every transport
    /// it hands out) must outlive the manager. `acquire` must return a
    /// *disconnected* transport; the manager connects it, and reconnects
    /// go through the transport's own `reconnect` (same implementation).
    /// `release` runs once, from `deinit`, after the client is gone —
    /// the pool-return seam.
    transport_provider: ?TransportProvider = null,
};

/// Source of transport implementations for managers that do not dial
/// `TcpFull` themselves. This is the seam the multi-session layer uses
/// to run thousands of sessions over in-memory links (and the seam a
/// connection pool would plug into): the manager owns none of the
/// transport storage, only the vtable handle.
pub const TransportProvider = struct {
    ctx: *anyopaque,
    acquire: *const fn (ctx: *anyopaque, io: std.Io, endpoint: transport.Endpoint) transport.Error!transport.Transport,
    release: *const fn (ctx: *anyopaque, io: std.Io, t: transport.Transport) void,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    /// Where to connect. `host` bytes are borrowed from the caller and
    /// must outlive the manager (same rule as `transport.TcpFull`).
    endpoint: transport.Endpoint,
    /// Secret; copied in at `init`, never logged.
    auth_key: [crypto.auth_key_size]u8,
    server_salt: i64,
    /// Backs the session's ids and frame padding and the backoff jitter;
    /// borrowed, must outlive the manager.
    random: std.Random,
    opts: Options,

    /// Storage for the default (provider-less) path: the TCP transport
    /// this manager dialed, of the mode `opts.transport` selected. Unused
    /// when `opts.transport_provider` is set.
    dialer: transport.Dialer = undefined,
    /// The transport interface the current client was built on (either
    /// `&tcp` or provider-acquired). Borrowed by `client` — a manager
    /// with a live client must never be moved.
    trans: transport.Transport = undefined,
    /// Whether `trans` came from the provider and must be released in
    /// `deinit`.
    trans_from_provider: bool = false,
    client: ?rpc.Client = null,

    backoff: Backoff,
    health: Health = .{},

    /// Copied onto every rpc.Client this manager creates (and refreshed
    /// on every reconnect): the application's updates hook — see
    /// `tdzig.updates.fetch.hook`.
    updates_handler: ?rpc.UpdatesHandler = null,

    /// Creates an idle manager over an established authorization key.
    /// No allocation, no connection: `ensureConnected` (or any operation)
    /// dials.
    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: transport.Endpoint,
        auth_key: *const [crypto.auth_key_size]u8,
        server_salt: i64,
        random: std.Random,
        opts: Options,
    ) Manager {
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .auth_key = auth_key.*,
            .server_salt = server_salt,
            .random = random,
            .opts = opts,
            .backoff = Backoff.init(opts.backoff_base, opts.backoff_max, random),
        };
    }

    /// Frees the client and drops the connection if still up, returning
    /// a provider-acquired transport to its provider. Safe to call from
    /// any state, including straight after `close`.
    pub fn deinit(self: *Manager, io: std.Io) void {
        if (self.client) |*c| {
            c.close(io);
            c.deinit();
            self.client = null;
        }
        if (self.trans_from_provider) {
            if (self.opts.transport_provider) |p| p.release(p.ctx, io, self.trans);
            self.trans_from_provider = false;
        }
    }

    // ------------------------------------------------------- lifecycle

    /// Current lifecycle state.
    pub fn state(self: *const Manager) State {
        return self.health.state;
    }

    /// Establishes the connection, connecting through the backoff curve
    /// on failure (`max_connect_attempts` attempts). Idempotent while
    /// connected; after a loss it re-establishes and recovers. First
    /// successful establishment of a manager is generation 1.
    pub fn ensureConnected(self: *Manager, io: std.Io) Error!void {
        if (self.health.state == .closed) return error.Closed;
        if (self.client != null and self.client.?.isConnected()) {
            self.health.state = .connected;
            return;
        }
        var attempt: u32 = 1;
        while (true) {
            self.health.state = .connecting;
            if (self.establish(io)) {
                self.health.generation += 1;
                if (self.health.generation > 1) self.health.reconnects += 1;
                self.health.state = .connected;
                self.health.consecutive_failures = 0;
                // last_error stays: it records why the previous
                // connection died, which is exactly what a monitor wants
                // to see after a recovery.
                self.health.last_ok_ns = nowNs(io);
                self.backoff.reset();
                // Re-send what the dead connection never answered. A
                // failure here means the fresh connection died
                // immediately; surface it and let the caller retry.
                const recovered = try self.client.?.recoverFailed(io);
                self.health.recovered_requests += recovered;
                return;
            } else |e| {
                self.health.consecutive_failures += 1;
                self.health.last_error = e;
                self.health.state = .backing_off;
                if (attempt >= self.opts.max_connect_attempts) return error.CannotConnect;
                self.sleepBackoff(io);
                attempt += 1;
            }
        }
    }

    /// One connection attempt, no backoff, no retries: dials the
    /// transport (first time) or drops and redials it (every reconnect),
    /// which resets the wire session while keeping the auth key.
    fn establish(self: *Manager, io: std.Io) rpc.Error!void {
        if (self.client) |*c| {
            c.updates_handler = self.updates_handler;
            return c.reconnect(io);
        }
        if (self.opts.transport_provider) |p| {
            self.trans = p.acquire(p.ctx, io, self.endpoint) catch |e| return e;
            self.trans_from_provider = true;
        } else {
            self.dialer = transport.Dialer.init(self.endpoint, self.opts.transport, self.opts.tcp, self.random);
            self.trans = self.dialer.transport();
        }
        // Covers everything from connect to client creation: on any
        // failure the transport is closed and a provider-acquired one
        // is released, leaving no checked-out resource behind.
        errdefer {
            self.trans.close(io);
            if (self.trans_from_provider) {
                if (self.opts.transport_provider) |p| p.release(p.ctx, io, self.trans);
                self.trans_from_provider = false;
            }
        }
        try self.trans.connect(io);
        self.client = try rpc.Client.init(
            self.allocator,
            self.trans,
            &self.auth_key,
            self.server_salt,
            self.random,
            self.opts.rpc,
        );
        self.client.?.updates_handler = self.updates_handler;
    }

    /// Graceful shutdown: best-effort flush of pending acknowledgements
    /// (so the server does not re-deliver content messages into the next
    /// session), cancellation of every outstanding request (their
    /// handles go stale), transport close. Terminal: later operations
    /// fail with `error.Closed`. Idempotent; `deinit` still applies.
    pub fn close(self: *Manager, io: std.Io) void {
        if (self.health.state == .closed) return;
        self.health.state = .closed;
        if (self.client) |*c| {
            c.flushAcks(io) catch {}; // the socket may already be gone
            c.cancelAll();
            c.close(io);
        }
    }

    // --------------------------------------------------------- traffic

    /// One-shot typed round trip with automatic recovery: a
    /// connection-level failure mid-flight triggers a reconnect round
    /// (backoff → redial → re-send) and the same handle is waited again,
    /// up to `max_retry_rounds`. Rpc-level failures (`RpcError`,
    /// decode errors) and response timeouts are surfaced, not retried.
    pub fn call(self: *Manager, io: std.Io, req: anytype, comptime R: type) Error!rpc.Response(R) {
        const sent = try self.send(io, req);
        // Re-wrap under the explicitly requested result type (the handle
        // value is just an id; `Result` decides the decoding).
        return self.wait(io, rpc.Handle(R){ .id = sent.id });
    }

    /// `call` with the result type resolved from the request's `Result`
    /// decl.
    pub fn invoke(self: *Manager, io: std.Io, req: anytype) Error!rpc.Response(rpc.ResultOf(@TypeOf(req))) {
        return self.call(io, req, rpc.ResultOf(@TypeOf(req)));
    }

    /// Pipelined send with automatic (re)connection. The write itself is
    /// atomic in recovery terms: if it fails at connection level nothing
    /// was registered and the retry sends the body fresh.
    pub fn send(self: *Manager, io: std.Io, req: anytype) Error!rpc.Handle(rpc.ResultOf(@TypeOf(req))) {
        var rounds: u32 = 0;
        while (true) {
            try self.ensureConnected(io);
            const c = &self.client.?;
            return c.send(io, req) catch |e| {
                if (!rpc.Client.isConnectionError(e)) return e;
                try self.retryRound(io, &rounds);
                continue;
            };
        }
    }

    /// Waits for a request sent through this manager. If the connection
    /// died before the answer arrived, the request was re-sent by the
    /// recovery round under the same handle — this simply retries the
    /// wait. Response timeouts are surfaced (the request stays
    /// registered; wait again or `cancel`).
    pub fn wait(self: *Manager, io: std.Io, handle: anytype) Error!rpc.Response(@TypeOf(handle).Result) {
        var rounds: u32 = 0;
        while (true) {
            try self.ensureConnected(io);
            const c = &self.client.?;
            return c.wait(io, handle) catch |e| {
                if (!rpc.Client.isConnectionError(e)) return e;
                try self.retryRound(io, &rounds);
                continue;
            };
        }
    }

    /// Raw pipelined send (see `Manager.send`).
    pub fn sendRaw(self: *Manager, io: std.Io, body: []const u8) Error!rpc.RawHandle {
        var rounds: u32 = 0;
        while (true) {
            try self.ensureConnected(io);
            const c = &self.client.?;
            return c.sendRaw(io, body) catch |e| {
                if (!rpc.Client.isConnectionError(e)) return e;
                try self.retryRound(io, &rounds);
                continue;
            };
        }
    }

    /// Waits for a raw request (see `Manager.wait`). The returned bytes
    /// are freed with the manager's allocator.
    pub fn waitRaw(self: *Manager, io: std.Io, handle: rpc.RawHandle) Error![]u8 {
        var rounds: u32 = 0;
        while (true) {
            try self.ensureConnected(io);
            const c = &self.client.?;
            return c.waitRaw(io, handle) catch |e| {
                if (!rpc.Client.isConnectionError(e)) return e;
                try self.retryRound(io, &rounds);
                continue;
            };
        }
    }

    /// Raw one-shot round trip with recovery.
    pub fn invokeRaw(self: *Manager, io: std.Io, body: []const u8) Error![]u8 {
        const h = try self.sendRaw(io, body);
        return self.waitRaw(io, h);
    }

    /// Technical ping/pong round trip with recovery.
    pub fn ping(self: *Manager, io: std.Io) Error!void {
        var rounds: u32 = 0;
        while (true) {
            try self.ensureConnected(io);
            const c = &self.client.?;
            return c.ping(io) catch |e| {
                if (!rpc.Client.isConnectionError(e)) return e;
                try self.retryRound(io, &rounds);
                continue;
            };
        }
    }

    /// Read loop: pumps incoming frames for up to `budget` — completing
    /// pipelined requests, acknowledging, counting updates. A
    /// connection-level failure is repaired in place (one retry round);
    /// a budget expiry with a surviving connection is success. Call
    /// repeatedly from idle loops to keep the session drained; pair with
    /// `maintain` for keep-alive.
    pub fn pump(self: *Manager, io: std.Io, budget: std.Io.Duration) Error!void {
        try self.ensureConnected(io);
        const c = &self.client.?;
        if (c.pump(io, budget)) {
            self.health.last_ok_ns = nowNs(io);
            return;
        } else |e| switch (e) {
            error.TimedOut => {
                if (c.isConnected()) {
                    // Budget exhausted on a healthy connection.
                    self.health.last_ok_ns = nowNs(io);
                    return;
                }
                // Timed out mid-frame: the framing died (waiting requests
                // were already failed as Disconnected). Repair.
                self.health.last_error = e;
                var rounds: u32 = 0;
                try self.retryRound(io, &rounds);
            },
            else => {
                if (!rpc.Client.isConnectionError(e)) return e;
                self.health.last_error = e;
                var rounds: u32 = 0;
                try self.retryRound(io, &rounds);
            },
        }
    }

    /// Cancels one outstanding request; its handle goes stale and a late
    /// result is ignored. Cancellation of an in-flight `wait` from the
    /// same thread happens between calls (single-threaded); `cancel` is
    /// for requests whose answer is no longer wanted.
    pub fn cancel(self: *Manager, handle: anytype) void {
        if (self.client) |*c| c.cancel(handle);
    }

    // ----------------------------------------------------------- health

    /// Health check: when `ping_interval` has passed since the last
    /// known-good moment, sends one ping (bounded by `ping_timeout`,
    /// carrying `ping_disconnect_delay`). A pong refreshes the
    /// known-good clock. Silence or a dead socket forces one reconnect
    /// round — the manager ends this call re-established or returns the
    /// error. Call from idle loops between `pump`s.
    pub fn maintain(self: *Manager, io: std.Io) Error!void {
        if (self.health.state == .closed) return error.Closed;
        if (self.health.last_ok_ns) |ok| {
            const elapsed = nowNs(io) - ok;
            if (elapsed < self.opts.ping_interval.nanoseconds) return;
        }
        try self.ensureConnected(io);
        const c = &self.client.?;
        if (c.pingWith(io, self.opts.ping_timeout, self.opts.ping_disconnect_delay)) {
            self.health.last_ok_ns = nowNs(io);
            return;
        } else |e| {
            self.health.last_error = e;
            // A timed-out ping stays registered for a late pong that is
            // no longer wanted on a connection we are about to drop.
            if (e == error.TimedOut) _ = c.cancelStalePings();
            if (!rpc.Client.isConnectionError(e) and e != error.TimedOut) return e;
            var rounds: u32 = 0;
            try self.retryRound(io, &rounds);
        }
    }

    // --------------------------------------------------------- plumbing

    /// Mid-operation loss: counts the round, waits out the backoff and
    /// re-establishes (which recovers every unanswered request). The
    /// manager ends connected or returns `error.CannotConnect`.
    fn retryRound(self: *Manager, io: std.Io, rounds: *u32) Error!void {
        rounds.* += 1;
        if (rounds.* > self.opts.max_retry_rounds) return error.CannotConnect;
        // The transport usually closed itself on the error; make the
        // redial unconditional (close is idempotent).
        if (self.client) |*c| c.close(io);
        self.sleepBackoff(io);
        try self.ensureConnected(io);
    }

    fn sleepBackoff(self: *Manager, io: std.Io) void {
        const d = self.backoff.next();
        const timeout: std.Io.Timeout = .{ .duration = .{ .raw = d, .clock = .awake } };
        // Only the driver can cancel a sleep and nothing here cancels it;
        // a driver that refuses to sleep must not kill the retry loop.
        timeout.sleep(io) catch {};
    }
};

fn nowNs(io: std.Io) i96 {
    return std.Io.Timestamp.now(io, .awake).nanoseconds;
}

// ---------------------------------------------------------------- tests

const test_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    break :blk k;
};

test "idle manager closes cleanly and gates every operation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var prng = std.Random.DefaultPrng.init(0x0dd1);
    var mgr = Manager.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 1 }, &test_key, 1, prng.random(), .{});
    try std.testing.expectEqual(State.idle, mgr.state());
    try std.testing.expectEqual(@as(u64, 0), mgr.health.generation);

    mgr.close(io);
    try std.testing.expectEqual(State.closed, mgr.state());
    mgr.close(io); // idempotent
    try std.testing.expectError(error.Closed, mgr.ensureConnected(io));
    try std.testing.expectError(error.Closed, mgr.send(io, TestRequest{ .query_id = 0 }));
    try std.testing.expectError(error.Closed, mgr.waitRaw(io, .{ .id = 1 }));
    try std.testing.expectError(error.Closed, mgr.ping(io));
    try std.testing.expectError(error.Closed, mgr.pump(io, std.Io.Duration.fromMilliseconds(1)));
    try std.testing.expectError(error.Closed, mgr.maintain(io));
    mgr.cancel(.{ .id = 9 }); // no-op without a client
    mgr.deinit(io);

    // A manager closed before ever connecting holds no resources.
    try std.testing.expect(mgr.client == null);
}

test "options default to a jittered curve with server keep-alive" {
    const opts = Options{};
    try std.testing.expectEqual(@as(u32, 3), opts.max_connect_attempts);
    try std.testing.expectEqual(@as(u32, 3), opts.max_retry_rounds);
    try std.testing.expect(opts.backoff_base.nanoseconds > 0);
    try std.testing.expect(opts.backoff_max.nanoseconds > opts.backoff_base.nanoseconds);
    try std.testing.expectEqual(opts.ping_disconnect_delay, 75);
    try std.testing.expect(opts.tcp.read_timeout != null);
    // Abridged is the default framing.
    try std.testing.expectEqual(transport.TransportMode.abridged, opts.transport);
}

/// Minimal request shaped like a generated function (ctor + one i32).
const TestRequest = struct {
    pub const Result = i32;

    query_id: i32,

    pub fn serialize(self: *const TestRequest, w: anytype) !void {
        try w.writeConstructorId(0x0d91a548);
        try w.writeInt(self.query_id);
    }
};
