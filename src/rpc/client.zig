//! RPC client: invokes Telegram functions over one encrypted MTProto
//! session and decodes the answers into generated types.
//!
//! Layering:
//!
//!     Transport (framing)  →  Session (encryption, ids, acks)  →  **RPC**
//!
//! The client owns a `mtproto.Session` and drives it through any
//! `transport.Transport`. Sending and waiting are separate operations, so
//! requests pipeline naturally: two `send`s, then two `wait`s, share one
//! receive pump — the server's answers (individually or packed in one
//! container) are matched to their requests by `rpc_result.req_msg_id`.
//!
//!   * `invoke(io, req)` — one-shot typed round trip; requires the request
//!     struct to carry a `Result` decl (the generator emits one for every
//!     function; the committed `src/api` gains them on the next
//!     `just api` regeneration).
//!   * `call(io, req, R)` — same, with the result type passed explicitly.
//!   * `send`/`wait` — pipelined form of the above.
//!   * `invokeRaw`/`sendRaw`/`waitRaw` — pre-serialized bytes in, raw
//!     result-object bytes out (gzip already inflated); the low-level path.
//!   * `ping` — technical ping/pong round trip.
//!   * `pump` — service loop: dispatch frames for a time budget without
//!     waiting for one specific request.
//!   * `recoverFailed` — connection-manager hook: re-sends every request
//!     a dead connection never answered (the recoverable error family of
//!     `isConnectionError`) under fresh msg_ids, keeping handles valid.
//!
//! While a request is outstanding the client keeps a copy of its serialized
//! body: `bad_server_salt` and the resolvable `bad_msg_notification` codes
//! re-send the query under a fresh msg_id automatically.
//!
//! Service messages are handled per the MTProto spec: `rpc_result` (which
//! doubles as the acknowledgement of the request), `rpc_error` (surfaced as
//! `error.RpcError` with details in `lastRpcError`), `msgs_ack`,
//! `bad_msg_notification`, `bad_server_salt`, `new_session_created`,
//! `pong`, `future_salts` (completes the requesting handle with the raw
//! body). Server-pushed updates (unknown top-level API objects) are
//! counted (`updates_seen`) and, when `updates_handler` is set, handed
//! to the application raw — decoding and dispatch live in the updates
//! subsystem (`td.updates`).
//!
//! Single `std.Io`, single thread: "concurrent requests" means pipelined,
//! not parallel. `io` is passed per call, like everywhere in td.

const std = @import("std");
const crypto = @import("../crypto/mod.zig");
const transport = @import("../transport/mod.zig");
const mtproto = @import("../mtproto/mod.zig");
const message = mtproto.message;
const decode_mod = @import("decode.zig");
const api = @import("../api/mod.zig");
const tl = @import("../tl/mod.zig");
const Writer = tl.Writer;
const Reader = tl.Reader;
const errors_gen = @import("errors_gen.zig");

pub const Error = transport.Error || message.Error || error{
    /// The server answered `rpc_error`; code and message are in
    /// `Client.lastRpcError` (valid until the next completed request).
    RpcError,
    /// A response body could not be parsed as the service message it
    /// claimed to be, or the result object did not decode as `T`.
    BadResponse,
    /// An inflated `gzip_packed` result exceeded `max_inflated_bytes`.
    ResponseTooLarge,
    /// A `gzip_packed` payload failed to inflate.
    GzipInvalid,
    /// The handle is unknown: already waited out, cancelled, or from
    /// another client.
    StaleHandle,
};

pub const Options = struct {
    /// Bound on each `wait`/`invoke` call, checked between frames. The
    /// transport's own `read_timeout` is the only way to interrupt a
    /// blocking read mid-frame (see `transport.tcp_full.Options`); with
    /// none set, a silent server stalls the wait despite this deadline.
    /// On `error.TimedOut` the request stays registered — retry `wait`
    /// with a longer budget or `cancel` it.
    response_timeout: ?std.Io.Duration = std.Io.Duration.fromSeconds(60),
    /// Bound on `gzip_packed` inflation (decompression-bomb guard).
    max_inflated_bytes: usize = 32 << 20,
};

/// Code and message of the last `rpc_error` (`FLOOD_WAIT_60`, ...). The
/// message borrows a fixed buffer inside the client; `id`/`value`
/// classify it against the generated error catalog (`.flood_wait_x`
/// with value 60 in the example).
pub const RpcErrorInfo = struct {
    code: i32,
    message: []const u8,
    /// Catalog classification of `message`; null when unknown to the
    /// generated catalog (`errors_gen.classify`).
    id: ?errors_gen.Id = null,
    /// Numeric parameter of a parameterized id (`FLOOD_WAIT_60` -> 60).
    value: ?u32 = null,
};

/// Seconds a flood-wait error asks to wait: the parameter of
/// `FLOOD_WAIT_X` or `FLOOD_PREMIUM_WAIT_X`, or null when `info` is not
/// a flood error. Classifies `info.message` directly, so it works for
/// hand-built infos too.
pub fn floodWaitSeconds(info: RpcErrorInfo) ?u32 {
    const c = errors_gen.classify(info.message) orelse return null;
    return switch (c.id) {
        .flood_wait_x, .flood_premium_wait_x => c.value,
        else => null,
    };
}

/// Callback for server-pushed updates (unknown top-level API objects).
/// `onUpdates` receives the raw TL object bytes, constructor id included,
/// borrowed from the frame being dispatched — valid only for the
/// duration of the call, so decode inside the callee (see
/// `td.updates.fetch.hook`). Runs from inside `pump`: it must not
/// re-enter this client (no `call`/`pump`/`wait` here — queue follow-up
/// RPCs until the pump returns, which is exactly what
/// `updates.Engine.reconcile` is for).
pub const UpdatesHandler = struct {
    ctx: *anyopaque,
    onUpdates: *const fn (ctx: *anyopaque, io: std.Io, body: []const u8) void,
};

/// A completed, typed RPC result. `value` borrows from an arena owned by
/// the response — call `deinit` exactly once, and finish using `value`
/// first. Strings decoded from the wire borrow; vectors and recursive-type
/// boxes were allocated from the same arena.
pub fn Response(comptime T: type) type {
    return struct {
        arena_state: std.heap.ArenaAllocator,
        value: T,

        pub fn deinit(self: *@This()) void {
            self.arena_state.deinit();
        }
    };
}

/// Handle returned by `send`; `wait(io, handle)` yields `Response(T)`.
pub fn Handle(comptime T: type) type {
    return struct {
        pub const Result = T;
        id: u32,
    };
}

/// Handle of a raw (pre-serialized) request; `waitRaw` yields its bytes.
pub const RawHandle = Handle([]const u8);

/// Result type of a generated request struct (its `Result` decl).
pub fn ResultOf(comptime T: type) type {
    if (@hasDecl(T, "Result")) return T.Result;
    @compileError(
        "td.rpc: request type " ++ @typeName(T) ++ " has no `Result` decl; " ++
            "pass the result type explicitly with Client.call(io, req, R), or " ++
            "regenerate the API with a td-gen that emits Result (`just api`)",
    );
}

const Kind = enum { rpc, ping };

const Pending = struct {
    id: u32,
    /// The msg_id the request was last sent under (`bad_server_salt`
    /// resends replace it; late answers to the old id are ignored).
    req_msg_id: i64,
    /// Non-zero for pings: the nonce `pong` echoes back.
    ping_id: i64,
    kind: Kind,
    /// Owned copy of the serialized request, kept for resends.
    body: []u8,
    state: State,

    const State = union(enum) {
        waiting,
        /// Owned result-object bytes (gzip already inflated).
        done: []u8,
        failed: Error,
    };
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    transport: transport.Transport,
    session: mtproto.Session,
    opts: Options,

    pending: std.ArrayList(Pending) = .empty,
    next_id: u32 = 1,
    next_ping_id: i64 = 1,

    /// Receive flattening buffer: one slot per possible container entry.
    rx_messages: []message.Incoming,
    /// Reusable encode scratch (outgoing frames and ack flushes).
    tx_buf: std.ArrayList(u8) = .empty,

    last_rpc_error: ?RpcErrorInfo = null,
    rpc_error_buf: [256]u8 = undefined,

    /// Server-pushed API objects (updates) seen since `init`.
    updates_seen: usize = 0,

    /// Frames received and dispatched since `init` (every successful
    /// transport read, whatever the payload turned out to be). The
    /// observability signal the multi-session scheduler sums for
    /// event-loop utilization: work delivered per pumped session.
    frames_seen: usize = 0,

    /// Invoked for each server-pushed update body, when set (copied
    /// onto every client a `connman.Manager` creates).
    updates_handler: ?UpdatesHandler = null,

    /// Pongs matched to a pending ping since `init` (health-check signal).
    pongs_seen: usize = 0,

    /// Creates a client over an established authorization key. `t` is
    /// borrowed (must outlive the client); `random` backs the session's
    /// ids and frame padding and must outlive it too. Connect with
    /// `connect` before invoking.
    pub fn init(
        allocator: std.mem.Allocator,
        t: transport.Transport,
        auth_key: *const [crypto.auth_key_size]u8,
        server_salt: i64,
        random: std.Random,
        opts: Options,
    ) Error!Client {
        const rx = allocator.alloc(message.Incoming, message.max_container_messages)
            catch return error.OutOfMemory;
        errdefer allocator.free(rx);
        const session = try mtproto.Session.init(allocator, auth_key, server_salt, random);
        return .{
            .allocator = allocator,
            .transport = t,
            .session = session,
            .opts = opts,
            .rx_messages = rx,
        };
    }

    pub fn deinit(self: *Client) void {
        self.cancelAll();
        self.pending.deinit(self.allocator);
        self.allocator.free(self.rx_messages);
        self.tx_buf.deinit(self.allocator);
        self.session.deinit();
    }

    pub fn connect(self: *Client, io: std.Io) Error!void {
        return self.transport.connect(io);
    }

    pub fn close(self: *Client, io: std.Io) void {
        self.transport.close(io);
    }

    pub fn isConnected(self: *const Client) bool {
        return self.transport.isConnected();
    }

    /// Drops the connection, resets the session (fresh session_id, zeroed
    /// counters) and fails every outstanding request: their msg_ids belong
    /// to the dead session. Re-invoke what still matters.
    pub fn reconnect(self: *Client, io: std.Io) Error!void {
        try self.transport.reconnect(io);
        self.session.reset();
        self.failAllWaiting(error.Disconnected);
    }

    /// Whether `e` means the connection is gone — the transport closed
    /// itself (or must be re-established) and every request it failed was
    /// never answered: no `rpc_error` arrived, so MTProto permits
    /// re-sending them (`recoverFailed`). Deliberately false for
    /// `error.TimedOut`: a response-deadline expiry leaves the request
    /// registered and the connection usable (retry the wait).
    pub fn isConnectionError(e: Error) bool {
        return switch (e) {
            error.Disconnected,
            error.ConnectionReset,
            error.IoFailed,
            error.NotConnected,
            error.InvalidFrame,
            => true,
            else => false,
        };
    }

    /// Re-sends every registered request that a connection-level failure
    /// killed (`isConnectionError`), each under a fresh msg_id, and
    /// returns it to `waiting`: its handle stays valid and the next
    /// `wait` completes normally. Requests failed with `RpcError`/
    /// `BadResponse` stay failed; completed results are untouched. Call
    /// right after a successful (re)connect. The trade-off MTProto
    /// accepts for an interrupted connection: the server may execute a
    /// re-sent query twice. Returns how many requests were recovered.
    pub fn recoverFailed(self: *Client, io: std.Io) Error!usize {
        var n: usize = 0;
        for (self.pending.items) |*p| {
            const failed_err = switch (p.state) {
                .failed => |fe| fe,
                else => continue,
            };
            if (!isConnectionError(failed_err)) continue;
            const sent = try self.writeRequest(io, p.body, p.kind == .rpc);
            p.req_msg_id = sent.msg_id;
            p.state = .waiting;
            n += 1;
        }
        return n;
    }
    /// Code and message of the most recent `rpc_error`. Meaningful after a
    /// call failed with `error.RpcError`; valid until the next request
    /// completes.
    pub fn lastRpcError(self: *const Client) RpcErrorInfo {
        return self.last_rpc_error orelse .{ .code = 0, .message = "" };
    }

    // ------------------------------------------------------------ invoke

    /// One-shot typed round trip: serialize `req`, send it as a
    /// content-related query and pump until its result arrives.
    pub fn invoke(self: *Client, io: std.Io, req: anytype) Error!Response(ResultOf(@TypeOf(req))) {
        return self.call(io, req, ResultOf(@TypeOf(req)));
    }

    /// `invoke` with the result type spelled out — for request structs
    /// that carry no `Result` decl (e.g. the committed API file before its
    /// next regeneration, or hand-built requests).
    pub fn call(self: *Client, io: std.Io, req: anytype, comptime R: type) Error!Response(R) {
        var w = Writer.init(self.allocator);
        defer w.deinit();
        req.serialize(&w) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.MessageTooLarge,
        };
        const h = try self.sendRaw(io, w.items());
        const bytes = try self.waitRaw(io, h);
        return self.respond(R, bytes);
    }

    /// Pipelined `invoke`: sends the request and returns a handle. Any
    /// number of requests may be outstanding; each is matched to its
    /// `rpc_result` by msg_id.
    pub fn send(self: *Client, io: std.Io, req: anytype) Error!Handle(ResultOf(@TypeOf(req))) {
        var w = Writer.init(self.allocator);
        defer w.deinit();
        req.serialize(&w) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.MessageTooLarge,
        };
        const h = try self.sendRaw(io, w.items());
        return .{ .id = h.id };
    }

    /// Waits for the request behind `handle` and decodes it. Other
    /// requests completed by the same pump keep their results until their
    /// own `wait`.
    pub fn wait(self: *Client, io: std.Io, handle: anytype) Error!Response(@TypeOf(handle).Result) {
        const bytes = try self.waitRaw(io, .{ .id = handle.id });
        return self.respond(@TypeOf(handle).Result, bytes);
    }

    /// Raw one-shot path: pre-serialized request body in, owned
    /// result-object bytes out (gzip already inflated). Free the returned
    /// slice with the client's allocator. This is also how to invoke
    /// generic wrappers (`invokeWithLayer`, `invokeAfterMsg`) that the
    /// generator intentionally does not emit as structs.
    pub fn invokeRaw(self: *Client, io: std.Io, body: []const u8) Error![]u8 {
        const h = try self.sendRaw(io, body);
        return self.waitRaw(io, h);
    }

    /// The wire-session id this client's frames travel under. The peer
    /// sees it in every encrypted frame; the PFS binding pins it.
    pub fn sessionId(self: *const Client) i64 {
        return self.session.session_id;
    }

    /// Reserves the next outgoing msg_id from the session counter
    /// without sending. The one legitimate consumer is the PFS bind,
    /// whose request body embeds the msg_id it travels under: reserve
    /// here, build the body around it, then send with `invokeRawWithId`.
    /// Single-threaded by contract — nothing else may send between the
    /// reservation and the send.
    pub fn reserveMsgId(self: *Client, io: std.Io) i64 {
        return self.session.nextMsgId(unixSeconds(io));
    }

    /// Raw round trip under a msg_id previously taken from
    /// `reserveMsgId` on this same session. The request registers like
    /// any other (bad_server_salt re-sends included — those re-stamp a
    /// fresh id and the server accepts either) and completes via its
    /// rpc_result.
    pub fn invokeRawWithId(self: *Client, io: std.Io, msg_id: i64, body: []const u8) Error![]u8 {
        const owned = self.allocator.dupe(u8, body) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        const sent = try self.writeRequestAt(io, owned, true, msg_id);
        const id = self.next_id;
        self.next_id +%= 1;
        self.pending.append(self.allocator, .{
            .id = id,
            .req_msg_id = sent.msg_id,
            .ping_id = 0,
            .kind = .rpc,
            .body = owned,
            .state = .waiting,
        }) catch return error.OutOfMemory;
        return self.waitRaw(io, .{ .id = id });
    }

    /// Raw pipelined send.
    pub fn sendRaw(self: *Client, io: std.Io, body: []const u8) Error!RawHandle {
        return self.enqueue(io, body, .rpc, 0);
    }

    /// Waits for a raw request and returns its result-object bytes.
    pub fn waitRaw(self: *Client, io: std.Io, handle: RawHandle) Error![]u8 {
        const deadline: ?std.Io.Timestamp = if (self.opts.response_timeout) |d|
            std.Io.Timestamp.now(io, .awake).addDuration(d)
        else
            null;
        try self.pumpUntil(io, handle.id, deadline);

        const idx = self.findIndex(handle.id) orelse return error.StaleHandle;
        const p = self.pending.items[idx];
        _ = self.pending.swapRemove(idx);
        self.allocator.free(p.body);
        switch (p.state) {
            .done => |bytes| return bytes,
            .failed => |e| return e,
            .waiting => return error.StaleHandle, // pumpUntil returns first; unreachable
        }
    }

    /// Drops a request without waiting: frees its body and any result that
    /// already arrived. A late `rpc_result` for it is ignored.
    pub fn cancel(self: *Client, handle: anytype) void {
        const idx = self.findIndex(handle.id) orelse return;
        const p = self.pending.items[idx];
        _ = self.pending.swapRemove(idx);
        self.allocator.free(p.body);
        switch (p.state) {
            .done => |bytes| self.allocator.free(bytes),
            else => {},
        }
    }

    /// Cancels every outstanding request: bodies and any already-arrived
    /// results are freed, all handles go stale (late results for them
    /// are ignored). Graceful-shutdown helper.
    pub fn cancelAll(self: *Client) void {
        for (self.pending.items) |p| {
            self.allocator.free(p.body);
            switch (p.state) {
                .done => |bytes| self.allocator.free(bytes),
                else => {},
            }
        }
        self.pending.clearRetainingCapacity();
    }

    /// Technical round trip: `ping#7abe77ec` in, matching `pong` out.
    /// Pings are not content-related and are not acknowledged.
    pub fn ping(self: *Client, io: std.Io) Error!void {
        return self.pingWith(io, null, null);
    }

    /// Ping with explicit bounds. `timeout` replaces
    /// `opts.response_timeout` for this call (health checks want a
    /// tighter bound); `disconnect_delay` (seconds) sends
    /// `ping_delay_disconnect#f3427b8c` instead: the server closes the
    /// connection when no further ping arrives within the delay — the
    /// standard keep-alive contract. On `error.TimedOut` the ping stays
    /// registered (the answer may still come); drop stale pings with
    /// `cancelStalePings`.
    pub fn pingWith(
        self: *Client,
        io: std.Io,
        timeout: ?std.Io.Duration,
        disconnect_delay: ?i32,
    ) Error!void {
        const ping_id = self.next_ping_id;
        self.next_ping_id += 1;
        var w = Writer.init(self.allocator);
        defer w.deinit();
        const p = message.Ping{ .ping_id = ping_id, .disconnect_delay = disconnect_delay };
        p.serialize(&w) catch return error.OutOfMemory;
        const saved = self.opts.response_timeout;
        if (timeout) |t| self.opts.response_timeout = t;
        defer self.opts.response_timeout = saved;
        const h = try self.enqueue(io, w.items(), .ping, ping_id);
        const bytes = try self.waitRaw(io, h);
        // Pongs complete with no result payload.
        self.allocator.free(bytes);
    }

    /// Drops waiting pings (health probes whose server went silent);
    /// their handles go stale and a late pong is ignored. Returns how
    /// many were dropped.
    pub fn cancelStalePings(self: *Client) usize {
        var n: usize = 0;
        var i: usize = 0;
        while (i < self.pending.items.len) {
            const p = self.pending.items[i];
            if (p.kind == .ping and p.state == .waiting) {
                self.allocator.free(p.body);
                _ = self.pending.swapRemove(i);
                n += 1;
            } else {
                i += 1;
            }
        }
        return n;
    }

    // ---------------------------------------------------------- plumbing

    fn enqueue(self: *Client, io: std.Io, body: []const u8, kind: Kind, ping_id: i64) Error!RawHandle {
        const owned = self.allocator.dupe(u8, body) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        const sent = try self.writeRequest(io, owned, kind == .rpc);
        const id = self.next_id;
        self.next_id +%= 1;
        self.pending.append(self.allocator, .{
            .id = id,
            .req_msg_id = sent.msg_id,
            .ping_id = ping_id,
            .kind = kind,
            .body = owned,
            .state = .waiting,
        }) catch return error.OutOfMemory;
        return .{ .id = id };
    }

    /// Encodes `body` through the session into the reusable tx buffer and
    /// writes one frame.
    fn writeRequest(self: *Client, io: std.Io, body: []const u8, content_related: bool) Error!message.Sent {
        return self.writeRequestAt(io, body, content_related, null);
    }

    /// `writeRequest` under an explicit msg_id — for the one wire case
    /// where the body embeds the msg_id it travels under (the PFS bind).
    /// The id must come from this session's own counter
    /// (`reserveMsgId`).
    fn writeRequestAt(self: *Client, io: std.Io, body: []const u8, content_related: bool, forced_msg_id: ?i64) Error!message.Sent {
        const len = message.frameLength(body.len);
        self.tx_buf.ensureTotalCapacity(self.allocator, len) catch return error.OutOfMemory;
        self.tx_buf.items.len = len;
        const sent = if (forced_msg_id) |msg_id|
            try self.session.encodeWithId(msg_id, content_related, body, self.tx_buf.items)
        else
            try self.session.encode(unixSeconds(io), content_related, body, self.tx_buf.items);
        try self.transport.write(io, self.tx_buf.items);
        return sent;
    }

    /// Sends one `msgs_ack` if acknowledgements are pending. The session
    /// queued them when the frames were received. Public for the
    /// connection manager's graceful shutdown (drain before close).
    pub fn flushAcks(self: *Client, io: std.Io) Error!void {
        const len = self.session.pendingAckFrameLength();
        if (len == 0) return;
        self.tx_buf.ensureTotalCapacity(self.allocator, len) catch return error.OutOfMemory;
        self.tx_buf.items.len = len;
        _ = try self.session.flushAcks(unixSeconds(io), self.tx_buf.items);
        try self.transport.write(io, self.tx_buf.items);
    }

    /// Receives and dispatches frames until the request `id` completes
    /// (result, failure or cancellation by a service message), the
    /// deadline passes, or the connection fails. On `error.TimedOut` the
    /// request stays registered — retry `wait` with a longer budget or
    /// `cancel` it; on a transport error every waiting request is failed
    /// with a connection error (the connection is gone).
    fn pumpUntil(self: *Client, io: std.Io, id: u32, deadline: ?std.Io.Timestamp) Error!void {
        while (true) {
            const idx = self.findIndex(id) orelse return error.StaleHandle;
            switch (self.pending.items[idx].state) {
                .done, .failed => return,
                .waiting => {},
            }
            if (deadline) |d| {
                if (d.nanoseconds <= std.Io.Timestamp.now(io, .awake).nanoseconds)
                    return error.TimedOut;
            }
            try self.pumpOnce(io);
        }
    }

    /// Pumps incoming frames for up to `budget`, dispatching service
    /// messages: outstanding requests complete as their results arrive,
    /// acknowledgements are flushed, updates counted. Returns
    /// `error.TimedOut` when the budget expired — with the connection
    /// still usable if the expiry was a clean idle timeout, and with
    /// waiting requests failed (connection errors) if the framing died
    /// mid-frame. Blocking reads are bounded by the transport's
    /// `read_timeout`; with it unset and a silent server, one read may
    /// stall past the budget (see `tcp_full.Options.read_timeout`).
    pub fn pump(self: *Client, io: std.Io, budget: std.Io.Duration) Error!void {
        const deadline = std.Io.Timestamp.now(io, .awake).addDuration(budget);
        while (true) {
            if (deadline.nanoseconds <= std.Io.Timestamp.now(io, .awake).nanoseconds)
                return error.TimedOut;
            try self.pumpOnce(io);
        }
    }

    /// One frame: read (bounded by the transport's read_timeout),
    /// dispatch, flush acks.
    fn pumpOnce(self: *Client, io: std.Io) Error!void {
        const frame = self.transport.read(io, self.allocator) catch |e| {
            // A timeout before any frame byte was consumed leaves the
            // connection usable and the requests valid — surface it
            // without failing them. Everything else means the connection
            // is gone; a mid-frame timeout (desynchronized framing)
            // counts as gone too and is reported as `error.Disconnected`
            // so the affected requests land in the recoverable family.
            if (e == error.TimedOut and self.transport.isConnected()) return e;
            const conn_err: Error = if (e == error.TimedOut) error.Disconnected else e;
            self.failAllWaiting(conn_err);
            return conn_err;
        };
        defer self.allocator.free(frame);
        self.frames_seen += 1;

        const recv = self.session.receive(frame, unixSeconds(io), self.rx_messages) catch |e| {
            // Validation rejected the frame; the session counters are
            // untouched, so later frames still parse. Report and let
            // the caller decide (other pendings may try again).
            return e;
        };
        for (recv.messages) |m| try self.handleIncoming(io, m);
        try self.flushAcks(io);
    }

    /// Classifies one received logical message and advances pending state.
    fn handleIncoming(self: *Client, io: std.Io, m: message.Incoming) Error!void {
        var body = message.parseServiceBody(self.allocator, m.body) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadResponse,
        };
        defer body.deinit(self.allocator);

        switch (body) {
            .rpc_result => |res| try self.completeRpc(io, res.req_msg_id, res.result),
            .bad_server_salt => |b| {
                // Re-send the offending message under the new salt.
                self.session.setServerSalt(b.new_server_salt);
                if (self.findIndexByMsgId(b.bad_msg_id)) |idx| {
                    try self.resendAt(io, idx);
                }
            },
            .bad_msg_notification => |b| {
                if (self.findIndexByMsgId(b.bad_msg_id)) |idx| {
                    switch (b.error_code) {
                        // id/seq violations and expired ids: re-send under
                        // a fresh id; the salt case arrives as
                        // bad_server_salt instead.
                        message.err_msg_id_too_low,
                        message.err_msg_id_too_high,
                        message.err_seq_no_too_low,
                        message.err_seq_no_too_high,
                        message.err_msg_id_too_old,
                        => try self.resendAt(io, idx),
                        // Container violations and unknown codes are not
                        // recoverable here.
                        else => self.failAt(idx, error.BadResponse),
                    }
                }
            },
            .new_session_created => |n| {
                // The session layer already queued the acknowledgement
                // (new_session_created is content-related).
                self.session.setServerSalt(n.server_salt);
            },
            .pong => |p| {
                if (self.findIndexByPingId(p.ping_id)) |idx| {
                    self.pongs_seen += 1;
                    // Pongs carry no result payload; complete with an
                    // owned empty slice.
                    const empty = self.allocator.alloc(u8, 0) catch return error.OutOfMemory;
                    self.completeAt(idx, empty);
                }
            },
            .future_salts => |f| {
                // Answered outside rpc_result; the raw body carries the
                // salts for the requesting handle.
                if (self.findIndexByMsgId(f.req_msg_id)) |idx| {
                    if (self.pending.items[idx].kind == .rpc) {
                        const dup = self.allocator.dupe(u8, m.body) catch return error.OutOfMemory;
                        self.completeAt(idx, dup);
                    }
                }
            },
            .msgs_ack => {},
            .gzip_packed => {
                // gzip only wraps rpc_result payloads; a bare one at
                // message level is not a thing the spec produces.
            },
            .unknown => |u| {
                // Server-pushed API object (an update): count it and
                // hand the raw bytes (constructor id included) to the
                // application hook. The body borrows the frame being
                // dispatched; the callee decodes inside the call.
                self.updates_seen += 1;
                if (self.updates_handler) |h| h.onUpdates(h.ctx, io, u.body);
            },
        }
    }

    /// Delivers a result to the pending rpc query with `req_msg_id`,
    /// classifying the payload: rpc_error, gzip_packed, an API object, or
    /// a server-pushed update wearing an rpc_result envelope.
    fn completeRpc(self: *Client, io: std.Io, req_msg_id: i64, result: []const u8) Error!void {
        const idx = self.findIndexByMsgId(req_msg_id) orelse return; // unsolicited/duplicate
        const p = &self.pending.items[idx];
        if (p.kind != .rpc or p.state != .waiting) return;

        if (result.len < 4) {
            self.failAt(idx, error.BadResponse);
            return;
        }
        const id = std.mem.readInt(u32, result[0..4], .little);

        if (id == message.rpc_error_id) {
            var r = Reader.init(result);
            _ = r.readConstructorId() catch {
                self.failAt(idx, error.BadResponse);
                return;
            };
            const code = r.readInt() catch {
                self.failAt(idx, error.BadResponse);
                return;
            };
            const msg = r.readString() catch {
                self.failAt(idx, error.BadResponse);
                return;
            };
            const n = @min(msg.len, self.rpc_error_buf.len);
            @memcpy(self.rpc_error_buf[0..n], msg[0..n]);
            const stored = self.rpc_error_buf[0..n];
            const c = errors_gen.classify(stored);
            self.last_rpc_error = .{
                .code = code,
                .message = stored,
                .id = if (c) |x| x.id else null,
                .value = if (c) |x| x.value else null,
            };
            self.failAt(idx, error.RpcError);
        } else if (id == message.gzip_packed_id) {
            var r = Reader.init(result);
            _ = r.readConstructorId() catch {
                self.failAt(idx, error.BadResponse);
                return;
            };
            const packed_data = r.readString() catch {
                self.failAt(idx, error.BadResponse);
                return;
            };
            const inflated = try decode_mod.inflateGzip(
                self.allocator,
                packed_data,
                self.opts.max_inflated_bytes,
            );
            self.completeAt(idx, inflated);
        } else if (id != tl.vector_constructor_id and api.registry.nameFor(id) == null) {
            // A constructor no schema defines cannot be the typed answer
            // to this request: it travels the updates path. Count it,
            // hand it to the application hook, and leave the request
            // registered — it completes only via a later rpc_result (or
            // surfaces as its timeout). The generic `vector#1cb5c415`
            // wrapper is a legitimate result (Vector<T> functions) and
            // is exempt from the lookup.
            self.updates_seen += 1;
            if (self.updates_handler) |h| h.onUpdates(h.ctx, io, result);
        } else {
            // The body borrows the receive frame; hand over an owned copy.
            const dup = self.allocator.dupe(u8, result) catch return error.OutOfMemory;
            self.completeAt(idx, dup);
        }
    }

    /// Re-sends the pending request under a fresh msg_id (bad_server_salt,
    /// resolvable bad_msg_notification codes).
    fn resendAt(self: *Client, io: std.Io, idx: usize) Error!void {
        const p = &self.pending.items[idx];
        const sent = try self.writeRequest(io, p.body, p.kind == .rpc);
        p.req_msg_id = sent.msg_id;
    }

    /// Marks a completion, guarding against double delivery (a second
    /// result for an already-completed request frees its payload).
    fn completeAt(self: *Client, idx: usize, bytes: []u8) void {
        const p = &self.pending.items[idx];
        if (p.state == .waiting) {
            p.state = .{ .done = bytes };
        } else {
            self.allocator.free(bytes);
        }
    }

    fn failAt(self: *Client, idx: usize, err: Error) void {
        const p = &self.pending.items[idx];
        if (p.state == .waiting) p.state = .{ .failed = err };
    }

    fn failAllWaiting(self: *Client, err: Error) void {
        for (self.pending.items) |*p| {
            if (p.state == .waiting) p.state = .{ .failed = err };
        }
    }

    /// Wraps raw result bytes in an arena and decodes `T` from the copy
    /// (decoded values borrow the input, so the wire bytes must outlive
    /// them — the arena does).
    fn respond(self: *Client, comptime T: type, bytes: []u8) Error!Response(T) {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena_state.deinit();
        const arena = arena_state.allocator();
        defer self.allocator.free(bytes);
        const copy = arena.dupe(u8, bytes) catch return error.OutOfMemory;
        const value = decode_mod.decode(T, arena, copy) catch |e| return e;
        return .{ .arena_state = arena_state, .value = value };
    }

    fn findIndex(self: *const Client, id: u32) ?usize {
        for (self.pending.items, 0..) |p, i| {
            if (p.id == id) return i;
        }
        return null;
    }

    fn findIndexByMsgId(self: *const Client, msg_id: i64) ?usize {
        for (self.pending.items, 0..) |p, i| {
            if (p.req_msg_id == msg_id) return i;
        }
        return null;
    }

    fn findIndexByPingId(self: *const Client, ping_id: i64) ?usize {
        for (self.pending.items, 0..) |p, i| {
            if (p.kind == .ping and p.ping_id == ping_id) return i;
        }
        return null;
    }
};

fn unixSeconds(io: std.Io) u64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

// ---------------------------------------------------------------- tests

const test_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 97 +% 5);
    break :blk k;
};

/// Transport stub: never connects; enough to drive the pure state machine.
/// Transport references are inline imports — the `transport` method below
/// shadows the file-scope import of the same name inside this container.
const StubTransport = struct {
    fn connectStub(_: *anyopaque, _: std.Io) @import("../transport/mod.zig").Error!void {
        return error.ConnectFailed;
    }
    fn closeStub(_: *anyopaque, _: std.Io) void {}
    fn writeStub(_: *anyopaque, _: std.Io, _: []const u8) @import("../transport/mod.zig").Error!void {
        return error.NotConnected;
    }
    fn readStub(_: *anyopaque, _: std.Io, _: std.mem.Allocator) @import("../transport/mod.zig").Error![]u8 {
        return error.NotConnected;
    }
    fn isConnectedStub(_: *anyopaque) bool {
        return false;
    }
    const vtable = @import("../transport/mod.zig").Transport.VTable{
        .connect = connectStub,
        .close = closeStub,
        .write = writeStub,
        .read = readStub,
        .isConnected = isConnectedStub,
    };
    fn transport(self: *StubTransport) @import("../transport/mod.zig").Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

// File-scope so the transport and RNG outlive the client (both are
// borrowed interfaces).
var stub_transport = StubTransport{};
var test_prng = std.Random.DefaultPrng.init(0);

fn newClient(allocator: std.mem.Allocator) !Client {
    return Client.init(allocator, stub_transport.transport(), &test_key, 1, test_prng.random(), .{});
}

test "pending table: completion, failure and double delivery" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const test_io = threaded.io();

    var client = try newClient(std.testing.allocator);
    defer client.deinit();

    // Register three pendings by hand (sendRaw would touch the transport).
    const body1 = try std.testing.allocator.dupe(u8, &[_]u8{ 1, 2, 3, 4 });
    const body2 = try std.testing.allocator.dupe(u8, &[_]u8{ 5, 6, 7, 8 });
    const body3 = try std.testing.allocator.dupe(u8, &[_]u8{ 9, 10, 11, 12 });
    try client.pending.append(std.testing.allocator, .{
        .id = 1,
        .req_msg_id = 0x100,
        .ping_id = 0,
        .kind = .rpc,
        .body = body1,
        .state = .waiting,
    });
    try client.pending.append(std.testing.allocator, .{
        .id = 2,
        .req_msg_id = 0x200,
        .ping_id = 0,
        .kind = .rpc,
        .body = body2,
        .state = .waiting,
    });
    try client.pending.append(std.testing.allocator, .{
        .id = 3,
        .req_msg_id = 0x300,
        .ping_id = 0,
        .kind = .rpc,
        .body = body3,
        .state = .waiting,
    });

    // rpc_error result for the first: state failed, details recorded.
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(message.rpc_error_id);
    try w.writeInt(420);
    try w.writeString("FLOOD_WAIT_60");
    try client.completeRpc(test_io, 0x100, w.items());

    try std.testing.expect(client.pending.items[0].state.failed == error.RpcError);
    try std.testing.expectEqual(@as(i32, 420), client.lastRpcError().code);
    try std.testing.expectEqualStrings("FLOOD_WAIT_60", client.lastRpcError().message);
    // The failure is classified against the generated error catalog.
    try std.testing.expect(client.lastRpcError().id == .flood_wait_x);
    try std.testing.expectEqual(@as(u32, 60), client.lastRpcError().value.?);
    try std.testing.expectEqual(@as(u32, 60), floodWaitSeconds(client.lastRpcError()).?);

    // Overlong messages are truncated, not overflowing.
    var long_w = Writer.init(std.testing.allocator);
    defer long_w.deinit();
    try long_w.writeConstructorId(message.rpc_error_id);
    try long_w.writeInt(500);
    try long_w.writeString("X" ** 300);
    try client.completeRpc(test_io, 0x200, long_w.items());
    try std.testing.expectEqual(@as(usize, 256), client.lastRpcError().message.len);

    // A plain result completes the third; a second result for the same
    // request is dropped (its payload freed, the first one kept).
    const first = try std.testing.allocator.dupe(u8, &[_]u8{ 0x99, 0, 0, 0 });
    client.completeAt(2, first);
    const second = try std.testing.allocator.dupe(u8, &[_]u8{ 0x88, 0, 0, 0 });
    client.completeAt(2, second);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x99, 0, 0, 0 }, client.pending.items[2].state.done);

    // failAllWaiting only touches waiting entries.
    client.failAllWaiting(error.Disconnected);
    try std.testing.expect(client.pending.items[0].state.failed == error.RpcError);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x99, 0, 0, 0 }, client.pending.items[2].state.done);
}

test "connection-error family, stale pings and cancelAll" {
    var client = try newClient(std.testing.allocator);
    defer client.deinit();

    // Classification: connection-level failures are recoverable; response
    // deadlines (the request may still complete) and server answers are
    // final.
    try std.testing.expect(Client.isConnectionError(error.Disconnected));
    try std.testing.expect(Client.isConnectionError(error.ConnectionReset));
    try std.testing.expect(Client.isConnectionError(error.IoFailed));
    try std.testing.expect(Client.isConnectionError(error.NotConnected));
    try std.testing.expect(Client.isConnectionError(error.InvalidFrame));
    try std.testing.expect(!Client.isConnectionError(error.TimedOut));
    try std.testing.expect(!Client.isConnectionError(error.RpcError));
    try std.testing.expect(!Client.isConnectionError(error.BadResponse));

    // Three pendings registered by hand: one recoverable failure, one
    // final failure, one completed result — plus a waiting ping.
    const bodies = [_][]const u8{ &[_]u8{ 1, 2, 3, 4 }, &[_]u8{ 5, 6, 7, 8 }, &[_]u8{ 9, 10, 11, 12 } };
    for (bodies, 0..) |bytes, i| {
        try client.pending.append(std.testing.allocator, .{
            .id = @intCast(i + 1),
            .req_msg_id = 0x100 * @as(i64, @intCast(i + 1)),
            .ping_id = 0,
            .kind = .rpc,
            .body = try std.testing.allocator.dupe(u8, bytes),
            .state = .waiting,
        });
    }
    client.failAt(0, error.Disconnected);
    client.failAt(1, error.RpcError);
    const done = try std.testing.allocator.dupe(u8, &[_]u8{ 0x99, 0, 0, 0 });
    client.completeAt(2, done);

    try client.pending.append(std.testing.allocator, .{
        .id = 4,
        .req_msg_id = 0,
        .ping_id = 7,
        .kind = .ping,
        .body = try std.testing.allocator.dupe(u8, &[_]u8{ 0, 0, 0, 0 }),
        .state = .waiting,
    });

    // cancelStalePings drops only the waiting ping.
    try std.testing.expectEqual(@as(usize, 1), client.cancelStalePings());
    try std.testing.expectEqual(@as(usize, 3), client.pending.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.cancelStalePings()); // nothing left

    // cancelAll frees bodies and results, emptying the table — deinit
    // below must stay leak-free.
    client.cancelAll();
    try std.testing.expectEqual(@as(usize, 0), client.pending.items.len);
}

test "ResultOf resolves the Result decl" {
    const Sample = struct {
        pub const Result = api.Bool;
        pub fn serialize(_: *const @This(), _: *Writer) anyerror!void {}
    };
    try std.testing.expect(ResultOf(Sample) == api.Bool);
}
