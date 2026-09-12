//! High-level client: the one object an application holds.
//!
//! Everything below this file is a layer — transports, the encrypted
//! session, RPC matching, DC knowledge, connection management, session
//! persistence. `Client` composes them into the "just connect and
//! invoke" surface, so a program reads as:
//!
//!     var store = td.session.FileStore.init(gpa, "session.bin");
//!     defer store.deinit();
//!
//!     var client = try td.Client.init(gpa, .{
//!         .session_store = store.store(),
//!     });
//!     defer client.deinit(io);
//!     try client.connect(io); // stored session or fresh handshake
//!
//!     const dc = try client.invoke(io, td.api.help.getNearestDc{});
//!     defer dc.deinit();
//!     std.debug.print("nearest dc: {d}\n", .{dc.value.nearest_dc});
//!
//! What `connect` does for the caller: restores a stored session (auth
//! key, server salt, current DC — and on the same DC, the wire-session
//! identity), runs the authorization-key handshake when no key is known
//! for the DC (one short connection, then dropped), builds a
//! `connman.Manager` over the endpoint and persists the fresh state so
//! reruns skip the handshake.
//!
//! What `invoke` adds over the manager: the first query on every fresh
//! server session is wrapped in
//! `invokeWithLayer` → `initConnection` (app identity) — the wrapper
//! Telegram answers `CONNECTION_NOT_INITED` without — tracked per
//! connection generation and re-applied after reconnects. On top of
//! that, `PHONE_MIGRATE`/`NETWORK_MIGRATE` rpc errors are followed
//! automatically — switch DC, rebuild the connection, repeat the
//! request (bounded by `max_migrations`). A redirect to an unknown DC
//! first refreshes the endpoint list through `help.getConfig`.
//! `USER_MIGRATE`/`FILE_MIGRATE` need authorization transfer or media
//! connections and are surfaced as the rpc error they arrived as.
//!
//! Everything else is passed through: `call`/`send`/`wait` for typed
//! and pipelined traffic, `invokeRaw` for hand-serialized bodies,
//! `ping` for keep-alive, `saveSession` for explicit persistence.
//! Lifecycle: `connect` (idempotent) establishes, `disconnect` drops
//! the connection while keeping the client usable, `close` is
//! terminal (later operations fail with `error.Closed`), and `deinit`
//! frees. Concurrency model unchanged: one `std.Io`, one thread, `io`
//! per call.

const std = @import("std");
const crypto = @import("crypto/mod.zig");
const mtproto = @import("mtproto/mod.zig");
const transport = @import("transport/mod.zig");
const rpc = @import("rpc/mod.zig");
const dc = @import("dc/mod.zig");
const connman = @import("connman/mod.zig");
const session = @import("session/mod.zig");
const migration = @import("dc/migration.zig");
const api = @import("api/mod.zig");
const tl = @import("tl/mod.zig");
const errors_mod = @import("errors.zig");

/// `invokeWithLayer#da9b0d0d {X} layer:int query:!X = X` — the generic
/// wrapper the generator intentionally does not emit as a struct; ids
/// from the vendored schema (schema/api.tl). The layer
/// number itself is generated with the API: `api.layer`.
const invoke_with_layer_id: u32 = 0xda9b0d0d;
const init_connection_id: u32 = 0xc1cd5ea9;
/// `invokeWithoutUpdates#bf9459b7 {X} query:!X = X` — the third generic
/// wrapper the generator intentionally does not emit (schema/api.tl).
/// Wrapping a query opts the session out of the updates that query
/// would subscribe it to; see `Options.no_updates`.
const invoke_without_updates_id: u32 = 0xbf9459b7;
/// rpc_error message a server answers when the session's first query
/// missed the initConnection wrapper.
const connection_not_inited = "CONNECTION_NOT_INITED";

pub const ConnectError = dc.ConnectError || connman.Error || session.store.LoadStateError || session.state.ApplyError || error{
    /// An operation needs a connection and `connect` has not succeeded.
    NotConnected,
    /// `Options.session_string` is not a portable session string.
    InvalidSessionString,
    /// Binding the PFS temporary key failed (`auth.bindTempAuthKey`
    /// answered an rpc_error or something other than `true`). Code and
    /// message are in `lastRpcError` (ENCRYPTED_MESSAGE_INVALID,
    /// EXPIRES_AT_INVALID, TEMP_AUTH_KEY_ALREADY_BOUND, ...).
    TempKeyBindFailed,
};

pub const Error = ConnectError || error{
    /// A `*_MIGRATE_X` redirect named a DC that is still unknown after
    /// a `help.getConfig` refresh.
    CannotMigrate,
};

/// `saveSession` failures: storage errors, or no live session to
/// capture.
pub const SaveError = session.store.Error || error{ NotConnected, Closed };

/// Application identity sent in the `initConnection` wrapper of every
/// fresh server session's first query. All strings are borrowed.
pub const AppInfo = struct {
    /// Application id (from my.telegram.org). Required — there is no
    /// default; every client states its own identity.
    api_id: i32,
    device_model: []const u8 = "tdzig",
    system_version: []const u8 = "zig",
    app_version: []const u8 = "0.1.0",
    system_lang_code: []const u8 = "en",
    lang_pack: []const u8 = "",
    lang_code: []const u8 = "en",
};

pub const Options = struct {
    /// Production or test network (bootstrap endpoints, handshake DC
    /// ids, session compatibility).
    environment: dc.Environment = .production,
    /// Server RSA public keys accepted in the handshake; the vendored
    /// official Telegram keys by default.
    pubkeys: []const mtproto.RsaPublicKey = mtproto.server_keys.production,
    /// Session persistence: loaded on `connect`, written after it, on
    /// `close`, and by `saveSession`. null keeps everything in memory.
    /// Ignored when `session_string` is set — an imported string is the
    /// session.
    session_store: ?session.Store = null,
    /// A portable session string to import on `connect` (see
    /// `session.string`): data center, application id, authorization
    /// key and signed-in identity, ready to use without a handshake.
    /// Its network (production/test) must match `environment`. The
    /// string is borrowed; its authorization key is secret material.
    session_string: ?[]const u8 = null,
    /// Prefer IPv6 endpoints when the DC has both families.
    prefer_ipv6: bool = false,
    /// What the connection will carry (endpoint filtering; see
    /// `dc.Purpose`).
    purpose: dc.Purpose = .general,
    /// RSA layout of the authorization-key handshake.
    handshake_mode: mtproto.rsa.Mode = .rsa_pad,
    /// Which TCP transport framing every connection of this client
    /// speaks — the working connection and the handshake connections
    /// (authorization key, PFS temp key) alike; see
    /// `transport.TransportMode`. Abridged is the lightest framing and
    /// the default. Switching the mode changes only the wire framing:
    /// the encrypted MTProto messages inside are unaffected. This
    /// overrides the connman-level `conn.transport`, which exists for
    /// connman-only users.
    transport: transport.TransportMode = .abridged,
    /// Perfect forward secrecy (https://core.telegram.org/api/pfs).
    /// When true, every connection encrypts with a short-lived
    /// temporary auth key bound to the permanent one via
    /// `auth.bindTempAuthKey` — the permanent key itself never
    /// encrypts traffic. The temp key lives in RAM only (never
    /// persisted, matching the spec), is regenerated and re-bound on
    /// every connection establishment, and rotates ahead of expiry
    /// before `invoke` (per-connection cost: one extra DH handshake).
    /// A persisted session keeps the permanent key only; the next run
    /// binds a fresh temp key.
    pfs: bool = false,
    /// Connection management: retries, backoff, timeouts, and the
    /// transport provider for non-TCP transports (loopback, pools).
    conn: connman.Options = .{},
    /// Hook receiving server-pushed updates raw (see
    /// `rpc.UpdatesHandler`; decoding lives in `td.updates`).
    updates_handler: ?rpc.UpdatesHandler = null,
    /// Never receive updates: every `invoke` travels inside the
    /// `invokeWithoutUpdates` wrapper, so the server does not
    /// subscribe this session to the updates its queries would
    /// normally cause (pyrogram's `no_updates`; gotd pairs its
    /// `NoUpdates` flag with skipping the update-subscription call).
    /// With no `updates_handler` set (the default) the client then
    /// sees no updates at all. Like the init wrapper this applies to
    /// `invoke`/`call` only — pipelined `send` goes out bare. The
    /// wrapper is result-transparent; answers decode unchanged.
    no_updates: bool = false,
    /// How many `PHONE_MIGRATE`/`NETWORK_MIGRATE` redirects one
    /// `invoke` follows before surfacing the rpc error.
    max_migrations: u32 = 1,
    /// Application identity for the initConnection wrapper. Required —
    /// `api_id` has no default.
    app: AppInfo,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    /// Internal entropy: an IoSource created from the first `io` the
    /// client connects with, backing handshakes, session ids and
    /// backoff jitter. Nothing for the caller to own or pass.
    rng: ?std.Random.IoSource = null,
    /// The interface handed to the layers below; borrows `rng`, so the
    /// client must not move once connected (as with the manager).
    random: std.Random = undefined,
    /// Endpoint knowledge and per-DC authorization keys.
    dcs: dc.DataCenters,
    /// The current connection; rebuilt on `connect` and every DC
    /// migration. Its endpoint's address bytes borrow `dcs`, so the
    /// manager is dropped before any endpoint-list update.
    manager: ?connman.Manager = null,
    /// Restored wire-session half from a stored state, adopted onto the
    /// first connection to the same DC, then consumed.
    pending_session: ?session.State = null,
    /// Connection generation whose first query has already carried the
    /// initConnection wrapper. Every fresh establishment (connect,
    /// reconnect, migration) starts a new server session that expects
    /// the wrapper again.
    inited_generation: u64 = 0,
    /// The signed-in identity, from an imported session string or a
    /// completed sign-in observed through `invoke`; carried into
    /// `exportSessionString`. null = not signed in.
    authorized: ?Authorization = null,
    /// Set by `close`: the client refuses every further operation and
    /// reconnection (`deinit` still applies). The terminal counterpart
    /// to a `disconnect` that keeps the client reusable.
    closed: bool = false,
    /// The temporary key the current connection encrypts with
    /// (`opts.pfs` only). RAM-only by spec — it never reaches a store
    /// or session string, and dies with the connection: every
    /// `openConnection` generates a fresh one and binds it.
    pfs_temp: ?mtproto.pfs.TempKey = null,

    /// Who the session is signed in as.
    pub const Authorization = struct {
        user_id: i64 = 0,
        is_bot: bool = false,
    };

    /// Creates an idle client. No network, no I/O, no entropy: all of
    /// that is set up internally when `connect` first runs. Fails only
    /// on the endpoint list allocation.
    pub fn init(allocator: std.mem.Allocator, opts: Options) dc.Error!Client {
        return .{
            .allocator = allocator,
            .opts = opts,
            .dcs = try dc.DataCenters.init(allocator, opts.environment),
        };
    }

    /// Connects: imports a portable session string when one is given
    /// (overriding any store — the string *is* the session), otherwise
    /// restores a stored session when one exists; ensures the current
    /// DC has an authorization key (handshake if not), builds the
    /// connection manager and establishes the connection. With a
    /// `session_store` set the state is persisted right away, so a
    /// rerun continues where this one started. Idempotent while
    /// connected; after `disconnect` it re-establishes. Fails with
    /// `error.Closed` after `close`.
    pub fn connect(self: *Client, io: std.Io) ConnectError!void {
        if (self.closed) return error.Closed;
        // Idempotent while connected; a dropped connection falls
        // through and is rebuilt.
        if (self.manager) |*m| {
            if (m.client != null and m.client.?.isConnected()) return;
        }
        if (self.opts.session_string) |ss| {
            const parsed = session.string.parse(ss) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.InvalidSessionString => error.InvalidSessionString,
            };
            if (parsed.test_mode != (self.dcs.list.environment == .@"test"))
                return error.EnvironmentMismatch;

            // The wire salt is not part of the string; the server
            // corrects the first request through bad_server_salt.
            var sha1: [20]u8 = undefined;
            std.crypto.hash.Sha1.hash(&parsed.auth_key, &sha1, .{});
            try self.dcs.setAuthKey(parsed.dc_id, .{
                .key = parsed.auth_key,
                .id = crypto.authKeyId(&parsed.auth_key),
                .aux_hash = sha1[0..8].*,
                .server_salt = [_]u8{0} ** 8,
            });
            try self.dcs.setCurrent(parsed.dc_id);
            if (parsed.api_id) |id| self.opts.app.api_id = id;
            self.authorized = if (parsed.user_id != 0)
                .{ .user_id = parsed.user_id, .is_bot = parsed.is_bot }
            else
                null;
        } else if (self.opts.session_store) |st| {
            if (try st.loadState(io, self.allocator)) |loaded| {
                try loaded.applyTo(&self.dcs);
                self.pending_session = loaded;
            }
        }
        try self.openConnection(io);
        if (self.opts.session_store != null) try self.saveSession(io);
    }

    /// One-shot typed round trip over the generated API, with automatic
    /// recovery (via the manager), initConnection wrapping of the first
    /// query on every fresh server session, and
    /// `PHONE_MIGRATE`/`NETWORK_MIGRATE` following:
    ///
    ///     const me = try client.invoke(io, td.api.help.getNearestDc{});
    ///
    /// The returned response owns its arena — `deinit` it (and stop
    /// using `value`) when done. Rpc-level failures surface as
    /// `error.RpcError`; code and message are in `lastRpcError`.
    pub fn invoke(self: *Client, io: std.Io, req: anytype) Error!rpc.Response(rpc.ResultOf(@TypeOf(req))) {
        return self.invokeAs(io, req, rpc.ResultOf(@TypeOf(req)));
    }

    fn invokeAs(self: *Client, io: std.Io, req: anytype, comptime R: type) Error!rpc.Response(R) {
        var migrations: u32 = 0;
        var session_retries: u32 = 0;
        while (true) {
            // PFS rotation: within the margin of the temp key's expiry,
            // the connection is torn down and re-opened — which
            // generates and binds a fresh temp key (a server expiring a
            // key early surfaces as a connection failure and lands
            // here on the next invoke). Pipelined handles from `send`
            // go stale, as with `disconnect`.
            if (self.opts.pfs and self.manager != null and
                self.tempKeyNeedsRotation(unixSeconds(io)))
            {
                self.closeConnection(io);
                try self.openConnection(io);
            }
            const m = try self.requireManager();
            const generation = m.health.generation;
            const wrapped = generation != self.inited_generation;
            const result = self.invokeOn(io, m, req, R, wrapped) catch |e| {
                // The persisted wire session no longer matches what the
                // server remembers (session state discarded server-side
                // after a long gap): rebuild with a fresh identity, once
                // per invoke. The fresh session also gets the init
                // wrapper again (openConnection resets the generation).
                if (e == error.SeqNoInvalid and session_retries < 1) {
                    session_retries += 1;
                    self.closeConnection(io);
                    try self.openConnection(io);
                    continue;
                }
                if (e != error.RpcError) return e;
                const info = m.client.?.lastRpcError();
                // The server demands the init wrapper for the session's
                // first query. Handled proactively above; this retry
                // covers reconnects that reset the wire session under
                // in-flight traffic (recovery re-sends the body bare).
                if (!wrapped and std.mem.eql(u8, info.message, connection_not_inited)) {
                    self.inited_generation = 0;
                    continue;
                }
                const mig = migration.fromRpcError(info) orelse return e;
                switch (mig.kind) {
                    // Moving the authorization itself (export/import) or
                    // opening a media connection is not this layer's
                    // job; surface the redirect as the rpc error it
                    // arrived as.
                    .user, .file => return e,
                    .phone, .network => {},
                }
                if (migrations >= self.opts.max_migrations) return e;
                migrations += 1;
                try self.moveTo(io, mig);
                continue;
            };
            if (comptime R == api.auth.Authorization_) self.trackAuthorization(result.value);
            self.inited_generation = generation;
            return result;
        }
    }

    /// Records the signed-in identity observed in an authorization
    /// result (auth.signIn, auth.importBotAuthorization, ...), so
    /// `exportSessionString` carries it.
    fn trackAuthorization(self: *Client, value: api.auth.Authorization_) void {
        switch (value) {
            .authorization => |a| switch (a.user) {
                .user => |u| {
                    if (u.id != 0) self.authorized = .{ .user_id = u.id, .is_bot = u.bot };
                },
                else => {},
            },
            else => {},
        }
    }

    /// Records the signed-in identity explicitly — for authorization
    /// flows that did not run through `invoke` (e.g. `td.auth.flow`),
    /// or to correct it after a logout.
    pub fn setAuthorized(self: *Client, user_id: i64, is_bot: bool) void {
        self.authorized = .{ .user_id = user_id, .is_bot = is_bot };
    }

    /// Exports the portable session string (see `session.string`): the
    /// current DC, its authorization key, the application id, the
    /// network, and — when known — the signed-in identity. Works
    /// without a live connection as long as the key is known (e.g.
    /// right after importing a string or connecting once). The result
    /// is owned by the caller; treat it as a secret.
    pub fn exportSessionString(self: *Client, allocator: std.mem.Allocator) Error![]u8 {
        const stored = self.dcs.authKey(self.dcs.current) orelse return error.NotConnected;
        const auth = self.authorized orelse Authorization{};
        return session.string.encode(allocator, .{
            .dc_id = self.dcs.current,
            .api_id = self.opts.app.api_id,
            .test_mode = self.dcs.list.environment == .@"test",
            .auth_key = stored.key,
            .user_id = auth.user_id,
            .is_bot = auth.is_bot,
        });
    }

    fn invokeOn(
        self: *Client,
        io: std.Io,
        m: *connman.Manager,
        req: anytype,
        comptime R: type,
        wrapped: bool,
    ) Error!rpc.Response(R) {
        if (!wrapped and !self.opts.no_updates) return m.invoke(io, req);
        var w = tl.Writer.init(self.allocator);
        defer w.deinit();
        // Outermost first: invokeWithoutUpdates{ invokeWithLayer{
        // initConnection{ query } } }. Both wrappers are
        // result-transparent — the rpc_result decodes as the inner
        // query's type.
        if (self.opts.no_updates)
            w.writeConstructorId(invoke_without_updates_id) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.MessageTooLarge,
            };
        if (wrapped) {
            self.writeInitWrapper(&w) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.MessageTooLarge,
            };
        }
        req.serialize(&w) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.MessageTooLarge,
        };
        const bytes = try m.invokeRaw(io, w.items());
        return self.respond(R, bytes);
    }

    /// Serializes the `invokeWithLayer > initConnection` envelope; the
    /// caller appends the wrapped query's own bytes. The wrapper is
    /// result-transparent: the rpc_result decodes as the inner query's
    /// type.
    fn writeInitWrapper(self: *Client, w: *tl.Writer) errors_mod.TlError!void {
        try w.writeConstructorId(invoke_with_layer_id);
        try w.writeInt(api.layer);
        try w.writeConstructorId(init_connection_id);
        try w.writeInt(0); // flags: neither proxy nor params
        try w.writeInt(self.opts.app.api_id);
        try w.writeString(self.opts.app.device_model);
        try w.writeString(self.opts.app.system_version);
        try w.writeString(self.opts.app.app_version);
        try w.writeString(self.opts.app.system_lang_code);
        try w.writeString(self.opts.app.lang_pack);
        try w.writeString(self.opts.app.lang_code);
    }

    /// Wraps raw result bytes in an arena and decodes `R` from the copy
    /// (decoded values borrow their input, so the wire bytes must
    /// outlive them — the arena does).
    fn respond(self: *Client, comptime R: type, bytes: []u8) Error!rpc.Response(R) {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena_state.deinit();
        const arena = arena_state.allocator();
        defer self.allocator.free(bytes);
        const copy = arena.dupe(u8, bytes) catch return error.OutOfMemory;
        const value = rpc.decodeResult(R, arena, copy) catch |e| return e;
        return .{ .arena_state = arena_state, .value = value };
    }

    /// `invoke` with the result type spelled out — for request structs
    /// without a `Result` decl.
    pub fn call(self: *Client, io: std.Io, req: anytype, comptime R: type) Error!rpc.Response(R) {
        return (try self.requireManager()).call(io, req, R);
    }

    /// Pipelined send (no migration handling and no wrappers — neither
    /// the init wrapper nor `no_updates`; the manager still reconnects
    /// and recovers on connection-level failures).
    pub fn send(self: *Client, io: std.Io, req: anytype) Error!rpc.Handle(rpc.ResultOf(@TypeOf(req))) {
        return (try self.requireManager()).send(io, req);
    }

    /// Waits for a request sent through this client.
    pub fn wait(self: *Client, io: std.Io, handle: anytype) Error!rpc.Response(@TypeOf(handle).Result) {
        return (try self.requireManager()).wait(io, handle);
    }

    /// Raw round trip: pre-serialized body in, owned result-object
    /// bytes out (gzip already inflated). No migration handling.
    pub fn invokeRaw(self: *Client, io: std.Io, body: []const u8) Error![]u8 {
        return (try self.requireManager()).invokeRaw(io, body);
    }

    /// Technical ping/pong round trip with recovery.
    pub fn ping(self: *Client, io: std.Io) Error!void {
        return (try self.requireManager()).ping(io);
    }

    /// Code and message of the most recent `rpc_error`; meaningful
    /// after a call failed with `error.RpcError`, valid until the next
    /// request completes.
    pub fn lastRpcError(self: *Client) rpc.RpcErrorInfo {
        if (self.manager == null) return .{ .code = 0, .message = "" };
        const m = &self.manager.?;
        if (m.client == null) return .{ .code = 0, .message = "" };
        return m.client.?.lastRpcError();
    }

    /// Current connection state: `.closed` after `close`, `.idle`
    /// before the first `connect` and after `disconnect`, the manager's
    /// state in between.
    pub fn state(self: *const Client) connman.State {
        if (self.closed) return .closed;
        if (self.manager) |*m| return m.state();
        return .idle;
    }

    /// Captures the live session (auth key with the current salt, wire
    /// identity and counters) and stores it. Called automatically after
    /// `connect`; call again at any durability point. With no
    /// `session_store` configured this is a no-op.
    pub fn saveSession(self: *Client, io: std.Io) SaveError!void {
        const st = self.opts.session_store orelse return;
        const m = try self.requireManager();
        // Under PFS the live session is keyed by the RAM-only temp key
        // (`capture` would find no stored key for it): persist the
        // permanent key without the wire-session half instead.
        const captured = if (self.pfs_temp != null)
            session.State.capturePermanent(&self.dcs) orelse return error.NotConnected
        else
            session.State.capture(&self.dcs, &m.client.?) orelse return error.NotConnected;
        try st.saveState(io, captured);
    }

    /// Drops the current connection: persists the session best-effort,
    /// flushes acknowledgements, cancels outstanding requests (their
    /// handles go stale) and closes the transport. The client stays
    /// fully usable — `connect` re-establishes, and nothing else needs
    /// resetting. Safe from any state.
    pub fn disconnect(self: *Client, io: std.Io) void {
        if (self.manager) |*m| {
            if (self.opts.session_store != null) {
                const captured = if (self.pfs_temp != null)
                    session.State.capturePermanent(&self.dcs)
                else if (m.client) |*c|
                    session.State.capture(&self.dcs, c)
                else
                    null;
                if (captured) |st| self.opts.session_store.?.saveState(io, st) catch {};
            }
        }
        self.closeConnection(io);
    }

    /// Terminal shutdown: `disconnect`, then the client refuses every
    /// further operation — `connect`, `invoke` and friends fail with
    /// `error.Closed`. For the "drop the connection but keep the
    /// client" case, use `disconnect`. `deinit` still applies and
    /// remains the one that frees memory.
    pub fn close(self: *Client, io: std.Io) void {
        if (self.closed) return;
        self.disconnect(io);
        self.closed = true;
    }

    /// Tears everything down. Safe from any state, including straight
    /// after `close`.
    pub fn deinit(self: *Client, io: std.Io) void {
        self.closeConnection(io);
        self.dcs.deinit();
    }

    // ------------------------------------------------------------ plumbing

    fn requireManager(self: *Client) error{Closed, NotConnected}!*connman.Manager {
        if (self.closed) return error.Closed;
        if (self.manager) |*m| return m;
        return error.NotConnected;
    }

    /// Resolves the current DC's endpoint, ensures its authorization
    /// key (handshake on a short-lived connection when missing), builds
    /// the manager and establishes the connection. Rebuilt this way on
    /// `connect` and every migration.
    fn openConnection(self: *Client, io: std.Io) ConnectError!void {
        // First io seen wins: the internal entropy source lives for the
        // client's lifetime (the layers below borrow it).
        if (self.rng == null) {
            self.rng = .{ .io = io };
            self.random = self.rng.?.interface();
        }
        // Replace semantics: any connection still held is torn down
        // first, so a repeated connect never orphans a transport.
        self.closeConnection(io);
        // Every connection built here starts a server session whose
        // first query needs the initConnection wrapper again.
        self.inited_generation = 0;
        const dc_id = self.dcs.current;
        const ep = self.dcs.endpointFor(dc_id, self.opts.purpose, self.opts.prefer_ipv6) orelse
            return error.NoEndpoint;
        try self.ensureAuthKey(io, dc_id, ep);
        const stored = self.dcs.authKey(dc_id).?;

        // PFS: the connection encrypts with a fresh temporary key; the
        // permanent one only ever seals the bind payload below.
        var key: *const [crypto.auth_key_size]u8 = &stored.key;
        var salt = std.mem.readInt(i64, &stored.server_salt, .little);
        if (self.opts.pfs) {
            try self.ensureTempKey(io, dc_id, ep);
            const temp = &self.pfs_temp.?;
            key = &temp.key;
            salt = std.mem.readInt(i64, &temp.server_salt, .little);
        }

        // A stale salt is corrected by the server through
        // bad_server_salt, which the RPC client answers with a re-send.
        // The client-level transport mode wins over the connman-level
        // knob (which connman-only callers set directly).
        var conn_opts = self.opts.conn;
        conn_opts.transport = self.opts.transport;
        self.manager = connman.Manager.init(self.allocator, ep, key, salt, self.random, conn_opts);
        const m = &self.manager.?;
        m.updates_handler = self.opts.updates_handler;
        try m.ensureConnected(io);

        if (self.opts.pfs) try self.bindTempKey(io, stored);

        // Continue the persisted wire session — only ever on the DC it
        // was captured on; a migration draws a fresh identity. A PFS
        // session identity is never persisted (the temp key it belonged
        // to is gone), so nothing is adopted here for it.
        if (self.pending_session) |st| {
            defer self.pending_session = null;
            if (!self.opts.pfs and st.dc == dc_id) st.adoptOn(&m.client.?, unixSeconds(io));
        }
    }

    /// Generates a fresh temporary auth key (`p_q_inner_data_temp_dc`
    /// handshake on a dedicated, immediately dropped connection). The
    /// previous temp key — bound or not — is replaced: temp keys are
    /// RAM-only per the spec, one per connection establishment.
    fn ensureTempKey(self: *Client, io: std.Io, dc_id: i32, ep: transport.Endpoint) ConnectError!void {
        if (self.opts.conn.transport_provider) |p| {
            const t = try p.acquire(p.ctx, io, ep);
            errdefer p.release(p.ctx, io, t);
            try t.connect(io);
            errdefer t.close(io);
            try self.tempHandshakeOver(io, dc_id, t);
        } else {
            var dialer = transport.Dialer.init(ep, self.opts.transport, self.opts.conn.tcp, self.random);
            const t = dialer.transport();
            try t.connect(io);
            defer t.close(io);
            try self.tempHandshakeOver(io, dc_id, t);
        }
    }

    fn tempHandshakeOver(self: *Client, io: std.Io, dc_id: i32, t: transport.Transport) ConnectError!void {
        var adapter = mtproto.HandshakePipe.init(t, io);
        var hs = mtproto.Handshake.init(self.allocator, adapter.pipe(), self.opts.pubkeys, self.random, unixSeconds(io), .{
            .mode = self.opts.handshake_mode,
            .dc = self.dcs.handshakeDcId(dc_id),
        });
        self.pfs_temp = try hs.runTemp(mtproto.pfs.default_expires_in);
    }

    /// Binds the fresh temp key to the permanent one: `auth.bindTempAuthKey`
    /// over the temp-key connection. The request travels encrypted with
    /// the temporary key; its `encrypted_message` is a v1 packet sealed
    /// with the permanent key, embedding the exact msg_id the request is
    /// sent under — hence `reserveMsgId` + `invokeRawWithId`. Success is
    /// `boolTrue`; anything else (rpc_error included) is
    /// `error.TempKeyBindFailed` with the rpc detail in `lastRpcError`.
    fn bindTempKey(self: *Client, io: std.Io, perm: *const mtproto.AuthKey) ConnectError!void {
        const m = try self.requireManager();
        const c = &m.client.?;
        const temp = &self.pfs_temp.?;

        const msg_id = c.reserveMsgId(io);
        // One nonce, in both the inner blob and the request — the server
        // validates that they are equal.
        const nonce = self.random.int(i64);
        const blob = mtproto.pfs.buildBindBlob(self.allocator, &perm.key, .{
            .nonce = nonce,
            .temp_auth_key_id = @bitCast(temp.id),
            .perm_auth_key_id = @bitCast(perm.id),
            .temp_session_id = c.sessionId(),
            .expires_at = temp.expires_at,
        }, msg_id, self.random) catch return error.OutOfMemory;
        defer self.allocator.free(blob);

        var w = tl.Writer.init(self.allocator);
        defer w.deinit();
        const req = api.auth.bindTempAuthKey{
            .perm_auth_key_id = @bitCast(perm.id),
            .nonce = nonce,
            .expires_at = temp.expires_at,
            .encrypted_message = blob,
        };
        req.serialize(&w) catch return error.MessageTooLarge;

        const bytes = c.invokeRawWithId(io, msg_id, w.items()) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            // rpc_error (ENCRYPTED_MESSAGE_INVALID, TEMP_AUTH_KEY_*)
            // and transport-level failures alike: the temp key is not
            // bound, so the connection is not usable as-is.
            else => return error.TempKeyBindFailed,
        };
        defer self.allocator.free(bytes);
        const ok = bytes.len == 4 and std.mem.readInt(u32, bytes[0..4], .little) == 0x997275b5;
        if (!ok) return error.TempKeyBindFailed;
    }

    /// Whether the active temp key is within the rotation margin of its
    /// expiry (client clock; the margin absorbs skew). Servers may also
    /// expire keys early at any moment — that surfaces as a connection
    /// failure, and the next connect binds a fresh key.
    fn tempKeyNeedsRotation(self: *Client, now_seconds: u64) bool {
        const temp = self.pfs_temp orelse return true;
        const remaining: i64 = @as(i64, temp.expires_at) - @as(i64, @intCast(now_seconds));
        return remaining <= mtproto.pfs.rotate_margin_seconds;
    }

    /// Runs the authorization-key handshake on a dedicated connection
    /// (dropped right after) and stores the key. With a transport
    /// provider the handshake uses it — the working connection later
    /// gets its own transport from the same provider.
    fn ensureAuthKey(self: *Client, io: std.Io, dc_id: i32, ep: transport.Endpoint) ConnectError!void {
        if (self.dcs.authKey(dc_id) != null) return;

        if (self.opts.conn.transport_provider) |p| {
            const t = try p.acquire(p.ctx, io, ep);
            errdefer p.release(p.ctx, io, t);
            try t.connect(io);
            errdefer t.close(io);
            try self.handshakeOver(io, dc_id, t);
        } else {
            var dialer = transport.Dialer.init(ep, self.opts.transport, self.opts.conn.tcp, self.random);
            const t = dialer.transport();
            try t.connect(io);
            defer t.close(io);
            try self.handshakeOver(io, dc_id, t);
        }
    }

    fn handshakeOver(self: *Client, io: std.Io, dc_id: i32, t: transport.Transport) ConnectError!void {
        var adapter = mtproto.HandshakePipe.init(t, io);
        var hs = mtproto.Handshake.init(self.allocator, adapter.pipe(), self.opts.pubkeys, self.random, unixSeconds(io), .{
            .mode = self.opts.handshake_mode,
            .dc = self.dcs.handshakeDcId(dc_id),
        });
        const key = try hs.run();
        try self.dcs.setAuthKey(dc_id, key);
    }

    /// Applies a migration: switches the DC, dropping the old
    /// connection (its endpoint borrows the endpoint list, which a
    /// config refresh may mutate) and opening a fresh one.
    fn moveTo(self: *Client, io: std.Io, m: migration.Migration) Error!void {
        var switched = try self.dcs.migrate(m);
        if (!switched) {
            // The bootstrap list does not know the target: learn the
            // network's current dc_options from the still-live
            // connection first. Plain manager invoke — a redirect loop
            // here would recurse through `invoke`'s migration handling.
            const old = try self.requireManager();
            var cfg = try old.invoke(io, api.help.getConfig{});
            defer cfg.deinit();
            // Drop the connection before mutating the list its
            // endpoint's address bytes borrow from.
            self.closeConnection(io);
            try self.dcs.list.updateFromConfig(&cfg.value.config);
            switched = try self.dcs.migrate(m);
            if (!switched) return error.CannotMigrate;
        } else {
            self.closeConnection(io);
        }
        // The wire-session identity belongs to the old DC's connection.
        self.pending_session = null;
        try self.openConnection(io);
    }

    fn closeConnection(self: *Client, io: std.Io) void {
        if (self.manager) |*m| {
            m.close(io);
            m.deinit(io);
            self.manager = null;
        }
    }
};

fn unixSeconds(io: std.Io) u64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

// ---------------------------------------------------------------- tests
//
// Network-free: the connection layer runs over in-memory loopback links
// (real MTProto encryption and validation both sides), reached through
// a connman transport provider. Per-DC keys are pre-seeded so no
// handshake is needed; the DC2 peer answers `help.getNearestDc` with
// `PHONE_MIGRATE_5`, the DC5 peer with a `nearestDc` result — driving
// the full connect → invoke → migrate → invoke choreography.

const message = mtproto.message;
const multi = @import("multi/mod.zig");

const get_nearest_dc_id: u32 = 0x1fb33026;
const nearest_dc_id: u32 = 0x8e1a1775;

const TestNet = struct {
    allocator: std.mem.Allocator,
    salt: i64 = 0x51a1,
    key2: [crypto.auth_key_size]u8,
    key5: [crypto.auth_key_size]u8,
    /// Endpoint hosts as the DataCenters list spells them; acquire
    /// matches the requested endpoint against them (real DCs all use
    /// port 443, so the host is the discriminator).
    host2: []const u8 = "",
    host5: []const u8 = "",
    link2: ?*multi.Link = null,
    link5: ?*multi.Link = null,
    /// Queries seen carrying the invokeWithLayer wrapper vs. bare vs.
    /// the no-updates shell.
    wrapped_seen: usize = 0,
    bare_seen: usize = 0,
    no_updates_seen: usize = 0,

    fn init(allocator: std.mem.Allocator) TestNet {
        var self = TestNet{
            .allocator = allocator,
            .key2 = undefined,
            .key5 = undefined,
        };
        for (&self.key2, 0..) |*b, i| b.* = @truncate(i *% 73 +% 11);
        for (&self.key5, 0..) |*b, i| b.* = @truncate(i *% 57 +% 29);
        return self;
    }

    /// Creates the links. Must run after the TestNet reached its final
    /// location: each link's key pointer addresses this struct.
    fn wire(self: *TestNet) !void {
        const l2 = try self.allocator.create(multi.Link);
        errdefer self.allocator.destroy(l2);
        l2.* = multi.Link.init(self.allocator, &self.key2, self.salt);
        errdefer l2.deinit();
        const l5 = try self.allocator.create(multi.Link);
        errdefer self.allocator.destroy(l5);
        l5.* = multi.Link.init(self.allocator, &self.key5, self.salt);
        errdefer l5.deinit();
        l2.responder = .{ .ctx = self, .onBody = onBody };
        l5.responder = .{ .ctx = self, .onBody = onBody };
        self.link2 = l2;
        self.link5 = l5;
    }

    fn deinit(self: *TestNet) void {
        if (self.link2) |l| {
            l.deinit();
            self.allocator.destroy(l);
        }
        if (self.link5) |l| {
            l.deinit();
            self.allocator.destroy(l);
        }
    }

    fn provider(self: *TestNet) connman.TransportProvider {
        return .{ .ctx = self, .acquire = acquireImpl, .release = releaseImpl };
    }

    fn acquireImpl(ctx: *anyopaque, _: std.Io, ep: transport.Endpoint) transport.Error!transport.Transport {
        const self: *TestNet = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, ep.host, self.host5)) return self.link5.?.transport();
        return self.link2.?.transport();
    }

    fn releaseImpl(_: *anyopaque, _: std.Io, _: transport.Transport) void {
        // Links live in the TestNet; nothing to return to.
    }

    fn onBody(
        ctx: *anyopaque,
        link: *multi.Link,
        dec: *const message.Decrypted,
        arena: std.mem.Allocator,
    ) ?multi.Reply {
        const self: *TestNet = @ptrCast(@alignCast(ctx));
        if (dec.body.len < 4) return null;

        // The query may arrive bare or inside the invokeWithLayer >
        // initConnection wrapper the facade puts on every fresh
        // session's first query — the wrapper is result-transparent, so
        // match on the trailing constructor (getNearestDc has no
        // arguments, its serialization is exactly its 4 id bytes).
        // Everything else (msgs_ack and friends) drains silently.
        switch (std.mem.readInt(u32, dec.body[0..4], .little)) {
            get_nearest_dc_id => self.bare_seen += 1,
            invoke_with_layer_id => {
                if (std.mem.readInt(u32, dec.body[dec.body.len - 4 ..][0..4], .little) != get_nearest_dc_id)
                    return null;
                self.wrapped_seen += 1;
            },
            invoke_without_updates_id => {
                if (std.mem.readInt(u32, dec.body[dec.body.len - 4 ..][0..4], .little) != get_nearest_dc_id)
                    return null;
                self.no_updates_seen += 1;
            },
            else => return null,
        }
        var w = tl.Writer.init(arena);
        w.writeConstructorId(message.rpc_result_id) catch return null;
        w.writeLong(dec.msg_id) catch return null;
        if (link == self.link5) {
            w.writeConstructorId(nearest_dc_id) catch return null;
            w.writeString("US") catch return null;
            w.writeInt(5) catch return null;
            w.writeInt(5) catch return null;
        } else {
            w.writeConstructorId(message.rpc_error_id) catch return null;
            w.writeInt(303) catch return null;
            w.writeString("PHONE_MIGRATE_5") catch return null;
        }
        return .{ .body = w.items(), .content_related = true };
    }
};

test "high-level client: connect, typed invoke, and PHONE_MIGRATE following" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var testnet = TestNet.init(std.testing.allocator);
    defer testnet.deinit();
    try testnet.wire();


    var client = try Client.init(std.testing.allocator, .{
        .app = .{ .api_id = 424242 },
        .conn = .{
            .transport_provider = testnet.provider(),
            .max_connect_attempts = 2,
            .backoff_base = std.Io.Duration.fromMilliseconds(1),
            .backoff_max = std.Io.Duration.fromMilliseconds(5),
            .ping_interval = std.Io.Duration.fromSeconds(3600),
            .ping_disconnect_delay = null,
            .rpc = .{ .response_timeout = std.Io.Duration.fromMilliseconds(500) },
        },
    });
    defer client.deinit(io);

    // Capture the endpoint hosts acquire matches against.
    testnet.host2 = client.dcs.endpointFor(2, .general, false).?.host;
    testnet.host5 = client.dcs.endpointFor(5, .general, false).?.host;

    // Per-DC keys pre-seeded: no handshake (it needs a real peer).
    try client.dcs.setAuthKey(2, seededKey(&testnet.key2, testnet.salt));
    try client.dcs.setAuthKey(5, seededKey(&testnet.key5, testnet.salt));

    try client.connect(io);
    try std.testing.expectEqual(connman.State.connected, client.state());
    try std.testing.expectEqual(@as(i32, 2), client.dcs.current);

    // DC2's peer redirects; the client follows to DC5 and re-invokes.
    var resp = try client.invoke(io, api.help.getNearestDc{});
    defer resp.deinit();
    switch (resp.value) {
        .nearestDc => |nd| {
            try std.testing.expectEqualStrings("US", nd.country);
            try std.testing.expectEqual(@as(i32, 5), nd.this_dc);
            try std.testing.expectEqual(@as(i32, 5), nd.nearest_dc);
        },
    }
    try std.testing.expectEqual(@as(i32, 5), client.dcs.current);
    try std.testing.expectEqual(connman.State.connected, client.state());

    // Every fresh session's first query went out init-wrapped (DC2,
    // then DC5 after the migration), never bare.
    try std.testing.expectEqual(@as(usize, 2), testnet.wrapped_seen);
    try std.testing.expectEqual(@as(usize, 0), testnet.bare_seen);

    client.close(io);
    try std.testing.expectEqual(connman.State.closed, client.state());
}

test "high-level client: session persistence across clients" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var testnet = TestNet.init(std.testing.allocator);
    defer testnet.deinit();
    try testnet.wire();

    var store = session.MemoryStore.init(std.testing.allocator);
    defer store.deinit();

    const conn_opts: connman.Options = .{
        .transport_provider = testnet.provider(),
        .max_connect_attempts = 2,
        .backoff_base = std.Io.Duration.fromMilliseconds(1),
        .backoff_max = std.Io.Duration.fromMilliseconds(5),
        .ping_interval = std.Io.Duration.fromSeconds(3600),
        .ping_disconnect_delay = null,
        .rpc = .{ .response_timeout = std.Io.Duration.fromMilliseconds(500) },
    };

    // First run: connect straight to DC5, invoke, persist on close.
    {
        var client = try Client.init(std.testing.allocator, .{
            .session_store = store.store(),
            .app = .{ .api_id = 424242 },
            .conn = conn_opts,
        });
        defer client.deinit(io);
        testnet.host5 = client.dcs.endpointFor(5, .general, false).?.host;
        try client.dcs.setAuthKey(5, seededKey(&testnet.key5, testnet.salt));
        try client.dcs.setCurrent(5);

        try client.connect(io);
        var resp = try client.invoke(io, api.help.getNearestDc{});
        defer resp.deinit();
        client.close(io);
    }

    // Second run: the stored session restores DC5 and its key; no
    // handshake, no seeding, and the wire session continues.
    {
        var client = try Client.init(std.testing.allocator, .{
            .session_store = store.store(),
            .app = .{ .api_id = 424242 },
            .conn = conn_opts,
        });
        defer client.deinit(io);
        testnet.host5 = client.dcs.endpointFor(5, .general, false).?.host;

        try client.connect(io);
        try std.testing.expectEqual(@as(i32, 5), client.dcs.current);
        try std.testing.expect(client.dcs.authKey(5) != null);

        var resp = try client.invoke(io, api.help.getNearestDc{});
        defer resp.deinit();
        switch (resp.value) {
            .nearestDc => |nd| try std.testing.expectEqual(@as(i32, 5), nd.this_dc),
        }
    }

    // Both clients wrapped their first query per fresh session.
    try std.testing.expectEqual(@as(usize, 2), testnet.wrapped_seen);
    try std.testing.expectEqual(@as(usize, 0), testnet.bare_seen);
}

test "high-level client: session string import and export" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var testnet = TestNet.init(std.testing.allocator);
    defer testnet.deinit();
    try testnet.wire();


    // A bot session on DC5 (the TestNet's DC5 key), exported in the
    // portable format with a distinct application id.
    const imported = try session.string.encode(std.testing.allocator, .{
        .dc_id = 5,
        .api_id = 424242,
        .test_mode = false,
        .auth_key = testnet.key5,
        .user_id = 6_123_456_789,
        .is_bot = true,
    });
    defer std.testing.allocator.free(imported);

    var client = try Client.init(std.testing.allocator, .{
        .session_string = imported,
        .app = .{ .api_id = 424242 },
        .conn = .{
            .transport_provider = testnet.provider(),
            .max_connect_attempts = 2,
            .backoff_base = std.Io.Duration.fromMilliseconds(1),
            .backoff_max = std.Io.Duration.fromMilliseconds(5),
            .ping_interval = std.Io.Duration.fromSeconds(3600),
            .ping_disconnect_delay = null,
            .rpc = .{ .response_timeout = std.Io.Duration.fromMilliseconds(500) },
        },
    });
    defer client.deinit(io);
    testnet.host5 = client.dcs.endpointFor(5, .general, false).?.host;

    try client.connect(io);
    try std.testing.expectEqual(@as(i32, 5), client.dcs.current);
    try std.testing.expectEqual(@as(i64, 6_123_456_789), client.authorized.?.user_id);
    try std.testing.expect(client.authorized.?.is_bot);
    // The imported application id replaced the default.
    try std.testing.expectEqual(@as(i32, 424242), client.opts.app.api_id);

    // The imported key works: one typed round trip.
    var resp = try client.invoke(io, api.help.getNearestDc{});
    defer resp.deinit();
    switch (resp.value) {
        .nearestDc => |nd| try std.testing.expectEqual(@as(i32, 5), nd.this_dc),
    }

    // Export reproduces the imported string exactly (same DC, key,
    // application id, identity, network).
    const exported = try client.exportSessionString(std.testing.allocator);
    defer std.testing.allocator.free(exported);
    try std.testing.expectEqualStrings(imported, exported);

    // Sign-out clears the identity; a subsequent export reflects it.
    client.setAuthorized(0, false);
    const logged_out = try client.exportSessionString(std.testing.allocator);
    defer std.testing.allocator.free(logged_out);
    const back = try session.string.parse(logged_out);
    try std.testing.expectEqual(@as(i64, 0), back.user_id);
    try std.testing.expect(!back.is_bot);
}

test "high-level client: no_updates wraps the first and later queries" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var testnet = TestNet.init(std.testing.allocator);
    defer testnet.deinit();
    try testnet.wire();

    var client = try Client.init(std.testing.allocator, .{
        .app = .{ .api_id = 424242 },
        .no_updates = true,
        .conn = .{
            .transport_provider = testnet.provider(),
            .max_connect_attempts = 2,
            .backoff_base = std.Io.Duration.fromMilliseconds(1),
            .backoff_max = std.Io.Duration.fromMilliseconds(5),
            .ping_interval = std.Io.Duration.fromSeconds(3600),
            .ping_disconnect_delay = null,
            .rpc = .{ .response_timeout = std.Io.Duration.fromMilliseconds(500) },
        },
    });
    defer client.deinit(io);
    testnet.host5 = client.dcs.endpointFor(5, .general, false).?.host;
    try client.dcs.setAuthKey(5, seededKey(&testnet.key5, testnet.salt));
    try client.dcs.setCurrent(5);

    try client.connect(io);

    // The fresh session's first query carries the full chain
    // invokeWithoutUpdates > invokeWithLayer > initConnection; answers
    // still decode as the inner query's type (result-transparent).
    var first = try client.invoke(io, api.help.getNearestDc{});
    defer first.deinit();
    switch (first.value) {
        .nearestDc => |nd| try std.testing.expectEqual(@as(i32, 5), nd.this_dc),
    }

    // A later query (session already inited) still goes out wrapped —
    // the no-updates shell is on every invoke, not only the first.
    var second = try client.invoke(io, api.help.getNearestDc{});
    defer second.deinit();

    try std.testing.expectEqual(@as(usize, 2), testnet.no_updates_seen);
    try std.testing.expectEqual(@as(usize, 0), testnet.wrapped_seen);
    try std.testing.expectEqual(@as(usize, 0), testnet.bare_seen);
}

test "high-level client: disconnect/reconnect cycle, close is terminal" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var testnet = TestNet.init(std.testing.allocator);
    defer testnet.deinit();
    try testnet.wire();


    var client = try Client.init(std.testing.allocator, .{
        .app = .{ .api_id = 424242 },
        .conn = .{
            .transport_provider = testnet.provider(),
            .max_connect_attempts = 2,
            .backoff_base = std.Io.Duration.fromMilliseconds(1),
            .backoff_max = std.Io.Duration.fromMilliseconds(5),
            .ping_interval = std.Io.Duration.fromSeconds(3600),
            .ping_disconnect_delay = null,
            .rpc = .{ .response_timeout = std.Io.Duration.fromMilliseconds(500) },
        },
    });
    defer client.deinit(io);
    testnet.host5 = client.dcs.endpointFor(5, .general, false).?.host;
    try client.dcs.setAuthKey(5, seededKey(&testnet.key5, testnet.salt));
    try client.dcs.setCurrent(5);

    try client.connect(io);
    var first = try client.invoke(io, api.help.getNearestDc{});
    defer first.deinit();

    // Disconnect drops the connection but keeps the client: state is
    // idle and connect re-establishes over the same session key.
    client.disconnect(io);
    try std.testing.expectEqual(connman.State.idle, client.state());
    try client.connect(io);
    try std.testing.expectEqual(connman.State.connected, client.state());
    var second = try client.invoke(io, api.help.getNearestDc{});
    defer second.deinit();

    // Close is terminal: reconnecting and invoking both refuse.
    client.close(io);
    try std.testing.expectEqual(connman.State.closed, client.state());
    try std.testing.expectError(error.Closed, client.connect(io));
    try std.testing.expectError(error.Closed, client.invoke(io, api.help.getNearestDc{}));
}

fn seededKey(bytes: *const [crypto.auth_key_size]u8, salt: i64) mtproto.AuthKey {
    var key = mtproto.AuthKey{
        .key = bytes.*,
        .id = crypto.authKeyId(bytes),
        .aux_hash = undefined,
        .server_salt = undefined,
    };
    var sha1: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(bytes, &sha1, .{});
    @memcpy(&key.aux_hash, sha1[0..8]);
    std.mem.writeInt(i64, &key.server_salt, salt, .little);
    return key;
}

test "options default to the production network with vendored keys" {
    const opts = Options{ .app = .{ .api_id = 424242 } };
    try std.testing.expect(opts.environment == .production);
    try std.testing.expect(opts.pubkeys.ptr == mtproto.server_keys.production.ptr);
    try std.testing.expect(opts.purpose == .general);
    try std.testing.expect(!opts.prefer_ipv6);
    try std.testing.expectEqual(@as(u32, 1), opts.max_migrations);
    try std.testing.expect(opts.session_store == null);
    // Abridged is the default framing: nothing to configure.
    try std.testing.expectEqual(transport.TransportMode.abridged, opts.transport);
    // Updates flow by default; opting out is explicit.
    try std.testing.expect(!opts.no_updates);
}
