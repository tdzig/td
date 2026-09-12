//! DC management: current-DC state, per-DC authorization keys and the
//! connection composition.
//!
//! `DataCenters` is the piece of client state that survives connection
//! churn: which DC the client is working on (`current`), every endpoint
//! it knows (`DcList`), and one authorization key per DC it has already
//! shaken hands with. `connect` composes the existing layers into the
//! full "give me an RPC client for DC X" operation:
//!
//!     DcList (endpoint selection) → transport (TCP-full) →
//!     handshake (per-DC auth key, cached) → rpc.Client
//!
//! Migration (see `migration.zig`) is a state transition here: parse the
//! rpc error, `migrate` to the target DC, `connect` it and repeat the
//! request. `USER_MIGRATE` additionally needs
//! `auth.exportAuthorization`/`auth.importAuthorization` (a later
//! milestone); every other case works with per-DC keys alone.

const std = @import("std");
const mtproto = @import("../mtproto/mod.zig");
const handshake = @import("../mtproto/handshake.zig");
const transport = @import("../transport/mod.zig");
const rpc = @import("../rpc/mod.zig");
const options = @import("options.zig");
const migration = @import("migration.zig");

const AuthKey = mtproto.AuthKey;
const DcList = options.DcList;
const Environment = options.Environment;

pub const Error = error{
    OutOfMemory,
    /// The DC id is not present in the endpoint list.
    UnknownDc,
    /// The DC has no usable endpoint for the request (unknown family
    /// situation or only `tcpo_only` entries, which need the obfuscated
    /// transport).
    NoEndpoint,
};

/// Everything `connect` can fail with.
pub const ConnectError = Error || rpc.Error || handshake.Error;

/// The DC every fresh client starts from — the classic production entry
/// point (also `tdzig-keygen`'s default).
pub const default_entry_dc: i32 = 2;

/// One stored authorization key. Secret material: never logged.
const KeyEntry = struct {
    dc: i32,
    key: AuthKey,
};

pub const DataCenters = struct {
    allocator: std.mem.Allocator,
    /// Endpoint knowledge (bootstrap + config updates).
    list: DcList,
    /// The DC the client currently works on.
    current: i32,
    /// Authorization keys, at most a handful (one per visited DC).
    keys: std.ArrayList(KeyEntry) = .empty,

    pub fn init(allocator: std.mem.Allocator, environment: Environment) Error!DataCenters {
        return .{
            .allocator = allocator,
            .list = try DcList.init(allocator, environment),
            .current = default_entry_dc,
        };
    }

    pub fn deinit(self: *DataCenters) void {
        self.list.deinit();
        self.keys.deinit(self.allocator);
    }

    /// The stored authorization key for `dc`, if any. The pointer borrows
    /// this manager's storage: valid until the next key-store mutation.
    pub fn authKey(self: *const DataCenters, dc: i32) ?*const AuthKey {
        for (self.keys.items) |*k| {
            if (k.dc == dc) return &k.key;
        }
        return null;
    }

    /// The stored key whose public id matches `id`, with its DC — the
    /// session layer uses this to identify which DC a live client's key
    /// belongs to. The key is copied, so the result stays valid across
    /// key-store mutations.
    pub fn authKeyForId(self: *const DataCenters, id: *const [8]u8) ?struct { dc: i32, key: AuthKey } {
        for (self.keys.items) |*k| {
            if (std.mem.eql(u8, &k.key.id, id)) return .{ .dc = k.dc, .key = k.key };
        }
        return null;
    }

    /// Stores (or replaces) the authorization key of `dc`. The key struct
    /// is copied; callers discard their original afterwards.
    pub fn setAuthKey(self: *DataCenters, dc: i32, key: AuthKey) Error!void {
        for (self.keys.items) |*k| {
            if (k.dc == dc) {
                k.key = key;
                return;
            }
        }
        self.keys.append(self.allocator, .{ .dc = dc, .key = key }) catch return error.OutOfMemory;
    }

    pub fn removeAuthKey(self: *DataCenters, dc: i32) void {
        for (self.keys.items, 0..) |k, i| {
            if (k.dc == dc) {
                _ = self.keys.orderedRemove(i);
                return;
            }
        }
    }

    /// Where to connect for `dc` (delegates to the list; see
    /// `DcList.endpointFor` for the selection rules).
    pub fn endpointFor(
        self: *const DataCenters,
        dc: i32,
        purpose: options.Purpose,
        prefer_ipv6: bool,
    ) ?transport.Endpoint {
        return self.list.endpointFor(dc, purpose, prefer_ipv6);
    }

    /// The DC id to place in the handshake's `p_q_inner_data_dc` for this
    /// network: test servers expect the id shifted by +10000.
    pub fn handshakeDcId(self: *const DataCenters, dc: i32) i32 {
        return if (self.list.environment == .@"test") dc + 10000 else dc;
    }

    /// Switches the current DC. Fails with `error.UnknownDc` when no
    /// endpoint is known for it (fetch a fresh config first).
    pub fn setCurrent(self: *DataCenters, dc: i32) Error!void {
        if (!self.list.hasDc(dc)) return error.UnknownDc;
        self.current = dc;
    }

    /// Applies a parsed migration: switches `current` to the target DC
    /// and returns true. Returns false — leaving the state untouched —
    /// when the target DC is unknown (refresh the config from a reachable
    /// DC, then retry). Dropping/rebuilding the live connection is the
    /// caller's business; the stored keys stay.
    pub fn migrate(self: *DataCenters, m: migration.Migration) Error!bool {
        if (!self.list.hasDc(m.dc)) return false;
        self.current = m.dc;
        return true;
    }

    // ----------------------------------------------------------- connect

    /// Establishes a connection to `dc` and returns an RPC client over
    /// it: resolves the endpoint, connects the TCP-full transport and
    /// either reuses the stored auth key or runs the authorization-key
    /// handshake first (storing the result for later connections).
    ///
    /// `pubkeys` are the server RSA public keys (Telegram publishes them
    /// with the protocol documentation; see also `tdzig-keygen`). Both
    /// `random` and `tcp_storage` are borrowed and must outlive the
    /// returned client; `tcp_storage` in turn borrows the endpoint's
    /// address bytes from this manager's `DcList`, so don't update the
    /// list while the connection lives.
    pub fn connect(
        self: *DataCenters,
        io: std.Io,
        dc: i32,
        random: std.Random,
        pubkeys: []const mtproto.RsaPublicKey,
        tcp_storage: *transport.TcpFull,
        opts: ConnectOptions,
    ) ConnectError!rpc.Client {
        if (!self.list.hasDc(dc)) return error.UnknownDc;
        const ep = self.endpointFor(dc, opts.purpose, opts.prefer_ipv6) orelse
            return error.NoEndpoint;

        // Storage may still hold the previous (migration-dead) connection;
        // drop it before overwriting.
        tcp_storage.close(io);
        tcp_storage.* = transport.TcpFull.init(.{ .host = ep.host, .port = ep.port }, opts.tcp);
        try tcp_storage.connect(io);
        errdefer tcp_storage.close(io);

        if (self.authKey(dc) == null) {
            var adapter = mtproto.HandshakePipe.init(tcp_storage.transport(), io);
            var hs = handshake.Handshake.init(self.allocator, adapter.pipe(), pubkeys, random, unixSeconds(io), .{
                .mode = opts.handshake_mode,
                .dc = self.handshakeDcId(dc),
            });
            const auth_key = try hs.run();
            try self.setAuthKey(dc, auth_key);
        }

        const stored = self.authKey(dc).?;
        // server_salt is the wire (little-endian) i64 form of the XOR
        // bytes the handshake derived. A stale salt is corrected by the
        // server through bad_server_salt, which the RPC client handles.
        const salt = std.mem.readInt(i64, &stored.server_salt, .little);
        return rpc.Client.init(self.allocator, tcp_storage.transport(), &stored.key, salt, random, opts.rpc);
    }
};

/// Options for `DataCenters.connect`.
pub const ConnectOptions = struct {
    /// Prefer IPv6 endpoints when the DC has both families.
    prefer_ipv6: bool = false,
    /// What the connection will carry (endpoint filtering).
    purpose: options.Purpose = .general,
    /// TCP-full options for the new connection.
    tcp: transport.tcp_full.Options = .{},
    /// RSA layout of the handshake (the DC id is filled in automatically).
    handshake_mode: mtproto.rsa.Mode = .rsa_pad,
    /// RPC client options.
    rpc: rpc.Options = .{},
};


fn unixSeconds(io: std.Io) u64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

// ---------------------------------------------------------------- tests

test "auth key store is per DC" {
    var dcs = try DataCenters.init(std.testing.allocator, .production);
    defer dcs.deinit();

    var key: mtproto.AuthKey = undefined;
    for (&key.key, 0..) |*b, i| b.* = @truncate(i *% 7);
    for (&key.id, 0..) |*b, i| b.* = @truncate(i +% 3);
    for (&key.aux_hash, 0..) |*b, i| b.* = @truncate(i *% 11);
    for (&key.server_salt, 0..) |*b, i| b.* = @truncate(i *% 13);

    try dcs.setAuthKey(2, key);
    try std.testing.expectEqualSlices(u8, &key.key, &dcs.authKey(2).?.key);
    try std.testing.expect(dcs.authKey(5) == null);

    // Replace: the newest key wins.
    key.key[0] ^= 0xff;
    try dcs.setAuthKey(2, key);
    try std.testing.expectEqual(@as(u8, 0xff), dcs.authKey(2).?.key[0]);

    // And a second DC coexists with the first.
    try dcs.setAuthKey(4, key);
    try std.testing.expect(dcs.authKey(4) != null);
    dcs.removeAuthKey(2);
    try std.testing.expect(dcs.authKey(2) == null);
    try std.testing.expect(dcs.authKey(4) != null);
}

test "handshake dc id shifts by 10000 on the test network" {
    var prod = try DataCenters.init(std.testing.allocator, .production);
    defer prod.deinit();
    try std.testing.expectEqual(@as(i32, 2), prod.handshakeDcId(2));

    var tst = try DataCenters.init(std.testing.allocator, .@"test");
    defer tst.deinit();
    try std.testing.expectEqual(@as(i32, 10002), tst.handshakeDcId(2));
}

test "migration switches the current DC when the target is known" {
    var dcs = try DataCenters.init(std.testing.allocator, .production);
    defer dcs.deinit();
    try std.testing.expectEqual(@as(i32, 2), dcs.current);

    const m = migration.fromMessage("USER_MIGRATE_4").?;
    try std.testing.expect(m.kind == .user);
    try std.testing.expectEqual(@as(i32, 4), m.dc);
    try std.testing.expect(try dcs.migrate(m));
    try std.testing.expectEqual(@as(i32, 4), dcs.current);

    // Unknown target: refused, state untouched (fetch a config first).
    const unknown = migration.Migration{ .kind = .network, .dc = 9 };
    try std.testing.expect(!(try dcs.migrate(unknown)));
    try std.testing.expectEqual(@as(i32, 4), dcs.current);
    try std.testing.expectError(error.UnknownDc, dcs.setCurrent(9));
    try dcs.setCurrent(5);
    try std.testing.expectEqual(@as(i32, 5), dcs.current);
}

test "connect options default to a plain IPv4 general connection" {
    const opts = ConnectOptions{};
    try std.testing.expect(!opts.prefer_ipv6);
    try std.testing.expect(opts.purpose == .general);
    try std.testing.expect(opts.handshake_mode == .rsa_pad);
    // Reference the composition (and through it the handshake adapter)
    // so its full body stays analyzed, although no test touches the
    // network.
    _ = DataCenters.connect;
}
