//! Serializable client-session state: everything needed to reconnect
//! without repeating authorization.
//!
//! One `State` captures, for the DC the client was working on:
//!
//!   * the secret **authorization key** (with its public id and the
//!     **server salt** current at capture time — later `bad_server_salt`
//!     / `new_session_created` corrections included, unlike the
//!     handshake-time salt stored inside the key);
//!   * the wire **session id** and the outgoing msg_id/seq counters,
//!     plus the incoming seq counter the server continues from, so a
//!     restored client can continue the same logical session instead of
//!     starting a fresh identity;
//!   * the **environment** (production/test) and DC number the key
//!     belongs to.
//!
//! The binary format (`serialize`/`deserialize`) is a fixed 320-byte
//! little-endian layout with a magic header, a version, a CRC-32 trailer
//! and a consistency check between the key and its public id — accidental
//! corruption is detected, hand edits of the key material are rejected.
//!
//! Secret hygiene: this module has no logging, and `describe` (the only
//! rendering helper) never outputs the auth key, its hash, the salt or
//! the session id. The auth key *id* is printed in hex — it is public by
//! construction: it travels in the clear in the header of every
//! encrypted frame. The `format` method makes the redacted form reachable
//! through `{f}`; note that Zig's default struct printing (`{}`/`{any}`,
//! which does NOT consult `format`) would dump raw fields — never print
//! a `State` that way.

const std = @import("std");
const crypto = @import("../crypto/mod.zig");
const mtproto = @import("../mtproto/mod.zig");
const dc = @import("../dc/mod.zig");
const rpc = @import("../rpc/mod.zig");

const AuthKey = mtproto.AuthKey;

/// How far a persisted msg_id may sit in the future of `adoptOn`'s clock
/// before the continuation is abandoned: matches the receive window the
/// message layer allows server ids (30 s future).
pub const clock_regress_grace_seconds: u64 = 30;

pub const DeserializeError = error{
    /// Not a tdzig session (wrong magic).
    BadMagic,
    /// Written by a different format version (or carrying unknown flag
    /// bits with newer semantics).
    UnsupportedVersion,
    /// Not `serialized_size` bytes long.
    InvalidLength,
    /// The CRC-32 trailer does not cover the payload.
    ChecksumMismatch,
    /// The stored auth key and its stored id disagree (the id is SHA1 of
    /// the key by construction — this catches edited key material with a
    /// recomputed checksum).
    KeyIdMismatch,
    /// The DC number is not a plausible data-center id.
    InvalidDc,
    /// A msg_id counter that could never have been generated.
    InvalidState,
};

pub const ApplyError = dc.Error || error{
    /// The state was captured on the other network (production vs test);
    /// authorization keys are network-specific, so this fails closed.
    EnvironmentMismatch,
};

/// Fixed on-wire (on-disk) size of one serialized state.
pub const serialized_size: usize = 320;

/// File magic: "tdzig session".
pub const magic = [4]u8{ 'T', 'D', 'Z', 'S' };

/// Bumped whenever the layout below changes in any way.
pub const format_version: u16 = 2;

/// All flag bits this version assigns. Unknown bits fail deserialization
/// (`UnsupportedVersion`): their semantics are not known here.
pub const known_flags: u16 = 0b1;

/// Layout (all integers little-endian):
///
///   [  0..  4)  magic "TDZS"
///   [  4..  6)  format version (u16)
///   [  6..  8)  flags (u16): bit0 = test network
///   [  8.. 12)  dc (i32)
///   [ 12..268)  auth_key.key          (secret)
///   [268..276)  auth_key.id           (public)
///   [276..284)  auth_key.aux_hash     (secret-adjacent)
///   [284..292)  auth_key.server_salt  (secret-adjacent, capture-time)
///   [292..300)  session_id   (i64, 0 = none captured)
///   [300..308)  last_msg_id  (i64, 0 = none generated)
///   [308..312)  content_count (u32, outgoing)
///   [312..316)  remote_content_count (u32, incoming seq counter)
///   [316..320)  CRC-32 (ISO-HDLC) over bytes [0..316)
pub const State = struct {
    /// Which network the key belongs to; must match the `DataCenters` the
    /// state is restored into.
    environment: dc.Environment,
    /// The data center this key authorizes and the client was working on.
    dc: i32,
    /// Secret. Never logged, never formatted.
    auth_key: AuthKey,
    /// Wire session id of the captured connection (0 = none: a fresh
    /// identity is drawn on the next connect).
    session_id: i64,
    /// Outgoing msg_id high-water mark and content-message counter at
    /// capture time; restored together with `session_id` by `adoptOn`.
    last_msg_id: i64,
    content_count: u32,
    /// The incoming seq counter at capture time. A server that still
    /// remembers the session continues its outgoing seq_no from here —
    /// without it, a restored client would expect the first incoming
    /// message to carry seq 0/1 and reject the server's continuation
    /// (verified against a production DC).
    remote_content_count: u32,

    /// Captures the state of a live client: finds the stored key whose id
    /// matches the client's session (so the DC follows the key, not the
    /// manager's `current` pointer), and writes the **current** server
    /// salt of the live session over the handshake-time one. Returns null
    /// when no stored key matches (the client was not built through this
    /// manager — or the key was removed).
    pub fn capture(dcs: *const dc.DataCenters, client: *const rpc.Client) ?State {
        const entry = dcs.authKeyForId(&client.session.auth_key_id) orelse return null;
        var key = entry.key;
        std.mem.writeInt(i64, &key.server_salt, client.session.server_salt, .little);
        return .{
            .environment = dcs.list.environment,
            .dc = entry.dc,
            .auth_key = key,
            .session_id = client.session.session_id,
            .last_msg_id = client.session.last_msg_id,
            .content_count = client.session.content_count,
            .remote_content_count = client.session.remote_content_count,
        };
    }

    /// Captures only the durable half: the current DC's stored
    /// (**permanent**) authorization key, with no wire-session identity
    /// (`session_id = 0` makes `adoptOn` a no-op). This is the PFS
    /// capture: the live session is keyed by a temporary key which is
    /// RAM-only by spec, so neither it nor the session it opened may be
    /// persisted — a restored client gets the permanent key and binds a
    /// fresh temp key on connect. The stored salt may be stale; the
    /// server corrects it via `bad_server_salt` as usual.
    pub fn capturePermanent(dcs: *const dc.DataCenters) ?State {
        const dc_id = dcs.current;
        const key = dcs.authKey(dc_id) orelse return null;
        return .{
            .environment = dcs.list.environment,
            .dc = dc_id,
            .auth_key = key.*,
            .session_id = 0,
            .last_msg_id = 0,
            .content_count = 0,
            .remote_content_count = 0,
        };
    }

    /// Restores the durable half into `dcs`: the per-DC authorization key
    /// (with the capture-time salt) and the current DC. After this,
    /// `DataCenters.connect` skips the handshake for that DC — the whole
    /// point of a persisted session.
    pub fn applyTo(self: State, dcs: *dc.DataCenters) ApplyError!void {
        if (dcs.list.environment != self.environment) return error.EnvironmentMismatch;
        try dcs.setAuthKey(self.dc, self.auth_key);
        try dcs.setCurrent(self.dc);
    }

    /// Restores the per-connection half onto a **freshly connected**
    /// client: the captured session id plus the outgoing msg_id/seq
    /// counters and the incoming seq counter, so both sides see one
    /// continuing session. `adoptOn`
    /// expects the client not to have sent anything yet (asserted on the
    /// pending table).
    ///
    /// If the captured msg_id sits further in the future than
    /// `clock_regress_grace_seconds` (the clock regressed across the
    /// restart), continuing from it could only produce ids the server
    /// rejects as too new — a fresh identity is kept instead. Prefer to
    /// skip `adoptOn` entirely when compatibility with conservative
    /// per-connection server accounting matters more than continuity:
    /// `applyTo` + a plain connect is always valid.
    pub fn adoptOn(self: State, client: *rpc.Client, now_seconds: u64) void {
        if (self.session_id == 0) return;
        std.debug.assert(client.pending.items.len == 0);
        const horizon: u64 = (now_seconds + clock_regress_grace_seconds) << 32;
        const last: u64 = @bitCast(self.last_msg_id);
        if (last > horizon) return; // clock regressed: keep the fresh identity
        client.session.session_id = self.session_id;
        client.session.last_msg_id = self.last_msg_id;
        client.session.content_count = self.content_count;
        client.session.remote_content_count = self.remote_content_count;
    }

    // -------------------------------------------------------- serialization

    /// Writes the fixed-size binary form into `dst`.
    pub fn serialize(self: State, dst: *[serialized_size]u8) void {
        @memcpy(dst[0..4], &magic);
        std.mem.writeInt(u16, dst[4..6], format_version, .little);
        const flags: u16 = if (self.environment == .@"test") 1 else 0;
        std.mem.writeInt(u16, dst[6..8], flags, .little);
        std.mem.writeInt(i32, dst[8..12], self.dc, .little);
        @memcpy(dst[12..268], &self.auth_key.key);
        @memcpy(dst[268..276], &self.auth_key.id);
        @memcpy(dst[276..284], &self.auth_key.aux_hash);
        @memcpy(dst[284..292], &self.auth_key.server_salt);
        std.mem.writeInt(i64, dst[292..300], self.session_id, .little);
        std.mem.writeInt(i64, dst[300..308], self.last_msg_id, .little);
        std.mem.writeInt(u32, dst[308..312], self.content_count, .little);
        std.mem.writeInt(u32, dst[312..316], self.remote_content_count, .little);
        std.mem.writeInt(u32, dst[316..320], std.hash.Crc32.hash(dst[0..316]), .little);
    }

    /// Parses and validates the binary form produced by `serialize`.
    pub fn deserialize(bytes: []const u8) DeserializeError!State {
        // The magic identifies the format before any size or content
        // rule can speak: a file that is not a session at all must be
        // reported as BadMagic, whatever its length.
        if (bytes.len < magic.len or !std.mem.eql(u8, bytes[0..magic.len], &magic))
            return error.BadMagic;
        if (bytes.len != serialized_size) return error.InvalidLength;
        if (std.hash.Crc32.hash(bytes[0..316]) != std.mem.readInt(u32, bytes[316..320], .little))
            return error.ChecksumMismatch;
        if (std.mem.readInt(u16, bytes[4..6], .little) != format_version)
            return error.UnsupportedVersion;
        const flags = std.mem.readInt(u16, bytes[6..8], .little);
        if (flags & ~known_flags != 0) return error.UnsupportedVersion;

        var st: State = undefined;
        st.environment = if (flags & 1 != 0) .@"test" else .production;
        st.dc = std.mem.readInt(i32, bytes[8..12], .little);
        @memcpy(&st.auth_key.key, bytes[12..268]);
        @memcpy(&st.auth_key.id, bytes[268..276]);
        @memcpy(&st.auth_key.aux_hash, bytes[276..284]);
        @memcpy(&st.auth_key.server_salt, bytes[284..292]);
        st.session_id = std.mem.readInt(i64, bytes[292..300], .little);
        st.last_msg_id = std.mem.readInt(i64, bytes[300..308], .little);
        st.content_count = std.mem.readInt(u32, bytes[308..312], .little);
        st.remote_content_count = std.mem.readInt(u32, bytes[312..316], .little);

        if (st.dc <= 0) return error.InvalidDc;
        // Generated msg ids are positive and divisible by four; anything
        // else could not have come from `Session.nextMsgId`.
        if (st.last_msg_id < 0 or (st.last_msg_id != 0 and @rem(st.last_msg_id, 4) != 0))
            return error.InvalidState;
        if (!std.mem.eql(u8, &st.auth_key.id, &crypto.authKeyId(&st.auth_key.key)))
            return error.KeyIdMismatch;
        return st;
    }

    // ------------------------------------------------------------ rendering

    /// Writes a strictly non-secret summary. The auth key, its hash, the
    /// salt and the session id are rendered as `<redacted>`; the key id
    /// is shown because it is public (cleartext in every frame header).
    pub fn describe(self: State, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print(
            "session.State{{environment={s}, dc={d}, auth_key_id={s}, auth_key=<redacted>, salt=<redacted>, session_id=<redacted>, last_msg_id={d}, content_count={d}, remote_content_count={d}}}",
            .{
                @tagName(self.environment),
                self.dc,
                &hexId(&self.auth_key.id),
                self.last_msg_id,
                self.content_count,
                self.remote_content_count,
            },
        );
    }

    /// Makes the redacted `describe` form reachable through the `{f}`
    /// format specifier. (`{}` / `{any}` bypass this and would dump raw
    /// fields — they must not be used on a `State`.)
    pub fn format(self: State, w: *std.Io.Writer) std.Io.Writer.Error!void {
        return self.describe(w);
    }
};

fn hexId(id: *const [8]u8) [16]u8 {
    const hex = "0123456789abcdef";
    var buf: [16]u8 = undefined;
    for (id, 0..) |b, i| {
        buf[i * 2] = hex[b >> 4];
        buf[i * 2 + 1] = hex[b & 15];
    }
    return buf;
}

// ---------------------------------------------------------------- tests

const test_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 97 +% 5);
    break :blk k;
};

fn sampleState() State {
    var key = AuthKey{
        .key = test_key,
        .id = crypto.authKeyId(&test_key),
        .aux_hash = undefined,
        .server_salt = undefined,
    };
    for (&key.aux_hash, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    for (&key.server_salt, 0..) |*b, i| b.* = @truncate(i *% 13 +% 3);
    return .{
        .environment = .production,
        .dc = 4,
        .auth_key = key,
        .session_id = 0x0123_4567_89ab_cdef,
        .last_msg_id = (@as(i64, 1_700_000_000) << 32) | 32,
        .content_count = 11,
        .remote_content_count = 6,
    };
}

test "serialize/deserialize roundtrip is byte-exact and deterministic" {
    const st = sampleState();
    var a: [serialized_size]u8 = undefined;
    var b: [serialized_size]u8 = undefined;
    st.serialize(&a);
    st.serialize(&b);
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expectEqual(@as(usize, 320), a.len);

    const back = try State.deserialize(&a);
    try std.testing.expectEqual(@as(dc.Environment, .production), back.environment);
    try std.testing.expectEqual(@as(i32, 4), back.dc);
    try std.testing.expectEqualSlices(u8, &st.auth_key.key, &back.auth_key.key);
    try std.testing.expectEqualSlices(u8, &st.auth_key.id, &back.auth_key.id);
    try std.testing.expectEqualSlices(u8, &st.auth_key.aux_hash, &back.auth_key.aux_hash);
    try std.testing.expectEqualSlices(u8, &st.auth_key.server_salt, &back.auth_key.server_salt);
    try std.testing.expectEqual(st.session_id, back.session_id);
    try std.testing.expectEqual(st.last_msg_id, back.last_msg_id);
    try std.testing.expectEqual(st.content_count, back.content_count);
    try std.testing.expectEqual(st.remote_content_count, back.remote_content_count);

    // The test-network flag roundtrips too.
    var tst = sampleState();
    tst.environment = .@"test";
    tst.dc = 2;
    var buf: [serialized_size]u8 = undefined;
    tst.serialize(&buf);
    const back_t = try State.deserialize(&buf);
    try std.testing.expectEqual(@as(dc.Environment, .@"test"), back_t.environment);
}

test "deserialize rejects wrong-size, wrong-magic and corrupted input" {
    const st = sampleState();
    var buf: [serialized_size]u8 = undefined;
    st.serialize(&buf);

    try std.testing.expectError(error.InvalidLength, State.deserialize(buf[0..319]));
    buf[0] = 'X';
    try std.testing.expectError(error.BadMagic, State.deserialize(&buf));

    st.serialize(&buf);
    buf[100] ^= 0xff;
    try std.testing.expectError(error.ChecksumMismatch, State.deserialize(&buf));
}

/// Re-CRCs a tampered buffer so the semantic checks fire, not the
/// checksum one.
fn reseal(buf: *[serialized_size]u8) void {
    std.mem.writeInt(u32, buf[316..320], std.hash.Crc32.hash(buf[0..316]), .little);
}

test "deserialize rejects version, flags, dc, msg-id and key-id violations" {
    const st = sampleState();
    var buf: [serialized_size]u8 = undefined;

    // Newer format version.
    st.serialize(&buf);
    std.mem.writeInt(u16, buf[4..6], format_version + 1, .little);
    reseal(&buf);
    try std.testing.expectError(error.UnsupportedVersion, State.deserialize(&buf));

    // Unknown flag bit.
    st.serialize(&buf);
    std.mem.writeInt(u16, buf[6..8], 0b10, .little);
    reseal(&buf);
    try std.testing.expectError(error.UnsupportedVersion, State.deserialize(&buf));

    // Implausible DC.
    st.serialize(&buf);
    std.mem.writeInt(i32, buf[8..12], 0, .little);
    reseal(&buf);
    try std.testing.expectError(error.InvalidDc, State.deserialize(&buf));

    // A msg_id no generator could have produced.
    st.serialize(&buf);
    std.mem.writeInt(i64, buf[300..308], 3, .little);
    reseal(&buf);
    try std.testing.expectError(error.InvalidState, State.deserialize(&buf));

    // Edited key material with the checksum fixed: the id/key pair no
    // longer checks out.
    st.serialize(&buf);
    buf[12] ^= 0xff;
    reseal(&buf);
    try std.testing.expectError(error.KeyIdMismatch, State.deserialize(&buf));
}

test "describe and format never contain secret material" {
    const st = sampleState();

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try st.describe(&w);
    const out = w.buffered();

    // Public fields are present...
    try std.testing.expect(std.mem.indexOf(u8, out, "production") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "dc=4") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, &hexId(&st.auth_key.id)) != null);
    // ...and nothing secret is: no key bytes, no hash, no salt, no
    // session id, with explicit redaction markers.
    try std.testing.expect(std.mem.indexOf(u8, out, "<redacted>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, st.auth_key.key[0..8]) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, &st.auth_key.aux_hash) == null);
    try std.testing.expect(std.mem.indexOf(u8, out, &st.auth_key.server_salt) == null);

    // The `{f}` formatting path goes through the same redaction.
    var fbuf: [512]u8 = undefined;
    var fw: std.Io.Writer = .fixed(&fbuf);
    try fw.print("{f}", .{st});
    try std.testing.expectEqualSlices(u8, out, fw.buffered());
}

// capture/apply/adopt need a client; a stub transport is enough (the
// session layer is transport-independent).
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

var stub_transport = StubTransport{};
var test_prng = std.Random.DefaultPrng.init(0);

test "capture finds the key by session and refreshes the salt" {
    var dcs = try dc.DataCenters.init(std.testing.allocator, .production);
    defer dcs.deinit();
    var client = try rpc.Client.init(
        std.testing.allocator,
        stub_transport.transport(),
        &test_key,
        0x11,
        test_prng.random(),
        .{},
    );
    defer client.deinit();
    // The manager's connect path would have stored the key; simulate it.
    try dcs.setAuthKey(2, .{
        .key = test_key,
        .id = crypto.authKeyId(&test_key),
        .aux_hash = undefined,
        .server_salt = undefined,
    });
    dcs.current = 2;

    // A salt correction arrived mid-connection (bad_server_salt).
    client.session.setServerSalt(0xfeed_face);

    const st = State.capture(&dcs, &client) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i32, 2), st.dc);
    try std.testing.expectEqual(@as(dc.Environment, .production), st.environment);
    try std.testing.expectEqual(client.session.session_id, st.session_id);
    try std.testing.expectEqual(
        @as(i64, 0xfeed_face),
        std.mem.readInt(i64, &st.auth_key.server_salt, .little),
    );

    // A client whose key is not stored captures nothing.
    var other: [crypto.auth_key_size]u8 = test_key;
    other[0] ^= 0xff;
    var other_client = try rpc.Client.init(
        std.testing.allocator,
        stub_transport.transport(),
        &other,
        1,
        test_prng.random(),
        .{},
    );
    defer other_client.deinit();
    try std.testing.expect(State.capture(&dcs, &other_client) == null);
}

test "applyTo restores key, current DC and rejects environment mismatch" {
    const st = sampleState();
    var dcs = try dc.DataCenters.init(std.testing.allocator, .production);
    defer dcs.deinit();
    try st.applyTo(&dcs);
    try std.testing.expectEqual(@as(i32, 4), dcs.current);
    try std.testing.expectEqualSlices(u8, &st.auth_key.key, &dcs.authKey(4).?.key);
    try std.testing.expectEqualSlices(u8, &st.auth_key.server_salt, &dcs.authKey(4).?.server_salt);

    var tst_dcs = try dc.DataCenters.init(std.testing.allocator, .@"test");
    defer tst_dcs.deinit();
    try std.testing.expectError(error.EnvironmentMismatch, st.applyTo(&tst_dcs));

    // A DC the list knows nothing about (config not yet merged).
    var empty_list = try dc.DataCenters.init(std.testing.allocator, .production);
    empty_list.list.deinit();
    empty_list.list = dc.DcList.initEmpty(std.testing.allocator, .production);
    defer empty_list.deinit();
    try std.testing.expectError(error.UnknownDc, st.applyTo(&empty_list));
}

test "adoptOn continues the session unless the clock regressed" {
    const now: u64 = 1_700_000_000;
    var client = try rpc.Client.init(
        std.testing.allocator,
        stub_transport.transport(),
        &test_key,
        1,
        test_prng.random(),
        .{},
    );
    defer client.deinit();

    var st = sampleState();
    st.session_id = 0xabc;
    st.last_msg_id = @as(i64, now) << 32;
    st.content_count = 5;
    st.remote_content_count = 2;
    st.adoptOn(&client, now);
    try std.testing.expectEqual(@as(i64, 0xabc), client.session.session_id);
    try std.testing.expectEqual(st.last_msg_id, client.session.last_msg_id);
    try std.testing.expectEqual(@as(u32, 5), client.session.content_count);
    // The incoming counter continues from the captured value, so the
    // server's next content message (seq 2·2+1) validates.
    try std.testing.expectEqual(@as(u32, 2), client.session.remote_content_count);
    // The next id continues above the restored high-water mark.
    const next = client.session.nextMsgId(now);
    try std.testing.expectEqual(st.last_msg_id + 4, next);

    // Captured far in the future (clock regressed): the fresh identity is
    // kept (a freshly drawn nonzero session id, not the captured one) and
    // the counters stay untouched.
    var future_client = try rpc.Client.init(
        std.testing.allocator,
        stub_transport.transport(),
        &test_key,
        1,
        test_prng.random(),
        .{},
    );
    defer future_client.deinit();
    var future = sampleState();
    future.session_id = 0xdef;
    future.last_msg_id = @as(i64, @intCast((now + 3600) << 32));
    future.adoptOn(&future_client, now);
    try std.testing.expect(future_client.session.session_id != 0xdef);
    try std.testing.expect(future_client.session.session_id != 0);
    try std.testing.expectEqual(@as(i64, 0), future_client.session.last_msg_id);

    // session_id 0 means "nothing captured": no adoption either.
    var none = sampleState();
    none.session_id = 0;
    var none_client = try rpc.Client.init(
        std.testing.allocator,
        stub_transport.transport(),
        &test_key,
        1,
        test_prng.random(),
        .{},
    );
    defer none_client.deinit();
    none.adoptOn(&none_client, now);
    try std.testing.expect(none_client.session.session_id != 0);
    try std.testing.expectEqual(@as(i32, 1), none_client.session.nextSeqNo(true));
}
