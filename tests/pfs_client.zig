//! Client-level PFS integration test: the full
//! https://core.telegram.org/api/pfs choreography against one in-process
//! peer that implements the *server* side of every step — no network, no
//! protocol shortcuts:
//!
//!   1. permanent-key handshake   (req_pq → dh_gen_ok, test RSA key)
//!   2. temporary-key handshake   (p_q_inner_data_temp_dc)
//!   3. `auth.bindTempAuthKey`    (arrives encrypted with the *temp* key;
//!      the peer opens the v1 `encrypted_message` with the *permanent*
//!      key through `td.mtproto.pfs.openBindBlob` and validates every
//!      binding field before answering boolTrue)
//!   4. typed invoke over the bound temp key (init-wrapped first query)
//!
//! Assertions cover the wire the client produced (blob fields, msg_id
//! match, session pin, expiry anchored to the server clock), that
//! traffic really flows under the temp key, and that persistence under
//! PFS stores the permanent key only (temp keys are RAM-only by spec).

const std = @import("std");
const td = @import("td");

const mtproto = td.mtproto;
const message = mtproto.message;
const crypto = td.crypto;
const tl = td.tl;

const Reader = tl.Reader;
const Writer = tl.Writer;

/// dh_prime from the official worked example
/// (https://core.telegram.org/mtproto/samples-auth_key).
const dh_prime_hex =
    "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F" ++
    "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720" ++
    "FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477F" ++
    "E96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A6958" ++
    "11051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D" ++
    "5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EB" ++
    "EA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE" ++
    "2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B";

// p, q from the official example (pq = p*q).
const example_p: u64 = 1786331737;
const example_q: u64 = 1880278339;

const temp_expires_in: i32 = 3600;
const link_salt: i64 = 0x51a1;

const get_nearest_dc_id: u32 = 0x1fb33026;
const nearest_dc_id: u32 = 0x8e1a1775;
const invoke_with_layer_id: u32 = 0xda9b0d0d;
const bind_temp_auth_key_id: u32 = 0xcdd42a05;
const rpc_result_id: u32 = 0xf35c6d01;
const bool_true: u32 = 0x997275b5;

const test_rsa_key = mtproto.rsa.PublicKey{ .n = mtproto.testkeys.modulus_be };

/// The embedded peer: a handshake server (both handshakes) and the
/// encrypted-session server (bind + queries) behind one transport.
const Peer = struct {
    allocator: std.mem.Allocator,
    random: std.Random,
    prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0x9eef),
    /// Set by `connectT`; the server clock source.
    io: std.Io = undefined,

    // ----- handshake-server state (fresh per plain connection) --------
    hs_server_nonce: [16]u8 = undefined,
    hs_new_nonce: [32]u8 = undefined,
    hs_a: [256]u8 = undefined,
    /// The server_time this handshake reported; anchors expires_at.
    hs_server_time: i32 = 0,

    // ----- learned keys (derived from the handshakes) ------------------
    perm_key: [256]u8 = undefined,
    perm_set: bool = false,
    temp_key: [256]u8 = undefined,
    temp_set: bool = false,
    /// expires_at the server enforces for the temp key.
    temp_expires_at: i32 = 0,

    // ----- encrypted-session state -------------------------------------
    bound: bool = false,
    bind_seen: usize = 0,
    queries_answered: usize = 0,
    wrapped_seen: usize = 0,
    session_id: i64 = 0,
    content: u32 = 0,
    next_low: u32 = 1,

    connected: bool = false,
    outbox: std.ArrayList([]u8) = .empty,

    fn init(allocator: std.mem.Allocator, random: std.Random) Peer {
        return .{ .allocator = allocator, .random = random };
    }

    fn deinit(self: *Peer) void {
        self.clearOutbox();
        self.outbox.deinit(self.allocator);
    }

    fn clearOutbox(self: *Peer) void {
        for (self.outbox.items) |f| self.allocator.free(f);
        self.outbox.clearRetainingCapacity();
    }

    fn transport(self: *Peer) td.transport.Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn keyId(key: *const [256]u8) [8]u8 {
        return crypto.authKeyId(key);
    }

    fn unixNow(self: *const Peer) i32 {
        return @intCast(@divTrunc(std.Io.Timestamp.now(self.io, .real).nanoseconds, std.time.ns_per_s));
    }

    // ---------------------------------------------- server: handshake --

    fn onPlainFrame(self: *Peer, frame: []const u8) !void {
        if (frame.len < 20) return error.BadFrame;
        const length = std.mem.readInt(u32, frame[16..20], .little);
        if (20 + @as(usize, length) > frame.len) return error.BadFrame;
        const body = frame[20 .. 20 + length];

        var r = Reader.init(body);
        const ctor = try r.readConstructorId();
        switch (ctor) {
            mtproto.schema.req_pq_id, mtproto.schema.req_pq_multi_id => try self.onReqPq(body),
            mtproto.schema.req_DH_params_id => try self.onReqDhParams(body),
            mtproto.schema.set_client_DH_params_id => try self.onSetClientDhParams(body),
            else => return error.BadFrame,
        }
    }

    fn wrapPlain(self: *Peer, body: []const u8, msg_id: i64) !void {
        const total = body.len + (16 - body.len % 16) % 16;
        const frame = try self.allocator.alloc(u8, 20 + total);
        std.mem.writeInt(u64, frame[0..8], 0, .little);
        std.mem.writeInt(i64, frame[8..16], msg_id, .little);
        std.mem.writeInt(u32, frame[16..20], @intCast(body.len), .little);
        @memcpy(frame[20..][0..body.len], body);
        self.random.bytes(frame[20 + body.len ..]);
        try self.outbox.append(self.allocator, frame);
    }

    fn onReqPq(self: *Peer, body: []const u8) !void {
        var r = Reader.init(body);
        _ = try r.readConstructorId();
        const client_nonce = try r.readInt128();

        for (&self.hs_server_nonce, 0..) |*b, i| b.* = @truncate(0x60 +% i);
        var prime: [256]u8 = undefined;
        _ = std.fmt.hexToBytes(&prime, dh_prime_hex) catch unreachable;
        mtproto.bigint.randomDhScalar(self.random, &self.hs_a);

        var w = Writer.init(self.allocator);
        defer w.deinit();
        try w.writeConstructorId(mtproto.schema.resPQ_id);
        try w.writeInt128(client_nonce);
        try w.writeInt128(self.hs_server_nonce);
        var pq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &pq_bytes, example_p * example_q, .big);
        try w.writeBytes(&pq_bytes);
        try w.writeVectorOfLong(&.{@bitCast(@byteSwap(test_rsa_key.fingerprint()))});
        try self.wrapPlain(w.items(), 0x7000000000000001);
    }

    fn onReqDhParams(self: *Peer, body: []const u8) !void {
        var r = Reader.init(body);
        _ = try r.readConstructorId();
        const nonce = try r.readInt128();
        const server_nonce = try r.readInt128();
        _ = try r.readString(); // p
        _ = try r.readString(); // q
        _ = try r.readLong(); // fingerprint
        const encrypted_data = try r.readString();
        if (!std.mem.eql(u8, &server_nonce, &self.hs_server_nonce)) return error.NoncesDiffer;

        var plain: [256]u8 = undefined;
        var enc: [256]u8 = undefined;
        @memcpy(&enc, encrypted_data);
        try mtproto.rsa.decryptForTests(self.allocator, &mtproto.testkeys.modulus_be, &mtproto.testkeys.d_be, &enc, &plain);
        var buf: [192]u8 = undefined;
        try mtproto.rsa.unwrapRsaPadForTests(&plain, &buf);
        const data: []const u8 = &buf;

        var ir = Reader.init(data);
        const inner_ctor = try ir.readConstructorId();
        if (inner_ctor != mtproto.schema.p_q_inner_data_dc_id and
            inner_ctor != mtproto.schema.p_q_inner_data_temp_dc_id) return error.BadFrame;
        _ = try ir.readString(); // pq
        _ = try ir.readString(); // p
        _ = try ir.readString(); // q
        _ = try ir.readInt128(); // nonce
        _ = try ir.readInt128(); // server_nonce
        self.hs_new_nonce = try ir.readInt256();
        _ = try ir.readInt(); // dc
        self.hs_server_time = self.unixNow();
        if (inner_ctor == mtproto.schema.p_q_inner_data_temp_dc_id) {
            // PFS: the key dies at server_time + expires_in.
            self.temp_expires_at = self.hs_server_time +| (try ir.readInt());
        }

        var prime: [256]u8 = undefined;
        _ = std.fmt.hexToBytes(&prime, dh_prime_hex) catch unreachable;
        var g_a: [256]u8 = undefined;
        var g_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &g_bytes, 3, .big);
        try mtproto.bigint.powmod(self.allocator, g_bytes[3..4], &self.hs_a, &prime, &g_a);

        var w = Writer.init(self.allocator);
        defer w.deinit();
        try w.writeConstructorId(mtproto.schema.server_DH_inner_data_id);
        try w.writeInt128(nonce);
        try w.writeInt128(self.hs_server_nonce);
        try w.writeInt(3); // g
        try w.writeBytes(&prime);
        try w.writeBytes(&g_a);
        try w.writeInt(self.hs_server_time);
        const server_inner = w.toOwnedSlice() catch return error.OutOfMemory;

        const aes = mtproto.inner.tmpAesParams(&self.hs_new_nonce, &self.hs_server_nonce);
        const sealed = try mtproto.inner.sealInner(self.allocator, aes, server_inner, self.random);
        defer self.allocator.free(sealed);
        self.allocator.free(server_inner);

        var w2 = Writer.init(self.allocator);
        defer w2.deinit();
        try w2.writeConstructorId(mtproto.schema.server_DH_params_ok_id);
        try w2.writeInt128(nonce);
        try w2.writeInt128(self.hs_server_nonce);
        try w2.writeBytes(sealed);
        try self.wrapPlain(w2.items(), 0x7000000000000005);
    }

    fn onSetClientDhParams(self: *Peer, body: []const u8) !void {
        var r = Reader.init(body);
        _ = try r.readConstructorId();
        const nonce = try r.readInt128();
        const server_nonce = try r.readInt128();
        const encrypted_data = try r.readString();
        if (!std.mem.eql(u8, &server_nonce, &self.hs_server_nonce)) return error.NoncesDiffer;

        const aes = mtproto.inner.tmpAesParams(&self.hs_new_nonce, &self.hs_server_nonce);
        const buf = try self.allocator.dupe(u8, encrypted_data);
        defer self.allocator.free(buf);
        const opened = try mtproto.inner.openInnerDecrypt(aes, buf);
        var ir = Reader.init(opened[20..]);
        if ((try ir.readConstructorId()) != mtproto.schema.client_DH_inner_data_id) return error.BadFrame;
        _ = try ir.readInt128();
        _ = try ir.readInt128();
        _ = try ir.readLong(); // retry_id
        const g_b = try ir.readString();
        const consumed = (opened.len - 20) - ir.remaining();
        try mtproto.inner.verifyInnerHash(opened, consumed);

        var prime: [256]u8 = undefined;
        _ = std.fmt.hexToBytes(&prime, dh_prime_hex) catch unreachable;
        var auth_key: [256]u8 = undefined;
        try mtproto.bigint.powmod(self.allocator, g_b, &self.hs_a, &prime, &auth_key);

        const aux = mtproto.inner.authKeyAuxHash(&auth_key);
        const hash1 = mtproto.inner.newNonceHash(&self.hs_new_nonce, 1, &aux);

        var w = Writer.init(self.allocator);
        defer w.deinit();
        try w.writeConstructorId(mtproto.schema.dh_gen_ok_id);
        try w.writeInt128(nonce);
        try w.writeInt128(self.hs_server_nonce);
        try w.writeInt128(hash1);
        try self.wrapPlain(w.items(), 0x7000000000000009);

        // First handshake = permanent key, second = temporary (PFS) key,
        // in the order Client.connect runs them.
        if (!self.perm_set) {
            self.perm_key = auth_key;
            self.perm_set = true;
        } else {
            self.temp_key = auth_key;
            self.temp_set = true;
        }
    }

    // ------------------------------------------ server: encrypted frames

    fn nextMsgId(self: *Peer) i64 {
        const id = (@as(i64, self.unixNow()) << 32) | self.next_low;
        self.next_low +%= 4;
        return id;
    }

    fn encryptReply(self: *Peer, body: []const u8, content_related: bool) ![]u8 {
        const frame = try self.allocator.alloc(u8, message.frameLength(body.len));
        errdefer self.allocator.free(frame);
        const seq: i32 = @intCast(2 * self.content + @as(u32, if (content_related) 1 else 0));
        if (content_related) self.content += 1;
        message.writeEncrypted(&self.temp_key, .server_to_client, .{
            .salt = link_salt,
            .session_id = self.session_id,
            .msg_id = self.nextMsgId(),
            .seq_no = seq,
            .body = body,
        }, self.prng.random(), frame) catch return error.BadFrame;
        return frame;
    }

    fn queue(self: *Peer, frame: []u8) void {
        self.outbox.append(self.allocator, frame) catch self.allocator.free(frame);
    }

    fn serveEncrypted(self: *Peer, payload: []const u8) void {
        var buf = self.allocator.dupe(u8, payload) catch return;
        defer self.allocator.free(buf);

        // Select the key by the cleartext auth_key_id, exactly like a
        // real server looks the key up.
        const under_temp = self.temp_set and std.mem.eql(u8, buf[0..8], &keyId(&self.temp_key));
        var key: *const [256]u8 = &self.perm_key;
        if (under_temp) key = &self.temp_key else if (!self.perm_set) return;

        const dec = message.readEncrypted(key, .client_to_server, 0, buf) catch return;
        if (dec.session_id != self.session_id) {
            self.session_id = dec.session_id;
            self.content = 0;
        }
        if (dec.body.len < 4) return;
        const ctor = std.mem.readInt(u32, dec.body[0..4], .little);

        if (ctor == bind_temp_auth_key_id) {
            // The binding must arrive encrypted with the temp key it
            // names — this is what makes the bind unforgeable.
            if (!under_temp) return;
            self.onBind(&dec) catch return;
            return;
        }
        if (ctor == message.msgs_ack_id) return; // drained silently

        // Any real query: only legal once the temp key is bound.
        if (!self.bound or !under_temp) return;
        if (ctor == invoke_with_layer_id) {
            // Result-transparent wrapper: match the trailing query id.
            if (std.mem.readInt(u32, dec.body[dec.body.len - 4 ..][0..4], .little) != get_nearest_dc_id) return;
            self.wrapped_seen += 1;
        } else if (ctor != get_nearest_dc_id) {
            return;
        }
        self.queries_answered += 1;
        var w = Writer.init(self.allocator);
        defer w.deinit();
        w.writeConstructorId(rpc_result_id) catch return;
        w.writeLong(dec.msg_id) catch return;
        w.writeConstructorId(nearest_dc_id) catch return;
        w.writeString("US") catch return;
        w.writeInt(2) catch return; // this_dc
        w.writeInt(2) catch return; // nearest_dc
        const frame = self.encryptReply(w.items(), true) catch return;
        self.queue(frame);
    }

    /// Server side of auth.bindTempAuthKey: open the v1 blob with the
    /// permanent key and validate every binding field before binding.
    fn onBind(self: *Peer, dec: *const message.Decrypted) !void {
        if (!self.temp_set or !self.perm_set) return error.NoKeys;
        var r = Reader.init(dec.body);
        _ = try r.readConstructorId(); // bindTempAuthKey
        const perm_id = try r.readLong();
        const nonce = try r.readLong();
        const expires_at = try r.readInt();
        const encrypted_message = try r.readString();

        const blob = try self.allocator.dupe(u8, encrypted_message);
        defer self.allocator.free(blob);
        const opened = try mtproto.pfs.openBindBlob(@constCast(blob), &self.perm_key);

        const temp_key_id: i64 = @bitCast(keyId(&self.temp_key));
        const perm_key_id: i64 = @bitCast(keyId(&self.perm_key));
        var ok = true;
        ok = ok and opened.msg_id == dec.msg_id; // payload pins the msg_id
        ok = ok and opened.inner.nonce == nonce; // inner/outer nonce match
        ok = ok and opened.inner.temp_auth_key_id == temp_key_id;
        ok = ok and opened.inner.perm_auth_key_id == perm_key_id and perm_key_id == perm_id;
        ok = ok and opened.inner.temp_session_id == dec.session_id; // session pin
        ok = ok and opened.inner.expires_at == expires_at;
        ok = ok and expires_at == self.temp_expires_at; // anchored to server clock
        if (!ok) return error.BindingMismatch;

        self.bind_seen += 1;
        self.bound = true;

        var w = Writer.init(self.allocator);
        defer w.deinit();
        w.writeConstructorId(rpc_result_id) catch return;
        w.writeLong(dec.msg_id) catch return;
        w.writeUInt(bool_true) catch return;
        const frame = try self.encryptReply(w.items(), true);
        self.queue(frame);
    }

    // --------------------------------------------------- vtable plumbing

    fn connectT(ctx: *anyopaque, io: std.Io) td.transport.Error!void {
        const self: *Peer = @ptrCast(@alignCast(ctx));
        // Every acquisition is a fresh connection (the client connects
        // this transport three times: permanent handshake, temp
        // handshake, then the managed session); a fresh plain
        // connection starts a fresh handshake with fresh nonces.
        self.io = io;
        self.connected = true;
        self.clearOutbox();
    }

    fn closeT(ctx: *anyopaque, _: std.Io) void {
        const self: *Peer = @ptrCast(@alignCast(ctx));
        self.connected = false;
        self.clearOutbox();
    }

    fn writeT(ctx: *anyopaque, io: std.Io, payload: []const u8) td.transport.Error!void {
        _ = io;
        const self: *Peer = @ptrCast(@alignCast(ctx));
        if (!self.connected) return error.NotConnected;
        if (payload.len < 8) return error.InvalidFrame;
        const key_id = std.mem.readInt(u64, payload[0..8], .little);
        if (key_id == 0) {
            self.onPlainFrame(payload) catch return error.InvalidFrame;
        } else {
            self.serveEncrypted(payload);
        }
    }

    fn readT(ctx: *anyopaque, _: std.Io, allocator: std.mem.Allocator) td.transport.Error![]u8 {
        const self: *Peer = @ptrCast(@alignCast(ctx));
        if (!self.connected) return error.NotConnected;
        if (self.outbox.items.len == 0) return error.TimedOut;
        const frame = self.outbox.orderedRemove(0);
        defer self.allocator.free(frame);
        return allocator.dupe(u8, frame) catch return error.OutOfMemory;
    }

    fn isConnectedT(ctx: *anyopaque) bool {
        const self: *Peer = @ptrCast(@alignCast(ctx));
        return self.connected;
    }

    const vtable = td.transport.Transport.VTable{
        .connect = connectT,
        .close = closeT,
        .write = writeT,
        .read = readT,
        .isConnected = isConnectedT,
    };
};

fn peerProvider(ctx: *anyopaque) td.connman.TransportProvider {
    return .{ .ctx = ctx, .acquire = acquireT, .release = releaseT };
}

fn acquireT(ctx: *anyopaque, _: std.Io, _: td.transport.Endpoint) td.transport.Error!td.transport.Transport {
    const self: *Peer = @ptrCast(@alignCast(ctx));
    return self.transport();
}

fn releaseT(_: *anyopaque, _: std.Io, _: td.transport.Transport) void {}

test "client PFS: temp handshake, bind, traffic under the temp key, permanent-only persistence" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer_prng = std.Random.DefaultPrng.init(0xfee);
    var peer = Peer.init(std.testing.allocator, peer_prng.random());
    defer peer.deinit();

    var store = td.session.MemoryStore.init(std.testing.allocator);
    defer store.deinit();

    var client = try td.Client.init(std.testing.allocator, .{
        .session_store = store.store(),
        .app = .{ .api_id = 424242 },
        .pubkeys = &.{test_rsa_key},
        .pfs = true,
        .conn = .{
            .transport_provider = peerProvider(&peer),
            .max_connect_attempts = 2,
            .backoff_base = std.Io.Duration.fromMilliseconds(1),
            .backoff_max = std.Io.Duration.fromMilliseconds(5),
            .ping_interval = std.Io.Duration.fromSeconds(3600),
            .ping_disconnect_delay = null,
            .rpc = .{ .response_timeout = std.Io.Duration.fromSeconds(5) },
        },
    });
    defer client.deinit(io);

    try client.connect(io);

    // Both handshakes ran; the temp key is in RAM only, and the server
    // bound it after validating the v1 blob.
    try std.testing.expect(peer.perm_set and peer.temp_set);
    try std.testing.expect(!std.mem.eql(u8, &peer.perm_key, &peer.temp_key));
    try std.testing.expectEqual(@as(usize, 1), peer.bind_seen);
    try std.testing.expect(peer.bound);
    try std.testing.expect(client.pfs_temp != null);
    try std.testing.expectEqualSlices(u8, &peer.temp_key, &client.pfs_temp.?.key);

    // Traffic flows over the bound temp key; the first query of the
    // fresh session carried the initConnection wrapper.
    var resp = try client.invoke(io, td.api.help.getNearestDc{});
    defer resp.deinit();
    switch (resp.value) {
        .nearestDc => |nd| {
            try std.testing.expectEqualStrings("US", nd.country);
            try std.testing.expectEqual(@as(i32, 2), nd.this_dc);
        },
    }
    try std.testing.expectEqual(@as(usize, 1), peer.wrapped_seen);
    try std.testing.expectEqual(@as(usize, 1), peer.queries_answered);

    // Persistence kept the *permanent* key and no wire-session identity
    // (the temp key is RAM-only by spec).
    try client.saveSession(io);
    const loaded = (try store.store().loadState(io, std.testing.allocator)).?;
    try std.testing.expectEqualSlices(u8, &peer.perm_key, &loaded.auth_key.key);
    try std.testing.expectEqual(@as(i64, 0), loaded.session_id);
}
