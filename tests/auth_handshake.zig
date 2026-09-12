//! Controlled integration test for MTProto authorization-key creation.
//!
//! A deterministic in-process loopback server implements the server side of
//! the handshake (resPQ → server_DH_params_ok → dh_gen_ok) using a
//! test-only RSA keypair, the official example dh_prime and g=3. The client
//! (`td.mtproto.Handshake`) must complete the full flow in both RSA
//! modes, and both sides must derive the same auth_key.
//!
//! Additional error-path tests cover unknown fingerprints, server_DH_params
//! failure, tampered dh_gen_ok hashes and nonce mismatches.

const std = @import("std");
const td = @import("td");
const mtproto = td.mtproto;
const tl = td.tl;

const Reader = tl.Reader;
const Writer = tl.Writer;
const schema = mtproto.schema;
const testkeys = mtproto.testkeys;

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

const ServerConfig = struct {
    mode: mtproto.rsa.Mode,
    /// Deliberately wrong fingerprint to trigger UnknownFingerprint.
    wrong_fingerprint: bool = false,
    /// Reply with server_DH_params_fail instead of ok.
    dh_fail: bool = false,
    /// Tamper the new_nonce_hash1 in dh_gen_ok.
    tamper_gen_hash: bool = false,
    /// Send a mismatched nonce in resPQ.
    bad_nonce: bool = false,
};

const Server = struct {
    arena: std.mem.Allocator,
    cfg: ServerConfig,
    random: std.Random,
    key: mtproto.rsa.PublicKey,
    server_nonce: [16]u8,
    new_nonce: [32]u8 = undefined,
    a: [256]u8 = undefined,
    auth_key: ?[256]u8 = null,
    /// Set when the client used p_q_inner_data_temp_dc (PFS).
    temp_expires_in: ?i32 = null,
    /// Frames waiting for the client.
    outbox: std.ArrayList([]u8),

    fn init(arena: std.mem.Allocator, cfg: ServerConfig, random: std.Random) Server {
        var server_nonce: [16]u8 = undefined;
        for (&server_nonce, 0..) |*b, i| b.* = @truncate(0x60 + i);
        return .{
            .arena = arena,
            .cfg = cfg,
            .random = random,
            .key = .{ .n = testkeys.modulus_be },
            .server_nonce = server_nonce,
            .outbox = .empty,
        };
    }

    /// Wire form of the key fingerprint: resPQ/req_DH_params carry the
    /// SHA1 slice verbatim (not little-endian-rearranged), so the i64 the
    /// vector codec expects is the byte-reversed fingerprint value — the
    /// same encoding the production servers use.
    fn fingerprint(self: *const Server) i64 {
        if (self.cfg.wrong_fingerprint) return 0xdeadbeef;
        return @bitCast(@byteSwap(self.key.fingerprint()));
    }

    /// Handles one plain-message frame from the client.
    fn onClientFrame(self: *Server, frame: []const u8) !void {
        if (frame.len < 20) return error.BadFrame;
        const length = std.mem.readInt(u32, frame[16..20], .little);
        if (20 + @as(usize, length) > frame.len) return error.BadFrame;
        const body = frame[20 .. 20 + length];

        var r = Reader.init(body);
        const ctor = try r.readConstructorId();
        switch (ctor) {
            schema.req_pq_id, schema.req_pq_multi_id => try self.onReqPq(body),
            schema.req_DH_params_id => try self.onReqDhParams(body),
            schema.set_client_DH_params_id => try self.onSetClientDhParams(body),
            else => return error.BadFrame,
        }
    }

    fn wrap(self: *Server, body: []const u8, msg_id: i64) !void {
        const total = body.len + (16 - body.len % 16) % 16;
        const frame = try self.arena.alloc(u8, 20 + total);
        std.mem.writeInt(u64, frame[0..8], 0, .little);
        std.mem.writeInt(i64, frame[8..16], msg_id, .little);
        std.mem.writeInt(u32, frame[16..20], @intCast(body.len), .little);
        @memcpy(frame[20..][0..body.len], body);
        self.random.bytes(frame[20 + body.len ..]);
        try self.outbox.append(self.arena, frame);
    }

    fn onReqPq(self: *Server, body: []const u8) !void {
        var r = Reader.init(body);
        _ = try r.readConstructorId();
        const client_nonce = try r.readInt128();

        var w = Writer.init(self.arena);
        try w.writeConstructorId(schema.resPQ_id);
        try w.writeInt128(if (self.cfg.bad_nonce) [_]u8{0} ** 16 else client_nonce);
        try w.writeInt128(self.server_nonce);
        var pq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &pq_bytes, example_p * example_q, .big);
        try w.writeBytes(&pq_bytes);
        try w.writeVectorOfLong(&.{self.fingerprint()});
        try self.wrap(w.items(), 0x7000000000000001);
    }

    fn onReqDhParams(self: *Server, body: []const u8) !void {
        var r = Reader.init(body);
        _ = try r.readConstructorId();
        const nonce = try r.readInt128();
        const server_nonce = try r.readInt128();
        _ = try r.readString(); // p
        _ = try r.readString(); // q
        _ = try r.readLong(); // fingerprint
        const encrypted_data = try r.readString();
        if (!std.mem.eql(u8, &server_nonce, &self.server_nonce)) return error.NoncesDiffer;

        // RSA private op + layout unwrap.
        var plain: [256]u8 = undefined;
        var enc: [256]u8 = undefined;
        @memcpy(&enc, encrypted_data);
        try mtproto.rsa.decryptForTests(self.arena, &testkeys.modulus_be, &testkeys.d_be, &enc, &plain);

        var data: []const u8 = undefined;
        switch (self.cfg.mode) {
            .classic => data = mtproto.rsa.stripClassicForTests(&plain),
            .rsa_pad => {
                var buf: [192]u8 = undefined;
                try mtproto.rsa.unwrapRsaPadForTests(&plain, &buf);
                data = try self.arena.dupe(u8, &buf);
            },
        }

        var ir = Reader.init(data);
        const inner_ctor = try ir.readConstructorId();
        // Both the permanent-key and the PFS temp-key inner variants are
        // accepted (https://core.telegram.org/api/pfs); the temp one
        // carries an extra expires_in int at the end.
        if (inner_ctor != schema.p_q_inner_data_dc_id and
            inner_ctor != schema.p_q_inner_data_temp_dc_id) return error.BadFrame;
        _ = try ir.readString(); // pq
        _ = try ir.readString(); // p
        _ = try ir.readString(); // q
        _ = try ir.readInt128(); // nonce
        _ = try ir.readInt128(); // server_nonce
        self.new_nonce = try ir.readInt256();
        _ = try ir.readInt(); // dc
        if (inner_ctor == schema.p_q_inner_data_temp_dc_id) {
            self.temp_expires_in = try ir.readInt();
        }

        // Server DH: a fixed-ish random exponent, g=3, example dh_prime.
        var prime: [256]u8 = undefined;
        _ = std.fmt.hexToBytes(&prime, dh_prime_hex) catch unreachable;
        mtproto.bigint.randomDhScalar(self.random, &self.a);
        var g_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &g_bytes, 3, .big);
        var g_a: [256]u8 = undefined;
        try mtproto.bigint.powmod(self.arena, g_bytes[3..4], &self.a, &prime, &g_a);

        const server_inner = try schema.serializeAlloc(self.arena, &schema.ServerDhInnerData{
            .nonce = nonce,
            .server_nonce = self.server_nonce,
            .g = 3,
            .dh_prime = &prime,
            .g_a = &g_a,
            .server_time = 1000,
        });

        if (self.cfg.dh_fail) {
            const fail = try schema.serializeAlloc(self.arena, &struct {
                nonce: [16]u8,
                server_nonce: [16]u8,
                new_nonce_hash: [16]u8,
                pub fn serialize(self2: *const @This(), w: *Writer) td.TlError!void {
                    try w.writeConstructorId(schema.server_DH_params_fail_id);
                    try w.writeInt128(self2.nonce);
                    try w.writeInt128(self2.server_nonce);
                    try w.writeInt128(self2.new_nonce_hash);
                }
            }{ .nonce = nonce, .server_nonce = self.server_nonce, .new_nonce_hash = [_]u8{0} ** 16 });
            try self.wrap(fail, 0x7000000000000005);
            return;
        }

        const aes = mtproto.inner.tmpAesParams(&self.new_nonce, &self.server_nonce);
        const sealed = try mtproto.inner.sealInner(self.arena, aes, server_inner, self.random);

        var w = Writer.init(self.arena);
        try w.writeConstructorId(schema.server_DH_params_ok_id);
        try w.writeInt128(nonce);
        try w.writeInt128(self.server_nonce);
        try w.writeBytes(sealed);
        try self.wrap(w.items(), 0x7000000000000005);
    }

    fn onSetClientDhParams(self: *Server, body: []const u8) !void {
        var r = Reader.init(body);
        _ = try r.readConstructorId();
        const nonce = try r.readInt128();
        const server_nonce = try r.readInt128();
        const encrypted_data = try r.readString();
        if (!std.mem.eql(u8, &server_nonce, &self.server_nonce)) return error.NoncesDiffer;

        const aes = mtproto.inner.tmpAesParams(&self.new_nonce, &self.server_nonce);
        const buf = try self.arena.dupe(u8, encrypted_data);
        const opened = try mtproto.inner.openInnerDecrypt(aes, buf);
        var ir = Reader.init(opened[20..]);
        if ((try ir.readConstructorId()) != schema.client_DH_inner_data_id) return error.BadFrame;
        _ = try ir.readInt128();
        _ = try ir.readInt128();
        _ = try ir.readLong(); // retry_id
        const g_b = try ir.readString();
        const consumed = (opened.len - 20) - ir.remaining();
        try mtproto.inner.verifyInnerHash(opened, consumed);

        var prime: [256]u8 = undefined;
        _ = std.fmt.hexToBytes(&prime, dh_prime_hex) catch unreachable;
        var auth_key: [256]u8 = undefined;
        try mtproto.bigint.powmod(self.arena, g_b, &self.a, &prime, &auth_key);
        self.auth_key = auth_key;

        const aux = mtproto.inner.authKeyAuxHash(&auth_key);
        var hash1 = mtproto.inner.newNonceHash(&self.new_nonce, 1, &aux);
        if (self.cfg.tamper_gen_hash) hash1[0] ^= 0xff;

        var w = Writer.init(self.arena);
        try w.writeConstructorId(schema.dh_gen_ok_id);
        try w.writeInt128(nonce);
        try w.writeInt128(self.server_nonce);
        try w.writeInt128(hash1);
        try self.wrap(w.items(), 0x7000000000000009);
    }
};

/// In-memory transport: client sends are handled synchronously by the
/// server; receives pull from the server's outbox.
const Loopback = struct {
    server: *Server,
    fail_next_recv: bool = false,

    fn transport(self: *Loopback) mtproto.Transport {
        return .{
            .ctx = self,
            .sendFn = sendTrampoline,
            .recvFn = recvTrampoline,
        };
    }

    fn sendTrampoline(ctx: *anyopaque, frame: []const u8) mtproto.handshake.Error!void {
        const self: *Loopback = @ptrCast(@alignCast(ctx));
        self.server.onClientFrame(frame) catch return error.Transport;
    }

    fn recvTrampoline(ctx: *anyopaque, allocator: std.mem.Allocator) mtproto.handshake.Error![]u8 {
        const self: *Loopback = @ptrCast(@alignCast(ctx));
        if (self.server.outbox.items.len == 0) return error.Transport;
        const frame = self.server.outbox.orderedRemove(0);
        return allocator.dupe(u8, frame) catch return error.OutOfMemory;
    }
};

fn runHandshake(arena: std.mem.Allocator, cfg: ServerConfig, options: mtproto.handshake.Options, seed: u64) !mtproto.AuthKey {
    var server_prng = std.Random.DefaultPrng.init(seed ^ 0x5eed);
    var server = Server.init(arena, cfg, server_prng.random());
    var loopback = Loopback{ .server = &server };

    var client_prng = std.Random.DefaultPrng.init(seed);
    var hs = mtproto.Handshake.init(
        arena,
        loopback.transport(),
        &.{.{ .n = testkeys.modulus_be }},
        client_prng.random(),
        1770000000,
        options,
    );
    const auth_key = try hs.run();

    // Both sides must agree on the key, and the public id must be
    // consistent with it (SHA1 lower 64 bits).
    const server_key = server.auth_key orelse return error.NoServerKey;
    try std.testing.expectEqualSlices(u8, &server_key, &auth_key.key);
    try std.testing.expectEqualSlices(u8, &mtproto.inner.authKeyId(&auth_key.key), &auth_key.id);
    return auth_key;
}

test "auth key handshake: rsa_pad mode (loopback)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const key = try runHandshake(arena_state.allocator(), .{ .mode = .rsa_pad }, .{ .mode = .rsa_pad }, 1);
    try std.testing.expect(key.key.len == 256);
}

test "auth key handshake: classic mode (loopback)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const key = try runHandshake(arena_state.allocator(), .{ .mode = .classic }, .{ .mode = .classic }, 2);
    try std.testing.expect(key.key.len == 256);
}

test "auth key handshake: unknown fingerprint is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.UnknownFingerprint,
        runHandshake(arena_state.allocator(), .{ .mode = .rsa_pad, .wrong_fingerprint = true }, .{ .mode = .rsa_pad }, 3),
    );
}

test "auth key handshake: server_DH_params_fail is surfaced" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.ServerDhFail,
        runHandshake(arena_state.allocator(), .{ .mode = .rsa_pad, .dh_fail = true }, .{ .mode = .rsa_pad }, 4),
    );
}

test "auth key handshake: tampered dh_gen_ok hash is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.BadInnerHash,
        runHandshake(arena_state.allocator(), .{ .mode = .classic, .tamper_gen_hash = true }, .{ .mode = .classic }, 5),
    );
}

test "auth key handshake: mismatched nonce in resPQ is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.NonceMismatch,
        runHandshake(arena_state.allocator(), .{ .mode = .classic, .bad_nonce = true }, .{ .mode = .classic }, 6),
    );
}

test "auth key handshake: mode mismatch (server rsa_pad, client classic) fails server-side unwrap" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    // Fingerprints are mode-independent (SHA1 of the modulus, per the
    // handshake contract), so selection succeeds and the client sends
    // req_DH_params classic-encrypted; the rsa_pad server cannot unwrap
    // it, and the transport trampoline surfaces that as error.Transport.
    try std.testing.expectError(
        error.Transport,
        runHandshake(arena_state.allocator(), .{ .mode = .rsa_pad }, .{ .mode = .classic }, 7),
    );
}

test "auth key handshake: temp (PFS) key agrees on the key and the expiry" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server_prng = std.Random.DefaultPrng.init(1 ^ 0x5eed);
    var server = Server.init(arena, .{ .mode = .rsa_pad }, server_prng.random());
    var loopback = Loopback{ .server = &server };

    var client_prng = std.Random.DefaultPrng.init(1);
    var hs = mtproto.Handshake.init(
        arena,
        loopback.transport(),
        &.{.{ .n = testkeys.modulus_be }},
        client_prng.random(),
        1770000000,
        .{ .mode = .rsa_pad },
    );
    const temp = try hs.runTemp(3600);

    // Both sides derived the same key, and expires_at is anchored to the
    // server clock the handshake reported (server_time = 1000).
    const server_key = server.auth_key orelse return error.NoServerKey;
    try std.testing.expectEqualSlices(u8, &server_key, &temp.key);
    try std.testing.expectEqualSlices(u8, &mtproto.inner.authKeyId(&temp.key), &temp.id);
    try std.testing.expectEqual(@as(i32, 1000 + 3600), temp.expires_at);
    try std.testing.expect(server.temp_expires_in.? == 3600);
}

// -------------------------------------------- real sockets (the keygen path)

fn readExact(io: std.Io, stream: *std.Io.net.Stream, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        var iovec = [1][]u8{buf[got..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &iovec);
        if (n == 0) return error.EndOfStream;
        got += n;
    }
}

fn writeAllRaw(io: std.Io, stream: *std.Io.net.Stream, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, &.{bytes[sent..]}, 1);
        if (n == 0) return error.IoFailed;
        sent += n;
    }
}

/// Serves the fake DC over a real TCP socket using the TCP-full framing
/// (length, seq, payload, crc32 — see `td.transport.tcp_full.Codec`) of
/// the `td.transport.TcpFull` client — the exact wire path `td-keygen`
/// uses.
fn serveDcOnce(io: std.Io, listener: *std.Io.net.Server, dc: *Server) void {
    var stream = listener.accept(io) catch return;
    defer stream.close(io);
    var seq: u32 = 0;
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        var hdr: [8]u8 = undefined;
        readExact(io, &stream, &hdr) catch return;
        const parsed = td.transport.tcp_full.Codec.parseHeader(&hdr);
        const plen = td.transport.tcp_full.Codec.validate(parsed, 1 << 20) catch return;
        const buf = dc.arena.alloc(u8, plen) catch return;
        readExact(io, &stream, buf) catch return;
        var trailer: [4]u8 = undefined;
        readExact(io, &stream, &trailer) catch return;
        // Inbound checksums must verify, like the real server.
        if (td.transport.tcp_full.Codec.checksum(&hdr, buf) != std.mem.readInt(u32, &trailer, .little)) return;

        dc.onClientFrame(buf) catch return;
        while (dc.outbox.items.len > 0) {
            const frame = dc.outbox.orderedRemove(0);
            const out_h = td.transport.tcp_full.Codec.header(frame.len, seq);
            var out_tr: [4]u8 = undefined;
            std.mem.writeInt(u32, &out_tr, td.transport.tcp_full.Codec.checksum(&out_h, frame), .little);
            writeAllRaw(io, &stream, &out_h) catch return;
            writeAllRaw(io, &stream, frame) catch return;
            writeAllRaw(io, &stream, &out_tr) catch return;
            seq += 1;
        }
        if (dc.auth_key != null) {
            // dh_gen_ok is already in flight; the FIN follows the queued
            // bytes, so the client reads it all before seeing EOF.
            return;
        }
    }
}

test "auth key handshake over a real socket through TcpFull (keygen path)" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var server_arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena_state.deinit();
    var server_prng = std.Random.DefaultPrng.init(0xdc);
    var dc = Server.init(server_arena_state.allocator(), .{ .mode = .rsa_pad }, server_prng.random());

    const th = try std.Thread.spawn(.{}, serveDcOnce, .{ io, &listener, &dc });

    var tcp = td.transport.TcpFull.init(
        .{ .host = "127.0.0.1", .port = listener.socket.address.getPort() },
        .{},
    );
    try tcp.connect(io);
    defer tcp.close(io);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var client_prng = std.Random.DefaultPrng.init(0xfee);
    var pipe = td.mtproto.HandshakePipe.init(tcp.transport(), io);
    var hs = mtproto.Handshake.init(
        arena_state.allocator(),
        pipe.pipe(),
        &.{.{ .n = testkeys.modulus_be }},
        client_prng.random(),
        1770000000,
        .{ .mode = .rsa_pad },
    );
    const auth_key = try hs.run();

    th.join();

    const server_key = dc.auth_key orelse return error.NoServerKey;
    try std.testing.expectEqualSlices(u8, &server_key, &auth_key.key);
    try std.testing.expectEqualSlices(u8, &mtproto.inner.authKeyId(&auth_key.key), &auth_key.id);
}
