//! Authentication-system tests — Step 14's definition of done: a client
//! authenticates a Telegram account and the resulting session is
//! capturable/persistable.
//!
//! Two layers are covered:
//!
//!   * the SRP/2FA math (`td.auth.password`) against an in-test
//!     server implementation: a correct password proof verifies, a
//!     wrong one does not, and the new-password KDF recomputes by hand;
//!   * the full login choreography — sendCode → resendCode → signIn →
//!     SESSION_PASSWORD_NEEDED → checkPassword (a real SRP exchange,
//!     verified server-side) → logout — over the real stack (`rpc.Client`
//!     over the encrypted session over TCP-full) on real loopback
//!     sockets. The flow methods block on the server's answer, so the
//!     in-process peer runs on its own thread (unlike the strict
//!     single-thread alternation of `tests/rpc.zig`); it records the
//!     request sequence it saw, and the main thread asserts on it after
//!     joining. After authorization the session is captured through
//!     `session.State.capture` and cycled through a `MemoryStore`.

const std = @import("std");
const net = std.Io.net;
const td = @import("td");

const message = td.mtproto.message;
const Writer = td.tl.Writer;
const Reader = td.tl.Reader;
const bigint = td.mtproto.bigint;
const Managed = std.math.big.int.Managed;
const TcpFull = td.transport.TcpFull;
const tcp_full = td.transport.tcp_full;
const api = td.api;
const pw = td.auth.password;

// Shared authorization key (varied bytes so the per-direction auth_key
// windows genuinely differ).
const auth_key = blk: {
    var k: [256]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 89 +% 3);
    break :blk k;
};

fn startServer(io: std.Io) !net.Server {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    return addr.listen(io, .{ .reuse_address = true });
}

fn writeAllRaw(io: std.Io, stream: *net.Stream, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, &.{bytes[sent..]}, 1);
        sent += n;
    }
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

fn serverReadFrame(io: std.Io, stream: *net.Stream, arena: std.mem.Allocator) ![]u8 {
    var h: [8]u8 = undefined;
    try readExactRaw(io, stream, &h);
    const parsed = tcp_full.Codec.parseHeader(&h);
    if (parsed.length < tcp_full.frame_overhead) return error.BadFrame;
    const payload = try arena.alloc(u8, parsed.length - tcp_full.frame_overhead);
    try readExactRaw(io, stream, payload);
    var trailer: [4]u8 = undefined;
    try readExactRaw(io, stream, &trailer);
    if (tcp_full.Codec.checksum(&h, payload) != std.mem.readInt(u32, &trailer, .little))
        return error.BadFrame;
    return payload;
}

/// Sends header+payload+trailer as one vectored write: three separate
/// small writes interact with Nagle + delayed ACK into ~40 ms stalls on
/// a request/response exchange.
fn sendFrameRaw(io: std.Io, stream: *net.Stream, h: []const u8, payload: []const u8, trailer: []const u8) !void {
    const parts = [3][]const u8{ h, payload, trailer };
    const total = h.len + payload.len + trailer.len;
    var sent: usize = 0;
    while (sent < total) {
        var iovecs: [3][]const u8 = undefined;
        var n_iov: usize = 0;
        var idx: usize = 0;
        var off: usize = sent;
        while (idx < parts.len) : (idx += 1) {
            if (off >= parts[idx].len) {
                off -= parts[idx].len;
                continue;
            }
            iovecs[n_iov] = parts[idx][off..];
            n_iov += 1;
            off = 0;
        }
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, iovecs[0..n_iov], 1);
        if (n == 0) return error.IoFailed;
        sent += n;
    }
}

fn serverSendFrame(io: std.Io, stream: *net.Stream, payload: []const u8, out_seq: *u32) !void {
    const h = tcp_full.Codec.header(payload.len, out_seq.*);
    const crc = tcp_full.Codec.checksum(&h, payload);
    var trailer: [4]u8 = undefined;
    std.mem.writeInt(u32, &trailer, crc, .little);
    try sendFrameRaw(io, stream, &h, payload, &trailer);
    out_seq.* += 1;
}

fn nowBase(io: std.Io) i64 {
    const s = @divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s);
    return @as(i64, @intCast(s)) << 32;
}

/// Minimal MTProto peer (same shape as `tests/rpc.zig`).
const TestServer = struct {
    salt: i64 = 0x51a1,
    session_id: i64,
    next_low: u32 = 1,
    content: u32 = 0,
    last_client_id: i64 = 0,
    out_seq: u32 = 0,

    fn nextMsgId(self: *TestServer, io: std.Io) i64 {
        const id = nowBase(io) | self.next_low;
        self.next_low += 4;
        return id;
    }

    fn nextSeqNo(self: *TestServer, content_related: bool) i32 {
        const seq: i32 = @intCast(2 * self.content + @as(u32, if (content_related) 1 else 0));
        if (content_related) self.content += 1;
        return seq;
    }

    fn frame(self: *TestServer, io: std.Io, arena: std.mem.Allocator, content_related: bool, body: []const u8) ![]u8 {
        var prng = std.Random.DefaultPrng.init(0xabc);
        const buf = try arena.alloc(u8, message.frameLength(body.len));
        try message.writeEncrypted(&auth_key, .server_to_client, .{
            .salt = self.salt,
            .session_id = self.session_id,
            .msg_id = self.nextMsgId(io),
            .seq_no = self.nextSeqNo(content_related),
            .body = body,
        }, prng.random(), buf);
        return buf;
    }

    fn replyRpc(self: *TestServer, io: std.Io, stream: *net.Stream, arena: std.mem.Allocator, req_msg_id: i64, result: []const u8) !void {
        var w = Writer.init(arena);
        try w.writeConstructorId(message.rpc_result_id);
        try w.writeLong(req_msg_id);
        try w.writeRaw(result);
        const body = try w.toOwnedSlice();
        try serverSendFrame(io, stream, try self.frame(io, arena, true, body), &self.out_seq);
    }

    /// Reads, decrypts and validates one client frame.
    fn read(self: *TestServer, io: std.Io, stream: *net.Stream, arena: std.mem.Allocator) !message.Decrypted {
        const payload = try serverReadFrame(io, stream, arena);
        const dec = try message.readEncrypted(&auth_key, .client_to_server, self.session_id, payload);
        if (!message.isValidClientMsgId(dec.msg_id)) return error.BadClientId;
        if (dec.msg_id <= self.last_client_id) return error.ClientIdOutOfOrder;
        self.last_client_id = dec.msg_id;
        return dec;
    }

    /// Reads the acknowledgement the client's pump sends after each
    /// content-related reply.
    fn drainAck(self: *TestServer, io: std.Io, stream: *net.Stream, arena: std.mem.Allocator) !void {
        const dec = try self.read(io, stream, arena);
        var body = try message.parseServiceBody(arena, dec.body);
        defer body.deinit(arena);
        if (body != .msgs_ack) return error.ExpectedAck;
    }
};

/// Server-side 2FA parameters, precomputed before the flow starts.
const SrpServer = struct {
    salt1: []const u8 = srp_salt1,
    salt2: []const u8 = srp_salt2,
    p: [pw.group_len]u8 = undefined,
    g: u8 = 3,
    v: [pw.group_len]u8 = undefined,
    b: [pw.group_len]u8 = undefined,
    B: [pw.group_len]u8 = undefined,

    fn init(self: *SrpServer, random: std.Random) !void {
        _ = std.fmt.hexToBytes(&self.p, test_prime_hex) catch unreachable;
        const x = try pw.computeX(std.testing.allocator, cloud_password, self.salt1, self.salt2);
        try bigint.powmod(std.testing.allocator, &.{self.g}, &x, &self.p, &self.v);
        random.bytes(&self.b);
        self.b[0] |= 0x80;

        // B = k·v + g^b (mod p) — the SRP-6a form the client expects
        // (its `answer` folds B - k·v back to g^b).
        var gb: [pw.group_len]u8 = undefined;
        try bigint.powmod(std.testing.allocator, &.{self.g}, &self.b, &self.p, &gb);
        const k = pw.computeK(self.g, &self.p);
        var k_int = try bigint.fromBytes(std.testing.allocator, &k);
        defer k_int.deinit();
        var v_int = try bigint.fromBytes(std.testing.allocator, &self.v);
        defer v_int.deinit();
        var gb_int = try bigint.fromBytes(std.testing.allocator, &gb);
        defer gb_int.deinit();
        var p_int = try bigint.fromBytes(std.testing.allocator, &self.p);
        defer p_int.deinit();
        var kv = Managed.init(std.testing.allocator) catch return error.OutOfMemory;
        defer kv.deinit();
        kv.mul(&k_int, &v_int) catch return error.OutOfMemory;
        modReduce(&kv, &p_int);
        var b_man = Managed.init(std.testing.allocator) catch return error.OutOfMemory;
        defer b_man.deinit();
        b_man.add(&kv, &gb_int) catch return error.OutOfMemory;
        modReduce(&b_man, &p_int);
        try bigint.toBytes(&self.B, &b_man);
    }
};

// -------------------------------------------------------- SRP unit tests

const test_prime_hex = "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B";

/// A known 2048-bit safe prime: the MTProto sample dh_prime
/// (https://core.telegram.org/mtproto/samples-auth_key).

/// The server-side expected M1 for `A` under secret `b` and verifier
/// `v`: s = (A·v^u)^b mod p with u = SHA256(A ∥ B), then
/// M1 = SHA256(Hx(p) ∥ Hx(g) ∥ salt1 ∥ salt2 ∥ A ∥ B ∥ K). This is the
/// https://core.telegram.org/api/srp server, used both by the unit test
/// below and the e2e flow's peer.
fn expectedM1(
    arena: std.mem.Allocator,
    g: u8,
    p: *const [pw.group_len]u8,
    salt1: []const u8,
    salt2: []const u8,
    A: []const u8,
    B: *const [pw.group_len]u8,
    b: *const [pw.group_len]u8,
    v: [pw.group_len]u8,
) ![]const u8 {
    const a = arena;
    const ab = try pw.concat(a, &.{ A, B });
    const u = pw.sha256(ab);

    var p_int = try bigint.fromBytes(a, p);
    defer p_int.deinit();
    var A_int = try bigint.fromBytes(a, A);
    defer A_int.deinit();

    // v^u is an exponentiation, not a product.
    var vu_buf: [pw.group_len]u8 = undefined;
    try bigint.powmod(a, &v, &u, p, &vu_buf);
    var vu_int = try bigint.fromBytes(a, &vu_buf);
    defer vu_int.deinit();
    var avu = Managed.init(a) catch return error.OutOfMemory;
    defer avu.deinit();
    avu.mul(&A_int, &vu_int) catch return error.OutOfMemory;
    modReduce(&avu, &p_int);
    var avu_buf: [pw.group_len]u8 = undefined;
    try bigint.toBytes(&avu_buf, &avu);

    var s: [pw.group_len]u8 = undefined;
    try bigint.powmod(a, &avu_buf, b, p, &s);
    const K = pw.sha256(&s);
    var g_padded: [pw.group_len]u8 = @splat(0);
    g_padded[pw.group_len - 1] = g;
    const hx_p = pw.hx(p);
    const hx_g = pw.hx(&g_padded);
    const pre = try pw.concat(a, &.{
        &hx_p,
        &hx_g,
        salt1,
        salt2,
        A,
        B,
        &K,
    });
    const digest = pw.sha256(pre);
    return a.dupe(u8, &digest);
}

fn modReduce(v: *Managed, modulus: *const Managed) void {
    var q = Managed.init(v.allocator) catch unreachable;
    defer q.deinit();
    var r = Managed.init(v.allocator) catch unreachable;
    defer r.deinit();
    q.divFloor(&r, v, modulus) catch unreachable;
    v.copy(r.toConst()) catch unreachable;
}

test "srp: correct password verifies, wrong password does not" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(23);
    const random = prng.random();

    var p_buf: [pw.group_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&p_buf, test_prime_hex) catch unreachable;

    const salt1 = "salt-one1";
    const salt2 = "salt-two2";

    var algo = try pw.Algo.initRaw(std.testing.allocator, 3, &p_buf, salt1, salt2, random);
    defer algo.deinit();

    // Server: verifier for the correct password, random b, B = k·v + g^b.
    const x = try pw.computeX(std.testing.allocator, cloud_password, salt1, salt2);
    var v: [pw.group_len]u8 = undefined;
    try bigint.powmod(std.testing.allocator, &.{3}, &x, &p_buf, &v);
    var b: [pw.group_len]u8 = undefined;
    random.bytes(&b);
    b[0] |= 0x80;
    var B: [pw.group_len]u8 = undefined;
    {
        var gb: [pw.group_len]u8 = undefined;
        try bigint.powmod(std.testing.allocator, &.{3}, &b, &p_buf, &gb);
        const k = pw.computeK(3, &p_buf);
        var k_int = try bigint.fromBytes(std.testing.allocator, &k);
        defer k_int.deinit();
        var v_int = try bigint.fromBytes(std.testing.allocator, &v);
        defer v_int.deinit();
        var gb_int = try bigint.fromBytes(std.testing.allocator, &gb);
        defer gb_int.deinit();
        var p_int = try bigint.fromBytes(std.testing.allocator, &p_buf);
        defer p_int.deinit();
        var kv = Managed.init(std.testing.allocator) catch return error.OutOfMemory;
        defer kv.deinit();
        kv.mul(&k_int, &v_int) catch return error.OutOfMemory;
        modReduce(&kv, &p_int);
        var b_man = Managed.init(std.testing.allocator) catch return error.OutOfMemory;
        defer b_man.deinit();
        b_man.add(&kv, &gb_int) catch return error.OutOfMemory;
        modReduce(&b_man, &p_int);
        try bigint.toBytes(&B, &b_man);
    }

    // Correct password: the server-side M1 check passes.
    {
        var srp = try pw.Srp.init(std.testing.allocator, random, &algo, cloud_password);
        defer srp.deinit();
        const ans = try srp.answer(7, &B);
        const expect = try expectedM1(arena, 3, &p_buf, salt1, salt2, &srp.A, &B, &b, v);
        try std.testing.expectEqualSlices(u8, expect, ans.M1);
    }

    // Wrong password: the proof binds the password — mismatch.
    {
        var srp = try pw.Srp.init(std.testing.allocator, random, &algo, "hunter3");
        defer srp.deinit();
        const ans = try srp.answer(7, &B);
        const expect = try expectedM1(arena, 3, &p_buf, salt1, salt2, &srp.A, &B, &b, v);
        try std.testing.expect(!std.mem.eql(u8, expect, ans.M1));
    }
}

test "srp: new-password hash is the specified KDF chain" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var prng = std.Random.DefaultPrng.init(29);
    const random = prng.random();

    var p_buf: [pw.group_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&p_buf, test_prime_hex) catch unreachable;
    var algo = try pw.Algo.initRaw(std.testing.allocator, 3, &p_buf, "srv", "", random);
    defer algo.deinit();

    const new_salt = try algo.withExtendedSalt(std.testing.allocator, random);
    defer std.testing.allocator.free(new_salt);
    const hash = try pw.newPasswordHash(std.testing.allocator, &algo, new_salt, "new-pw");

    // Recompute the chain by hand: PH2(pw) → PBKDF2-HMAC-SHA512(64
    // bytes) → SHA-256 → g^x mod p.
    const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var ph2_buf: [32]u8 = undefined;
    Sha256.hash("new-pw", &ph2_buf, .{});
    var ph1_buf: [32]u8 = undefined;
    Sha256.hash(&ph2_buf, &ph1_buf, .{});
    var pbkdf_out: [64]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&pbkdf_out, &ph1_buf, new_salt, 100_000, HmacSha512);
    var x_buf: [32]u8 = undefined;
    Sha256.hash(&pbkdf_out, &x_buf, .{});
    var expect: [pw.group_len]u8 = undefined;
    try bigint.powmod(std.testing.allocator, &.{3}, &x_buf, &p_buf, &expect);
    try std.testing.expectEqualSlices(u8, &expect, &hash);
}

// ------------------------------------------------------------- e2e flow

const phone = "+15551530901";
const phone_code_hash = "c0dehash42";
const cloud_password = "hunter2";
const srp_salt1 = "salt-one1";
const srp_salt2 = "salt-two2";
const test_user_id: i64 = 777;

/// Serializes one generated value into arena bytes.
fn serializeAlloc(arena: std.mem.Allocator, value: anytype) ![]u8 {
    var w = Writer.init(arena);
    try value.serialize(&w);
    return w.toOwnedSlice();
}

fn rpcError(arena: std.mem.Allocator, code: i32, msg: []const u8) ![]const u8 {
    var w = Writer.init(arena);
    try w.writeConstructorId(message.rpc_error_id);
    try w.writeInt(code);
    try w.writeString(msg);
    return w.items();
}

/// What the in-process peer saw, for main-thread assertions (testing
/// assertions are not thread-safe, so the thread only records).
const EventLog = struct {
    ids: [8]u32 = undefined,
    len: usize = 0,
    m1_ok: bool = true,
    failure: ?anyerror = null,
};

/// Answers one request following the choreography.
fn dispatch(
    ts: *TestServer,
    io: std.Io,
    srv: *net.Stream,
    arena: std.mem.Allocator,
    req_msg_id: i64,
    body: []const u8,
    srp: *const SrpServer,
    log: *EventLog,
) !void {
    const id = std.mem.readInt(u32, body[0..4], .little);
    switch (id) {
        api.auth.sendCode.constructor_id, api.auth.resendCode.constructor_id => {
            if (id == api.auth.sendCode.constructor_id) {
                var r = Reader.init(body);
                _ = try r.readConstructorId();
                const got_phone = try r.readString();
                if (!std.mem.eql(u8, phone, got_phone)) return error.WrongPhone;
            }
            try ts.replyRpc(io, srv, arena, req_msg_id, try serializeAlloc(arena, api.auth.SentCode{ .sentCode = .{
                .type_ = .{ .sentCodeTypeSms = .{ .length = 5 } },
                .phone_code_hash = phone_code_hash,
                .timeout = 60,
            } }));
        },
        api.auth.signIn.constructor_id => {
            try ts.replyRpc(io, srv, arena, req_msg_id, try rpcError(arena, 400, "SESSION_PASSWORD_NEEDED"));
        },
        api.account.getPassword.constructor_id => {
            try ts.replyRpc(io, srv, arena, req_msg_id, try serializeAlloc(arena, api.account.Password{ .password = .{
                .has_password = true,
                .current_algo = .{ .passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow = .{
                    .salt1 = srp.salt1,
                    .salt2 = srp.salt2,
                    .g = srp.g,
                    .p = &srp.p,
                } },
                .srp_B = &srp.B,
                .srp_id = 42,
                .hint = "hunter?",
                .new_algo = .{ .passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow = .{
                    .salt1 = "new-salt-1",
                    .salt2 = "new-salt-2",
                    .g = srp.g,
                    .p = &srp.p,
                } },
                .new_secure_algo = .{ .securePasswordKdfAlgoUnknown = .{} },
                .secure_random = "",
            } }));
        },
        api.auth.checkPassword.constructor_id => {
            var r = Reader.init(body);
            _ = try r.readConstructorId();
            const input = try api.InputCheckPasswordSRP.deserialize(arena, &r);
            const answer = input.inputCheckPasswordSRP;
            if (answer.srp_id != 42) return error.WrongSrpId;
            if (answer.A.len != pw.group_len) return error.WrongA;

            // Verify the proof: a mismatched M1 would mean the client
            // hashed a different password. Recorded, not asserted —
            // the main thread checks after joining.
            const expect = expectedM1(
                arena,
                srp.g,
                &srp.p,
                srp.salt1,
                srp.salt2,
                answer.A,
                &srp.B,
                &srp.b,
                srp.v,
            ) catch |e| return e;
            if (!std.mem.eql(u8, expect, answer.M1)) log.m1_ok = false;

            try ts.replyRpc(io, srv, arena, req_msg_id, try serializeAlloc(arena, api.auth.Authorization_{ .authorization = .{
                .user = .{ .user = .{ .id = test_user_id, .first_name = "T" } },
            } }));
        },
        api.auth.logOut.constructor_id => {
            try ts.replyRpc(io, srv, arena, req_msg_id, try serializeAlloc(arena, api.auth.LoggedOut{ .loggedOut = .{} }));
        },
        else => return error.UnexpectedRequest,
    }
}

/// The in-process peer loop: answer every request, drain the matching
/// ack, stop after the logout.
fn serverThread(
    io: std.Io,
    srv: *net.Stream,
    ts: *TestServer,
    srp: *const SrpServer,
    log: *EventLog,
) void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    while (log.len < log.ids.len) {
        const dec = ts.read(io, srv, arena) catch |e| {
            log.failure = e;
            return;
        };
        if (dec.body.len < 4) {
            log.failure = error.ShortRequest;
            return;
        }
        const id = std.mem.readInt(u32, dec.body[0..4], .little);
        dispatch(ts, io, srv, arena, dec.msg_id, dec.body, srp, log) catch |e| {
            log.failure = e;
            return;
        };
        log.ids[log.len] = id;
        log.len += 1;
        if (id == api.auth.logOut.constructor_id) return;
        ts.drainAck(io, srv, arena) catch |e| {
            log.failure = e;
            return;
        };
    }
}

/// One client + server pair on a fresh loopback connection.
const Pair = struct {
    client: td.rpc.Client,
    tcp: *TcpFull,
    server: net.Server,
    srv: net.Stream,
    ts: *TestServer,

    fn deinitPair(self: *Pair, io: std.Io) void {
        self.client.deinit();
        self.srv.close(io);
        self.server.deinit(io);
        self.tcp.close(io);
    }
};

var pair_prng = std.Random.DefaultPrng.init(17);

fn makePair(
    io: std.Io,
    tcp_storage: *TcpFull,
    ts_storage: *TestServer,
) !Pair {
    var server = try startServer(io);
    errdefer server.deinit(io);

    tcp_storage.* = TcpFull.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{},
    );
    try tcp_storage.connect(io);
    errdefer tcp_storage.close(io);

    var srv = try server.accept(io);
    errdefer srv.close(io);

    const client = try td.rpc.Client.init(
        std.testing.allocator,
        tcp_storage.transport(),
        &auth_key,
        0x51a1,
        pair_prng.random(),
        .{},
    );
    ts_storage.* = .{ .session_id = client.session.session_id };
    return .{
        .client = client,
        .tcp = tcp_storage,
        .server = server,
        .srv = srv,
        .ts = ts_storage,
    };
}

/// The stored form of the key, as `DataCenters.setAuthKey` would have
/// received it from the handshake (see tests/session.zig).
fn handshakeKey(salt: i64) td.mtproto.AuthKey {
    var key: td.mtproto.AuthKey = undefined;
    @memcpy(&key.key, &auth_key);
    key.id = td.crypto.authKeyId(&auth_key);
    for (&key.aux_hash, 0..) |*b, i| b.* = @truncate(i *% 19 +% 6);
    std.mem.writeInt(i64, &key.server_salt, salt, .little);
    return key;
}

test "definition of done: code → sign-in → 2FA → authorized → persist → logout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var flow_prng = std.Random.DefaultPrng.init(31);
    var srp_srv = SrpServer{};
    try srp_srv.init(flow_prng.random());

    // The session that gets persisted after authorization.
    var dcs = try td.dc.DataCenters.init(std.testing.allocator, .production);
    defer dcs.deinit();
    try dcs.setAuthKey(2, handshakeKey(0x51a1));
    try dcs.setCurrent(2);

    var tcp_storage: TcpFull = undefined;
    var ts_storage: TestServer = undefined;
    var pair = try makePair(io, &tcp_storage, &ts_storage);
    defer pair.deinitPair(io);

    var auth_client = td.auth.Client.init(std.testing.allocator, &pair.client, 8, "test-api-hash");
    defer auth_client.deinit();
    try std.testing.expect(auth_client.userId() == null);
    try std.testing.expect(auth_client.state == .logged_out);

    // The peer lives on its own thread: the flow methods block on the
    // server's answers, so someone must serve while they wait.
    var log = EventLog{};
    const worker = try std.Thread.spawn(.{}, serverThread, .{
        io, &pair.srv, pair.ts, &srp_srv, &log,
    });

    // 1. sendCode: the state carries the phone + hash the server sent.
    try auth_client.sendCode(io, phone, .{ .codeSettings = .{} });
    try std.testing.expect(auth_client.state == .waiting_code);

    // 2. resendCode reaches the server with the stored hash.
    try auth_client.resendCode(io);
    try std.testing.expect(auth_client.state == .waiting_code);

    // 3. signIn: the server demands the second factor; the state moves
    //    to waiting_password.
    try std.testing.expectError(error.SessionPasswordNeeded, auth_client.signIn(io, "12345"));
    try std.testing.expect(auth_client.state == .waiting_password);

    // 4. checkPassword: real SRP exchange — getPassword then
    //    auth.checkPassword, with the peer verifying M1.
    try auth_client.checkPassword(io, flow_prng.random(), cloud_password);
    try std.testing.expect(auth_client.state == .authorized);
    try std.testing.expectEqual(@as(i64, test_user_id), auth_client.userId().?);

    // 5. Persist the resulting session: capture from the live client
    //    (the authorized key + current salt) and cycle it through a
    //    store. The capture/store format itself is covered by
    //    tests/session.zig; here it must simply work after a login.
    var mem = td.session.MemoryStore.init(std.testing.allocator);
    defer mem.deinit();
    const captured = td.session.State.capture(&dcs, &pair.client) orelse
        return error.TestUnexpectedResult;
    try mem.store().saveState(io, captured);
    const reloaded = (try mem.store().loadState(io, std.testing.allocator)).?;
    try std.testing.expectEqualSlices(u8, &captured.auth_key.key, &reloaded.auth_key.key);
    try std.testing.expectEqual(captured.session_id, reloaded.session_id);
    try std.testing.expectEqual(@as(i32, 2), reloaded.dc);

    // 6. logout clears the authorization state.
    try auth_client.logOut(io);
    try std.testing.expect(auth_client.state == .logged_out);
    try std.testing.expect(auth_client.userId() == null);

    worker.join();

    // The peer saw the exact request sequence and verified M1.
    try std.testing.expect(log.failure == null);
    try std.testing.expect(log.m1_ok);
    const expected_ids = [_]u32{
        api.auth.sendCode.constructor_id,
        api.auth.resendCode.constructor_id,
        api.auth.signIn.constructor_id,
        api.account.getPassword.constructor_id,
        api.auth.checkPassword.constructor_id,
        api.auth.logOut.constructor_id,
    };
    try std.testing.expectEqual(expected_ids.len, log.len);
    for (expected_ids, log.ids[0..log.len]) |e, a| {
        try std.testing.expectEqual(e, a);
    }
}
