//! MTProto authorization-key creation (client side).
//!
//! Implements the handshake exactly as documented at
//! https://core.telegram.org/mtproto/auth_key (validated against
//! https://core.telegram.org/mtproto/samples-auth_key):
//!
//!   req_pq → resPQ → (factor pq, RSA-encrypt p_q_inner_data_dc) →
//!   req_DH_params → server_DH_params_ok → (open with tmp AES) →
//!   set_client_DH_params (client_DH_inner_data sealed with tmp AES) →
//!   dh_gen_ok → auth_key = g_a^b mod dh_prime.
//!
//! Security: this module never logs or exposes nonces, keys or decrypted
//! payloads — it has no logging at all. `AuthKey` is returned to the caller
//! who owns the secret. `Transport` abstracts the byte pipe so the
//! handshake is testable against a loopback server without networking.

const std = @import("std");
const tl = @import("../tl/mod.zig");
const schema = @import("schema.zig");
const rsa = @import("rsa.zig");
const inner = @import("inner.zig");
const bigint = @import("bigint.zig");
const factor = @import("factor.zig");
const pfs = @import("pfs.zig");
const Reader = tl.Reader;
const Writer = tl.Writer;

/// The resulting authorization key and its public identifiers.
/// `key`, `aux_hash` and `server_salt` are secret-adjacent: never log them.
pub const AuthKey = struct {
    key: [256]u8,
    id: [8]u8,
    aux_hash: [8]u8,
    server_salt: [8]u8,
};

/// Byte-pipe abstraction (frames of complete plain MTProto messages,
/// including their 20-byte envelope and padding). Production callers
/// adapt a `transport.TcpFull` frame pipe to this (see `dc.manager` and
/// `td-keygen`); tests use an in-memory loopback.
pub const Transport = struct {
    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, frame: []const u8) Error!void,
    recvFn: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) Error![]u8,

    pub fn send(self: Transport, frame: []const u8) Error!void {
        return self.sendFn(self.ctx, frame);
    }

    pub fn recv(self: Transport, allocator: std.mem.Allocator) Error![]u8 {
        return self.recvFn(self.ctx, allocator);
    }
};

pub const Error = error{
    OutOfMemory,
    // transport
    Transport,
    // protocol
    NonceMismatch,
    UnknownFingerprint,
    BadInnerHash,
    InvalidResponse,
    InvalidDhParams,
    DhGenRetry,
    DhGenFail,
    ServerDhFail,
    InvalidLength,
    // surfaced from the TL reader/writer on malformed server messages
    EndOfStream,
    InvalidValue,
    // surfaced from inner-data sealing/opening
    HashMismatch,
    InvalidFormat,
};

pub const Options = struct {
    /// RSA encryption layout (both are accepted by real servers; rsa_pad is
    /// the currently documented scheme).
    mode: rsa.Mode = .rsa_pad,
    /// DC id placed in p_q_inner_data_dc (add 10000 for test servers).
    dc: i32 = 2,
    /// Whether to send req_pq_multi instead of req_pq.
    multi: bool = true,
};

pub const Handshake = struct {
    allocator: std.mem.Allocator,
    transport: Transport,
    keys: []const rsa.PublicKey,
    random: std.Random,
    options: Options,
    /// Base for generated msg_ids: (now_s << 32) | counter, counter += 4.
    /// Client msg_ids are divisible by 4 (protocol description); the
    /// counter starts at 4 so the lower 32 bits are never empty — the
    /// doc's replay-protection requirement.
    now_seconds: u64,
    msg_counter: u32 = 4,

    // handshake state (never log)
    nonce: [16]u8 = undefined,
    server_nonce: [16]u8 = undefined,
    new_nonce: [32]u8 = undefined,

    pub fn init(
        allocator: std.mem.Allocator,
        transport: Transport,
        keys: []const rsa.PublicKey,
        random: std.Random,
        now_seconds: u64,
        options: Options,
    ) Handshake {
        return .{
            .allocator = allocator,
            .transport = transport,
            .keys = keys,
            .random = random,
            .options = options,
            .now_seconds = now_seconds,
        };
    }

    fn nextMsgId(self: *Handshake) i64 {
        const id = (self.now_seconds << 32) | self.msg_counter;
        self.msg_counter += 4;
        return @bitCast(id);
    }

    /// Wraps `body` in a plain (unencrypted) MTProto message:
    /// auth_key_id=0, msg_id, message_length, body, random padding to %16.
    fn sendPlain(self: *Handshake, body: []const u8) Error!void {
        const total = body.len + (16 - body.len % 16) % 16;
        const frame = self.allocator.alloc(u8, 20 + total) catch return error.OutOfMemory;
        defer self.allocator.free(frame);

        std.mem.writeInt(u64, frame[0..8], 0, .little); // auth_key_id = 0
        std.mem.writeInt(i64, frame[8..16], self.nextMsgId(), .little);
        std.mem.writeInt(u32, frame[16..20], @intCast(body.len), .little);
        @memcpy(frame[20..][0..body.len], body);
        self.random.bytes(frame[20 + body.len ..]);
        try self.transport.send(frame);
    }

    /// Receives a plain message and returns the (borrowed) body slice within
    /// `buf` after validating the envelope.
    fn recvPlain(buf: []u8) Error![]const u8 {
        if (buf.len < 20) return error.InvalidLength;
        const auth_key_id = std.mem.readInt(u64, buf[0..8], .little);
        if (auth_key_id != 0) return error.InvalidResponse;
        const msg_id = std.mem.readInt(i64, buf[8..16], .little);
        // Server msg_ids are odd: ≡1 mod 4 responses and ≡3 notifications
        // (protocol description; verified against production endpoints).
        if (@rem(msg_id, 2) == 0) return error.InvalidResponse;
        const length = std.mem.readInt(u32, buf[16..20], .little);
        if (20 + @as(usize, length) > buf.len) return error.InvalidLength;
        return buf[20 .. 20 + length];
    }

    /// Runs the full handshake. On success returns the authorization key.
    /// All intermediate allocations are freed; the caller owns nothing but
    /// the returned value.
    pub fn run(self: *Handshake) Error!AuthKey {
        var key: AuthKey = undefined;
        var expires_at: i32 = 0;
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        try self.runArena(arena_state.allocator(), null, &key, &expires_at);
        return key;
    }

    /// Runs the handshake for a **temporary** (PFS) key:
    /// `p_q_inner_data_temp_dc` instead of `p_q_inner_data_dc`. The
    /// server invalidates the key at `server_time + expires_in`
    /// (https://core.telegram.org/api/pfs) — `expires_at` carries that
    /// server-clock deadline. Everything else (RSA, DH, key derivation)
    /// is identical to `run`.
    pub fn runTemp(self: *Handshake, expires_in: i32) Error!pfs.TempKey {
        var key: AuthKey = undefined;
        var expires_at: i32 = 0;
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        try self.runArena(arena_state.allocator(), expires_in, &key, &expires_at);
        return .{
            .key = key.key,
            .id = key.id,
            .server_salt = key.server_salt,
            .expires_at = expires_at,
        };
    }

    fn runArena(
        self: *Handshake,
        arena: std.mem.Allocator,
        temp_expires_in: ?i32,
        out_key: *AuthKey,
        out_expires_at: *i32,
    ) Error!void {
        // --- Step 1: req_pq ------------------------------------------------
        self.random.bytes(&self.nonce);
        const req = try schema.serializeAlloc(arena, &schema.ReqPq{ .nonce = self.nonce, .multi = self.options.multi });
        try self.sendPlain(req);

        const res_frame = try self.transport.recv(arena);
        const res_body = try recvPlain(res_frame);
        var r = Reader.init(res_body);
        const respq = try schema.ResPQ.deserialize(arena, &r);
        if (!std.mem.eql(u8, &respq.nonce, &self.nonce)) return error.NonceMismatch;

        self.server_nonce = respq.server_nonce;
        self.random.bytes(&self.new_nonce);

        // --- Step 2: select RSA key by fingerprint -------------------------
        var selected: ?usize = null;
        var fingerprint: i64 = 0;
        for (respq.server_public_key_fingerprints) |fp| {
            for (self.keys, 0..) |*key, i| {
                // The fingerprint identifies the key's TL rsa_public_key
                // serialization (see rsa.PublicKey.fingerprint). On the
                // wire the long carries the SHA1 slice verbatim — hash
                // bytes are "not rearranged" into little-endian per the
                // protocol description — so the LE-decoded value is the
                // byte-reversed fingerprint.
                const want: i64 = @bitCast(@byteSwap(key.fingerprint()));
                if (fp == want) {
                    selected = i;
                    fingerprint = fp;
                    break;
                }
            }
            if (selected != null) break;
        }
        const key = &self.keys[selected orelse return error.UnknownFingerprint];

        // --- Step 3: factor pq ---------------------------------------------
        if (respq.pq.len > 8) return error.InvalidDhParams;
        var pq_int: u64 = 0;
        for (respq.pq) |b| pq_int = (pq_int << 8) | b;
        const factors = factor.factorPq(pq_int, self.random) catch return error.InvalidDhParams;
        var p_bytes: [4]u8 = undefined;
        var q_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &p_bytes, @intCast(factors.p), .big);
        std.mem.writeInt(u32, &q_bytes, @intCast(factors.q), .big);

        // --- Step 4: RSA-encrypt p_q_inner_data_dc (or its PFS variant) ---
        const inner_data = if (temp_expires_in) |expires_in|
            try schema.serializeAlloc(arena, &schema.PQInnerDataTempDc{
                .pq = respq.pq,
                .p = &p_bytes,
                .q = &q_bytes,
                .nonce = self.nonce,
                .server_nonce = self.server_nonce,
                .new_nonce = self.new_nonce,
                .dc = self.options.dc,
                .expires_in = expires_in,
            })
        else
            try schema.serializeAlloc(arena, &schema.PQInnerDataDc{
                .pq = respq.pq,
                .p = &p_bytes,
                .q = &q_bytes,
                .nonce = self.nonce,
                .server_nonce = self.server_nonce,
                .new_nonce = self.new_nonce,
                .dc = self.options.dc,
            });
        var encrypted: [256]u8 = undefined;
        switch (self.options.mode) {
            .classic => rsa.encryptClassic(arena, key, inner_data, self.random, &encrypted) catch return error.InvalidResponse,
            .rsa_pad => rsa.encryptRsaPad(arena, key, inner_data, self.random, &encrypted) catch return error.InvalidResponse,
        }
        // --- Step 5: req_DH_params -----------------------------------------
        const req_dh = try schema.serializeAlloc(arena, &schema.ReqDhParams{
            .nonce = self.nonce,
            .server_nonce = self.server_nonce,
            .p = &p_bytes,
            .q = &q_bytes,
            .public_key_fingerprint = fingerprint,
            .encrypted_data = &encrypted,
        });
        try self.sendPlain(req_dh);

        // --- Step 6: open server_DH_params_ok ------------------------------
        const dh_frame = try self.transport.recv(arena);
        const dh_body = try recvPlain(dh_frame);
        var dr = Reader.init(dh_body);
        const dh_params = try schema.ServerDhParams.deserialize(&dr);
        const answer = switch (dh_params) {
            .ok => |v| v,
            .fail => return error.ServerDhFail,
        };
        if (!std.mem.eql(u8, &answer.nonce, &self.nonce)) return error.NonceMismatch;
        if (!std.mem.eql(u8, &answer.server_nonce, &self.server_nonce)) return error.NonceMismatch;

        const aes = inner.tmpAesParams(&self.new_nonce, &self.server_nonce);
        const answer_bytes = arena.dupe(u8, answer.encrypted_answer) catch return error.OutOfMemory;
        const server_inner = inner.openInnerDecrypt(aes, answer_bytes) catch return error.BadInnerHash;

        var sr = Reader.init(server_inner[20..]);
        const server_data = try schema.ServerDhInnerData.deserialize(&sr);
        const consumed = (server_inner.len - 20) - sr.remaining();
        inner.verifyInnerHash(server_inner, consumed) catch return error.BadInnerHash;
        if (!std.mem.eql(u8, &server_data.nonce, &self.nonce)) return error.NonceMismatch;
        if (!std.mem.eql(u8, &server_data.server_nonce, &self.server_nonce)) return error.NonceMismatch;
        if (server_data.dh_prime.len != 256 or server_data.g_a.len != 256) return error.InvalidDhParams;

        // --- Step 7: compute g_b, seal client_DH_inner_data ----------------
        var b: [256]u8 = undefined;
        bigint.randomDhScalar(self.random, &b);
        var g_b: [256]u8 = undefined;
        var g_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &g_bytes, @bitCast(server_data.g), .big);
        const g_len: usize = if (server_data.g > 0xffffff) 4 else if (server_data.g > 0xffff) 3 else if (server_data.g > 0xff) 2 else 1;
        const g_min = g_bytes[4 - g_len ..];
        bigint.powmod(arena, g_min, &b, server_data.dh_prime, &g_b) catch return error.InvalidDhParams;

        const client_inner = try schema.serializeAlloc(arena, &schema.ClientDhInnerData{
            .nonce = self.nonce,
            .server_nonce = self.server_nonce,
            .retry_id = 0,
            .g_b = &g_b,
        });
        const sealed_client = try inner.sealInner(arena, aes, client_inner, self.random);

        const set_dh = try schema.serializeAlloc(arena, &schema.SetClientDhParams{
            .nonce = self.nonce,
            .server_nonce = self.server_nonce,
            .encrypted_data = sealed_client,
        });
        try self.sendPlain(set_dh);

        // --- Step 8: dh_gen_ok ----------------------------------------------
        const gen_frame = try self.transport.recv(arena);
        const gen_body = try recvPlain(gen_frame);
        var gr = Reader.init(gen_body);
        const gen = try schema.DhGenAnswer.deserialize(&gr);
        const ok = switch (gen) {
            .ok => |v| v,
            .retry => return error.DhGenRetry,
            .fail => return error.DhGenFail,
        };
        if (!std.mem.eql(u8, &ok.nonce, &self.nonce)) return error.NonceMismatch;
        if (!std.mem.eql(u8, &ok.server_nonce, &self.server_nonce)) return error.NonceMismatch;

        // auth_key = g_a^b mod dh_prime
        var auth_key: [256]u8 = undefined;
        bigint.powmod(arena, server_data.g_a, &b, server_data.dh_prime, &auth_key) catch return error.InvalidDhParams;

        const aux = inner.authKeyAuxHash(&auth_key);
        const want_hash = inner.newNonceHash(&self.new_nonce, 1, &aux);
        if (!std.mem.eql(u8, &want_hash, &ok.new_nonce_hash1)) return error.BadInnerHash;

        out_key.* = .{
            .key = auth_key,
            .id = inner.authKeyId(&auth_key),
            .aux_hash = aux,
            .server_salt = inner.serverSalt(&self.new_nonce, &self.server_nonce),
        };
        // The server clock (server_DH_inner_data.server_time) anchors the
        // temp key's lifetime, so clock skew on the client cannot shorten
        // or extend it.
        out_expires_at.* = if (temp_expires_in != null)
            std.math.add(i32, server_data.server_time, temp_expires_in.?) catch return error.InvalidDhParams
        else
            0;
    }
};
