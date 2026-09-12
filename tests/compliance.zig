//! Protocol-compliance integration tests: hostile and malformed MTProto
//! traffic must be rejected with the documented errors, and a rejected
//! input must never desynchronize the receiver or take the session down.
//!
//! Two directions:
//!
//! - **inbound frames** — hand-crafted server→client frames (including
//!   ones `writeEncrypted` cannot produce: undersized padding, unordered
//!   containers, tampered msg_keys) through `Session.receive`, asserting
//!   the exact spec errors;
//! - **inbound RPC** — a real `rpc.Client` over an in-memory loopback
//!   link whose peer answers with hostile payloads: unexpected
//!   constructors (updates path), rpc_error, gzip bombs, and truncation
//!   at the typed-decode layer.
//!
//! Every case here is deterministic and runs in the normal test suite;
//! the mutation-driven versions of the same surfaces live in
//! tests/fuzz.zig.

const std = @import("std");
const td = @import("td");

const message = td.mtproto.message;
const crypto = td.crypto;
const Session = td.mtproto.Session;
const Writer = td.tl.Writer;
const Link = td.multi.Link;
const Client = td.rpc.Client;

const auth_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 97 +% 5);
    break :blk k;
};

const salt: i64 = 0x51a1;
const session_id: i64 = 0x1122_3344_5566_7788;

/// Fixed receive clock; every crafted msg_id is built relative to it.
const now: u64 = 1_700_000_000;

fn serverMsgId(low: u32) i64 {
    return (@as(i64, @intCast(now)) << 32) | (low | 1); // server parity: ≡ 1 (mod 4)
}

/// An rpc_result{bool_true} body — the well-formed control payload.
fn rpcResultOk(arena: std.mem.Allocator, req_msg_id: i64) ![]const u8 {
    var w = Writer.init(arena);
    try w.writeConstructorId(message.rpc_result_id);
    try w.writeLong(req_msg_id);
    try w.writeUInt(0x997275b5); // bool_true
    return w.items();
}

/// Builds an encrypted server frame with an *explicit* padding length
/// — including ones `writeEncrypted` would never produce.
fn craftFrame(
    gpa: std.mem.Allocator,
    dir: crypto.Direction,
    sid: i64,
    msg_id: i64,
    seq_no: i32,
    body: []const u8,
    pad_len: usize,
) ![]u8 {
    const plain_len = message.inner_header_size + body.len + pad_len;
    try std.testing.expect(plain_len % crypto.block_size == 0);
    const frame = try gpa.alloc(u8, message.frame_header_size + plain_len);
    errdefer gpa.free(frame);
    const plain = frame[message.frame_header_size..];
    std.mem.writeInt(i64, plain[0..8], salt, .little);
    std.mem.writeInt(i64, plain[8..16], sid, .little);
    std.mem.writeInt(i64, plain[16..24], msg_id, .little);
    std.mem.writeInt(i32, plain[24..28], seq_no, .little);
    std.mem.writeInt(u32, plain[28..32], @intCast(body.len), .little);
    @memcpy(plain[32..][0..body.len], body);
    @memset(plain[32 + body.len ..], 0xaa);

    var msg_key: [crypto.msg_key_size]u8 = undefined;
    try crypto.encryptMessage(&auth_key, dir, plain, plain, &msg_key);
    @memcpy(frame[0..8], &crypto.authKeyId(&auth_key));
    @memcpy(frame[8..24], &msg_key);
    return frame;
}

fn receiveExpect(frame_in: []u8, expected: anyerror) !void {
    var prng_state = std.Random.DefaultPrng.init(0x51);
    var session = try Session.init(std.testing.allocator, &auth_key, salt, prng_state.random());
    defer session.deinit();
    var out: [4]message.Incoming = undefined;
    try std.testing.expectError(expected, session.receive(frame_in, now, &out));
}

test "msg_key tampering is rejected (constant-time compare upstream)" {
    var prng_state = std.Random.DefaultPrng.init(0x52);
    var session = try Session.init(std.testing.allocator, &auth_key, salt, prng_state.random());
    defer session.deinit();

    const body = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const frame = try std.testing.allocator.alloc(u8, message.frameLength(body.len));
    defer std.testing.allocator.free(frame);
    try message.writeEncrypted(&auth_key, .server_to_client, .{
        .salt = salt,
        .session_id = session.session_id,
        .msg_id = serverMsgId(1),
        .seq_no = 0,
        .body = &body,
    }, prng_state.random(), frame);

    // Control: the honest frame is accepted.
    var out: [1]message.Incoming = undefined;
    _ = try session.receive(frame, now, &out);

    // One flipped msg_key byte (region [8..24)) — rejected.
    frame[10] ^= 0x40;
    try std.testing.expectError(error.MessageKeyMismatch, session.receive(frame, now, &out));
}

test "undersized padding is rejected" {
    // 8-byte body + 8-byte padding: 48-byte plaintext (block-aligned)
    // but padding below the spec minimum of 12 bytes.
    const body = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const frame = try craftFrame(
        std.testing.allocator,
        .server_to_client,
        session_id,
        serverMsgId(1),
        0,
        &body,
        8,
    );
    defer std.testing.allocator.free(frame);
    try receiveExpect(frame, error.PaddingInvalid);
}

test "foreign auth_key_id is rejected before decryption" {
    const body = [_]u8{ 1, 2, 3, 4 };
    const frame = try craftFrame(
        std.testing.allocator,
        .server_to_client,
        session_id,
        serverMsgId(1),
        0,
        &body,
        12,
    );
    defer std.testing.allocator.free(frame);
    frame[3] ^= 0x01; // inside the cleartext auth_key_id
    try receiveExpect(frame, error.AuthKeyIdMismatch);
}

test "msg_id outside the receive window is rejected (code 20 family)" {
    var prng_state = std.Random.DefaultPrng.init(0x53);
    var session = try Session.init(std.testing.allocator, &auth_key, salt, prng_state.random());
    defer session.deinit();

    const body = [_]u8{ 1, 2, 3, 4 };
    const frame = try std.testing.allocator.alloc(u8, message.frameLength(body.len));
    defer std.testing.allocator.free(frame);
    const ancient: i64 = (@as(i64, 1_500_000_000) << 32) | 1; // 2000s-era clock
    try message.writeEncrypted(&auth_key, .server_to_client, .{
        .salt = salt,
        .session_id = session.session_id,
        .msg_id = ancient,
        .seq_no = 0,
        .body = &body,
    }, prng_state.random(), frame);
    var out: [1]message.Incoming = undefined;
    try std.testing.expectError(error.MsgIdTooOld, session.receive(frame, now, &out));
    // Failed validation must not move the expectations.
    try std.testing.expectEqual(@as(i64, 0), session.highest_remote_msg_id);
}

test "seq_no counter violation is rejected (code 18/19 family)" {
    var prng_state = std.Random.DefaultPrng.init(0x54);
    var session = try Session.init(std.testing.allocator, &auth_key, salt, prng_state.random());
    defer session.deinit();

    const body = [_]u8{ 1, 2, 3, 4 };
    const frame = try std.testing.allocator.alloc(u8, message.frameLength(body.len));
    defer std.testing.allocator.free(frame);
    // First service message from the server must carry seq_no 0; 4 skips.
    try message.writeEncrypted(&auth_key, .server_to_client, .{
        .salt = salt,
        .session_id = session.session_id,
        .msg_id = serverMsgId(1),
        .seq_no = 4,
        .body = &body,
    }, prng_state.random(), frame);
    var out: [1]message.Incoming = undefined;
    try std.testing.expectError(error.SeqNoInvalid, session.receive(frame, now, &out));
    try std.testing.expectEqual(@as(u32, 0), session.remote_content_count);
}

test "container with unordered msg_ids is rejected (code 64)" {
    var prng_state = std.Random.DefaultPrng.init(0x55);
    var session = try Session.init(std.testing.allocator, &auth_key, salt, prng_state.random());
    defer session.deinit();

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(message.msg_container_id);
    try w.writeUInt(2);
    // Inner message ids must strictly increase; the second is lower.
    try w.writeLong(serverMsgId(5));
    try w.writeInt(0);
    try w.writeInt(4);
    try w.writeUInt(0x11111111);
    try w.writeLong(serverMsgId(1));
    try w.writeInt(0);
    try w.writeInt(4);
    try w.writeUInt(0x22222222);

    const frame = try std.testing.allocator.alloc(u8, message.frameLength(w.len()));
    defer std.testing.allocator.free(frame);
    try message.writeEncrypted(&auth_key, .server_to_client, .{
        .salt = salt,
        .session_id = session.session_id,
        .msg_id = serverMsgId(9),
        .seq_no = 0,
        .body = w.items(),
    }, prng_state.random(), frame);
    var out: [4]message.Incoming = undefined;
    try std.testing.expectError(error.ContainerInvalid, session.receive(frame, now, &out));
}

// ------------------------------------------------------ RPC hostilities

const query_ctor_id: u32 = 0x0d91a548;

const query_body: [8]u8 = blk: {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], query_ctor_id, .little);
    std.mem.writeInt(u32, b[4..8], 7, .little);
    break :blk b;
};

/// Serves pre-built reply bodies as rpc_result frames for every query.
const Responder = struct {
    result: []const u8,

    fn onBody(ctx: *anyopaque, _: *Link, dec: *const message.Decrypted, arena: std.mem.Allocator) ?td.multi.Reply {
        const self: *Responder = @ptrCast(@alignCast(ctx));
        if (dec.body.len < 4) return null;
        if (std.mem.readInt(u32, dec.body[0..4], .little) != query_ctor_id) return null;
        var w = Writer.init(arena);
        w.writeConstructorId(message.rpc_result_id) catch return null;
        w.writeLong(dec.msg_id) catch return null;
        w.writeRaw(self.result) catch return null;
        return .{ .body = w.items(), .content_related = true };
    }
};

const Rig = struct {
    link: Link,
    responder: Responder,
    client: Client,
    prng_state: std.Random.DefaultPrng,

    fn init(gpa: std.mem.Allocator, io: std.Io, result: []const u8, opts: td.rpc.Options) !*Rig {
        const self = try gpa.create(Rig);
        errdefer gpa.destroy(self);
        self.* = .{
            .link = Link.init(gpa, &auth_key, salt),
            .responder = .{ .result = result },
            .client = undefined,
            .prng_state = std.Random.DefaultPrng.init(0x77),
        };
        self.link.responder = .{ .ctx = &self.responder, .onBody = Responder.onBody };
        const t = self.link.transport();
        self.client = try Client.init(gpa, t, &auth_key, salt, self.prng_state.random(), opts);
        try self.client.connect(io);
        return self;
    }

    fn deinit(self: *Rig, gpa: std.mem.Allocator, io: std.Io) void {
        _ = io;
        self.client.deinit();
        self.link.deinit();
        gpa.destroy(self);
    }
};

test "unexpected constructor travels the updates path and never completes a request" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var handler_calls: usize = 0;
    const H = struct {
        fn onUpdates(ctx: *anyopaque, _: std.Io, body: []const u8) void {
            const c: *usize = @ptrCast(@alignCast(ctx));
            c.* += 1;
            _ = body;
        }
    };

    // A constructor from no schema, carrying junk.
    const weird = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4 };
    var rig = try Rig.init(std.testing.allocator, io, &weird, .{
        .response_timeout = std.Io.Duration.fromMilliseconds(150),
    });
    defer rig.deinit(std.testing.allocator, io);
    rig.client.updates_handler = .{ .ctx = &handler_calls, .onUpdates = H.onUpdates };

    const h = try rig.client.sendRaw(io, &query_body);
    // The 20 ms budget expires on a silent link once the update frame
    // was dispatched; a clean idle expiry is not a pump failure.
    rig.client.pump(io, std.Io.Duration.fromMilliseconds(20)) catch |e| switch (e) {
        error.TimedOut => {},
        else => return e,
    };
    try std.testing.expectEqual(@as(usize, 1), rig.client.updates_seen);
    try std.testing.expectEqual(@as(usize, 1), handler_calls);
    // The request itself was not answered by an update: it stays
    // registered until its deadline, then surfaces as a timeout.
    try std.testing.expectError(error.TimedOut, rig.client.waitRaw(io, h));
    rig.client.cancel(h);
}

test "rpc_error inside rpc_result surfaces code and message" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(message.rpc_error_id);
    try w.writeInt(420);
    try w.writeString("FLOOD_WAIT_420");

    var rig = try Rig.init(std.testing.allocator, io, w.items(), .{});
    defer rig.deinit(std.testing.allocator, io);

    try std.testing.expectError(error.RpcError, rig.client.invokeRaw(io, &query_body));
    try std.testing.expectEqual(@as(i32, 420), rig.client.lastRpcError().code);
    try std.testing.expectEqualStrings("FLOOD_WAIT_420", rig.client.lastRpcError().message);
}

test "gzip bomb beyond max_inflated_bytes is refused" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // One mebibyte of pattern, gzipped — small on the wire, huge past
    // the inflate gate.
    const big = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 251 +% 13);
    const gz = try td.rpc.decode.buildGzipStored(std.testing.allocator, big);
    defer std.testing.allocator.free(gz);

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(message.gzip_packed_id);
    try w.writeBytes(gz);

    var rig = try Rig.init(std.testing.allocator, io, w.items(), .{
        .max_inflated_bytes = 64 * 1024,
    });
    defer rig.deinit(std.testing.allocator, io);

    try std.testing.expectError(error.ResponseTooLarge, rig.client.invokeRaw(io, &query_body));
}

test "typed decode of truncated and trailing-garbage results fails cleanly" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeLong(-1);
    try w.writeLong(77);
    const full = try arena.dupe(u8, w.items());

    // Every truncation of a valid inputPeerUser is an error, never a
    // partially-filled struct.
    for (0..full.len) |n| {
        try std.testing.expectError(error.BadResponse, td.rpc.decodeResult(td.api.inputPeerUser, arena, full[0..n]));
    }
    // Trailing garbage is rejected (exact-consumption rule).
    const padded = try arena.alloc(u8, full.len + 4);
    @memcpy(padded[0..full.len], full);
    @memset(padded[full.len..], 0);
    try std.testing.expectError(error.BadResponse, td.rpc.decodeResult(td.api.inputPeerUser, arena, padded));
    // And the honest bytes decode.
    const peer = try td.rpc.decodeResult(td.api.inputPeerUser, arena, full);
    try std.testing.expectEqual(@as(i64, -1), peer.user_id);
    try std.testing.expectEqual(@as(i64, 77), peer.access_hash);
}
