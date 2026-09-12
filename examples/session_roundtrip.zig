//! Example: the session-persistence flow — capture → store → reload →
//! continue — without a network. `td.Client` runs this whole loop
//! automatically behind `connect`/`saveSession` (examples/quickstart.zig
//! and the session-string support); this example shows the primitive
//! steps the facade composes.
//!
//! Runs a live client over an in-memory link, completes a real RPC
//! round trip, captures its session `State` (the DC manager owns the
//! matching authorization key), stores the serialized fixed-size record,
//! drops everything, then restores: load → deserialize → `applyTo` a
//! fresh `DataCenters` (so its next connect skips the handshake) →
//! `adoptOn` a fresh client (continuing the same wire session id and
//! counters).
//!
//! This is exactly the reconnect flow against a real DC; only the
//! transport is in-memory here.
//!
//! Run: `just build && ./zig-out/bin/example-session`

const std = @import("std");
const td = @import("td");

const message = td.mtproto.message;

const auth_key = blk: {
    var k: [td.crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 41 +% 9);
    break :blk k;
};
const salt: i64 = 0x51a1;

// A stand-in for a generated function: `query#0d91a548 id:int`.
const query_ctor_id: u32 = 0x0d91a548;

/// The embedded peer: answers every query with rpc_result{bool_true}.
fn onBody(
    _: *anyopaque,
    _: *td.multi.Link,
    dec: *const message.Decrypted,
    arena: std.mem.Allocator,
) ?td.multi.Reply {
    if (dec.body.len < 4) return null;
    if (std.mem.readInt(u32, dec.body[0..4], .little) != query_ctor_id) return null;
    var w = td.tl.Writer.init(arena);
    w.writeConstructorId(message.rpc_result_id) catch return null;
    w.writeLong(dec.msg_id) catch return null;
    w.writeUInt(0x997275b5) catch return null; // bool_true
    return .{ .body = w.items(), .content_related = true };
}

fn makeKey() td.mtproto.AuthKey {
    return .{
        .key = auth_key,
        .id = td.crypto.authKeyId(&auth_key),
        .aux_hash = [_]u8{7} ** 8,
        .server_salt = [_]u8{11} ** 8,
    };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    // The DC manager owns the authorization key a handshake produced
    // (here: a fixed key; with a real DC this comes from td-keygen or a
    // previously stored session).
    var dcs = try td.dc.DataCenters.init(gpa, .production);
    defer dcs.deinit();
    _ = try dcs.setAuthKey(2, makeKey());

    // --- live session: real traffic, then capture --------------------
    var link = td.multi.Link.init(gpa, &auth_key, salt);
    defer link.deinit();
    link.responder = .{ .ctx = undefined, .onBody = onBody };
    var prng_state = std.Random.DefaultPrng.init(0xcafe);
    var client = try td.rpc.Client.init(
        gpa,
        link.transport(),
        &auth_key,
        salt,
        prng_state.random(),
        .{},
    );
    defer client.deinit();
    try client.connect(io);

    var req = td.tl.Writer.init(gpa);
    defer req.deinit();
    try req.writeConstructorId(query_ctor_id);
    try req.writeInt(42);
    const answer = try client.invokeRaw(io, req.items());
    gpa.free(answer);

    const st = td.session.State.capture(&dcs, &client) orelse return error.CaptureFailed;
    std.debug.print("captured: dc={d}, content messages sent={d}\n", .{ st.dc, st.content_count });

    // --- persist -------------------------------------------------------
    var store = td.session.MemoryStore.init(gpa);
    defer store.deinit();
    try store.store().saveState(io, st);

    // --- restart: everything above is gone; this is all new -----------
    const restored = (try store.store().loadState(io, gpa)) orelse return error.NotStored;

    var dcs2 = try td.dc.DataCenters.init(gpa, .production);
    defer dcs2.deinit();
    try restored.applyTo(&dcs2); // key restored → next connect skips the handshake

    // A fresh client (new link, new randomness) continues the session.
    var link2 = td.multi.Link.init(gpa, &auth_key, salt);
    defer link2.deinit();
    link2.responder = .{ .ctx = undefined, .onBody = onBody };
    var prng2 = std.Random.DefaultPrng.init(0xbeef);
    var client2 = try td.rpc.Client.init(
        gpa,
        link2.transport(),
        &auth_key,
        salt,
        prng2.random(),
        .{},
    );
    defer client2.deinit();
    try client2.connect(io);
    restored.adoptOn(
        &client2,
        @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s)),
    );

    if (client2.session.session_id != client.session.session_id) return error.SessionNotContinued;
    if (client2.session.content_count != client.session.content_count)
        return error.CountersNotContinued;
    std.debug.print("restored: same wire session continues ({d} content messages so far)\n", .{
        client2.session.content_count,
    });
}
