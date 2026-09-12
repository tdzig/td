//! Example: a full MTProto round trip without a network.
//!
//! Builds one RPC client over an in-memory loopback link (real MTProto
//! encryption, envelopes and validation on the embedded peer), sends a
//! raw query, receives the answer, and pings. This is the shape of the
//! layer below the high-level client — for the whole stack in one
//! object see `td.Client` (examples/quickstart.zig); everything above
//! this transport stays identical.
//!
//! Run: `just build && ./zig-out/bin/example-loopback`

const std = @import("std");
const td = @import("td");

const message = td.mtproto.message;

const auth_key = blk: {
    var k: [td.crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 73 +% 11);
    break :blk k;
};
const salt: i64 = 0x51a1;

// A stand-in for a generated function: `query#0d91a548 id:int`.
const query_ctor_id: u32 = 0x0d91a548;

/// The embedded peer: answers every query with rpc_result{bool_true}
/// and every ping with a matching pong; anything else drains silently
/// (msgs_ack on a real server is not answered either).
fn onBody(
    _: *anyopaque,
    _: *td.multi.Link,
    dec: *const message.Decrypted,
    arena: std.mem.Allocator,
) ?td.multi.Reply {
    if (dec.body.len < 4) return null;
    var w = td.tl.Writer.init(arena);
    switch (std.mem.readInt(u32, dec.body[0..4], .little)) {
        query_ctor_id => {
            w.writeConstructorId(message.rpc_result_id) catch return null;
            w.writeLong(dec.msg_id) catch return null;
            w.writeUInt(0x997275b5) catch return null; // bool_true
            return .{ .body = w.items(), .content_related = true };
        },
        message.ping_id => {
            // pong#347773c5 msg_id:long ping_id:long — technical message.
            if (dec.body.len < 12) return null;
            w.writeConstructorId(message.pong_id) catch return null;
            w.writeLong(dec.msg_id) catch return null;
            w.writeLong(std.mem.readInt(i64, dec.body[4..12], .little)) catch return null;
            return .{ .body = w.items(), .content_related = false };
        },
        else => return null,
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var link = td.multi.Link.init(gpa, &auth_key, salt);
    defer link.deinit();
    link.responder = .{ .ctx = undefined, .onBody = onBody };

    var prng_state = std.Random.DefaultPrng.init(0xdecafbad);
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

    // Raw round trip: pre-serialized request in, result bytes out.
    var req = td.tl.Writer.init(gpa);
    defer req.deinit();
    try req.writeConstructorId(query_ctor_id);
    try req.writeInt(42);
    const answer = try client.invokeRaw(io, req.items());
    defer gpa.free(answer);
    std.debug.print("rpc answer: {x} ({d} bytes)\n", .{
        std.mem.readInt(u32, answer[0..4], .little),
        answer.len,
    });

    // Technical ping/pong.
    try client.ping(io);
    std.debug.print("ping/pong ok (pongs seen: {d})\n", .{client.pongs_seen});

    // Typed decode of the answer object through the generated layer:
    // decode the result as its union type (Bool) — the union's
    // dispatcher reads the constructor id; a bare constructor struct
    // has no fields and would leave the id bytes unconsumed.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const decoded = try td.rpc.decodeResult(td.api.Bool, arena_state.allocator(), answer);
    if (decoded != .boolTrue) return error.UnexpectedBool;
    std.debug.print("decoded as td.api.Bool.boolTrue\n", .{});}
