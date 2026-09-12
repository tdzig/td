//! Fuzz targets for every supported input path, plus the adversarial
//! corpora as plain regression tests.
//!
//! Each target is a small function `fuzz(ctx, smith)` that materializes
//! input through the Smith provider (`smith.slice` — a u32 length
//! prefix followed by bytes) and hands it to an `impl([]const u8)`.
//! The same functions run twice:
//!
//!   * as plain tests over a fixed corpus (hostile hand-picked inputs —
//!     always executed by `zig build test`, which iterates the corpus
//!     and additionally runs one empty-input case per target), and
//!   * under the coverage-guided fuzzer (`just fuzz` /
//!     `zig build test --fuzz`), which mutates beyond the corpus.
//!
//! Surfaces: TL schema parser, TL reader, TL writer↔reader roundtrip,
//! generated deserializers + the type-driven RPC decode, the encrypted
//! message parser (both raw and through `Session.receive` stateful
//! validation, in a structured variant that re-encrypts so the fuzzer
//! reaches *past* the msg_key check), session-state loading, and the
//! transport framing codec.

const std = @import("std");
const td = @import("td");

const message = td.mtproto.message;
const crypto = td.crypto;
const Session = td.mtproto.Session;
const Reader = td.tl.Reader;
const Writer = td.tl.Writer;
const Smith = std.testing.Smith;

/// Accumulator so ReleaseFast builds cannot fold target work away.
var sink: usize = 0;

/// Length-prefixes a corpus entry so `smith.slice` materializes the
/// whole byte string (slice reads a little-endian u32 length first).
/// `return comptime` makes every call evaluate at compile time, so the
/// returned slice is comptime-known even when the call site is runtime
/// code — the fuzz options require corpus data that outlives the call.
fn entry(comptime bytes: []const u8) []const u8 {
    return comptime blk: {
        const out = fill: {
            var buf: [4 + bytes.len]u8 = undefined;
            std.mem.writeInt(u32, buf[0..4], @intCast(bytes.len), .little);
            @memcpy(buf[4..], bytes);
            break :fill buf;
        };
        break :blk &out;
    };
}

// Shared fixture: the key and salt every encrypted-path target uses.
const auth_key = blk: {
    var k: [crypto.auth_key_size]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 61 +% 29);
    break :blk k;
};
const salt: i64 = 0x51a1;

// ---------------------------------------------------------- TL parser

/// TL schema text in, AST out: any `ParseError` is fine, a panic is not.
fn schemaParserImpl(input: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const schema = td.tl.parseSchema(arena.allocator(), input) catch return;
    sink +%= schema.constructors.len;
}

fn fuzzSchemaParser(_: void, smith: *Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    try schemaParserImpl(buf[0..smith.slice(&buf)]);
}

/// Deterministic battery for the parser (runs in every `zig build test`).
fn parserBattery() !void {
    const cases = [_][]const u8{
        "",
        "   \n\t ",
        "user#d10d979a flags:# = User;",
        "---functions---",
        "---",
        "#",
        "a# = ;",
        "a#00000000 = T;",
        "a = Vector<int>;",
        "a flags:# x:flags.0?int y:flags.1?Vector<string> = T;",
        "a {X:Type} v:Vector<X> = T;",
        "a [ int long ] = T;",
        "a x:%Int = T;",
        "a x:!Int = T;",
        "/* unterminated",
        "// line only",
        "a#zzzz = T;",
        "a#\xff\xff\xff\xff = T;",
        "\x00\x01\x02 binary garbage \xf0\x9f",
        "a b c d e f = T;",
        "a {X:NotAType} x:X = T;",
        "a ====== T;",
        "a = T; b = U; ---functions--- c#1 = X;",
    };
    for (cases) |c| try schemaParserImpl(c);
}

test "fuzz corpus: TL schema parser" {
    try parserBattery();
    try std.testing.fuzz({}, fuzzSchemaParser, .{
        .corpus = &.{
            entry("user#d10d979a flags:# = User;"),
            entry("a {X:Type} v:# = T;"),
            entry("---functions--- a#1 = X;"),
            entry("\x00\x01\x02 garbage"),
        },
    });
}

// ----------------------------------------------------------- TL reader

/// TL bytes in, primitive reads out: any error is fine.
fn readerImpl(input: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var r = Reader.init(input);
    _ = r.readInt() catch {};
    _ = r.readLong() catch {};
    _ = r.readUInt() catch {};
    _ = r.readDouble() catch {};
    _ = r.readInt128() catch {};
    _ = r.readInt256() catch {};
    _ = r.readBool() catch {};
    _ = r.readString() catch {};
    _ = r.readBytes() catch {};
    _ = r.readVectorOfInt(arena.allocator()) catch {};
    _ = r.readVectorOfLong(arena.allocator()) catch {};
    _ = r.readVectorOfString(arena.allocator()) catch {};
    _ = r.readRaw(input.len) catch {};
}

fn fuzzReader(_: void, smith: *Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    try readerImpl(buf[0..smith.slice(&buf)]);
}

/// A valid vector followed by every truncation of it: the length
/// prefix promises more than any truncated input can deliver.
fn truncationsOfValidVector() !void {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(td.tl.vector_constructor_id);
    try w.writeUInt(3);
    try w.writeInt(1);
    try w.writeInt(2);
    try w.writeInt(3);
    const full = try std.testing.allocator.dupe(u8, w.items());
    defer std.testing.allocator.free(full);
    for (0..full.len + 1) |n| try readerImpl(full[0..n]);
}

test "fuzz corpus: TL reader (incl. every truncation of a valid vector)" {
    try truncationsOfValidVector();
    try readerImpl(&[_]u8{ 0x15, 0xc4, 0xb5, 0x1c, 0xff, 0xff, 0xff, 0xff });
    try readerImpl(&[_]u8{ 0x15, 0xc4, 0xb5, 0x1c, 0x00, 0x00, 0x00, 0x80 });
    try std.testing.fuzz({}, fuzzReader, .{
        .corpus = &.{
            entry(&[_]u8{ 0x15, 0xc4, 0xb5, 0x1c, 0x01, 0x00, 0x00, 0x00, 7, 0, 0, 0 }),
            entry(&[_]u8{ 0xfe, 3, 0, 0, 'a', 'b', 'c', 0 }),
        },
    });
}

// ------------------------------------------------- TL writer roundtrip

/// Typed values derived from the input go writer→reader and must come
/// back identical (padding and length-prefixing are the risk).
fn writerRoundtripImpl(input: []const u8) !void {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeString(input);
    try w.writeBytes(input);
    // Truncations exercise the reader's length/padding acceptance.
    const items = w.items();
    for (0..items.len + 1) |n| {
        var r = Reader.init(items[0..n]);
        if (r.readString()) |s| {
            // Only a fully-present string may compare equal.
            if (n == items.len) try std.testing.expectEqualSlices(u8, input, s);
        } else |_| {}
    }
    var r2 = Reader.init(items);
    const s = try r2.readString();
    try std.testing.expectEqualSlices(u8, input, s);
    const b = try r2.readBytes();
    try std.testing.expectEqualSlices(u8, input, b);
}

fn fuzzWriterRoundtrip(_: void, smith: *Smith) anyerror!void {
    var buf: [8192]u8 = undefined;
    try writerRoundtripImpl(buf[0..smith.slice(&buf)]);
}

test "fuzz corpus: TL writer↔reader roundtrip" {
    const cases = [_][]const u8{
        "",
        "a",
        "ab",
        "abc",
        "abcd",
        "hello world",
        "\x00\x01\x02\xfe\xff",
        "x" ** 253,
        "y" ** 254,
        "z" ** 4096,
    };
    for (cases) |c| try writerRoundtripImpl(c);
    try std.testing.fuzz({}, fuzzWriterRoundtrip, .{
        .corpus = &.{ entry("abcd"), entry("y" ** 254) },
    });
}

// -------------------------------------------- generated deserializers

/// Wire bytes in, generated values out: errors are fine, panics are not.
/// Covers scalar+string, two-long, boxed-union-pointer fields and the
/// type-driven RPC decode over the `InputPeer` union.
fn generatedDecodeImpl(input: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    inline for (.{ td.api.error_, td.api.inputPeerUser, td.api.inputPeerUserFromMessage, td.api.inputPeerChat }) |T| {
        var r = Reader.init(input);
        if (T.deserialize(a, &r)) |v| {
            var w = Writer.init(a);
            v.serialize(&w) catch {};
        } else |_| {}
    }

    if (td.rpc.decodeResult(td.api.InputPeer, a, input)) |v| {
        sink +%= @sizeOf(@TypeOf(v));
    } else |_| {}
    if (td.rpc.decodeResult([]i32, a, input)) |v| {
        sink +%= v.len;
    } else |_| {}
}

fn fuzzGeneratedDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    try generatedDecodeImpl(buf[0..smith.slice(&buf)]);
}

test "fuzz corpus: generated deserializers and RPC decode" {
    // error_ = code + text
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeInt(420);
    try w.writeString("FLOOD_WAIT_420");
    try generatedDecodeImpl(w.items());
    // inputPeerUser = two longs; every truncation must error cleanly.
    var w2 = Writer.init(std.testing.allocator);
    defer w2.deinit();
    try w2.writeLong(-1);
    try w2.writeLong(0x0123456789abcdef);
    const peer = try std.testing.allocator.dupe(u8, w2.items());
    defer std.testing.allocator.free(peer);
    for (0..peer.len + 1) |n| try generatedDecodeImpl(peer[0..n]);
    try generatedDecodeImpl(&[_]u8{ 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef });
    try std.testing.fuzz({}, fuzzGeneratedDecode, .{
        .corpus = &.{
            entry(&[_]u8{ 0xa4, 0x01, 0, 0, 4, 0, 0, 0, 't', 'e', 's', 't', 0, 0, 0 }),
            // inputPeerUser = two longs (-1, 0x0123456789abcdef), the
            // same bytes the runtime truncation loop above exercises.
            entry(&[_]u8{
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
            }),
        },
    });
}

// -------------------------------------------- encrypted message parser

/// Raw hostile bytes straight into the frame decryptor: the auth_key_id
/// gate rejects almost everything; the rest must fail cleanly.
fn rawFrameImpl(input: []const u8) !void {
    var buf: [512]u8 = undefined;
    if (input.len > buf.len) return;
    @memcpy(buf[0..input.len], input);
    _ = message.readEncrypted(&auth_key, .server_to_client, 0x1122, buf[0..input.len]) catch return;
}

fn fuzzRawFrame(_: void, smith: *Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    try rawFrameImpl(buf[0..smith.slice(&buf)]);
}

/// Structured variant: the fuzz input controls the *plaintext* (msg_id,
/// seq_no, body), the envelope is built honestly — so every frame
/// decrypts and the fuzzing reaches the stateful validation the msg_key
/// check would otherwise shield. Layout: 8-byte msg_id | 4-byte seq_no
/// | body (truncated to %4).
fn envelopePlaintextImpl(input: []const u8) !void {
    if (input.len < 12) return;
    var prng_state = std.Random.DefaultPrng.init(0xf00d);
    const msg_id: i64 = @bitCast(std.mem.readInt(u64, input[0..8], .little));

    var body = input[12..];
    body.len -= body.len % 4;
    if (body.len == 0) return;

    const frame = std.testing.allocator.alloc(u8, message.frameLength(body.len)) catch return;
    defer std.testing.allocator.free(frame);
    message.writeEncrypted(&auth_key, .server_to_client, .{
        .salt = salt,
        .session_id = 0x1122_3344_5566_7788,
        .msg_id = msg_id,
        .seq_no = @bitCast(std.mem.readInt(u32, input[8..12], .little)),
        .body = body,
    }, prng_state.random(), frame) catch return;

    // Stateless parse (fresh session each time: stateful order rules
    // would reject all but the first id, which is their job).
    var session = Session.init(std.testing.allocator, &auth_key, salt, prng_state.random()) catch return;
    defer session.deinit();
    var out: [1]message.Incoming = undefined;
    _ = session.receive(frame, 1_700_000_000, &out) catch return;
}

fn fuzzEnvelopePlaintext(_: void, smith: *Smith) anyerror!void {
    var buf: [2048]u8 = undefined;
    try envelopePlaintextImpl(buf[0..smith.slice(&buf)]);
}

test "fuzz corpus: encrypted frame parser (raw + structured plaintext)" {
    try rawFrameImpl(&([_]u8{0} ** 48));
    try envelopePlaintextImpl(&([_]u8{0x10} ** 8 ++ [_]u8{0} ** 4 ++ "abcd".*));
    try std.testing.fuzz({}, fuzzRawFrame, .{});
    try std.testing.fuzz({}, fuzzEnvelopePlaintext, .{
        .corpus = &.{
            entry(&[_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 } ++ [_]u8{0} ** 4 ++ "abcd".*),
        },
    });
}

// --------------------------------------------------- session loading

/// Arbitrary bytes (padded/truncated to the fixed record size) into the
/// session-state deserializer. Valid states must re-serialize
/// byte-identical.
fn sessionLoadImpl(input: []const u8) !void {
    var buf: [td.session.state.serialized_size]u8 = undefined;
    @memset(&buf, 0xaa);
    @memcpy(buf[0..@min(input.len, buf.len)], input[0..@min(input.len, buf.len)]);
    const st = td.session.State.deserialize(&buf) catch return;
    var out: [td.session.state.serialized_size]u8 = undefined;
    st.serialize(&out);
    try std.testing.expectEqualSlices(u8, &buf, &out);
}

fn fuzzSessionLoad(_: void, smith: *Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    try sessionLoadImpl(buf[0..smith.slice(&buf)]);
}

test "fuzz corpus: session-state loading" {
    // A genuinely valid record must round-trip; single-bit flips of it
    // must be rejected (the CRC covers every payload byte and detects
    // all single-bit errors).
    var good: [td.session.state.serialized_size]u8 = undefined;
    var key = td.mtproto.AuthKey{
        .key = auth_key,
        .id = undefined,
        .aux_hash = undefined,
        .server_salt = undefined,
    };
    key.id = crypto.authKeyId(&auth_key);
    for (&key.aux_hash, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    for (&key.server_salt, 0..) |*b, i| b.* = @truncate(i *% 13 +% 3);
    (td.session.State{
        .environment = .production,
        .dc = 2,
        .auth_key = key,
        .session_id = 0x0123_4567_89ab_cdef,
        .last_msg_id = (@as(i64, 1_700_000_000) << 32) | 64,
        .content_count = 3,
        .remote_content_count = 0,
    }).serialize(&good);
    try sessionLoadImpl(&good);
    for (0..good.len) |i| {
        var flipped = good;
        flipped[i] ^= 0x01;
        if (td.session.State.deserialize(&flipped)) |_| {
            return error.TestUnexpectedResult; // CRC must catch every single-bit flip
        } else |_| {}
    }
    try sessionLoadImpl(&.{});
    // The valid record must seed the corpus from a runtime-built buffer:
    // `entry` is comptime-only, and `good` exists only at runtime.
    var good_seed: [4 + good.len]u8 = undefined;
    std.mem.writeInt(u32, good_seed[0..4], @intCast(good.len), .little);
    @memcpy(good_seed[4..], &good);
    try std.testing.fuzz({}, fuzzSessionLoad, .{
        .corpus = &.{ good_seed[0..], entry("TDZS") },
    });
}

// -------------------------------------------------- transport framing

/// Hostile bytes as frame headers through the pure codec.
fn framingImpl(input: []const u8) !void {
    if (input.len < 8) return;
    var hdr: [8]u8 = undefined;
    @memcpy(&hdr, input[0..8]);
    const parsed = td.transport.tcp_full.Codec.parseHeader(&hdr);
    const payload_len = td.transport.tcp_full.Codec.validate(parsed, 16 << 20) catch return;
    sink +%= payload_len;
}

fn fuzzFraming(_: void, smith: *Smith) anyerror!void {
    var buf: [64]u8 = undefined;
    try framingImpl(buf[0..smith.slice(&buf)]);
}

test "fuzz corpus: transport framing codec" {
    try framingImpl(&([_]u8{0xff} ** 8));
    try framingImpl(&([_]u8{0} ** 8));
    try framingImpl(&([_]u8{ 0x0d, 0xf0, 0xad, 0xba, 1, 2, 3, 4 }));
    try std.testing.fuzz({}, fuzzFraming, .{});
}
