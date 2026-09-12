//! RPC result decoding: gzip inflation and a comptime-generic decoder that
//! turns raw result-object bytes into the types the generator emits.
//!
//! Telegram function results are not always a single generated union:
//! `users.getUsers = Vector<User>` returns a top-level `vector#1cb5c415`
//! whose elements are unions, `help.getNearestDc` returns a plain union and
//! some helpers return bare scalars (`Bool`, `long`, `Vector<int>`). The
//! generated per-constructor `deserialize` covers one object at a time; this
//! module adds the shapes around it:
//!
//!   * `Vector<T>` results map to native slices (`[]T`), decoded here by
//!     the same rules the generated code uses for vector fields;
//!   * elements of recursive TL types are pointer-boxed (`[]*T`), exactly
//!     like generated struct fields;
//!   * `gzip_packed#3072cfa1` wrappers are inflated before decoding.
//!
//! The type-driven dispatch mirrors the generator 1:1, so `T.Result` decls
//! emitted on function request structs are directly usable as `decode`
//! types.
//!
//! All decoding borrows strings/bytes from the input and allocates vector
//! storage (and recursive-type boxes) with the caller's allocator — the
//! same memory model as the generated code. An arena is the natural caller
//! (see `Client.wait`).

const std = @import("std");
const tl = @import("../tl/mod.zig");
const Reader = tl.Reader;

pub const Error = error{
    OutOfMemory,
    /// The bytes are not a complete, well-formed value of `T` (truncated,
    /// trailing garbage, wrong constructor id, ...).
    BadResponse,
    /// A `gzip_packed` payload failed to inflate (bad header, checksum,
    /// bitstream or truncated input).
    GzipInvalid,
    /// The inflated result exceeded the caller's size bound.
    ResponseTooLarge,
};

/// Inflates one complete gzip stream. `max_len` bounds the output (a
/// decompression bomb must not OOM the client before it can answer with
/// `error.ResponseTooLarge`). The gzip footer is verified: std's flate
/// reader consumes the stored CRC32/ISIZE but does not check them, so a
/// corrupted member must be rejected here.
pub fn inflateGzip(
    allocator: std.mem.Allocator,
    packed_data: []const u8,
    max_len: usize,
) Error![]u8 {
    var input: std.Io.Reader = .fixed(packed_data);
    var decompress: std.compress.flate.Decompress = .init(&input, .gzip, &.{});
    const out = decompress.reader.allocRemaining(allocator, .limited(max_len)) catch |err|
        return switch (err) {
            error.StreamTooLong => error.ResponseTooLarge,
            error.OutOfMemory => error.OutOfMemory,
            // ReadFailed carries the flate-level cause in `decompress.err`;
            // EndOfStream means the stream was truncated. Either way the
            // payload is not a valid gzip member.
            else => error.GzipInvalid,
        };
    errdefer allocator.free(out);
    switch (decompress.container_metadata) {
        .gzip => |m| {
            if (m.crc != std.hash.Crc32.hash(out)) return error.GzipInvalid;
            if (m.count != @as(u32, @truncate(out.len))) return error.GzipInvalid;
        },
        // Not a gzip container after all (truncated before the footer).
        else => return error.GzipInvalid,
    }
    return out;
}

/// Decodes exactly one value of type `T` from `bytes`, requiring the whole
/// input to be consumed. `T` is a generated union/struct type, a native
/// slice of them, or one of the scalar mappings (`bool`, `i32`, `i64`,
/// `f64`, `[]const u8`, `[16]u8`, `[32]u8`).
pub fn decode(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) Error!T {
    var r = Reader.init(bytes);
    const value = try decodeValue(T, allocator, &r);
    if (r.remaining() != 0) return error.BadResponse;
    return value;
}

/// Decodes one value of `T` from `r` without consuming-checking the rest.
pub fn decodeValue(comptime T: type, allocator: std.mem.Allocator, r: *Reader) Error!T {
    if (T == bool) return r.readBool() catch |e| return mapTl(e);
    if (T == i32) return r.readInt() catch |e| return mapTl(e);
    if (T == i64) return r.readLong() catch |e| return mapTl(e);
    if (T == f64) return r.readDouble() catch |e| return mapTl(e);
    if (T == []const u8) return r.readString() catch |e| return mapTl(e);

    switch (@typeInfo(T)) {
        .array => |arr| {
            if (arr.child == u8 and arr.len == 16) return r.readInt128() catch |e| return mapTl(e);
            if (arr.child == u8 and arr.len == 32) return r.readInt256() catch |e| return mapTl(e);
        },
        .pointer => |ptr| {
            if (ptr.size == .slice and ptr.child != u8) {
                // Vector<T> result: boxed `vector#1cb5c415`, count, elements.
                const id = r.readUInt() catch |e| return mapTl(e);
                if (id != tl.vector_constructor_id) return error.BadResponse;
                const count = r.readVectorLength() catch |e| return mapTl(e);
                // Every wire element occupies at least four bytes, so a
                // count larger than remaining/4 can only be an attempt to
                // OOM the decoder through the allocation below.
                if (count > r.remaining() / 4) return error.BadResponse;
                const out = allocator.alloc(ptr.child, count) catch return error.OutOfMemory;
                for (out) |*slot| {
                    slot.* = try decodeValue(ptr.child, allocator, r);
                }
                return out;
            }
            if (ptr.size == .one) {
                // Recursive-type element: heap-boxed, like generated fields.
                const boxed = allocator.create(ptr.child) catch return error.OutOfMemory;
                boxed.* = try decodeValue(ptr.child, allocator, r);
                return boxed;
            }
        },
        else => {},
    }

    if (comptime std.meta.hasFn(T, "deserialize")) {
        return T.deserialize(allocator, r) catch |e| return mapTl(e);
    }

    @compileError("rpc decode: unsupported result type " ++ @typeName(T));
}

fn mapTl(err: @import("../errors.zig").TlError) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        // EndOfStream/InvalidLength/InvalidValue: the bytes are not a
        // well-formed value of the expected result type.
        else => error.BadResponse,
    };
}

// ---------------------------------------------------------------- tests

const Writer = tl.Writer;
const api = @import("../api/mod.zig");

/// Builds one valid gzip member wrapping `data` in deflate "stored"
/// (uncompressed) blocks — spec-constructed byte by byte, so tests can
/// produce gzip without pulling in a compressor. Data beyond one block's
/// 65535-byte maximum is split into a sequence of stored blocks:
///
///   gzip header (10 bytes) | { stored-block header (BFINAL/BTYPE,
///   LEN, ~LEN) | raw data }* | CRC32 | ISIZE
pub fn buildGzipStored(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &.{ 0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03 });
    var rest = data;
    while (true) {
        const n: u16 = @intCast(@min(rest.len, 65535));
        const final = rest.len <= 65535;
        try out.append(allocator, if (final) 0x01 else 0x00); // BFINAL=bit0, BTYPE=00 (stored)
        var len: [2]u8 = undefined;
        std.mem.writeInt(u16, &len, n, .little);
        try out.appendSlice(allocator, &len);
        var nlen: [2]u8 = undefined;
        std.mem.writeInt(u16, &nlen, ~n, .little);
        try out.appendSlice(allocator, &nlen);
        try out.appendSlice(allocator, rest[0..n]);
        rest = rest[n..];
        if (final) break;
    }
    var crc: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc, std.hash.Crc32.hash(data), .little);
    try out.appendSlice(allocator, &crc);
    var isize_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &isize_bytes, @truncate(data.len), .little);
    try out.appendSlice(allocator, &isize_bytes);
    return out.toOwnedSlice(allocator);
}

test "inflateGzip: stored-block member roundtrip" {
    const data = "user#b1b8cc83 boolTrue#997275b5 — any bytes deflate stores verbatim";
    const gz = try buildGzipStored(std.testing.allocator, data);
    defer std.testing.allocator.free(gz);

    const plain = try inflateGzip(std.testing.allocator, gz, 1 << 20);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings(data, plain);
}

test "inflateGzip: fixed-huffman member (std test vector)" {
    // gzip member from the Zig std flate test suite: "Hello world\n".
    const gz = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03, // header
        0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, // deflate
        0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00,
        0xd5, 0xe0, 0x39, 0xb7, 0x0c, 0x00, 0x00, 0x00, // footer
    };
    const plain = try inflateGzip(std.testing.allocator, &gz, 1 << 20);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings("Hello world\n", plain);
}

test "inflateGzip rejects corrupt, truncated and oversized input" {
    const data = "aaaaaaaaaaaaaaaabbbbbbbbbbbb";
    const good = try buildGzipStored(std.testing.allocator, data);
    defer std.testing.allocator.free(good);

    // Corrupted payload flips the CRC32.
    var bad = try std.testing.allocator.dupe(u8, good);
    defer std.testing.allocator.free(bad);
    bad[15] ^= 0xff;
    try std.testing.expectError(
        error.GzipInvalid,
        inflateGzip(std.testing.allocator, bad, 1 << 20),
    );

    // Truncated member.
    try std.testing.expectError(
        error.GzipInvalid,
        inflateGzip(std.testing.allocator, good[0 .. good.len - 3], 1 << 20),
    );

    // Not gzip at all.
    try std.testing.expectError(
        error.GzipInvalid,
        inflateGzip(std.testing.allocator, "not gzip", 1 << 20),
    );

    // Decompression bomb bound: the limit fires before the allocation.
    try std.testing.expectError(
        error.ResponseTooLarge,
        inflateGzip(std.testing.allocator, good, data.len - 1),
    );
}

test "decode: scalars" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeBool(true);
    try w.writeInt(-42);
    try w.writeLong(@bitCast(@as(u64, 0xdead_beef_cafe_f00d)));
    try w.writeDouble(2.5);
    try w.writeString("hi");

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var r = Reader.init(w.items());
    try std.testing.expectEqual(true, try decodeValue(bool, arena, &r));
    try std.testing.expectEqual(@as(i32, -42), try decodeValue(i32, arena, &r));
    try std.testing.expectEqual(@as(i64, @bitCast(@as(u64, 0xdead_beef_cafe_f00d))), try decodeValue(i64, arena, &r));
    try std.testing.expectEqual(@as(f64, 2.5), try decodeValue(f64, arena, &r));
    try std.testing.expectEqualStrings("hi", try decodeValue([]const u8, arena, &r));
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "decode: generated union" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try (api.Bool{ .boolTrue = .{} }).serialize(&w);

    const value = try decode(api.Bool, std.testing.allocator, w.items());
    try std.testing.expect(value == .boolTrue);
}

test "decode: Vector<T> results (scalars, unions, pointer-boxed)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // vector<Bool> on the wire: ctor, count, boolTrue, boolFalse.
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeConstructorId(tl.vector_constructor_id);
    try w.writeVectorLength(2);
    try (api.Bool{ .boolTrue = .{} }).serialize(&w);
    try (api.Bool{ .boolFalse = .{} }).serialize(&w);

    const unboxed = try decode([]api.Bool, arena, w.items());
    try std.testing.expectEqual(@as(usize, 2), unboxed.len);
    try std.testing.expect(unboxed[0] == .boolTrue);
    try std.testing.expect(unboxed[1] == .boolFalse);

    // Pointer-boxed elements decode elementwise into heap boxes.
    const boxed = try decode([]*api.Bool, arena, w.items());
    try std.testing.expectEqual(@as(usize, 2), boxed.len);
    try std.testing.expect(boxed[1].* == .boolFalse);

    // vector<long> — the plain scalar element case.
    var w2 = Writer.init(std.testing.allocator);
    defer w2.deinit();
    try w2.writeConstructorId(tl.vector_constructor_id);
    try w2.writeVectorLength(3);
    try w2.writeLong(1);
    try w2.writeLong(-2);
    try w2.writeLong(3);
    const longs = try decode([]i64, arena, w2.items());
    try std.testing.expectEqualSlices(i64, &.{ 1, -2, 3 }, longs);
}

test "decode rejects malformed results" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try (api.Bool{ .boolTrue = .{} }).serialize(&w);

    // Trailing garbage after a complete value.
    const padded = try std.testing.allocator.alloc(u8, w.items().len + 1);
    defer std.testing.allocator.free(padded);
    @memcpy(padded[0..w.items().len], w.items());
    padded[w.items().len] = 0;
    try std.testing.expectError(error.BadResponse, decode(api.Bool, std.testing.allocator, padded));

    // Truncated value.
    try std.testing.expectError(error.BadResponse, decode(api.Bool, std.testing.allocator, w.items()[0..2]));

    // Wrong constructor id for the expected union.
    var w2 = Writer.init(std.testing.allocator);
    defer w2.deinit();
    try w2.writeInt(123);
    try std.testing.expectError(error.BadResponse, decode(api.Bool, std.testing.allocator, w2.items()));

    // Not a vector where one is expected.
    try std.testing.expectError(error.BadResponse, decode([]api.Bool, std.testing.allocator, w.items()));

    // Vector claiming far more elements than the input can hold. The
    // count is written raw: writeVectorLength would reject it up front.
    var w3 = Writer.init(std.testing.allocator);
    defer w3.deinit();
    try w3.writeConstructorId(tl.vector_constructor_id);
    try w3.writeInt(0x7fff_ffff);
    try w3.writeLong(1);
    try std.testing.expectError(error.BadResponse, decode([]i64, std.testing.allocator, w3.items()));
}
