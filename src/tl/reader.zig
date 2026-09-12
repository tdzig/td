//! TL binary reader primitives.
//!
//! Counterpart to `Writer`: reads the Type Language wire format defined at
//! https://core.telegram.org/mtproto/serialize. All reads are **borrowing** —
//! `readString`/`readBytes` return slices into the input buffer, so no
//! allocation happens outside the explicitly-allocated vector helpers.

const std = @import("std");
const TlError = @import("../errors.zig").TlError;

pub const bool_true_id: u32 = 0x997275b5;
pub const bool_false_id: u32 = 0xbc799737;
pub const vector_constructor_id: u32 = 0x1cb5c415;

/// Bounds-checked cursor over TL-encoded bytes.
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn remaining(self: *const Reader) usize {
        return self.data.len - self.pos;
    }

    fn take(self: *Reader, n: usize) TlError![]const u8 {
        if (self.remaining() < n) return error.EndOfStream;
        const s = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    pub fn readUInt(self: *Reader) TlError!u32 {
        const b = try self.take(4);
        return @as(u32, b[0]) | (@as(u32, b[1]) << 8) | (@as(u32, b[2]) << 16) | (@as(u32, b[3]) << 24);
    }

    pub fn readInt(self: *Reader) TlError!i32 {
        return @bitCast(try self.readUInt());
    }

    /// Constructor id as an exact unsigned 32-bit value.
    pub fn readConstructorId(self: *Reader) TlError!u32 {
        return self.readUInt();
    }

    pub fn readLong(self: *Reader) TlError!i64 {
        const b = try self.take(8);
        var v: u64 = 0;
        var i: usize = 8;
        while (i > 0) {
            i -= 1;
            v = (v << 8) | b[i];
        }
        return @bitCast(v);
    }

    pub fn readInt128(self: *Reader) TlError![16]u8 {
        const b = try self.take(16);
        var out: [16]u8 = undefined;
        @memcpy(&out, b);
        return out;
    }

    pub fn readInt256(self: *Reader) TlError![32]u8 {
        const b = try self.take(32);
        var out: [32]u8 = undefined;
        @memcpy(&out, b);
        return out;
    }

    pub fn readDouble(self: *Reader) TlError!f64 {
        const b = try self.take(8);
        var v: u64 = 0;
        var i: usize = 8;
        while (i > 0) {
            i -= 1;
            v = (v << 8) | b[i];
        }
        return @bitCast(v);
    }

    /// Reads `boolTrue`/`boolFalse`; any other id is `error.InvalidValue`.
    pub fn readBool(self: *Reader) TlError!bool {
        const id = try self.readUInt();
        return switch (id) {
            bool_true_id => true,
            bool_false_id => false,
            else => error.InvalidValue,
        };
    }

    fn readLengthPrefixed(self: *Reader) TlError![]const u8 {
        const first = (try self.take(1))[0];
        var length: usize = first;
        var prefix_len: usize = 1;
        if (first == 0xfe) {
            const b = try self.take(3);
            prefix_len = 4;
            length = @as(usize, b[0]) | (@as(usize, b[1]) << 8) | (@as(usize, b[2]) << 16);
        }
        if (length > self.remaining()) return error.InvalidLength;
        const payload = try self.take(length);
        const pad = (4 - ((length + prefix_len) % 4)) % 4;
        _ = try self.take(pad);
        return payload;
    }

    /// Borrows a slice into the input buffer; no allocation.
    pub fn readString(self: *Reader) TlError![]const u8 {
        return self.readLengthPrefixed();
    }

    /// Borrows a slice into the input buffer; no allocation.
    pub fn readBytes(self: *Reader) TlError![]const u8 {
        return self.readLengthPrefixed();
    }

    /// Borrows `n` raw bytes with no TL framing (used for pre-serialized
    /// payloads such as message-container inner bodies).
    pub fn readRaw(self: *Reader, n: usize) TlError![]const u8 {
        return self.take(n);
    }

    /// Element count word of a vector body.
    pub fn readVectorLength(self: *Reader) TlError!usize {
        return @intCast(try self.readUInt());
    }

    /// Reads a `vector#1cb5c415` of 32-bit ints. The result is allocated with
    /// `allocator` and owned by the caller.
    pub fn readVectorOfInt(self: *Reader, allocator: std.mem.Allocator) TlError![]i32 {
        return self.readVectorInto(allocator, i32, readInt);
    }

    pub fn readVectorOfLong(self: *Reader, allocator: std.mem.Allocator) TlError![]i64 {
        return self.readVectorInto(allocator, i64, readLong);
    }

    /// Reads a `vector#1cb5c415` of strings. The slice and (for non-empty
    /// strings) nothing else is allocated — the strings themselves borrow
    /// from the input. Caller owns the returned slice.
    pub fn readVectorOfString(self: *Reader, allocator: std.mem.Allocator) TlError![][]const u8 {
        return self.readVectorInto(allocator, []const u8, readString);
    }

    /// Generic vector decoder: verifies the vector constructor id, reads the
    /// count, then decodes `count` elements with `readElement`. Used by the
    /// concrete helpers above and by future generated code.
    pub fn readVectorInto(
        self: *Reader,
        allocator: std.mem.Allocator,
        comptime Elem: type,
        readElement: *const fn (*Reader) TlError!Elem,
    ) TlError![]Elem {
        const id = try self.readUInt();
        if (id != vector_constructor_id) return error.InvalidValue;
        const count = try self.readVectorLength();
        // Every TL wire element occupies at least four bytes, so a count
        // above remaining/4 cannot be backed by the input: refusing it
        // here keeps a hostile 4-byte header from requesting a
        // multi-gigabyte allocation (same guard as rpc/decode.zig).
        if (count > self.remaining() / 4) return error.InvalidLength;
        const out = allocator.alloc(Elem, count) catch return error.OutOfMemory;
        errdefer allocator.free(out);
        for (out) |*slot| slot.* = try readElement(self);
        return out;
    }
};

test "int boundary values" {
    var r = Reader.init(&.{
        0x00, 0x00, 0x00, 0x80, // INT32_MIN
        0xff, 0xff, 0xff, 0x7f, // INT32_MAX
    });
    try std.testing.expectEqual(std.math.minInt(i32), try r.readInt());
    try std.testing.expectEqual(std.math.maxInt(i32), try r.readInt());
}

test "long boundary values" {
    var r = Reader.init(&.{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, // INT64_MAX
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // INT64_MIN
    });
    try std.testing.expectEqual(std.math.maxInt(i64), try r.readLong());
    try std.testing.expectEqual(std.math.minInt(i64), try r.readLong());
}

test "truncated int" {
    var r = Reader.init(&.{ 0x01, 0x02, 0x03 });
    try std.testing.expectError(error.EndOfStream, r.readInt());
}

test "malformed bool" {
    var r = Reader.init(&.{ 0xde, 0xad, 0xbe, 0xef });
    try std.testing.expectError(error.InvalidValue, r.readBool());
}

test "string length beyond input" {
    var r = Reader.init(&.{ 10, 'a' });
    try std.testing.expectError(error.InvalidLength, r.readString());
}

test "string missing padding" {
    var r = Reader.init(&.{ 2, 'a', 'b' }); // len 2 needs 1 pad byte
    try std.testing.expectError(error.EndOfStream, r.readString());
}

test "long string form (>= 254 bytes)" {
    const w = @import("writer.zig");
    var writer = w.Writer.init(std.testing.allocator);
    defer writer.deinit();
    const input = "a" ** 300; // 300 + 1 = 301, pad 3 -> total 4 + 300 + 3
    try writer.writeString(input);
    var r = Reader.init(writer.items());
    try std.testing.expectEqualStrings(input, try r.readString());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "double roundtrip" {
    const w = @import("writer.zig");
    var writer = w.Writer.init(std.testing.allocator);
    defer writer.deinit();
    try writer.writeDouble(-0.5);
    var r = Reader.init(writer.items());
    try std.testing.expectEqual(@as(f64, -0.5), try r.readDouble());
}

test "vector count beyond remaining input is refused before allocating" {
    // vector#1cb5c415 with count 0xffff_ffff backed by four bytes of
    // input: the old reader requested a ~16 GiB slice before failing.
    var r = Reader.init(&.{
        0x15, 0xc4, 0xb5, 0x1c, // vector constructor id
        0xff, 0xff, 0xff, 0xff, // claimed count
    });
    try std.testing.expectError(error.InvalidLength, r.readVectorOfInt(std.testing.allocator));
}

test "empty string needs its three padding bytes" {
    var full = Reader.init(&.{ 0, 0, 0, 0 });
    try std.testing.expectEqualStrings("", try full.readString());
    try std.testing.expectEqual(@as(usize, 0), full.remaining());

    // A length byte without the padding is a truncated value.
    var truncated = Reader.init(&.{0});
    try std.testing.expectError(error.EndOfStream, truncated.readString());
}

test "readVectorOfString refuses an impossible count and frees partial reads" {
    // A hostile count with eight bytes of input: refused before any
    // allocation, same guard as the int vector.
    var hostile = Reader.init(&.{
        0x15, 0xc4, 0xb5, 0x1c, // vector constructor id
        0xff, 0xff, 0xff, 0xff, // claimed count
        0x01, 'a', 0x00, 0x00, // one honest string follows
    });
    try std.testing.expectError(
        error.InvalidLength,
        hostile.readVectorOfString(std.testing.allocator),
    );

    // A count the input cannot back *element-wise*: the first string
    // reads, the second is truncated — the partially built slice must
    // be freed (the testing allocator fails the test on a leak).
    var truncated = Reader.init(&.{
        0x15, 0xc4, 0xb5, 0x1c, // vector constructor id
        0x02, 0x00, 0x00, 0x00, // count 2
        0x01, 'a', 0x00, 0x00, // "a"
        0xb0, // claims 176 bytes; four remain
    });
    try std.testing.expectError(
        error.InvalidLength,
        truncated.readVectorOfString(std.testing.allocator),
    );
}

test "readVectorOfString borrows from the input" {
    var r = Reader.init(&.{
        0x15, 0xc4, 0xb5, 0x1c, // vector constructor id
        0x02, 0x00, 0x00, 0x00, // count 2
        0x03, 'a', 'b', 'c', // "abc" (no padding needed)
        0x01, 'z', 0x00, 0x00, // "z" + 2 pad
    });
    const v = try r.readVectorOfString(std.testing.allocator);
    defer std.testing.allocator.free(v);
    try std.testing.expectEqual(@as(usize, 2), v.len);
    try std.testing.expectEqualStrings("abc", v[0]);
    try std.testing.expectEqualStrings("z", v[1]);
    // Zero-copy: the string bytes live inside the input buffer.
    const input_start = @intFromPtr(r.data.ptr);
    const input_end = input_start + r.data.len;
    for (v) |s| {
        try std.testing.expect(@intFromPtr(s.ptr) >= input_start);
        try std.testing.expect(@intFromPtr(s.ptr) + s.len <= input_end);
    }
}

test "readRaw bounds" {
    var r = Reader.init(&.{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, try r.readRaw(2));
    try std.testing.expectError(error.EndOfStream, r.readRaw(2));
    try std.testing.expectEqualSlices(u8, &.{3}, try r.readRaw(1));
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "fixed-size reads are all-or-nothing" {
    // Seven bytes: a long or double needs eight, everything bigger too.
    var r = Reader.init(&[_]u8{0} ** 7);
    try std.testing.expectError(error.EndOfStream, r.readLong());
    try std.testing.expectError(error.EndOfStream, r.readDouble());
    try std.testing.expectError(error.EndOfStream, r.readInt128());
    try std.testing.expectError(error.EndOfStream, r.readInt256());
    // A failed read consumes nothing.
    try std.testing.expectEqual(@as(usize, 7), r.remaining());

    // Fifteen bytes read longs fine but are one short for an int128.
    var r15 = Reader.init(&[_]u8{0} ** 15);
    _ = try r15.readLong();
    try std.testing.expectError(error.EndOfStream, r15.readInt128());
    try std.testing.expectEqual(@as(usize, 7), r15.remaining());
}
