//! TL binary writer primitives.
//!
//! Encodes values in the byte format defined by the Type Language:
//! fixed-width integers little-endian, strings/bytes length-prefixed and
//! padded to a multiple of four bytes, booleans as the `boolTrue#997275b5` /
//! `boolFalse#bc799737` constructor ids.
//! See https://core.telegram.org/mtproto/serialize.

const std = @import("std");
const TlError = @import("../errors.zig").TlError;

pub const bool_true_id: u32 = 0x997275b5;
pub const bool_false_id: u32 = 0xbc799737;

/// Maximum string/bytes length representable by the TL length prefix
/// (3 bytes after the 0xfe marker).
pub const max_blob_len: usize = 0x00ff_ffff;

/// Growable output buffer for TL-encoded values.
///
/// The writer owns `allocator`; callers must `deinit()` (or `toOwnedSlice()`)
/// exactly once. No hidden allocators are used.
pub const Writer = struct {
    allocator: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) Writer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(self.allocator);
    }

    /// Number of bytes written so far.
    pub fn len(self: *const Writer) usize {
        return self.buf.items.len;
    }

    /// View of the encoded bytes written so far.
    pub fn items(self: *const Writer) []const u8 {
        return self.buf.items;
    }

    /// Transfers ownership of the encoded bytes to the caller.
    /// The writer is reset to an empty state and remains usable.
    pub fn toOwnedSlice(self: *Writer) TlError![]u8 {
        return self.buf.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
    }

    fn appendSlice(self: *Writer, bytes: []const u8) TlError!void {
        self.buf.appendSlice(self.allocator, bytes) catch return error.OutOfMemory;
    }

    /// Raw 32-bit little-endian word (also used for constructor ids).
    pub fn writeUInt(self: *Writer, value: u32) TlError!void {
        const b = [4]u8{
            @truncate(value),
            @truncate(value >> 8),
            @truncate(value >> 16),
            @truncate(value >> 24),
        };
        try self.appendSlice(&b);
    }

    /// Write a constructor id exactly as the unsigned 32-bit value from the schema.
    pub fn writeConstructorId(self: *Writer, id: u32) TlError!void {
        try self.writeUInt(id);
    }

    pub fn writeInt(self: *Writer, value: i32) TlError!void {
        try self.writeUInt(@bitCast(value));
    }

    pub fn writeLong(self: *Writer, value: i64) TlError!void {
        const v: u64 = @bitCast(value);
        const b = [8]u8{
            @truncate(v),
            @truncate(v >> 8),
            @truncate(v >> 16),
            @truncate(v >> 24),
            @truncate(v >> 32),
            @truncate(v >> 40),
            @truncate(v >> 48),
            @truncate(v >> 56),
        };
        try self.appendSlice(&b);
    }

    /// 128-bit big integer, encoded as 16 raw little-endian bytes.
    pub fn writeInt128(self: *Writer, value: [16]u8) TlError!void {
        try self.appendSlice(&value);
    }

    /// 256-bit big integer, encoded as 32 raw little-endian bytes.
    pub fn writeInt256(self: *Writer, value: [32]u8) TlError!void {
        try self.appendSlice(&value);
    }

    pub fn writeDouble(self: *Writer, value: f64) TlError!void {
        const v: u64 = @bitCast(value);
        const b = [8]u8{
            @truncate(v),
            @truncate(v >> 8),
            @truncate(v >> 16),
            @truncate(v >> 24),
            @truncate(v >> 32),
            @truncate(v >> 40),
            @truncate(v >> 48),
            @truncate(v >> 56),
        };
        try self.appendSlice(&b);
    }

    /// `boolTrue` / `boolFalse` constructor id.
    pub fn writeBool(self: *Writer, value: bool) TlError!void {
        try self.writeUInt(if (value) bool_true_id else bool_false_id);
    }

    fn writeLengthPrefixed(self: *Writer, data: []const u8) TlError!void {
        if (data.len > max_blob_len) return error.InvalidLength;
        // The padding must account for the whole field: the length marker
        // (one byte below 0xfe, four bytes from 0xfe up) plus the data.
        const prefix_len: usize = if (data.len < 0xfe) 1 else 4;
        const pad = (4 - ((data.len + prefix_len) % 4)) % 4;
        if (data.len < 0xfe) {
            try self.appendSlice(&.{@intCast(data.len)});
        } else {
            const l: u32 = @intCast(data.len);
            try self.appendSlice(&.{ 0xfe, @truncate(l), @truncate(l >> 8), @truncate(l >> 16) });
        }
        try self.appendSlice(data);
        if (pad > 0) {
            const zeros = [4]u8{ 0, 0, 0, 0 };
            try self.appendSlice(zeros[0..pad]);
        }
    }

    /// TL `string`. UTF-8 validation is the caller's responsibility —
    /// MTProto treats strings as opaque bytes at this layer.
    pub fn writeString(self: *Writer, value: []const u8) TlError!void {
        try self.writeLengthPrefixed(value);
    }

    pub fn writeBytes(self: *Writer, value: []const u8) TlError!void {
        try self.writeLengthPrefixed(value);
    }

    /// Appends raw bytes with no TL framing (used for pre-serialized
    /// payloads such as message-container inner bodies).
    pub fn writeRaw(self: *Writer, value: []const u8) TlError!void {
        try self.appendSlice(value);
    }

    /// Header word of a `vector` body (the `vector#1cb5c415` constructor id
    /// is usually written first, then this element count).
    pub fn writeVectorLength(self: *Writer, count: usize) TlError!void {
        if (count > max_blob_len) return error.InvalidLength;
        try self.writeUInt(@intCast(count));
    }

    /// Convenience: writes the `vector` constructor id, element count and
    /// `count` 32-bit ints.
    pub fn writeVectorOfInt(self: *Writer, values: []const i32) TlError!void {
        try self.writeUInt(vector_constructor_id);
        try self.writeVectorLength(values.len);
        for (values) |v| try self.writeInt(v);
    }

    /// Convenience: writes the `vector` constructor id, element count and
    /// `count` 64-bit longs.
    pub fn writeVectorOfLong(self: *Writer, values: []const i64) TlError!void {
        try self.writeUInt(vector_constructor_id);
        try self.writeVectorLength(values.len);
        for (values) |v| try self.writeLong(v);
    }

    /// Convenience: writes the `vector` constructor id, element count and
    /// `count` strings.
    pub fn writeVectorOfString(self: *Writer, values: []const []const u8) TlError!void {
        try self.writeUInt(vector_constructor_id);
        try self.writeVectorLength(values.len);
        for (values) |v| try self.writeString(v);
    }
};

/// `vector#1cb5c415 {t:Type} # [ t ] = Vector t;`
pub const vector_constructor_id: u32 = 0x1cb5c415;

test "int roundtrip via reader" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeInt(-1);
    var r = reader.Reader.init(w.items());
    try std.testing.expectEqual(@as(i32, -1), try r.readInt());
}

test "bool roundtrip" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeBool(true);
    try w.writeBool(false);
    var r = reader.Reader.init(w.items());
    try std.testing.expectEqual(true, try r.readBool());
    try std.testing.expectEqual(false, try r.readBool());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "string padding" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeString("hello");
    try std.testing.expectEqualSlices(u8, &.{ 5, 'h', 'e', 'l', 'l', 'o', 0, 0 }, w.items());
    var r = reader.Reader.init(w.items());
    try std.testing.expectEqualStrings("hello", try r.readString());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "empty vector of ints" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeVectorOfInt(&.{});
    var r = reader.Reader.init(w.items());
    const v = try r.readVectorOfInt(std.testing.allocator);
    defer std.testing.allocator.free(v);
    try std.testing.expectEqual(@as(usize, 0), v.len);
}

test "empty string encodes as the length byte plus padding" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeString("");
    try std.testing.expectEqualSlices(u8, &.{0, 0, 0, 0}, w.items());
    var r = reader.Reader.init(w.items());
    try std.testing.expectEqualStrings("", try r.readString());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "length-prefix padding is exact for every length class" {
    const reader = @import("reader.zig");

    // Every residue class of the pad formula (0..8) plus a spread of
    // longer lengths: the encoded field is always prefix + data + pad,
    // 4-aligned, and reads back unchanged.
    var buf: [320]u8 = undefined;
    for ([_]usize{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 30, 31, 32, 33, 62, 63, 64, 100, 253 }) |len| {
        var w = Writer.init(std.testing.allocator);
        defer w.deinit();
        const data = buf[0..len];
        for (data, 0..) |*b, i| b.* = @truncate(i *% 251 +% len);
        try w.writeString(data);

        const prefix_len: usize = if (len < 0xfe) 1 else 4;
        const pad = (4 - ((len + prefix_len) % 4)) % 4;
        try std.testing.expectEqual(prefix_len + len + pad, w.len());
        try std.testing.expectEqual(@as(usize, 0), w.len() % 4);

        var r = reader.Reader.init(w.items());
        const back = try r.readString();
        try std.testing.expectEqualSlices(u8, data, back);
        try std.testing.expectEqual(@as(usize, 0), r.remaining());
    }

    // Exact short-form layouts: pad counts 2, 0 and 3 for lengths 1, 3, 4.
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    var off: usize = 0;
    try w.writeString("a");
    try std.testing.expectEqualSlices(u8, &.{ 1, 'a', 0, 0 }, w.items()[off..]);
    off += 4;
    try w.writeString("abc");
    try std.testing.expectEqualSlices(u8, &.{ 3, 'a', 'b', 'c' }, w.items()[off..]);
    off += 4;
    try w.writeString("abcd");
    try std.testing.expectEqualSlices(u8, &.{ 4, 'a', 'b', 'c', 'd', 0, 0, 0 }, w.items()[off..]);
}

test "0xfe boundary between the short and long string forms" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();

    // 253 is the last length with a one-byte prefix, 254 the first with
    // the 0xfe marker — the classic off-by-one seam. Encoded sizes:
    // 253 → 1+253+2, 254 → 4+254+2, 255 → 4+255+1.
    var off: usize = 0;
    var total: usize = 0;
    inline for ([_]usize{ 253, 254, 255 }) |len| {
        const prefix_len: usize = if (len < 0xfe) 1 else 4;
        const pad = (4 - ((len + prefix_len) % 4)) % 4;
        try w.writeString("a" ** len);
        try std.testing.expectEqual(@as(u8, if (len < 0xfe) len else 0xfe), w.items()[off]);
        try std.testing.expectEqualSlices(u8, "a" ** len, w.items()[off + prefix_len ..][0..len]);
        off += prefix_len + len + pad;
        total += prefix_len + len + pad;
    }
    try std.testing.expectEqual(total, off);
    try std.testing.expectEqual(@as(usize, total), w.len());

    var r = reader.Reader.init(w.items());
    inline for ([_]usize{ 253, 254, 255 }) |len| {
        const s = try r.readString();
        try std.testing.expectEqual(@as(usize, len), s.len);
        try std.testing.expectEqualSlices(u8, "a" ** len, s);
    }
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "long-form length uses all three bytes little-endian" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();

    // A length whose 24-bit encoding has distinct non-zero bytes.
    const data_len = 0x0f_0e_0d;
    const data = try std.testing.allocator.alloc(u8, data_len);
    defer std.testing.allocator.free(data);
    @memset(data, 0x5a);
    try w.writeBytes(data);
    try std.testing.expectEqualSlices(u8, &.{ 0xfe, 0x0d, 0x0e, 0x0f }, w.items()[0..4]);

    var r = reader.Reader.init(w.items());
    const back = try r.readBytes();
    try std.testing.expectEqual(data_len, back.len);
    // Borrowed from the writer's buffer, directly after the 4-byte prefix.
    try std.testing.expect(back.ptr == w.items().ptr + 4);
    // The writer emitted prefix + data + pad; the reader consumed it all.
    const pad = (4 - ((data_len + 4) % 4)) % 4;
    try std.testing.expectEqual(4 + data_len + pad, w.len());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "maximum string length round-trips and one byte more is refused" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();

    const data = try std.testing.allocator.alloc(u8, max_blob_len);
    defer std.testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 7);
    try w.writeString(data);

    var r = reader.Reader.init(w.items());
    const back = try r.readString();
    try std.testing.expectEqual(max_blob_len, back.len);
    try std.testing.expectEqualSlices(u8, data[123..133], back[123..133]);

    var w2 = Writer.init(std.testing.allocator);
    defer w2.deinit();
    const too_long = try std.testing.allocator.alloc(u8, max_blob_len + 1);
    defer std.testing.allocator.free(too_long);
    try std.testing.expectError(error.InvalidLength, w2.writeString(too_long));
    try std.testing.expectEqual(@as(usize, 0), w2.len()); // nothing was appended
}

test "writeVectorLength refuses counts beyond the u24 range" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeVectorLength(max_blob_len);
    var probe = reader.Reader.init(w.items());
    try std.testing.expectEqual(@as(usize, max_blob_len), try probe.readVectorLength());
    try std.testing.expectError(error.InvalidLength, w.writeVectorLength(max_blob_len + 1));
}

test "toOwnedSlice transfers the buffer and leaves the writer usable" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeUInt(0xdead_beef);
    const owned = try w.toOwnedSlice();
    defer std.testing.allocator.free(owned);
    try std.testing.expectEqualSlices(u8, &.{ 0xef, 0xbe, 0xad, 0xde }, owned);
    try std.testing.expectEqual(@as(usize, 0), w.len());

    // The writer keeps working after the hand-off.
    try w.writeInt(-1);
    try std.testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff }, w.items());
}

test "long, int, constructor id and double emit exact little-endian bytes" {
    const reader = @import("reader.zig");
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();

    try w.writeLong(@bitCast(@as(u64, 0x0123_4567_89ab_cdef)));
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 },
        w.items()[0..8],
    );
    try w.writeLong(std.math.minInt(i64));
    try w.writeLong(std.math.maxInt(i64));
    try w.writeLong(-1);
    try w.writeInt(std.math.minInt(i32));
    try w.writeInt(std.math.maxInt(i32));
    try w.writeConstructorId(0xffff_ffff);
    // 1.5 = 0x3FF8000000000000, -2.25 = 0xC002000000000000.
    try w.writeDouble(1.5);
    try w.writeDouble(-2.25);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 0, 0, 0xf8, 0x3f, 0, 0, 0, 0, 0, 0, 2, 0xc0 },
        w.items()[w.len() - 16 ..],
    );

    var r = reader.Reader.init(w.items());
    try std.testing.expectEqual(@as(i64, @bitCast(@as(u64, 0x0123_4567_89ab_cdef))), try r.readLong());
    try std.testing.expectEqual(std.math.minInt(i64), try r.readLong());
    try std.testing.expectEqual(std.math.maxInt(i64), try r.readLong());
    try std.testing.expectEqual(@as(i64, -1), try r.readLong());
    try std.testing.expectEqual(std.math.minInt(i32), try r.readInt());
    try std.testing.expectEqual(std.math.maxInt(i32), try r.readInt());
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), try r.readConstructorId());
    try std.testing.expectEqual(@as(f64, 1.5), try r.readDouble());
    try std.testing.expectEqual(@as(f64, -2.25), try r.readDouble());
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}
