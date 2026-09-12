//! TCP "abridged" transport — the lightest Telegram TCP framing, and the
//! library default.
//!
//! Wire format of one frame (integers little-endian):
//!
//!     +-+----...----+                payload/4 < 127
//!     |l|  payload  |
//!     +-+----...----+
//!     +----+------+------+----...----+   payload/4 >= 127
//!     |0x7f| len/4 |     payload    |
//!     +----+------+------+----...----+
//!        1     3
//!
//! * Before anything else goes into a fresh connection, the client sends
//!   the single byte `0xef`; the server never sends a tag back.
//! * Short form: one byte holding the payload length divided by four —
//!   so the payload is four-byte aligned and shorter than 127·4 bytes.
//! * Long form: `0x7f` followed by three bytes of payload/4, covering
//!   payloads up to (2^24 − 1)·4 bytes.
//! * A first inbound byte above `0x7f` is never a length (the space is
//!   reserved for obfuscated transports and quick-ack tokens, which this
//!   client never requests) and is rejected as `error.InvalidFrame`.
//!
//! Reference: https://core.telegram.org/mtproto/mtproto-transports

const std = @import("std");
const transport = @import("mod.zig");
const framed = @import("tcp_framed.zig");

const Error = transport.Error;

/// Pure framing helpers, kept free of sockets so the byte layout can be
/// tested without IO.
pub const Codec = struct {
    /// Sent once at the head of a fresh client stream.
    pub const init_tag: []const u8 = "\xef";
    /// The first byte decides between the short and the long form.
    pub const probe_len = 1;
    pub const has_padding = false;

    /// Total header size for the probe byte: 1, or 4 when the long-form
    /// marker `0x7f` announced three length bytes.
    pub fn headerLen(probe: *const [probe_len]u8) Error!usize {
        return switch (probe[0]) {
            0x7f => 4,
            0...0x7e => 1,
            else => error.InvalidFrame,
        };
    }

    /// Payload length from a complete header (1- or 4-byte forms).
    pub fn payloadLen(header: []const u8) Error!usize {
        return switch (header.len) {
            1 => @as(usize, header[0]) * 4,
            4 => (@as(usize, header[1]) | @as(usize, header[2]) << 8 | @as(usize, header[3]) << 16) * 4,
            else => unreachable,
        };
    }

    /// The 1- or 4-byte length prefix for a frame of `payload_len` bytes,
    /// written into `out`; the returned slice is the used prefix.
    pub fn encodeHeader(payload_len: usize, out: *[4]u8) []const u8 {
        const q = payload_len / 4;
        if (q < 0x7f) {
            out[0] = @intCast(q);
            return out[0..1];
        }
        out[0] = 0x7f;
        out[1] = @truncate(q);
        out[2] = @truncate(q >> 8);
        out[3] = @truncate(q >> 16);
        return out;
    }

    /// Outbound constraints: the payload divides into the length byte(s)
    /// only in four-byte units, and its quarter must fit the three
    /// long-form bytes.
    pub fn checkPayload(payload_len: usize) Error!void {
        if (payload_len % 4 != 0) return error.InvalidFrame;
        if (payload_len / 4 > 0xff_ffff) return error.MessageTooLarge;
    }
};

pub const TcpAbridged = framed.Framed(Codec);
pub const Options = framed.Options;

// ---------------------------------------------------------------- tests

test "abridged codec: short- and long-form header layout" {
    var out: [4]u8 = undefined;

    // 8-byte payload: one byte, the length divided by four.
    try std.testing.expectEqualSlices(u8, &[_]u8{0x02}, Codec.encodeHeader(8, &out));
    // The largest short-form payload: 126 · 4.
    try std.testing.expectEqualSlices(u8, &[_]u8{0x7e}, Codec.encodeHeader(126 * 4, &out));
    // payload/4 == 127 crosses into the long form.
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x7f, 0x7f, 0x00, 0x00 },
        Codec.encodeHeader(127 * 4, &out),
    );
    // Three little-endian length bytes.
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x7f, 0x56, 0x34, 0x12 },
        Codec.encodeHeader(0x12_34_56 * 4, &out),
    );
    // The empty payload is a legal frame (length byte 0).
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, Codec.encodeHeader(0, &out));

    // Decode mirrors encode, including across the form boundary.
    var long: [4]u8 = undefined;
    _ = Codec.encodeHeader(8, &long);
    try std.testing.expectEqual(@as(usize, 8), try Codec.payloadLen(long[0..1]));
    _ = Codec.encodeHeader(127 * 4, &long);
    try std.testing.expectEqual(@as(usize, 127 * 4), try Codec.payloadLen(&long));
    _ = Codec.encodeHeader(0x12_34_56 * 4, &long);
    try std.testing.expectEqual(@as(usize, 0x12_34_56 * 4), try Codec.payloadLen(&long));
}

test "abridged codec: probe classification" {
    try std.testing.expectEqual(@as(usize, 1), try Codec.headerLen(&.{0x00}));
    try std.testing.expectEqual(@as(usize, 1), try Codec.headerLen(&.{0x7e}));
    try std.testing.expectEqual(@as(usize, 4), try Codec.headerLen(&.{0x7f}));

    // 0x80..0xff: quick-ack tokens this client never requests, or
    // obfuscated-transport traffic — never a plain frame start.
    try std.testing.expectError(error.InvalidFrame, Codec.headerLen(&.{0x80}));
    try std.testing.expectError(error.InvalidFrame, Codec.headerLen(&.{0xef}));
    try std.testing.expectError(error.InvalidFrame, Codec.headerLen(&.{0xff}));
}

test "abridged codec: payload constraints" {
    try Codec.checkPayload(0);
    try Codec.checkPayload(4);
    try Codec.checkPayload(0xff_ffff * 4); // largest representable

    // Not divisible by four.
    try std.testing.expectError(error.InvalidFrame, Codec.checkPayload(3));
    try std.testing.expectError(error.InvalidFrame, Codec.checkPayload(505));
    // payload/4 no longer fits the three long-form bytes.
    try std.testing.expectError(error.MessageTooLarge, Codec.checkPayload(0x100_0000 * 4));
}
