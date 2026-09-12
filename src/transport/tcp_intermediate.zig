//! TCP "intermediate" transport — four-byte length prefixes over a tagged
//! stream, used when 4-byte data alignment matters.
//!
//! Wire format of one frame (integers little-endian):
//!
//!     +------+----...----+
//!     | len  |  payload  |
//!     +------+----...----+
//!       u32
//!
//! * Before anything else goes into a fresh connection, the client sends
//!   the four bytes `0xeeee_eeee`; the server never sends a tag back.
//! * `len` counts the payload only (the length field itself excluded),
//!   with the most-significant bit clear.
//! * A length with the most-significant bit set is the quick-ack slot —
//!   this client never requests quick acks, so such a "frame" is rejected
//!   as `error.InvalidFrame`.
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
    pub const init_tag: []const u8 = "\xee\xee\xee\xee";
    /// The whole length prefix arrives as one unit.
    pub const probe_len = 4;
    pub const has_padding = false;

    /// Every frame carries the full 4-byte header.
    pub fn headerLen(_: *const [probe_len]u8) Error!usize {
        return 4;
    }

    /// Payload length from the header; `error.InvalidFrame` marks the
    /// quick-ack slot (most-significant bit set), which is never a
    /// payload length.
    pub fn payloadLen(header: []const u8) Error!usize {
        const v = std.mem.readInt(u32, header[0..4], .little);
        if (v >> 31 != 0) return error.InvalidFrame;
        return v;
    }

    /// The 4-byte little-endian length prefix for a frame of
    /// `payload_len` bytes. (For the padded transport the same code
    /// encodes the padded total.)
    pub fn encodeHeader(payload_len: usize, out: *[4]u8) []const u8 {
        std.mem.writeInt(u32, out, @intCast(payload_len), .little);
        return out;
    }

    /// Outbound constraints: four-byte alignment, and the length field
    /// must keep its most-significant bit free.
    pub fn checkPayload(payload_len: usize) Error!void {
        if (payload_len % 4 != 0) return error.InvalidFrame;
        if (payload_len > std.math.maxInt(u31)) return error.MessageTooLarge;
    }
};

pub const TcpIntermediate = framed.Framed(Codec);
pub const Options = framed.Options;

// ---------------------------------------------------------------- tests

test "intermediate codec: header layout" {
    var out: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 8, 0, 0, 0 }, Codec.encodeHeader(8, &out));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, Codec.encodeHeader(0, &out));
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x00, 0x00, 0x00, 0x40 },
        Codec.encodeHeader(0x4000_0000, &out),
    );

    // Decode mirrors encode (checked on a fresh encode of the same value).
    var back: [4]u8 = undefined;
    _ = Codec.encodeHeader(8, &back);
    try std.testing.expectEqual(@as(usize, 8), try Codec.payloadLen(&back));
    try std.testing.expectEqual(@as(usize, 0x4000_0000), try Codec.payloadLen(out[0..4]));

    // An empty payload is a legal frame (length field 0).
    var zero: [4]u8 = undefined;
    _ = Codec.encodeHeader(0, &zero);
    try std.testing.expectEqual(@as(usize, 0), try Codec.payloadLen(&zero));
}

test "intermediate codec: quick-ack slot is never a length" {
    // 0x8000_0000 and 0xffff_ffff both have the most-significant bit set.
    try std.testing.expectError(
        error.InvalidFrame,
        Codec.payloadLen(&[_]u8{ 0, 0, 0, 0x80 }),
    );
    try std.testing.expectError(
        error.InvalidFrame,
        Codec.payloadLen(&[_]u8{ 0xff, 0xff, 0xff, 0xff }),
    );
}

test "intermediate codec: payload constraints" {
    try Codec.checkPayload(0);
    try Codec.checkPayload(4);
    // The largest four-byte-aligned length that keeps the msb clear.
    try Codec.checkPayload(std.math.maxInt(u31) - 3);

    // Not divisible by four.
    try std.testing.expectError(error.InvalidFrame, Codec.checkPayload(6));
    try std.testing.expectError(error.InvalidFrame, Codec.checkPayload(std.math.maxInt(u31)));
    // The most-significant bit of the length field stays clear.
    try std.testing.expectError(error.MessageTooLarge, Codec.checkPayload(std.math.maxInt(u31) + 1));
}
