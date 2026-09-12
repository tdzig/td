//! TCP "padded intermediate" transport — the intermediate framing with
//! 0..15 random padding bytes appended to every frame, obscuring the
//! payload length from passive observers.
//!
//! Wire format of one frame (integers little-endian):
//!
//!     +------+----...----+----...----+
//!     | tlen |  payload  |  padding  |
//!     +------+----...----+----...----+
//!       u32      bytes      0..15
//!
//! * Before anything else goes into a fresh connection, the client sends
//!   the four bytes `0xdddd_dddd`; the server never sends a tag back.
//! * `tlen` counts payload *and* padding together, most-significant bit
//!   clear (the quick-ack slot of the plain intermediate framing).
//! * Inbound frames are delivered **with** their padding: this layer
//!   moves opaque bytes, so stripping the padding is the consumer's job —
//!   the MTProto message layer recovers the exact message length from the
//!   decrypted frame and ignores the tail (`mtproto.message.readEncrypted`
//!   truncates to the 16-byte block size, as the reference clients do).
//!   For the plain intermediate framing this never triggers: its length
//!   field is the exact payload length.
//! * The padding length is 0..15 random bytes; without a randomness
//!   source (`Options.random == null`) zero-length padding is sent, which
//!   is still a legal padded-intermediate frame.
//!
//! Reference: https://core.telegram.org/mtproto/mtproto-transports

const std = @import("std");
const transport = @import("mod.zig");
const framed = @import("tcp_framed.zig");
const intermediate = @import("tcp_intermediate.zig");

/// The padded framing is the intermediate framing plus padding: same tag
/// handling, same header code, same quick-ack slot.
pub const Codec = struct {
    /// Sent once at the head of a fresh client stream.
    pub const init_tag: []const u8 = "\xdd\xdd\xdd\xdd";
    pub const probe_len = intermediate.Codec.probe_len;
    pub const has_padding = true;

    pub const headerLen = intermediate.Codec.headerLen;
    pub const payloadLen = intermediate.Codec.payloadLen;
    pub const encodeHeader = intermediate.Codec.encodeHeader;
    pub const checkPayload = intermediate.Codec.checkPayload;

    /// 0..15 random padding bytes for a frame; zero without a randomness
    /// source.
    pub fn padLen(random: ?std.Random, _: usize) usize {
        const r = random orelse return 0;
        return r.uintLessThan(usize, 16);
    }
};

pub const TcpPaddedIntermediate = framed.Framed(Codec);
pub const Options = framed.Options;

// ---------------------------------------------------------------- tests

test "padded codec: tag and shared framing" {
    try std.testing.expectEqualSlices(u8, "\xdd\xdd\xdd\xdd", Codec.init_tag);
    // Same header code as the plain intermediate framing.
    var out: [4]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        intermediate.Codec.encodeHeader(24, &out),
        Codec.encodeHeader(24, &out),
    );
    try std.testing.expectEqual(
        try intermediate.Codec.payloadLen(out[0..4]),
        try Codec.payloadLen(out[0..4]),
    );
    try std.testing.expectError(
        error.InvalidFrame,
        Codec.payloadLen(&[_]u8{ 0, 0, 0, 0x80 }),
    );
}

test "padded codec: padding stays within 0..15" {
    // Without a randomness source: zero-length padding.
    try std.testing.expectEqual(@as(usize, 0), Codec.padLen(null, 64));

    var prng = std.Random.DefaultPrng.init(0xfeed);
    const random = prng.random();
    for (0..64) |_| {
        const pad = Codec.padLen(random, 64);
        try std.testing.expect(pad < 16);
    }
}
