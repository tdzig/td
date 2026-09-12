//! Transport layer: framed message pipes over network connections.
//!
//! A transport moves *complete payload frames* between the client and a
//! Telegram server. Framing — length prefixes, sequence numbers, checksums,
//! any transport handshake bytes — is entirely the transport's business.
//! Encryption, message ids, acks, and RPC semantics belong to the MTProto
//! session layer that sits on top, so transports accept and deliver opaque
//! payload bytes and never look at their meaning:
//!
//!     Transport (framing + connection lifecycle)
//!         ↓
//!     MTProto session (encryption + RPC)
//!
//! All four plain TCP framings from the official transport specification
//! are implemented, sharing the connection machinery:
//!
//!   - `tcp_abridged`    1-byte length prefixes — the lightest, and the
//!                       default everywhere (`TransportMode.abridged`);
//!   - `tcp_intermediate` 4-byte length prefixes;
//!   - `tcp_padded_intermediate` — intermediate plus 0..15 random padding
//!                       bytes per frame;
//!   - `tcp_full`        the original length/seq/crc32 framing.
//!
//! The first three share `tcp_framed.Framed`; each contributes a pure
//! `Codec` describing its wire format. Implementations live behind the
//! `Transport` vtable interface so that further transports (obfuscated
//! variants, HTTP, WebSocket) can be added without touching the callers,
//! and `Dialer` builds a transport of any TCP mode from one options knob.

const std = @import("std");

pub const tcp_full = @import("tcp_full.zig");
pub const tcp_abridged = @import("tcp_abridged.zig");
pub const tcp_intermediate = @import("tcp_intermediate.zig");
pub const tcp_padded_intermediate = @import("tcp_padded_intermediate.zig");
pub const tcp_framed = @import("tcp_framed.zig");

pub const TcpFull = tcp_full.TcpFull;
pub const TcpAbridged = tcp_abridged.TcpAbridged;
pub const TcpIntermediate = tcp_intermediate.TcpIntermediate;
pub const TcpPaddedIntermediate = tcp_padded_intermediate.TcpPaddedIntermediate;

/// Which TCP framing a connection speaks. Abridged is the library
/// default, so plain `Options{}`-style configuration needs nothing.
pub const TransportMode = enum {
    /// One-byte length prefixes (`0xef` stream tag); the lightest.
    abridged,
    /// Four-byte length prefixes (`0xeeee_eeee` stream tag).
    intermediate,
    /// Intermediate framing plus 0..15 random padding bytes per frame
    /// (`0xdddd_dddd` stream tag).
    padded_intermediate,
    /// The original length/seq/crc32 framing (no stream tag).
    full,
};

/// Storage for a dialable plain-TCP transport of any mode: the value a
/// connection owner keeps on the side so its `Transport` handle stays
/// valid. `connman.Manager` and the client's handshake path both own one.
pub const Dialer = union(TransportMode) {
    abridged: TcpAbridged,
    intermediate: TcpIntermediate,
    padded_intermediate: TcpPaddedIntermediate,
    full: TcpFull,

    /// Builds a disconnected transport of `mode` over `endpoint`. `opts`
    /// is the shared TCP knob (`tcp_full.Options`: payload cap and the
    /// three timeouts; `verify_sequence` applies to the full mode only),
    /// and `random` feeds the padded transport's frame padding.
    pub fn init(endpoint: Endpoint, transport_mode: TransportMode, opts: tcp_full.Options, random: ?std.Random) Dialer {
        return switch (transport_mode) {
            .abridged => .{ .abridged = TcpAbridged.init(endpoint, .{
                .max_payload = opts.max_payload,
                .connect_timeout = opts.connect_timeout,
                .read_timeout = opts.read_timeout,
                .write_timeout = opts.write_timeout,
            }) },
            .intermediate => .{ .intermediate = TcpIntermediate.init(endpoint, .{
                .max_payload = opts.max_payload,
                .connect_timeout = opts.connect_timeout,
                .read_timeout = opts.read_timeout,
                .write_timeout = opts.write_timeout,
            }) },
            .padded_intermediate => .{ .padded_intermediate = TcpPaddedIntermediate.init(endpoint, .{
                .max_payload = opts.max_payload,
                .connect_timeout = opts.connect_timeout,
                .read_timeout = opts.read_timeout,
                .write_timeout = opts.write_timeout,
                .random = random,
            }) },
            .full => .{ .full = TcpFull.init(endpoint, opts) },
        };
    }

    /// The active mode.
    pub fn mode(self: *const Dialer) TransportMode {
        return std.meta.activeTag(self.*);
    }

    /// The type-erased transport handle; borrows this union, which must
    /// not move while the handle is live.
    pub fn transport(self: *Dialer) Transport {
        return switch (self.*) {
            inline else => |*t| t.transport(),
        };
    }
};

/// Where to connect: an IP literal or DNS host name plus a TCP port.
/// The host bytes are borrowed from the caller, not copied.
pub const Endpoint = struct {
    host: []const u8,
    port: u16,
};

/// Errors surfaced by every transport operation. After a connection-level
/// failure (`Disconnected`, `ConnectionReset`, `IoFailed`, or a framing
/// violation), the transport is closed by the implementation and must be
/// reconnected before further use; `error.TimedOut` raised before any frame
/// byte was consumed leaves the connection usable.
pub const Error = error{
    OutOfMemory,

    // Connection lifecycle.
    /// `connect` was called while a connection is already established.
    AlreadyConnected,
    /// The operation requires a connection that is not currently
    /// established.
    NotConnected,

    // Connection establishment.
    /// The host name could not be resolved to an address.
    ResolveFailed,
    /// The remote refused the connection.
    ConnectionRefused,
    /// connect/read/write exceeded its configured timeout.
    TimedOut,
    /// The connection attempt failed for another reason (unreachable
    /// network, exhausted fd quota, ...).
    ConnectFailed,

    // Established-connection failures.
    /// The peer closed the connection, possibly mid-frame.
    Disconnected,
    /// The connection was reset by the peer.
    ConnectionReset,
    /// Unclassified socket-level failure.
    IoFailed,

    // Framing.
    /// Malformed frame: impossible length, checksum mismatch, or (when
    /// enabled) a sequence-number mismatch.
    InvalidFrame,
    /// Frame payload exceeds the configured maximum.
    MessageTooLarge,
};

/// Type-erased transport interface. Implementations store their own state
/// and expose a vtable; `io` is passed per call so one instance can be
/// driven from whatever `std.Io` the host application provides.
pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Establishes the connection described by the implementation's
        /// endpoint/options. Must fail with `error.AlreadyConnected` if a
        /// connection is currently established.
        connect: *const fn (ctx: *anyopaque, io: std.Io) Error!void,
        /// Drops the connection (if any). Idempotent.
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
        /// Sends one complete payload frame.
        write: *const fn (ctx: *anyopaque, io: std.Io, payload: []const u8) Error!void,
        /// Receives one complete payload frame; the returned slice is
        /// allocated with `allocator` and owned by the caller.
        read: *const fn (ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator) Error![]u8,
        /// Whether a connection is currently established and not known to
        /// be broken.
        isConnected: *const fn (ctx: *anyopaque) bool,
    };

    pub fn connect(self: Transport, io: std.Io) Error!void {
        return self.vtable.connect(self.ctx, io);
    }

    pub fn close(self: Transport, io: std.Io) void {
        self.vtable.close(self.ctx, io);
    }

    pub fn write(self: Transport, io: std.Io, payload: []const u8) Error!void {
        return self.vtable.write(self.ctx, io, payload);
    }

    /// Receives one frame; the payload slice is allocated with `allocator`
    /// and owned by the caller. An empty payload yields an empty slice.
    pub fn read(self: Transport, io: std.Io, allocator: std.mem.Allocator) Error![]u8 {
        return self.vtable.read(self.ctx, io, allocator);
    }

    pub fn isConnected(self: Transport) bool {
        return self.vtable.isConnected(self.ctx);
    }

    /// Drops the current connection (if any) and re-establishes it with the
    /// same endpoint and options. Framing state (sequence numbers, any
    /// partially consumed frame) resets to a fresh session, exactly as
    /// after `init`.
    pub fn reconnect(self: Transport, io: std.Io) Error!void {
        self.close(io);
        return self.connect(io);
    }
};

test {
    _ = @import("tcp_full.zig");
    _ = @import("tcp_abridged.zig");
    _ = @import("tcp_intermediate.zig");
    _ = @import("tcp_padded_intermediate.zig");
    _ = @import("tcp_framed.zig");
}

test "dialer builds the requested mode" {
    const ep = Endpoint{ .host = "127.0.0.1", .port = 443 };
    inline for (@typeInfo(TransportMode).@"enum".fields) |f| {
        const want: TransportMode = @enumFromInt(f.value);
        var d = Dialer.init(ep, want, .{}, null);
        try std.testing.expectEqual(want, d.mode());
        try std.testing.expect(!d.transport().isConnected());
    }
}
