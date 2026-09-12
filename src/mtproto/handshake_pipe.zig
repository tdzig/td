//! Adapts the type-erased `transport.Transport` frame pipe to the plain
//! byte-pipe interface the authorization-key handshake expects.
//!
//! The handshake is protocol-only code (no networking), so every caller
//! that runs it over a real connection goes through this shim —
//! `dc.manager.connect`, `td-keygen`, and the loopback tests.

const std = @import("std");
const handshake = @import("handshake.zig");
const transport = @import("../transport/mod.zig");

pub const HandshakePipe = struct {
    t: transport.Transport,
    io: std.Io,

    pub fn init(t: transport.Transport, io: std.Io) HandshakePipe {
        return .{ .t = t, .io = io };
    }

    fn sendFn(ctx: *anyopaque, frame: []const u8) handshake.Error!void {
        const self: *HandshakePipe = @ptrCast(@alignCast(ctx));
        self.t.write(self.io, frame) catch return error.Transport;
    }

    fn recvFn(ctx: *anyopaque, allocator: std.mem.Allocator) handshake.Error![]u8 {
        const self: *HandshakePipe = @ptrCast(@alignCast(ctx));
        return self.t.read(self.io, allocator) catch return error.Transport;
    }

    /// The handshake-side byte pipe backed by this adapter; the
    /// `HandshakePipe` must outlive every use of the returned value.
    pub fn pipe(self: *HandshakePipe) handshake.Transport {
        return .{ .ctx = self, .sendFn = sendFn, .recvFn = recvFn };
    }
};
