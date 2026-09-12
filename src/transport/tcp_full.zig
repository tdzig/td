//! TCP "full" transport — the original Telegram TCP framing.
//!
//! Wire format of one frame (all integers little-endian):
//!
//!     +--------+--------+---------+--------+
//!     | length |   seq  | payload | crc32  |
//!     +--------+--------+---------+--------+
//!       u32       u32      bytes     u32
//!
//! * `length` counts the whole frame including itself: payload + 12.
//! * `seq` is a per-direction frame counter; the first frame of a connection
//!   is 0 and each subsequent frame increments it by one.
//! * `crc32` (the standard ISO-HDLC polynomial, as in zlib) covers the
//!   length, seq and payload bytes.
//!
//! Unlike the newer transports, "full" sends no initial protocol tag: the
//! first bytes on the wire are already a frame header. Its 12-byte overhead
//! and per-frame checksum are why clients moved to abridged/intermediate;
//! it is implemented first here because it is the reference framing of the
//! MTProto TCP transport family and carries no obfuscation or padding rules.
//!
//! Reference: https://core.telegram.org/mtproto/mtproto-transports

const std = @import("std");
const net = std.Io.net;
const builtin = @import("builtin");
const transport = @import("mod.zig");

const Endpoint = transport.Endpoint;
const Error = transport.Error;

/// Wire overhead of one frame: length (4) + seq (4) + crc32 (4).
pub const frame_overhead = 12;

/// Smallest valid frame: header and checksum around an empty payload.
pub const min_frame_len = frame_overhead;

pub const Options = struct {
    /// Maximum payload size in bytes, enforced both inbound (larger frames
    /// fail with `error.MessageTooLarge`) and outbound.
    max_payload: usize = 16 << 20,
    /// Verify that inbound sequence numbers increment by one starting from
    /// zero, failing with `error.InvalidFrame` on a mismatch. Telegram
    /// servers number frames correctly, but established clients
    /// traditionally do not check, so this is opt-in.
    verify_sequence: bool = false,
    /// Bound on the whole `connect` call, forwarded to the `Io` driver.
    /// The default blocking driver (`std.Io.Threaded`) does not implement
    /// connect timeouts and panics if one is requested — leave this null
    /// there.
    connect_timeout: ?std.Io.Duration = null,
    /// Bound on each `read` call, checked before every underlying socket
    /// operation: a `read` whose deadline expires before any frame byte was
    /// consumed returns `error.TimedOut` and leaves the connection usable;
    /// one that expires mid-frame (or hits a socket error) closes the
    /// connection, since the stream can no longer be framed reliably.
    ///
    /// With blocking drivers an in-flight socket read cannot be
    /// interrupted: a peer that never sends a byte stalls the call despite
    /// this timeout. Full in-flight cancellation requires an evented driver
    /// and belongs to the session layer above this one.
    read_timeout: ?std.Io.Duration = null,
    /// Bound on each `write` call, with the same deadline semantics as
    /// `read_timeout`. Any write error closes the connection, because a
    /// partially delivered frame desynchronizes the stream.
    write_timeout: ?std.Io.Duration = null,
};

/// Pure framing helpers, kept free of sockets so the byte layout can be
/// tested without IO.
pub const Codec = struct {
    /// The 8-byte frame header for `payload_len` payload bytes carrying
    /// sequence number `seq`.
    pub fn header(payload_len: usize, seq: u32) [8]u8 {
        var h: [8]u8 = undefined;
        std.mem.writeInt(u32, h[0..4], @intCast(payload_len + frame_overhead), .little);
        std.mem.writeInt(u32, h[4..8], seq, .little);
        return h;
    }

    /// The frame checksum over the header and payload bytes.
    pub fn checksum(h: *const [8]u8, payload: []const u8) u32 {
        var c = std.hash.Crc32.init();
        c.update(h);
        c.update(payload);
        return c.final();
    }

    /// A parsed frame header.
    pub const Header = struct {
        /// Total frame size on the wire, including this field.
        length: u32,
        /// Per-direction frame counter of the sender.
        seq: u32,
    };

    pub fn parseHeader(h: *const [8]u8) Header {
        return .{
            .length = std.mem.readInt(u32, h[0..4], .little),
            .seq = std.mem.readInt(u32, h[4..8], .little),
        };
    }

    /// Validates a parsed header against the payload limit and returns the
    /// payload length. `error.InvalidFrame` marks lengths that cannot frame
    /// anything; `error.MessageTooLarge` marks frames above the limit.
    pub fn validate(h: Header, max_payload: usize) Error!usize {
        if (h.length < min_frame_len) return error.InvalidFrame;
        const payload_len: usize = h.length - min_frame_len;
        if (payload_len > max_payload) return error.MessageTooLarge;
        return payload_len;
    }
};

pub const TcpFull = struct {
    endpoint: Endpoint,
    options: Options,

    stream: net.Stream = undefined,
    connected: bool = false,
    send_seq: u32 = 0,
    recv_seq: u32 = 0,

    /// Creates a disconnected transport. `endpoint.host` is borrowed: the
    /// bytes must outlive the transport.
    pub fn init(endpoint: Endpoint, options: Options) TcpFull {
        return .{
            .endpoint = endpoint,
            .options = options,
        };
    }

    /// Resolves the endpoint and establishes the TCP connection, resetting
    /// the framing state (sequence numbers restart at zero, exactly as the
    /// protocol requires on a fresh connection).
    pub fn connect(self: *TcpFull, io: std.Io) Error!void {
        if (self.connected) return error.AlreadyConnected;
        // resolve does no allocation; every failure means the host/port
        // could not be turned into an address.
        const address = net.IpAddress.resolve(io, self.endpoint.host, self.endpoint.port) catch
            return error.ResolveFailed;
        const timeout: std.Io.Timeout = if (self.options.connect_timeout) |d|
            .{ .duration = .{ .raw = d, .clock = .awake } }
        else
            .none;
        const stream = address.connect(io, .{
            .mode = .stream,
            .timeout = timeout,
        }) catch |err| return switch (err) {
            error.ConnectionRefused => error.ConnectionRefused,
            error.Timeout => error.TimedOut,
            else => error.ConnectFailed,
        };
        disableNagle(stream.socket.handle);
        self.stream = stream;
        self.connected = true;
        self.send_seq = 0;
        self.recv_seq = 0;
    }

    /// MTProto is a strict ping-pong protocol: every request/response pair
    /// would otherwise interact with Nagle + delayed ACK into ~40 ms
    /// stalls. The abstracted `Io` driver does not expose socket options,
    /// so this is done per-platform behind a comptime guard; failures are
    /// ignored (the connection still works, just slower).
    fn disableNagle(handle: net.Socket.Handle) void {
        if (builtin.os.tag == .windows) return;
        const one: c_int = 1;
        _ = std.posix.setsockopt(
            handle,
            std.posix.IPPROTO.TCP,
            std.posix.TCP.NODELAY,
            std.mem.asBytes(&one),
        ) catch {};
    }

    /// Drops the connection (if any). Idempotent.
    pub fn close(self: *TcpFull, io: std.Io) void {
        if (!self.connected) return;
        self.stream.close(io);
        self.connected = false;
    }

    pub fn isConnected(self: *const TcpFull) bool {
        return self.connected;
    }

    /// Sends one payload as a single framed message. The payload bytes are
    /// written as-is — framing, never encryption, is this layer's job.
    /// `error.MessageTooLarge` is raised before touching the socket, so the
    /// connection stays usable; any delivery error closes it.
    ///
    /// Header, payload and trailer go out as one vectored write: separate
    /// small writes interact with Nagle + delayed ACK on a request/response
    /// workload and stall every exchange by ~40 ms.
    pub fn write(self: *TcpFull, io: std.Io, payload: []const u8) Error!void {
        if (!self.connected) return error.NotConnected;
        if (payload.len > self.options.max_payload or
            payload.len + frame_overhead > std.math.maxInt(u32))
        {
            return error.MessageTooLarge;
        }
        const deadline = deadlineFrom(io, self.options.write_timeout);
        const h = Codec.header(payload.len, self.send_seq);
        var trailer: [4]u8 = undefined;
        std.mem.writeInt(u32, &trailer, Codec.checksum(&h, payload), .little);

        const parts = [3][]const u8{ &h, payload, &trailer };
        const total = h.len + payload.len + trailer.len;
        var sent: usize = 0;
        while (sent < total) {
            if (expired(io, deadline)) return error.TimedOut;
            var iovecs: [parts.len][]const u8 = undefined;
            var n_iov: usize = 0;
            var idx: usize = 0;
            var off: usize = sent;
            while (idx < parts.len) : (idx += 1) {
                if (off >= parts[idx].len) {
                    off -= parts[idx].len;
                    continue;
                }
                iovecs[n_iov] = parts[idx][off..];
                n_iov += 1;
                off = 0;
            }
            const n = io.vtable.netWrite(io.userdata, self.stream.socket.handle, &.{}, iovecs[0..n_iov], 1) catch |err|
                return self.fail(io, mapWriteError(err));
            if (n == 0) return self.fail(io, error.IoFailed);
            sent += n;
        }
        self.send_seq +%= 1;
    }

    /// Receives one framed message; the returned slice (allocated with
    /// `allocator`, caller-owned) holds exactly the payload bytes with
    /// header and checksum stripped. An empty payload yields an empty
    /// slice. Framing violations close the connection, since the byte
    /// stream can no longer be parsed reliably.
    pub fn read(self: *TcpFull, io: std.Io, allocator: std.mem.Allocator) Error![]u8 {
        if (!self.connected) return error.NotConnected;
        const deadline = deadlineFrom(io, self.options.read_timeout);

        var consumed: usize = 0;
        var h: [8]u8 = undefined;
        self.readExact(io, &h, deadline, &consumed) catch |err|
            return self.failRead(io, err, consumed);

        const parsed = Codec.parseHeader(&h);
        const payload_len = Codec.validate(parsed, self.options.max_payload) catch |err| {
            self.close(io);
            return err;
        };

        const buf = try allocator.alloc(u8, payload_len);
        errdefer allocator.free(buf);
        self.readExact(io, buf, deadline, &consumed) catch |err|
            return self.failRead(io, err, consumed);
        var trailer: [4]u8 = undefined;
        self.readExact(io, &trailer, deadline, &consumed) catch |err|
            return self.failRead(io, err, consumed);

        if (Codec.checksum(&h, buf) != std.mem.readInt(u32, &trailer, .little)) {
            self.close(io);
            return error.InvalidFrame;
        }
        if (self.options.verify_sequence) {
            if (parsed.seq != self.recv_seq) {
                self.close(io);
                return error.InvalidFrame;
            }
            self.recv_seq +%= 1;
        }
        return buf;
    }

    /// Error path for reads: a timeout before any frame byte was consumed
    /// leaves the stream clean and the connection reusable; anything else
    /// (or a timeout after partial data) desynchronized the framing and the
    /// connection is closed.
    fn failRead(self: *TcpFull, io: std.Io, err: Error, consumed: usize) Error {
        if (err == error.TimedOut and consumed == 0) return err;
        self.close(io);
        return err;
    }

    /// Error path for writes: a partially delivered frame desynchronizes
    /// the stream, so every delivery error closes the connection.
    fn fail(self: *TcpFull, io: std.Io, err: Error) Error {
        self.close(io);
        return err;
    }

    fn readExact(
        self: *TcpFull,
        io: std.Io,
        buf: []u8,
        deadline: ?std.Io.Timestamp,
        consumed: *usize,
    ) Error!void {
        var got: usize = 0;
        while (got < buf.len) {
            if (expired(io, deadline)) return error.TimedOut;
            // A blocking driver's readv would otherwise wait forever on a
            // quiet socket: poll first so the read deadline is honored.
            if (deadline != null and builtin.os.tag != .windows) {
                if (!awaitReadable(self.stream.socket.handle, io, deadline)) return error.TimedOut;
            }
            var iovec = [1][]u8{buf[got..]};
            const n = io.vtable.netRead(io.userdata, self.stream.socket.handle, &iovec) catch |err|
                return mapReadError(err);
            if (n == 0) return error.Disconnected;
            got += n;
            consumed.* += n;
        }
    }

    // NOTE: `@import` is spelled out here because this struct's own
    // `transport()` adapter method shadows the file-scope import.
    const vtable = @import("mod.zig").Transport.VTable{
        .connect = connectTrampoline,
        .close = closeTrampoline,
        .write = writeTrampoline,
        .read = readTrampoline,
        .isConnected = isConnectedTrampoline,
    };

    /// Adapts to the type-erased `transport.Transport` interface.
    pub fn transport(self: *TcpFull) @import("mod.zig").Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn connectTrampoline(ctx: *anyopaque, io: std.Io) Error!void {
        const self: *TcpFull = @ptrCast(@alignCast(ctx));
        return self.connect(io);
    }

    fn closeTrampoline(ctx: *anyopaque, io: std.Io) void {
        const self: *TcpFull = @ptrCast(@alignCast(ctx));
        self.close(io);
    }

    fn writeTrampoline(ctx: *anyopaque, io: std.Io, payload: []const u8) Error!void {
        const self: *TcpFull = @ptrCast(@alignCast(ctx));
        return self.write(io, payload);
    }

    fn readTrampoline(ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator) Error![]u8 {
        const self: *TcpFull = @ptrCast(@alignCast(ctx));
        return self.read(io, allocator);
    }

    fn isConnectedTrampoline(ctx: *anyopaque) bool {
        const self: *TcpFull = @ptrCast(@alignCast(ctx));
        return self.isConnected();
    }
};

fn deadlineFrom(io: std.Io, timeout: ?std.Io.Duration) ?std.Io.Timestamp {
    const d = timeout orelse return null;
    return std.Io.Timestamp.now(io, .awake).addDuration(d);
}

fn expired(io: std.Io, deadline: ?std.Io.Timestamp) bool {
    const d = deadline orelse return false;
    return d.nanoseconds <= std.Io.Timestamp.now(io, .awake).nanoseconds;
}

/// Waits until `fd` is readable or the deadline expires. Returns false on
/// timeout. Posix only; on Windows (no poll in this build) callers keep
/// the blocking semantics.
fn awaitReadable(fd: net.Socket.Handle, io: std.Io, deadline: ?std.Io.Timestamp) bool {
    const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
    const remaining_ns = @max(deadline.?.nanoseconds - now, 0);
    const timeout_ms: i32 = @intCast(@min(@divTrunc(remaining_ns, std.time.ns_per_ms) + 1, std.math.maxInt(i32)));
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&fds, timeout_ms) catch return true; // let the readv report the error
    return n > 0;
}

fn mapReadError(err: net.Stream.Reader.Error) Error {
    return switch (err) {
        error.ConnectionResetByPeer => error.ConnectionReset,
        error.Timeout => error.TimedOut,
        else => error.IoFailed,
    };
}

fn mapWriteError(err: net.Stream.Writer.Error) Error {
    return switch (err) {
        error.ConnectionResetByPeer, error.ConnectionRefused => error.ConnectionReset,
        else => error.IoFailed,
    };
}

// ---------------------------------------------------------------- tests

test "tcp full codec: header layout" {
    const h = Codec.header(9, 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 21, 0, 0, 0, 0, 0, 0, 0 }, &h);

    const parsed = Codec.parseHeader(&h);
    try std.testing.expectEqual(@as(u32, 21), parsed.length);
    try std.testing.expectEqual(@as(u32, 0), parsed.seq);

    const h2 = Codec.header(0x1_00_00, 0xdead_beef);
    const p2 = Codec.parseHeader(&h2);
    try std.testing.expectEqual(@as(u32, 0x1_00_0c), p2.length);
    try std.testing.expectEqual(@as(u32, 0xdead_beef), p2.seq);
}

test "tcp full codec: crc32 is the standard polynomial" {
    // Well-known CRC-32 (ISO-HDLC / zlib) check value.
    try std.testing.expectEqual(@as(u32, 0xCBF43926), std.hash.Crc32.hash("123456789"));

    // The frame checksum covers the header and the payload.
    const h = Codec.header(9, 0);
    var wire: [17]u8 = undefined;
    @memcpy(wire[0..8], &h);
    @memcpy(wire[8..], "123456789");
    try std.testing.expectEqual(std.hash.Crc32.hash(&wire), Codec.checksum(&h, "123456789"));
}

test "tcp full codec: header validation" {
    // Lengths below the overhead cannot frame anything.
    try std.testing.expectError(error.InvalidFrame, Codec.validate(.{ .length = 0, .seq = 0 }, 1024));
    try std.testing.expectError(error.InvalidFrame, Codec.validate(.{ .length = 8, .seq = 0 }, 1024));
    try std.testing.expectError(error.InvalidFrame, Codec.validate(.{ .length = 11, .seq = 0 }, 1024));

    // An empty payload is the smallest valid frame.
    try std.testing.expectEqual(@as(usize, 0), try Codec.validate(.{ .length = 12, .seq = 0 }, 1024));
    try std.testing.expectEqual(@as(usize, 4), try Codec.validate(.{ .length = 16, .seq = 7 }, 1024));

    // Payload above the configured maximum.
    try std.testing.expectError(error.MessageTooLarge, Codec.validate(.{ .length = 13, .seq = 0 }, 0));
    try std.testing.expectError(error.MessageTooLarge, Codec.validate(.{ .length = 0xffff_ffff, .seq = 0 }, 16 << 20));
}

test "tcp full codec: payload limit is exact, not off by one" {
    const max_payload = 4096;
    // A payload of exactly max_payload bytes is the largest valid frame
    // (seq is carried through unchanged).
    try std.testing.expectEqual(
        max_payload,
        try Codec.validate(.{ .length = max_payload + frame_overhead, .seq = 0xffff_ffff }, max_payload),
    );
    // One payload byte more is refused (no overflow, no wraparound).
    try std.testing.expectError(
        error.MessageTooLarge,
        Codec.validate(.{ .length = max_payload + frame_overhead + 1, .seq = 0 }, max_payload),
    );
}
