//! Shared machinery for the tag-prefixed TCP transports — abridged,
//! intermediate and padded intermediate — everything except the frame
//! layout itself, which each transport contributes as a pure `Codec`.
//!
//! A `Framed(Codec)` owns the connection lifecycle and the byte stream
//! with exactly the semantics of the TCP-full transport (`tcp_full.zig`):
//! one vectored write per frame, deadlines around every socket operation,
//! framing violations close the connection, and a read timeout firing
//! before the first frame byte leaves it usable. The codec supplies the
//! wire format:
//!
//!   - `init_tag`      bytes sent once at the head of a fresh connection
//!   - `probe_len`     bytes read up front to learn the header size
//!   - `headerLen`     total header size for the probe bytes
//!   - `payloadLen`    payload byte count carried by a complete header
//!   - `encodeHeader`  header bytes for an outgoing frame
//!   - `checkPayload`  static outbound constraints (alignment, maximum)
//!   - `has_padding`   whether frames end in transport padding, and
//!   - `padLen`        how many padding bytes to append (padded only)
//!
//! A future framing is therefore a codec plus a spec comment, not another
//! connection implementation. Frames here are opaque payload envelopes:
//! what travels inside them — MTProto encryption included — is invisible
//! to this layer.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const transport = @import("mod.zig");

const Endpoint = transport.Endpoint;
const Error = transport.Error;

pub const Options = struct {
    /// Maximum payload size in bytes, enforced both inbound (larger
    /// frames fail with `error.MessageTooLarge`) and outbound. For the
    /// padded transport this bounds payload and padding together.
    max_payload: usize = 16 << 20,
    /// Bound on the whole `connect` call, forwarded to the `Io` driver.
    /// The default blocking driver (`std.Io.Threaded`) does not implement
    /// connect timeouts and panics if one is requested — leave this null
    /// there.
    connect_timeout: ?std.Io.Duration = null,
    /// Bound on each `read` call, checked before every underlying socket
    /// operation: a `read` whose deadline expires before any frame byte
    /// was consumed returns `error.TimedOut` and leaves the connection
    /// usable; one that expires mid-frame (or hits a socket error) closes
    /// the connection, since the stream can no longer be framed reliably.
    read_timeout: ?std.Io.Duration = null,
    /// Bound on each `write` call, with the same deadline semantics as
    /// `read_timeout`.
    write_timeout: ?std.Io.Duration = null,
    /// Padded transport only: randomness for the 0..15 padding bytes
    /// appended to every frame. null sends zero-length padding — still a
    /// legal padded-intermediate frame, just without the length
    /// obfuscation.
    random: ?std.Random = null,
};

pub fn Framed(comptime Codec: type) type {
    return struct {
        const Self = @This();

        endpoint: Endpoint,
        options: Options,

        stream: net.Stream = undefined,
        connected: bool = false,
        /// Whether `Codec.init_tag` already went out on the current
        /// connection. The tag is written once per connection, prepended
        /// to the first frame so both ship in one segment.
        tag_sent: bool = false,

        /// Creates a disconnected transport. `endpoint.host` is borrowed:
        /// the bytes must outlive the transport.
        pub fn init(endpoint: Endpoint, options: Options) Self {
            return .{
                .endpoint = endpoint,
                .options = options,
            };
        }

        /// Resolves the endpoint and establishes the TCP connection,
        /// resetting the framing state: the initial tag (if the codec has
        /// one) goes out again on the fresh stream.
        pub fn connect(self: *Self, io: std.Io) Error!void {
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
            self.tag_sent = false;
        }

        /// MTProto is a strict ping-pong protocol: every request/response
        /// pair would otherwise interact with Nagle + delayed ACK into
        /// ~40 ms stalls. The abstracted `Io` driver does not expose
        /// socket options, so this is done per-platform behind a comptime
        /// guard; failures are ignored (the connection still works, just
        /// slower). Same as `tcp_full.TcpFull`.
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
        pub fn close(self: *Self, io: std.Io) void {
            if (!self.connected) return;
            self.stream.close(io);
            self.connected = false;
        }

        pub fn isConnected(self: *const Self) bool {
            return self.connected;
        }

        /// Sends one payload as a single framed message, prefixed by the
        /// codec's initial tag on the first write of a connection. The
        /// payload bytes are written as-is — framing, never encryption, is
        /// this layer's job. `error.MessageTooLarge` (and codec alignment
        /// violations) are raised before touching the socket, so the
        /// connection stays usable; any delivery error closes it.
        pub fn write(self: *Self, io: std.Io, payload: []const u8) Error!void {
            if (!self.connected) return error.NotConnected;
            Codec.checkPayload(payload.len) catch |e| return e;
            if (payload.len > self.options.max_payload) return error.MessageTooLarge;
            const pad_len = if (Codec.has_padding) Codec.padLen(self.options.random, payload.len) else 0;
            var hdr: [4]u8 = undefined;
            const header = Codec.encodeHeader(payload.len + pad_len, &hdr);
            var pad: [15]u8 = undefined;
            if (pad_len > 0) {
                if (self.options.random) |r| {
                    r.bytes(pad[0..pad_len]);
                } else {
                    @memset(pad[0..pad_len], 0);
                }
            }

            var parts: [4][]const u8 = undefined;
            var n_parts: usize = 0;
            if (!self.tag_sent) {
                parts[n_parts] = Codec.init_tag;
                n_parts += 1;
                self.tag_sent = true;
            }
            parts[n_parts] = header;
            n_parts += 1;
            parts[n_parts] = payload;
            n_parts += 1;
            if (pad_len > 0) {
                parts[n_parts] = pad[0..pad_len];
                n_parts += 1;
            }
            try self.writeAll(io, parts[0..n_parts]);
        }

        /// One vectored write per frame: separate small writes interact
        /// with Nagle + delayed ACK on a request/response workload and
        /// stall every exchange by ~40 ms.
        fn writeAll(self: *Self, io: std.Io, parts: []const []const u8) Error!void {
            const deadline = deadlineFrom(io, self.options.write_timeout);
            var total: usize = 0;
            for (parts) |p| total += p.len;
            var sent: usize = 0;
            while (sent < total) {
                if (expired(io, deadline)) return error.TimedOut;
                var iovecs: [4][]const u8 = undefined;
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
        }

        /// Receives one framed message; the returned slice (allocated
        /// with `allocator`, caller-owned) holds exactly the payload bytes
        /// with the header — and, for the padded transport, the trailing
        /// padding — kept as delivered. An empty payload yields an empty
        /// slice. Framing violations close the connection, since the byte
        /// stream can no longer be parsed reliably.
        pub fn read(self: *Self, io: std.Io, allocator: std.mem.Allocator) Error![]u8 {
            if (!self.connected) return error.NotConnected;
            const deadline = deadlineFrom(io, self.options.read_timeout);

            var consumed: usize = 0;
            var probe: [Codec.probe_len]u8 = undefined;
            self.readExact(io, &probe, deadline, &consumed) catch |err|
                return self.failRead(io, err, consumed);

            var header: [4]u8 = undefined;
            @memcpy(header[0..Codec.probe_len], &probe);
            const header_len = Codec.headerLen(&probe) catch |e| {
                self.close(io);
                return e;
            };
            if (header_len > Codec.probe_len) {
                self.readExact(io, header[Codec.probe_len..header_len], deadline, &consumed) catch |err|
                    return self.failRead(io, err, consumed);
            }
            const payload_len = Codec.payloadLen(header[0..header_len]) catch |e| {
                self.close(io);
                return e;
            };
            if (payload_len > self.options.max_payload) {
                self.close(io);
                return error.MessageTooLarge;
            }

            const buf = try allocator.alloc(u8, payload_len);
            errdefer allocator.free(buf);
            self.readExact(io, buf, deadline, &consumed) catch |err|
                return self.failRead(io, err, consumed);
            return buf;
        }

        /// Error path for reads: a timeout before any frame byte was
        /// consumed leaves the stream clean and the connection reusable;
        /// anything else (or a timeout after partial data) desynchronized
        /// the framing and the connection is closed.
        fn failRead(self: *Self, io: std.Io, err: Error, consumed: usize) Error {
            if (err == error.TimedOut and consumed == 0) return err;
            self.close(io);
            return err;
        }

        /// Error path for writes: a partially delivered frame
        /// desynchronizes the stream, so every delivery error closes the
        /// connection.
        fn fail(self: *Self, io: std.Io, err: Error) Error {
            self.close(io);
            return err;
        }

        fn readExact(
            self: *Self,
            io: std.Io,
            buf: []u8,
            deadline: ?std.Io.Timestamp,
            consumed: *usize,
        ) Error!void {
            var got: usize = 0;
            while (got < buf.len) {
                if (expired(io, deadline)) return error.TimedOut;
                // A blocking driver's readv would otherwise wait forever on
                // a quiet socket: poll first so the read deadline is
                // honored.
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
        pub fn transport(self: *Self) @import("mod.zig").Transport {
            return .{ .ctx = self, .vtable = &vtable };
        }

        fn connectTrampoline(ctx: *anyopaque, io: std.Io) Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return self.connect(io);
        }

        fn closeTrampoline(ctx: *anyopaque, io: std.Io) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.close(io);
        }

        fn writeTrampoline(ctx: *anyopaque, io: std.Io, payload: []const u8) Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return self.write(io, payload);
        }

        fn readTrampoline(ctx: *anyopaque, io: std.Io, allocator: std.mem.Allocator) Error![]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return self.read(io, allocator);
        }

        fn isConnectedTrampoline(ctx: *anyopaque) bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return self.isConnected();
        }
    };
}

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
