//! td-keygen: create an MTProto authorization key against a Telegram DC.
//!
//! Usage:
//!   td-keygen <host> [--port N] [--pubkey <modulus.hex>] [--mode classic|rsa_pad] [--out <key.bin>]
//!
//! Without `--pubkey`, the official server keys vendored in
//! `td.mtproto.server_keys` are used (decoded from the official
//! Telegram Desktop source at compile time). With `--pubkey`, a text
//! file with the 2048-bit RSA public modulus in hex is expected
//! (e.g. a rotated or custom-server key). The resulting 256-byte auth
//! key is written to --out (default: auth_key.bin). Only the
//! auth_key_id is printed — key material and handshake secrets are
//! never logged.

const std = @import("std");
const td = @import("td");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // program name

    var host: ?[]const u8 = null;
    var port: u16 = 443;
    var pubkey_path: ?[]const u8 = null;
    var out_path: []const u8 = "auth_key.bin";
    var mode: td.mtproto.rsa.Mode = .rsa_pad;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--pubkey")) {
            pubkey_path = args.next() orelse return usage();
        } else if (std.mem.eql(u8, arg, "--mode")) {
            const m = args.next() orelse return usage();
            mode = if (std.mem.eql(u8, m, "classic")) .classic else if (std.mem.eql(u8, m, "rsa_pad")) .rsa_pad else return usage();
        } else if (std.mem.eql(u8, arg, "--out")) {
            out_path = args.next() orelse return usage();
        } else if (std.mem.eql(u8, arg, "--port")) {
            const p = args.next() orelse return usage();
            port = std.fmt.parseInt(u16, p, 10) catch return usage();
        } else if (host == null) {
            host = arg;
        } else return usage();
    }

    const host_name = host orelse return usage();

    // Load the public key: caller-provided modulus hex, or the vendored
    // official keys.
    const pubkeys: []const td.mtproto.rsa.PublicKey = if (pubkey_path) |key_path| blk: {
        const hex = try std.Io.Dir.cwd().readFileAlloc(io, key_path, allocator, .limited(8 << 10));
        defer allocator.free(hex);
        const trimmed = std.mem.trim(u8, hex, " \t\r\n");
        if (trimmed.len != 512) {
            std.debug.print("error: public key modulus must be 512 hex chars (2048-bit)\n", .{});
            return error.Usage;
        }
        var public_key = td.mtproto.rsa.PublicKey{ .n = undefined };
        _ = std.fmt.hexToBytes(&public_key.n, trimmed) catch return error.Usage;
        const keys = try allocator.alloc(td.mtproto.rsa.PublicKey, 1);
        keys[0] = public_key;
        break :blk keys;
    } else td.mtproto.server_keys.production;

    // CSPRNG-backed Random interface straight from the OS entropy source.
    var rng_source = std.Random.IoSource{ .io = io };
    const random = rng_source.interface();

    std.debug.print("connecting to {s}:{d}...\n", .{ host_name, port });
    var tcp = td.transport.TcpFull.init(.{ .host = host_name, .port = port }, .{
        .read_timeout = std.Io.Duration.fromSeconds(30),
    });
    try tcp.connect(io);
    defer tcp.close(io);

    const now_s: u64 = @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
    var pipe = td.mtproto.HandshakePipe.init(tcp.transport(), io);
    var hs = td.mtproto.Handshake.init(allocator, pipe.pipe(), pubkeys, random, now_s, .{
        .mode = mode,
        .dc = 2,
    });

    const auth_key = hs.run() catch |e| {
        std.debug.print("handshake failed: {s}\n", .{@errorName(e)});
        return e;
    };

    // Persist the key; print only public identifiers.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = &auth_key.key });
    std.debug.print("authorization key created: id={x} (written to {s})\n", .{ fmtId(&auth_key.id), out_path });
}

fn fmtId(id: *const [8]u8) [16]u8 {
    var buf: [16]u8 = undefined;
    const hex = "0123456789abcdef";
    for (id, 0..) |b, i| {
        buf[i * 2] = hex[b >> 4];
        buf[i * 2 + 1] = hex[b & 15];
    }
    return buf;
}

fn usage() error{Usage} {
    std.debug.print(
        "usage: td-keygen <host> [--port N] [--pubkey <modulus.hex>] [--mode classic|rsa_pad] [--out <key.bin>]\n",
        .{},
    );
    return error.Usage;
}

