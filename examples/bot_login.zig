//! Example: bot login against a production Telegram DC through the
//! high-level client (`td.Client`) — every request is a generated
//! struct, every answer a generated type, no hand-serialized bytes.
//!
//!   1. `connect` — stored-key reuse (td-keygen's raw `auth_key.bin`,
//!      256 bytes) or a fresh authorization-key handshake, then the
//!      initConnection wrapper the client sends on every fresh
//!      session's first query (with the layer generated into
//!      `td.api.layer`).
//!   2. `auth.importBotAuthorization` with TD_BOT_TOKEN. The bot's
//!      home DC is not necessarily the entry DC; `invoke` follows the
//!      server's `*_MIGRATE_X` answers itself — switch DC, handshake a
//!      fresh per-DC key, repeat — and records the signed-in identity
//!      (user id, is_bot) from the result.
//!   3. MTProto getMe: `users.getUsers` over `inputUserSelf`, decoded
//!      through the generated `td.api.User`.
//!   4. `updates.getState` — a second authorized round trip through a
//!      method bots may call (`help.getNearestDc` answers
//!      BOT_METHOD_INVALID for bot authorizations).
//!   5. `disconnect` — connection down, client still usable.
//!
//! A stored key comes back with a zero server salt; the first content
//! request is corrected by the server's `bad_server_salt` and re-sent
//! automatically — so this example exercises real-server salt recovery
//! on every rerun.
//!
//! Credentials: the bot token is read from the **environment** only —
//! it is never embedded, logged, or written to disk by this program.
//! Without TD_BOT_TOKEN the example prints a notice and exits 0, so CI
//! runs stay green. TD_API_ID and TD_API_HASH (from my.telegram.org)
//! are required from the environment — nothing is defaulted. TD_PFS=1
//! enables perfect forward
//! secrecy (temp auth keys bound via auth.bindTempAuthKey) — the
//! opt-in real-server check of that path.
//!
//! Run: `TD_BOT_TOKEN=… ./zig-out/bin/example-bot-login`

const std = @import("std");
const td = @import("td");

// Schema-compatibility guards: a layer that changed any of these
// constructor ids fails this example at compile time.
comptime {
    std.debug.assert(td.api.auth.importBotAuthorization.constructor_id == 0x67a3ff2c);
    std.debug.assert(td.api.users.getUsers.constructor_id == 0x0d91a548);
    std.debug.assert(td.api.inputUserSelf.constructor_id == 0xf7c1b13f);
    std.debug.assert(td.api.updates.getState.constructor_id == 0xedd4882a);
}

const key_file = "auth_key.bin";

/// The classic production entry DC (also `td-keygen`'s and
/// `DataCenters`' default).
const entry_dc: i32 = 2;

fn loadStoredKey(io: std.Io, gpa: std.mem.Allocator, out: *[256]u8) bool {
    const data = std.Io.Dir.cwd().readFileAlloc(io, key_file, gpa, .limited(1024)) catch return false;
    defer gpa.free(data);
    if (data.len != out.len) return false;
    @memcpy(out, data);
    return true;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const token = init.environ_map.get("TD_BOT_TOKEN") orelse {
        std.debug.print("example-bot-login: TD_BOT_TOKEN not set — skipping (network test is opt-in)\n", .{});
        return;
    };
    const api_id_str = init.environ_map.get("TD_API_ID") orelse {
        std.debug.print("example-bot-login: TD_API_ID not set (get one at my.telegram.org) — nothing is defaulted\n", .{});
        return error.MissingApiId;
    };
    const api_id = std.fmt.parseInt(i32, api_id_str, 10) catch return error.BadApiId;
    const api_hash = init.environ_map.get("TD_API_HASH") orelse {
        std.debug.print("example-bot-login: TD_API_HASH not set (get one at my.telegram.org) — nothing is defaulted\n", .{});
        return error.MissingApiHash;
    };

    // TD_PFS=1: perfect forward secrecy — every connection encrypts with
    // a short-lived temp key bound to the permanent one
    // (https://core.telegram.org/api/pfs). The real-server validation of
    // the bind path; plain (pfs off) stays the default.
    const pfs = if (init.environ_map.get("TD_PFS")) |v|
        std.mem.eql(u8, v, "1") or std.ascii.eqlIgnoreCase(v, "true")
    else
        false;

    var client = try td.Client.init(gpa, .{
        .app = .{ .api_id = api_id },
        .pfs = pfs,
    });
    defer client.deinit(io);

    // Reuse td-keygen's raw key when present (the file has no DC tag,
    // so it can only ever be the entry DC's); otherwise `connect` runs
    // the handshake and the fresh key is persisted below.
    var stored: [td.crypto.auth_key_size]u8 = undefined;
    const have_key = loadStoredKey(io, gpa, &stored);
    if (have_key) {
        var sha1: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(&stored, &sha1, .{});
        var key_id = td.crypto.authKeyId(&stored);
        try client.dcs.setAuthKey(entry_dc, .{
            .key = stored,
            .id = key_id,
            .aux_hash = sha1[0..8].*,
            .server_salt = [_]u8{0} ** 8, // corrected via bad_server_salt
        });
        std.debug.print("using stored authorization key from {s} (id={x})\n", .{ key_file, fmtId(&key_id) });
    } else {
        std.debug.print("no stored key — running the authorization-key handshake against DC2...\n", .{});
    }

    try client.connect(io);
    if (pfs) std.debug.print("PFS enabled: temp key bound (expires at unix {d})\n", .{client.pfs_temp.?.expires_at});

    // --- 1. bot login: one typed invoke (DC hops handled inside) ------
    var auth = client.invoke(io, td.api.auth.importBotAuthorization{
        .flags = 0,
        .api_id = api_id,
        .api_hash = api_hash,
        .bot_auth_token = token,
    }) catch |e| {
        if (e == error.RpcError) {
            const info = client.lastRpcError();
            std.debug.print("bot login failed: rpc_error {d} {s}\n", .{ info.code, info.message });
        } else {
            std.debug.print("bot login failed: {s}\n", .{@errorName(e)});
        }
        return e;
    };
    defer auth.deinit();
    switch (auth.value) {
        // The facade recorded the identity from this result; the DC is
        // the bot's home after any migration the invoke followed.
        .authorization => std.debug.print("bot authorized (id={d}, dc={d})\n", .{
            client.authorized.?.user_id, client.dcs.current,
        }),
        else => return error.UnexpectedAuthAnswer,
    }

    // If the handshake created a key, persist it for reruns.
    if (!have_key) {
        if (client.dcs.authKey(entry_dc)) |k| {
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = key_file, .data = &k.key });
            std.debug.print("authorization key written to {s} (chmod 600 it if the directory is shared)\n", .{key_file});
        }
    }

    // --- 2. MTProto getMe: users.getUsers [inputUserSelf] ------------
    var self_user = [_]td.api.InputUser{.{ .inputUserSelf = .{} }};
    var users = try client.invoke(io, td.api.users.getUsers{ .id = &self_user });
    defer users.deinit();
    if (users.value.len != 1) return error.UnexpectedUsersLength;
    switch (users.value[0]) {
        .user => |me| {
            std.debug.print("MTProto getMe (td.api.User decoded):\n", .{});
            std.debug.print("  id            = {d}\n", .{me.id});
            if (me.username) |u| std.debug.print("  username      = @{s}\n", .{u});
            if (me.first_name) |n| std.debug.print("  first_name    = {s}\n", .{n});
        },
        else => return error.UnexpectedUser,
    }

    // --- 3. second authorized round trip ------------------------------
    var state = client.invoke(io, td.api.updates.getState{}) catch |e| {
        if (e == error.RpcError) {
            const info = client.lastRpcError();
            std.debug.print("updates.getState failed: rpc_error {d} {s}\n", .{ info.code, info.message });
        } else {
            std.debug.print("updates.getState failed: {s}\n", .{@errorName(e)});
        }
        return e;
    };
    defer state.deinit();
    switch (state.value) {
        .state => |s| std.debug.print("updates.getState: pts={d} qts={d} date={d} seq={d} unread={d}\n", .{
            s.pts, s.qts, s.date, s.seq, s.unread_count,
        }),
    }

    // Connection down, client reusable (deinit below still applies).
    client.disconnect(io);
    std.debug.print("OK: handshake, bot authorization, MTProto getMe and authorized RPC against a production DC all passed\n", .{});
}

fn fmtId(id: *const [8]u8) [16]u8 {
    const hex = "0123456789abcdef";
    var buf: [16]u8 = undefined;
    for (id, 0..) |b, i| {
        buf[i * 2] = hex[b >> 4];
        buf[i * 2 + 1] = hex[b & 15];
    }
    return buf;
}
