//! Example: the high-level client — the whole program is this file.
//!
//! `td.Client` composes every layer: stored-session restore or fresh
//! authorization-key handshake, connection management (reconnects,
//! recovery), DC migration, session persistence. The program itself is
//! just init / connect / invoke:
//!
//!   * `help.getNearestDc` — the classic first call, available without
//!     any authorization (bot authorizations are rejected with
//!     BOT_METHOD_INVALID, so a signed-in bot skips straight to
//!     `help.getConfig`);
//!
//! One credential is required: `TD_API_ID` (from my.telegram.org — no
//! api_hash is needed for unauthenticated calls), read from the
//! environment and never defaulted. This one talks to the real
//! network (production DC 2 first, then whatever
//! `getNearestDc` says). Sessions persist to `session.bin` (written
//! atomically with owner-only permissions): reruns skip the handshake
//! and continue the same wire session.
//!
//! `TD_SESSION_STRING` (a portable session string, see
//! `td.session.string`) overrides the file store: the string's
//! authorization key is imported and used as-is — the fastest way to
//! try a session produced elsewhere.
//!
//! Run: `just build && ./zig-out/bin/example-quickstart`

const std = @import("std");
const td = @import("td");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var store = try td.session.FileStore.init(gpa, "session.bin");
    defer store.deinit();

    const api_id_str = init.environ_map.get("TD_API_ID") orelse {
        std.debug.print("example-quickstart: TD_API_ID not set (get one at my.telegram.org) — nothing is defaulted\n", .{});
        return error.MissingApiId;
    };
    const api_id = std.fmt.parseInt(i32, api_id_str, 10) catch return error.BadApiId;

    var client = try td.Client.init(gpa, .{
        .session_store = store.store(),
        .session_string = init.environ_map.get("TD_SESSION_STRING"),
        .app = .{ .api_id = api_id },
    });
    defer client.deinit(io);
    try client.connect(io);
    if (client.authorized) |a| {
        std.debug.print("signed in as {s} {d}\n", .{
            if (a.is_bot) "bot" else "user",
            a.user_id,
        });
    }

    // `help.getNearestDc` is a user/unauthenticated method: bot
    // authorizations are rejected with `400 BOT_METHOD_INVALID`. The
    // identity is known from a `TD_SESSION_STRING`, but a restored
    // `session.bin` carries only the key — so the skip is driven by
    // the server's answer, not by `client.authorized`.
    //
    // Any generated function is one invoke away; the result decodes
    // into its generated type. Rpc-level failures surface as
    // `error.RpcError` with the server's code and message available.
    if (client.invoke(io, td.api.help.getNearestDc{})) |result| {
        var dc = result;
        defer dc.deinit();
        switch (dc.value) {
            .nearestDc => |nd| std.debug.print(
                "you are in {s}, this dc is {d}, nearest dc is {d}\n",
                .{ nd.country, nd.this_dc, nd.nearest_dc },
            ),
        }
    } else |e| {
        var bot_blocked = false;
        if (e == error.RpcError) {
            const info = client.lastRpcError();
            std.debug.print("getNearestDc failed: rpc_error {d} {s}\n", .{ info.code, info.message });
            bot_blocked = info.code == 400 and std.mem.eql(u8, info.message, "BOT_METHOD_INVALID");
        }
        if (!bot_blocked) return e;
        std.debug.print("skipping getNearestDc: not available to bots\n", .{});
    }

    var cfg = try client.invoke(io, td.api.help.getConfig{});
    defer cfg.deinit();
    const c = switch (cfg.value) {
        .config => |c| c,
    };
    std.debug.print("server config: {d} dc options, expires in {d}s\n", .{
        c.dc_options.len, c.expires,
    });

    // Lifecycle: drop the connection explicitly — the client stays
    // usable with another `connect` (`close` would end it for good;
    // `deinit` below frees regardless).
    client.disconnect(io);
    std.debug.print("OK: high-level client round trip against a production DC\n", .{});
}
