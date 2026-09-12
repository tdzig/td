//! Example: the invoke surface of the high-level client — how every
//! generated API call is made. Works with any session: a fresh key, a
//! bot, or a signed-in user (each section adapts to what the session
//! is allowed to do).
//!
//!   1. `invoke` — one typed round trip, no arguments:
//!      `help.getConfig` (available to everyone). The answer arrives
//!      as the generated union; the response owns its arena, so the
//!      decoded value lives until `deinit`.
//!   2. `invoke` with arguments — `auth.exportAuthorization` takes the
//!      current DC id; on a signed-in session the decoded result
//!      carries the `auth.importAuthorization` transfer material (its
//!      `bytes` borrow the response's arena — use them before
//!      `deinit`, copy if they must outlive it). A bare key is not
//!      signed in, so the server answers `401 AUTH_KEY_UNREGISTERED`:
//!      Rpc-level failures surface as `error.RpcError` with code and
//!      message in `lastRpcError`. Both outcomes are handled and the
//!      example continues.
//!   3. The failure half again, deliberately — `users.getUsers` over
//!      `inputUserSelf` prints the account when signed in, `401` on a
//!      bare key.
//!   4. Pipelining — `send` two requests back-to-back and `wait` for
//!      them in reverse order; each answer is matched by msg_id and
//!      decoded into its own result type. This path skips the
//!      initConnection wrapper and DC migration, so keep at least one
//!      plain `invoke` ahead of it on a fresh session (section 1 did)
//!      and only pipeline against the current DC. Bot sessions see
//!      `help.getNearestDc` skipped (`400 BOT_METHOD_INVALID`).
//!
//! Sessions persist to `session-invoke.bin` (0600, atomic rename);
//! `TD_SESSION_STRING` overrides the file store. Talks to the real
//! network; `TD_API_ID` (from my.telegram.org) is required from the
//! environment — nothing is defaulted.
//!
//! The escape hatch below all of this — pre-serialized bytes in,
//! result-object bytes out — is `invokeRaw`/`invokeRawWithId` (and the
//! generic wrappers the generator does not emit); see
//! examples/loopback_client.zig for that layer without the facade.
//!
//! Run: `just build && ./zig-out/bin/example-invoke`

const std = @import("std");
const td = @import("td");

// Schema-compatibility guards: a layer that changed any of these
// constructor ids fails this example at compile time.
comptime {
    std.debug.assert(td.api.help.getConfig.constructor_id == 0xc4f9186b);
    std.debug.assert(td.api.auth.exportAuthorization.constructor_id == 0xe5bfffcd);
    std.debug.assert(td.api.users.getUsers.constructor_id == 0x0d91a548);
    std.debug.assert(td.api.inputUserSelf.constructor_id == 0xf7c1b13f);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var store = try td.session.FileStore.init(gpa, "session-invoke.bin");
    defer store.deinit();

    const api_id_str = init.environ_map.get("TD_API_ID") orelse {
        std.debug.print("example-invoke: TD_API_ID not set (get one at my.telegram.org) — nothing is defaulted\n", .{});
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

    // --- 1. plain invoke: request struct in, decoded union out --------
    var cfg = try client.invoke(io, td.api.help.getConfig{});
    defer cfg.deinit();
    switch (cfg.value) {
        .config => |c| std.debug.print(
            "help.getConfig: {d} dc options, this dc is {d}, expires in {d}s\n",
            .{ c.dc_options.len, c.this_dc, c.expires },
        ),
    }

    // --- 2. invoke with arguments --------------------------------------
    // The argument is a plain struct field; here it comes from the
    // client itself. The `bytes` in the answer are the material for a
    // later `auth.importAuthorization` on another DC — treat them as
    // session material (never print them); this example just measures.
    var exported = client.invoke(io, td.api.auth.exportAuthorization{
        .dc_id = client.dcs.current,
    });
    if (exported) |*resp| {
        defer resp.deinit();
        switch (resp.value) {
            .exportedAuthorization => |x| std.debug.print(
                "exportAuthorization: id={d}, {d} bytes of transfer material\n",
                .{ x.id, x.bytes.len },
            ),
        }
    } else |e| {
        if (e == error.RpcError) {
            const info = client.lastRpcError();
            std.debug.print(
                "exportAuthorization rejected (expected on a bare key): rpc_error {d} {s}\n",
                .{ info.code, info.message },
            );
        } else return e;
    }

    // --- 3. the error half: RpcError + lastRpcError ---------------------
    // Signed in, this prints the account; a bare key gets
    // `401 AUTH_KEY_UNREGISTERED`. Both are normal outcomes of an
    // invoke — handled, not fatal.
    var self_user = [_]td.api.InputUser{.{ .inputUserSelf = .{} }};
    if (client.invoke(io, td.api.users.getUsers{ .id = &self_user })) |users| {
        var u = users;
        defer u.deinit();
        if (u.value.len == 1) switch (u.value[0]) {
            .user => |me| std.debug.print(
                "users.getUsers: id={d}{s}{s}\n",
                .{
                    me.id,
                    if (me.username != null) " @" else "",
                    if (me.username) |un| un else "",
                },
            ),
            else => {},
        };
    } else |e| {
        if (e == error.RpcError) {
            const info = client.lastRpcError();
            std.debug.print(
                "users.getUsers rejected (expected on a bare key): rpc_error {d} {s}\n",
                .{ info.code, info.message },
            );
        } else return e;
    }

    // --- 4. pipelining: send both, wait in reverse order ----------------
    // Handles go stale across a disconnect/PFS rotation; everything
    // here stays on the one connection opened above.
    const h_cfg = try client.send(io, td.api.help.getConfig{});
    const h_dc = try client.send(io, td.api.help.getNearestDc{});
    // Wait the later-sent request first; the earlier one's completed
    // answer stays queued until its own `wait`.
    var wait_dc = client.wait(io, h_dc);
    if (wait_dc) |*nd_resp| {
        defer nd_resp.deinit();
        switch (nd_resp.value) {
            .nearestDc => |nd| std.debug.print(
                "pipelined getNearestDc: you are in {s}, nearest dc is {d}\n",
                .{ nd.country, nd.nearest_dc },
            ),
        }
    } else |e| {
        if (e == error.RpcError) {
            const info = client.lastRpcError();
            std.debug.print(
                "pipelined getNearestDc skipped: rpc_error {d} {s}\n",
                .{ info.code, info.message },
            );
        } else return e;
    }
    var cfg2 = try client.wait(io, h_cfg);
    defer cfg2.deinit();
    std.debug.print("pipelined getConfig: {d} dc options\n", .{switch (cfg2.value) {
        .config => |c| c.dc_options.len,
    }});

    // Technical round trip (not an RPC): ping, and the matching pong
    // comes back through the same pump.
    try client.ping(io);
    std.debug.print("ping/pong ok\n", .{});

    client.disconnect(io);
    std.debug.print("OK: invoke, pipelined send/wait, and the RpcError path all exercised\n", .{});
}
