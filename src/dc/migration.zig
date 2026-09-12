//! Data-center migration errors: `*_MIGRATE_X` rpc-error messages parsed
//! into a target DC.
//!
//! Telegram redirects clients between data centers through rpc errors
//! (all carrying code 303; see
//! <https://core.telegram.org/api/errors#303-migrate-x>):
//!
//!   * `NETWORK_MIGRATE_X` — no authorization yet, the connection should
//!     use DC X: connect there and repeat the request;
//!   * `PHONE_MIGRATE_X` — the phone number is registered on DC X:
//!     continue the authorization flow there (a fresh auth key per DC);
//!   * `USER_MIGRATE_X` — the authorized user lives on DC X: export the
//!     authorization (`auth.exportAuthorization`) on the current DC,
//!     connect DC X, import it (`auth.importAuthorization`);
//!   * `FILE_MIGRATE_X` — the file lives on DC X: open a media
//!     connection there (its own auth key) and retry the download.
//!
//! This module only classifies (through the generated RPC error
//! catalog, `rpc.errors_gen`); `manager.DataCenters.migrate` applies the
//! target, and the authorization flows are later milestones.

const std = @import("std");
const rpc = @import("../rpc/mod.zig");

/// The migration error family a message belongs to.
pub const Kind = enum {
    /// `PHONE_MIGRATE_X`: the phone is registered on the target DC.
    phone,
    /// `NETWORK_MIGRATE_X`: the connection should move to the target DC.
    network,
    /// `USER_MIGRATE_X`: the authorized user lives on the target DC.
    user,
    /// `FILE_MIGRATE_X`: the file lives on the target DC.
    file,
};

/// A parsed migration: what kind of redirect it is and the DC to go to.
pub const Migration = struct {
    kind: Kind,
    /// Target DC id (the `_X` suffix of the error message).
    dc: i32,
};

/// The rpc-error code every `*_MIGRATE_X` error carries.
pub const error_code: i32 = 303;

/// Classifies an rpc-error message. Returns null for anything that is
/// not a `*_MIGRATE_<positive dc>` message. The code is deliberately
/// not checked — matching is by message through the generated error
/// catalog (`rpc.classifyRpcError`), like in every other client.
pub fn fromMessage(msg: []const u8) ?Migration {
    const c = rpc.classifyRpcError(msg) orelse return null;
    const kind: Kind = switch (c.id) {
        .phone_migrate_x => .phone,
        .network_migrate_x => .network,
        .user_migrate_x => .user,
        .file_migrate_x => .file,
        else => return null,
    };
    const dc = c.value orelse return null;
    if (dc < 1) return null;
    return .{ .kind = kind, .dc = @intCast(dc) };
}

/// Classifies the rpc error the RPC client reports after a request failed
/// with `error.RpcError`: `migration.fromRpcError(client.lastRpcError())`.
pub fn fromRpcError(info: rpc.RpcErrorInfo) ?Migration {
    return fromMessage(info.message);
}

// ---------------------------------------------------------------- tests

test "parses all four migration kinds" {
    const cases = [_]struct { msg: []const u8, kind: Kind, dc: i32 }{
        .{ .msg = "PHONE_MIGRATE_2", .kind = .phone, .dc = 2 },
        .{ .msg = "NETWORK_MIGRATE_5", .kind = .network, .dc = 5 },
        .{ .msg = "USER_MIGRATE_4", .kind = .user, .dc = 4 },
        .{ .msg = "FILE_MIGRATE_1", .kind = .file, .dc = 1 },
    };
    for (cases) |c| {
        const m = fromMessage(c.msg).?;
        try std.testing.expectEqual(c.kind, m.kind);
        try std.testing.expectEqual(c.dc, m.dc);
    }

    // The shape the RPC client reports (code 303, message string).
    const m = fromRpcError(.{ .code = 303, .message = "PHONE_MIGRATE_1" }).?;
    try std.testing.expect(m.kind == .phone);
    try std.testing.expectEqual(@as(i32, 1), m.dc);
}

test "non-migration messages are rejected" {
    for ([_][]const u8{
        "",                      // empty
        "FLOOD_WAIT_60",         // other error family
        "PHONE_CODE_INVALID",    // other error family
        "PHONE_MIGRATE",         // no underscore-dc suffix
        "PHONE_MIGRATE_",        // empty number
        "PHONE_MIGRATE_2x",      // trailing junk
        "PHONE_MIGRATE_0",       // not a DC number
        "PHONE_MIGRATE_-1",      // not a DC number
        "USER_MIGRATE_999999999999", // out of i32 range
    }) |msg| try std.testing.expect(fromMessage(msg) == null);
}
