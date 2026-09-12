//! Authentication subsystem: the Telegram account-login flows on top of
//! the RPC layer.
//!
//!   * `flow` — the stateless flow steps (`sendCode`, `signIn`, `signUp`,
//!     `checkPassword`, `updatePassword`, `logOut`, `resendCode`,
//!     `cancelCode`) over one `rpc.Client`, the well-known auth
//!     `rpc_error`s mapped to typed errors (`mapRpcError`), and the
//!     stateful `Client` state machine (`State`: `logged_out` →
//!     `waiting_code` → `authorized`, with `waiting_password` for 2FA
//!     and `waiting_registration` for fresh numbers).
//!   * `password` — the pure cloud-password (2FA) math per
//!     https://core.telegram.org/api/srp: `Algo` (server-parameter
//!     validation incl. the 2048-bit safe-prime checks), `Srp` (the
//!     login exchange producing `inputCheckPasswordSRP`), and
//!     `newPasswordHash` (the KDF for setting a password).
//!
//! Layering: this module never touches a transport; it speaks generated
//! API structs through `rpc.Client.call` and hands decoded results (and
//! the arena that owns them) back to the caller. Persisting the *session*
//! that results from a successful login is the session subsystem's job:
//! capture `session.State` from the live client (it already holds the
//! authorized key) and save it through a `session.Store` — see
//! `tests/auth.zig` for the full flow including that capture.
//!
//! Typical first login:
//!
//!     var auth = td.auth.Client.init(allocator, &rpc_client, api_id, api_hash);
//!     try auth.sendCode(io, "+15550101", .{ .codeSettings = .{} });
//!     // ... user types the code ...
//!     auth.signIn(io, code) catch |e| switch (e) {
//!         error.SessionPasswordNeeded => auth.checkPassword(io, random, password),
//!         else => return e,
//!     };
//!     // auth.userId() is set; capture/persist the session now.

pub const flow = @import("flow.zig");
pub const password = @import("password.zig");

pub const Client = flow.Client;
pub const State = flow.State;
pub const Error = flow.Error;
pub const mapRpcError = flow.mapRpcError;
pub const userIdOf = flow.userIdOf;

test {
    _ = @import("flow.zig");
    _ = @import("password.zig");
}
