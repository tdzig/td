//! The authentication flows over one `rpc.Client`: send code, sign in,
//! sign up, the 2FA (cloud password) exchange, logout — and the
//! authorization state they produce.
//!
//! Layering: everything Telegram-specific about *logging a human in*
//! lives here; the raw MTProto machinery stays in `rpc` and the SRP math
//! in `password.zig`. Two entry levels:
//!
//!   * Stateless functions (`sendCode`, `signIn`, `signUp`,
//!     `checkPassword`, `getPassword`, `updatePassword`, `logOut`,
//!     `resendCode`, `cancelCode`) — one flow step over a borrowed
//!     `rpc.Client`, returning the arena-backed `rpc.Response(T)` of the
//!     generated result union. Compose your own protocol from these.
//!   * `Client` — a thin state machine around the same steps: it carries
//!     the api id/hash, remembers the phone number and
//!     `phone_code_hash` between steps, classifies the well-known auth
//!     `rpc_error`s into typed errors (`error.SessionPasswordNeeded`,
//!     `error.PhoneCodeInvalid`, ...), tracks the `State` (`logged_out`
//!     → `waiting_code` → `authorized` / `waiting_password` /
//!     `waiting_registration`) and owns the state strings.
//!
//! Decoded values returned by the stateless functions borrow their
//! response arena and die with it (`Response.deinit`). That split — no
//! hand-rolled serialization, no transport knowledge — is what keeps
//! authentication logic separate from raw MTProto here.
//!
//! Not covered (by design): SMS-request rate limiting and the
//! `invokeWithLayer`/`initConnection` wrapping of outgoing queries —
//! that belongs to the connection-establishment layer above which these
//! functions sit.

const std = @import("std");
const rpc = @import("../rpc/mod.zig");
const api = @import("../api/mod.zig");
const crypto = @import("../crypto/mod.zig");
const password = @import("password.zig");

/// Everything the flows can fail with: the rpc error set, the SRP/2FA
/// errors, and the typed auth `rpc_error`s (see `mapRpcError`).
pub const Error = rpc.Error || password.Error || error{
    OutOfMemory,
    /// `signIn`/`resendCode` before a successful `sendCode`.
    NotWaitingForCode,
    /// `signUp` before the server asked for registration.
    NotWaitingForRegistration,
    /// `checkPassword` answered for an account with no password set.
    NoPasswordSet,
    /// The server's `current_algo`/`new_algo` is not an SRP algo this
    /// module accepts (see `password.Algo.init` for what it refuses).
    UnsupportedPasswordAlgo,
    /// The server kept failing the SRP proof checks on fresh attempts.
    InvalidServerProof,
    // ---- well-known auth rpc_errors (details in Client.lastRpcError)
    PhoneNumberInvalid,
    PhoneNumberUnoccupied,
    PhoneNumberOccupied,
    PhoneNumberBanned,
    PhoneCodeInvalid,
    PhoneCodeExpired,
    PhoneCodeEmpty,
    PhoneCodeHashEmpty,
    SessionPasswordNeeded,
    PasswordHashInvalid,
    PasswordMissing,
    FirstNameInvalid,
    LastNameInvalid,
    /// The session was terminated server-side (AUTH_KEY_UNREGISTERED).
    AuthorizationRevoked,
    /// `sentCodePaymentRequired`: this number needs a paid signup.
    PaymentRequired,
};

/// Maps `error.RpcError` onto the well-known auth errors using the
/// client's `lastRpcError()`; every other error passes through.
/// FLOOD_WAIT stays `error.RpcError` — read `client.lastRpcError()` for
/// the wait seconds.
pub fn mapRpcError(client: *rpc.Client, e: rpc.Error) Error {
    switch (e) {
        error.RpcError => {},
        else => return e,
    }
    const info = client.lastRpcError();
    const msg = info.message;
    if (std.mem.eql(u8, msg, "SESSION_PASSWORD_NEEDED")) return error.SessionPasswordNeeded;
    if (std.mem.eql(u8, msg, "PHONE_NUMBER_INVALID")) return error.PhoneNumberInvalid;
    if (std.mem.eql(u8, msg, "PHONE_NUMBER_UNOCCUPIED")) return error.PhoneNumberUnoccupied;
    if (std.mem.eql(u8, msg, "PHONE_NUMBER_OCCUPIED")) return error.PhoneNumberOccupied;
    if (std.mem.eql(u8, msg, "PHONE_NUMBER_BANNED")) return error.PhoneNumberBanned;
    if (std.mem.eql(u8, msg, "PHONE_CODE_INVALID")) return error.PhoneCodeInvalid;
    if (std.mem.eql(u8, msg, "PHONE_CODE_EXPIRED")) return error.PhoneCodeExpired;
    if (std.mem.eql(u8, msg, "PHONE_CODE_EMPTY")) return error.PhoneCodeEmpty;
    if (std.mem.eql(u8, msg, "PHONE_CODE_HASH_EMPTY")) return error.PhoneCodeHashEmpty;
    if (std.mem.eql(u8, msg, "PASSWORD_HASH_INVALID")) return error.PasswordHashInvalid;
    if (std.mem.eql(u8, msg, "PASSWORD_MISSING")) return error.PasswordMissing;
    if (std.mem.eql(u8, msg, "FIRSTNAME_INVALID")) return error.FirstNameInvalid;
    if (std.mem.eql(u8, msg, "LASTNAME_INVALID")) return error.LastNameInvalid;
    if (std.mem.eql(u8, msg, "AUTH_KEY_UNREGISTERED")) return error.AuthorizationRevoked;
    return error.RpcError;
}

// ------------------------------------------------------------- helpers

/// The logged-in user's id, when the `User` carries one.
pub fn userIdOf(user: *const api.User) ?i64 {
    return switch (user.*) {
        .user => |u| u.id,
        .userEmpty => |u| u.id,
    };
}

/// The user id of an `auth.Authorization` result, null for the
/// `authorizationSignUpRequired` tag.
pub fn authorizationUserId(value: *const api.auth.Authorization_) ?i64 {
    return switch (value.*) {
        .authorization => |a| userIdOf(&a.user),
        .authorizationSignUpRequired => null,
    };
}

// ------------------------------------------------- stateless flow steps

/// `auth.sendCode`: asks the server to deliver a login code to
/// `phone_number`. The `.sentCode` tag of the response carries the
/// `phone_code_hash` the following `signIn` needs (borrowed from the
/// response arena).
pub fn sendCode(
    client: *rpc.Client,
    io: std.Io,
    phone_number: []const u8,
    api_id: i32,
    api_hash: []const u8,
    settings: api.CodeSettings,
) Error!rpc.Response(api.auth.SentCode) {
    return client.call(io, api.auth.sendCode{
        .phone_number = phone_number,
        .api_id = api_id,
        .api_hash = api_hash,
        .settings = settings,
    }, api.auth.SentCode) catch |e| return mapRpcError(client, e);
}

/// `auth.signIn`: the code the user received. A `.signUpRequired`
/// result is a valid outcome, not an error — check `value` (or use the
/// stateful `Client`, which maps it to `.waiting_registration`).
pub fn signIn(
    client: *rpc.Client,
    io: std.Io,
    phone_number: []const u8,
    phone_code_hash: []const u8,
    phone_code: []const u8,
) Error!rpc.Response(api.auth.Authorization_) {
    return client.call(io, api.auth.signIn{
        .phone_number = phone_number,
        .phone_code_hash = phone_code_hash,
        .phone_code = phone_code,
    }, api.auth.Authorization_) catch |e| return mapRpcError(client, e);
}

/// `auth.signUp`: first registration of a fresh account, after the code
/// stage signalled sign-up-required.
pub fn signUp(
    client: *rpc.Client,
    io: std.Io,
    phone_number: []const u8,
    phone_code_hash: []const u8,
    phone_code: []const u8,
    first_name: []const u8,
    last_name: []const u8,
) Error!rpc.Response(api.auth.Authorization_) {
    return client.call(io, api.auth.signUp{
        .phone_number = phone_number,
        .phone_code_hash = phone_code_hash,
        .phone_code = phone_code,
        .first_name = first_name,
        .last_name = last_name,
    }, api.auth.Authorization_) catch |e| return mapRpcError(client, e);
}

/// `account.getPassword`: the 2FA parameters for the next
/// `checkPassword` / `updatePassword`.
pub fn getPassword(
    client: *rpc.Client,
    io: std.Io,
) Error!rpc.Response(api.account.Password) {
    return client.call(io, api.account.getPassword{}, api.account.Password) catch |e| return mapRpcError(client, e);
}

/// Internal: one SRP `inputCheckPasswordSRP` for `srp_id`/`srp_B` and
/// `password`. Validates the algo, retries with a fresh random `a` (per
/// the spec) while the server keeps failing the proof checks, and
/// copies the answer into `arena` — so the result outlives this call and
/// dies with the arena, just in time for the request serialization.
fn srpAnswerFor(
    arena: std.mem.Allocator,
    random: std.Random,
    current_algo: api.PasswordKdfAlgo,
    srp_id: i64,
    srp_B: []const u8,
    pw: []const u8,
) Error!api.inputCheckPasswordSRP {
    const algo = password.Algo.init(arena, current_algo, random) catch |e| switch (e) {
        error.InvalidAlgo => return error.UnsupportedPasswordAlgo,
        else => return e,
    };
    // No algo.deinit(): the salts are arena allocations, freed with it.

    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        var srp = try password.Srp.init(arena, random, &algo, pw);
        defer srp.deinit();
        if (srp.answer(srp_id, srp_B)) |ans| {
            return .{
                .srp_id = ans.srp_id,
                .A = arena.dupe(u8, ans.A) catch return error.OutOfMemory,
                .M1 = arena.dupe(u8, ans.M1) catch return error.OutOfMemory,
            };
        } else |e| switch (e) {
            // Fresh random `a` and retry, per the specification; give
            // up after a few attempts (a hostile server pattern).
            error.InvalidServerProof => {
                if (attempt >= 3) return error.InvalidServerProof;
            },
            else => return e,
        }
    }
}

/// `auth.checkPassword`: the second factor. Fetches the SRP parameters,
/// runs the SRP exchange locally and answers the server's challenge.
/// `error.PasswordHashInvalid` means the password was wrong.
pub fn checkPassword(
    client: *rpc.Client,
    io: std.Io,
    allocator: std.mem.Allocator,
    random: std.Random,
    pw: []const u8,
) Error!rpc.Response(api.auth.Authorization_) {
    var pw_res = try getPassword(client, io);
    defer pw_res.deinit();
    const info = switch (pw_res.value) {
        .password => |p| p,
    };
    if (!info.has_password) return error.NoPasswordSet;
    const current_algo = info.current_algo orelse return error.NoPasswordSet;
    const srp_id = info.srp_id orelse return error.UnsupportedPasswordAlgo;
    const srp_B = info.srp_B orelse return error.UnsupportedPasswordAlgo;

    // Everything below borrows this arena: the request is serialized
    // inside `call`, the response outlives it independently.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const answer = try srpAnswerFor(
        arena_state.allocator(),
        random,
        current_algo,
        srp_id,
        srp_B,
        pw,
    );

    return client.call(io, api.auth.checkPassword{
        .password = .{ .inputCheckPasswordSRP = answer },
    }, api.auth.Authorization_) catch |e| return mapRpcError(client, e);
}

/// `auth.logOut`.
pub fn logOut(
    client: *rpc.Client,
    io: std.Io,
) Error!rpc.Response(api.auth.LoggedOut) {
    return client.call(io, api.auth.logOut{}, api.auth.LoggedOut) catch |e| return mapRpcError(client, e);
}

/// `auth.resendCode`.
pub fn resendCode(
    client: *rpc.Client,
    io: std.Io,
    phone_number: []const u8,
    phone_code_hash: []const u8,
) Error!rpc.Response(api.auth.SentCode) {
    return client.call(io, api.auth.resendCode{
        .phone_number = phone_number,
        .phone_code_hash = phone_code_hash,
    }, api.auth.SentCode) catch |e| return mapRpcError(client, e);
}

/// `auth.cancelCode`.
pub fn cancelCode(
    client: *rpc.Client,
    io: std.Io,
    phone_number: []const u8,
    phone_code_hash: []const u8,
) Error!rpc.Response(api.Bool) {
    return client.call(io, api.auth.cancelCode{
        .phone_number = phone_number,
        .phone_code_hash = phone_code_hash,
    }, api.Bool) catch |e| return mapRpcError(client, e);
}

/// `account.updatePasswordSettings`: set (when `current` is null) or
/// change the cloud password, with optional hint and recovery email.
/// Requires an authorization; when a password is already set, `current`
/// must carry it (SRP-proofed, like `checkPassword`).
pub fn updatePassword(
    client: *rpc.Client,
    io: std.Io,
    allocator: std.mem.Allocator,
    random: std.Random,
    current: ?[]const u8,
    new_password: ?[]const u8,
    hint: ?[]const u8,
    email: ?[]const u8,
) Error!rpc.Response(api.Bool) {
    var pw_res = try getPassword(client, io);
    defer pw_res.deinit();
    const info = switch (pw_res.value) {
        .password => |p| p,
    };

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The `password:` field — SRP proof of the current password, or the
    // empty marker when none is set.
    const input: api.InputCheckPasswordSRP = blk: {
        if (info.has_password) {
            const cur = current orelse return error.PasswordMissing;
            const current_algo = info.current_algo orelse return error.NoPasswordSet;
            const srp_id = info.srp_id orelse return error.UnsupportedPasswordAlgo;
            const srp_B = info.srp_B orelse return error.UnsupportedPasswordAlgo;
            break :blk .{ .inputCheckPasswordSRP = try srpAnswerFor(
                arena,
                random,
                current_algo,
                srp_id,
                srp_B,
                cur,
            ) };
        }
        break :blk .{ .inputCheckPasswordEmpty = {} };
    };

    // The new settings — only when a new password was requested. The
    // server's `new_algo` carries the server-side salt; the spec
    // requires extending its salt1 with client randomness before
    // hashing. `new_algo`'s slices are copied into the arena (salt1 in
    // extended form), so everything lives until the serialization.
    const new_settings: api.account.passwordInputSettings = new_settings_blk: {
        if (new_password) |np| {
            const algo = password.Algo.init(arena, info.new_algo, random) catch |e| switch (e) {
                error.InvalidAlgo => return error.UnsupportedPasswordAlgo,
                else => return e,
            };
            const new_salt = try algo.withExtendedSalt(arena, random);
            const hash = try password.newPasswordHash(arena, &algo, new_salt, np);
            // Not deinit-ing `algo`: its buffers are arena-owned.
            break :new_settings_blk .{
                .new_algo = .{ .passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow = .{
                    .salt1 = new_salt,
                    .salt2 = algo.salt2,
                    .g = algo.g,
                    .p = &algo.p,
                } },
                .new_password_hash = &hash,
                .hint = hint,
                .email = email,
            };
        }
        break :new_settings_blk .{ .hint = hint, .email = email };
    };

    return client.call(io, api.account.updatePasswordSettings{
        .password = input,
        .new_settings = .{ .passwordInputSettings = new_settings },
    }, api.Bool) catch |e| return mapRpcError(client, e);
}

// ------------------------------------------------------ stateful client

/// Phone + hash pair carried between the code and the sign-in stages.
const Contact = struct {
    phone_number: []u8,
    phone_code_hash: []u8,
};

/// The login state `Client` sits in. The `Contact` payloads are owned
/// by the client.
pub const State = union(enum) {
    logged_out,
    /// A code was sent to the phone; keep the hash for `signIn`.
    waiting_code: Contact,
    /// The account has 2FA enabled; `checkPassword` finishes the login.
    waiting_password,
    /// The number is not registered; `signUp` finishes the login.
    waiting_registration: Contact,
    /// Logged in as this user id.
    authorized: struct {
        user_id: i64,
    },
};

/// Stateful authentication client over one `rpc.Client`. All methods
/// take `io` like the rest of td; the client borrows the rpc client
/// and owns only its own state strings.
pub const Client = struct {
    allocator: std.mem.Allocator,
    rpc: *rpc.Client,
    api_id: i32,
    api_hash: []const u8,
    state: State = .logged_out,

    pub fn init(
        allocator: std.mem.Allocator,
        rpc_client: *rpc.Client,
        api_id: i32,
        api_hash: []const u8,
    ) Client {
        return .{
            .allocator = allocator,
            .rpc = rpc_client,
            .api_id = api_id,
            .api_hash = api_hash,
        };
    }

    pub fn deinit(self: *Client) void {
        self.clearState();
    }

    fn clearState(self: *Client) void {
        switch (self.state) {
            .waiting_code, .waiting_registration => |c| {
                self.allocator.free(c.phone_number);
                self.allocator.free(c.phone_code_hash);
            },
            else => {},
        }
        self.state = .logged_out;
    }

    fn setContact(self: *Client, phone_number: []const u8, phone_code_hash: []const u8) Error!void {
        const phone = self.allocator.dupe(u8, phone_number) catch return error.OutOfMemory;
        errdefer self.allocator.free(phone);
        const hash = self.allocator.dupe(u8, phone_code_hash) catch return error.OutOfMemory;
        errdefer self.allocator.free(hash);
        self.clearState();
        self.state = .{ .waiting_code = .{
            .phone_number = phone,
            .phone_code_hash = hash,
        } };
    }

    /// The pending phone/hash pair, when the state carries one.
    fn contact(self: *const Client) ?Contact {
        return switch (self.state) {
            .waiting_code, .waiting_registration => |c| c,
            else => null,
        };
    }

    /// The user id when authorized, null otherwise.
    pub fn userId(self: *const Client) ?i64 {
        return switch (self.state) {
            .authorized => |a| a.user_id,
            else => null,
        };
    }

    /// Asks the server to send the login code. On success the state
    /// becomes `waiting_code`.
    pub fn sendCode(self: *Client, io: std.Io, phone_number: []const u8, settings: api.CodeSettings) Error!void {
        var res = try sendCodeReq(self.rpc, io, phone_number, self.api_id, self.api_hash, settings);
        defer res.deinit();
        switch (res.value) {
            .sentCode => |sc| try self.setContact(phone_number, sc.phone_code_hash),
            .sentCodeSuccess => |s| {
                self.clearState();
                self.state = .{ .authorized = .{
                    .user_id = authorizationUserId(&s.authorization) orelse 0,
                } };
            },
            .sentCodePaymentRequired => return error.PaymentRequired,
        }
    }

    /// Re-sends the code for the pending phone number.
    pub fn resendCode(self: *Client, io: std.Io) Error!void {
        const c = self.contact() orelse return error.NotWaitingForCode;
        var res = try resendCodeReq(self.rpc, io, c.phone_number, c.phone_code_hash);
        defer res.deinit();
        // A fresh code for the same hash does not change the state.
    }

    /// Verifies the code. On success → `authorized`; if the account has
    /// 2FA → error.SessionPasswordNeeded and state `waiting_password`;
    /// if the number is unregistered → state `waiting_registration`.
    pub fn signIn(self: *Client, io: std.Io, code: []const u8) Error!void {
        const c = self.contact() orelse return error.NotWaitingForCode;
        var res = signInReq(self.rpc, io, c.phone_number, c.phone_code_hash, code) catch |e| {
            if (e == error.SessionPasswordNeeded) {
                self.clearState();
                self.state = .waiting_password;
            }
            return e;
        };
        defer res.deinit();
        try self.applyAuthorization(&res.value);
    }

    /// Registers the fresh account with the pending code.
    pub fn signUp(self: *Client, io: std.Io, first_name: []const u8, last_name: []const u8) Error!void {
        if (self.state != .waiting_registration) return error.NotWaitingForRegistration;
        const c = self.contact().?;
        var res = try signUpReq(self.rpc, io, c.phone_number, c.phone_code_hash, "", first_name, last_name);
        defer res.deinit();
        try self.applyAuthorization(&res.value);
    }

    /// Second factor. On success → `authorized`;
    /// `error.PasswordHashInvalid` means wrong password.
    pub fn checkPassword(self: *Client, io: std.Io, random: std.Random, pw: []const u8) Error!void {
        var res = try checkPasswordReq(self.rpc, io, self.allocator, random, pw);
        defer res.deinit();
        try self.applyAuthorization(&res.value);
    }

    /// Logs out server-side and resets to `logged_out`. The server
    /// invalidates this authorization; the local `session.State` (auth
    /// key) should be dropped by the caller as well.
    pub fn logOut(self: *Client, io: std.Io) Error!void {
        var res = try logOutReq(self.rpc, io);
        defer res.deinit();
        self.clearState();
    }

    fn applyAuthorization(self: *Client, value: *const api.auth.Authorization_) Error!void {
        switch (value.*) {
            .authorization => |a| {
                self.clearState();
                self.state = .{ .authorized = .{
                    .user_id = userIdOf(&a.user) orelse 0,
                } };
            },
            .authorizationSignUpRequired => {
                const c = self.contact() orelse return error.NotWaitingForCode;
                const phone = self.allocator.dupe(u8, c.phone_number) catch return error.OutOfMemory;
                errdefer self.allocator.free(phone);
                const hash = self.allocator.dupe(u8, c.phone_code_hash) catch return error.OutOfMemory;
                errdefer self.allocator.free(hash);
                self.clearState();
                self.state = .{ .waiting_registration = .{
                    .phone_number = phone,
                    .phone_code_hash = hash,
                } };
            },
        }
    }
};

// The stateless steps, renamed for the stateful methods (a bare call
// inside `Client` would resolve to the method of the same name).
const sendCodeReq = sendCode;
const signInReq = signIn;
const signUpReq = signUp;
const checkPasswordReq = checkPassword;
const logOutReq = logOut;
const resendCodeReq = resendCode;

// ---------------------------------------------------------------- tests

test "mapRpcError classifies the well-known auth errors" {
    var prng = std.Random.DefaultPrng.init(3);

    var key: [crypto.auth_key_size]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);

    var client = try rpc.Client.init(
        std.testing.allocator,
        undefined, // transport never touched on this path
        &key,
        1,
        prng.random(),
        .{},
    );
    defer client.deinit();

    const Case = struct { msg: []const u8, expect: Error };
    const cases = [_]Case{
        .{ .msg = "SESSION_PASSWORD_NEEDED", .expect = error.SessionPasswordNeeded },
        .{ .msg = "PHONE_NUMBER_INVALID", .expect = error.PhoneNumberInvalid },
        .{ .msg = "PHONE_CODE_EXPIRED", .expect = error.PhoneCodeExpired },
        .{ .msg = "PASSWORD_HASH_INVALID", .expect = error.PasswordHashInvalid },
        .{ .msg = "AUTH_KEY_UNREGISTERED", .expect = error.AuthorizationRevoked },
        .{ .msg = "FLOOD_WAIT_60", .expect = error.RpcError },
    };
    for (cases) |c| {
        @memcpy(client.rpc_error_buf[0..c.msg.len], c.msg);
        client.last_rpc_error = .{ .code = 400, .message = client.rpc_error_buf[0..c.msg.len] };
        try std.testing.expectEqual(c.expect, mapRpcError(&client, error.RpcError));
    }

    // Non-rpc errors pass through untouched.
    try std.testing.expectEqual(@as(Error, error.Disconnected), mapRpcError(&client, error.Disconnected));
}
