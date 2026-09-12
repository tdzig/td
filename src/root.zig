//! td — a Telegram MTProto 2.0 client library for Zig.
//!
//! Current status: **TL foundation + full official-schema parser + TL
//! code generator + generated Telegram API + MTProto 2.0 crypto +
//! authorization-key handshake + TCP-full transport + encrypted-message
//! session layer + RPC invoke system + DC configuration/migration +
//! session persistence + connection management (automatic reconnection,
//! backoff, recovery, health) + updates dispatch, state tracking and
//! getDifference reconciliation + account authentication (code, sign-in,
//! sign-up, 2FA/SRP, logout) + multi-session scheduling with fleet-scale
//! benchmarks (written; pending first verified run — see README) +
//! high-level client facade (`td.Client`: init/connect/invoke over the
//! whole stack, portable session strings in and out) + structured
//! client storage (session record, peer cache, update state;
//! in-memory backend).**

pub const tl = @import("tl/mod.zig");
pub const errors = @import("errors.zig");
pub const errgen = @import("errgen.zig");
pub const crypto = @import("crypto/mod.zig");
pub const mtproto = @import("mtproto/mod.zig");
pub const transport = @import("transport/mod.zig");
pub const rpc = @import("rpc/mod.zig");
pub const dc = @import("dc/mod.zig");
pub const session = @import("session/mod.zig");
pub const storage = @import("storage/mod.zig");
pub const connman = @import("connman/mod.zig");
pub const updates = @import("updates/mod.zig");
pub const auth = @import("auth/mod.zig");
pub const multi = @import("multi/mod.zig");

/// High-level client facade: the one object an application holds.
/// Composes everything below — DC knowledge, handshake, connection
/// management, session persistence, migration — into
/// `Client.init` / `connect` / `invoke`.
pub const client = @import("client.zig");
pub const Client = client.Client;

/// Generated Telegram API layer (from the official schema in
/// `tests/data/telegram_api.tl`), split as a tree under `src/api/`:
/// `mod.zig` re-exports every declaration — the `td.api` surface is
/// identical to the old monolith — while `types/` holds the result-type
/// unions with their constructors grouped by namespace and theme,
/// `functions/` the request structs by namespace, and `registry.zig`
/// maps wire ids to names. Pure data types + serialization; completely
/// independent of any transport.
pub const api = @import("api/mod.zig");

pub const TlError = errors.TlError;
pub const ParseError = errors.ParseError;
pub const Diagnostic = errors.Diagnostic;

test {
    @import("std").testing.refAllDecls(@This());
    // Test discovery follows `_ = @import` chains: pulling in every source
    // file collects its inline test declarations.
    _ = @import("errors.zig");
    _ = @import("errgen.zig");
    _ = @import("tl/mod.zig");
    _ = @import("tl/writer.zig");
    _ = @import("tl/reader.zig");
    _ = @import("tl/types.zig");
    _ = @import("tl/parser.zig");
    _ = @import("tl/schema.zig");
    _ = @import("tl/validate.zig");
    _ = @import("tl/codegen/mod.zig");
    _ = @import("tl/codegen/naming.zig");
    _ = @import("tl/codegen/emit.zig");
    // The generated API carries its own self-test (full declaration analysis).
    _ = @import("api/mod.zig");
    _ = @import("crypto/mod.zig");
    _ = @import("mtproto/mod.zig");
    _ = @import("transport/mod.zig");
    _ = @import("rpc/mod.zig");
    _ = @import("dc/mod.zig");
    _ = @import("session/mod.zig");
    _ = @import("storage/mod.zig");
    _ = @import("connman/mod.zig");
    _ = @import("updates/mod.zig");
    _ = @import("auth/mod.zig");
    _ = @import("multi/mod.zig");
    _ = @import("client.zig");
}
