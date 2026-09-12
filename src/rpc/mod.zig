//! RPC subsystem: invoking Telegram functions over the encrypted MTProto
//! session and decoding the results into generated types.
//!
//!   * `Client` — request/response matching (msg_id keyed), pipelining,
//!     gzip inflation, automatic re-sends on bad_server_salt and the
//!     resolvable bad_msg_notification codes, and the service-message
//!     pump (acks, pongs, new sessions, future salts).
//!   * `decode` — comptime-generic result decoding (`Vector<T>` results,
//!     scalar results, pointer-boxed recursive elements) and gzip
//!     inflation.
//!
//! See `client.zig` for the layering and concurrency model, `decode.zig`
//! for the type-driven dispatch rules.

pub const client = @import("client.zig");
pub const decode = @import("decode.zig");
/// Generated Telegram RPC error catalog (`td-errgen` / `just errors`):
/// `Id` enum, descriptions and `classify` for `rpc_error` messages.
pub const errors_gen = @import("errors_gen.zig");

pub const Client = client.Client;
pub const Options = client.Options;
pub const Error = client.Error;
pub const RpcErrorInfo = client.RpcErrorInfo;
/// Error identifiers from the generated catalog (`errors_gen.Id`).
pub const RpcErrorId = errors_gen.Id;
/// Classifies a wire `rpc_error` message against the generated catalog
/// (`errors_gen.classify`).
pub const classifyRpcError = errors_gen.classify;
/// Seconds to wait for flood-wait errors; null otherwise.
pub const floodWaitSeconds = client.floodWaitSeconds;
pub const UpdatesHandler = client.UpdatesHandler;
pub const Response = client.Response;
pub const Handle = client.Handle;
pub const RawHandle = client.RawHandle;
pub const ResultOf = client.ResultOf;

pub const inflateGzip = decode.inflateGzip;
/// Type-driven decoding of raw result-object bytes (see `decode.zig`).
/// The module itself is exported as `decode` (for `buildGzipStored` and
/// friends); the function gets an unambiguous name.
pub const decodeResult = decode.decode;

test {
    _ = @import("client.zig");
    _ = @import("decode.zig");
}
