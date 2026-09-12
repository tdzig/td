//! MTProto protocol layer: authorization-key handshake, encrypted-message
//! framing and the stateful session on top of it. Transport-independent
//! by design — networking lives behind the `handshake.Transport` interface
//! (production callers adapt the `transport.TcpFull` frame pipe to it, as
//! `dc.manager` and `td-keygen` do) or the type-erased
//! `transport.Transport` vtable.

pub const bigint = @import("bigint.zig");
pub const factor = @import("factor.zig");
pub const rsa = @import("rsa.zig");
pub const inner = @import("inner.zig");
pub const schema = @import("schema.zig");
/// GENERATED from schema/mtproto.tl (`just mtp`); regenerate, never edit.
pub const schema_gen = @import("schema_gen.zig");
pub const handshake = @import("handshake.zig");
pub const message = @import("message.zig");
pub const session = @import("session.zig");
pub const pfs = @import("pfs.zig");
pub const handshake_pipe = @import("handshake_pipe.zig");

pub const Handshake = handshake.Handshake;
pub const HandshakePipe = handshake_pipe.HandshakePipe;
pub const Transport = handshake.Transport;
pub const AuthKey = handshake.AuthKey;
pub const RsaPublicKey = rsa.PublicKey;
pub const Session = session.Session;

/// Test-only 2048-bit RSA keypair for loopback handshake tests.
/// Never use with production keys.
pub const testkeys = @import("testkeys.zig");

/// Official Telegram server RSA public keys (vendored from the official
/// Telegram Desktop source; PEM decoded at compile time). Used by
/// `DataCenters.connect` and `td-keygen` by default.
pub const server_keys = @import("server_keys.zig");

test {
    _ = @import("bigint.zig");
    _ = @import("factor.zig");
    _ = @import("rsa.zig");
    _ = @import("inner.zig");
    _ = @import("schema.zig");
    _ = @import("schema_gen.zig");
    _ = @import("handshake.zig");
    _ = @import("message.zig");
    _ = @import("session.zig");
    _ = @import("pfs.zig");
    _ = @import("testkeys.zig");
    _ = @import("server_keys.zig");
}
