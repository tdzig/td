//! MTProto 2.0 cryptographic primitives (independent of networking).
//!
//! Hashes and the AES core come from Zig's audited `std.crypto`; the IGE
//! mode chaining and the MTProto key/msg_key derivation follow the official
//! specification at https://core.telegram.org/mtproto/description.

pub const aes_ige = @import("aes_ige.zig");
pub const mtproto = @import("mtproto.zig");

pub const Sha1 = mtproto.Sha1;
pub const Sha256 = mtproto.Sha256;
pub const auth_key_size = mtproto.auth_key_size;
pub const msg_key_size = mtproto.msg_key_size;
pub const block_size = mtproto.block_size;
pub const min_padding = mtproto.min_padding;
pub const authKeyId = mtproto.authKeyId;
pub const computeMsgKey = mtproto.computeMsgKey;
pub const deriveAesParams = mtproto.deriveAesParams;
pub const AesParams = mtproto.AesParams;
pub const padMessage = mtproto.padMessage;
pub const paddedLength = mtproto.paddedLength;
pub const encryptMessage = mtproto.encryptMessage;
pub const decryptMessage = mtproto.decryptMessage;
pub const computeMsgKeyV1 = mtproto.computeMsgKeyV1;
pub const deriveAesParamsV1 = mtproto.deriveAesParamsV1;
pub const randomBytes = mtproto.randomBytes;
pub const Direction = mtproto.Direction;

test {
    _ = @import("aes_ige.zig");
    _ = @import("mtproto.zig");
}
