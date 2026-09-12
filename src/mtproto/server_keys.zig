//! Official Telegram MTProto server RSA public keys, vendored from the
//! official Telegram Desktop source (telegramdesktop/tdesktop, dev
//! branch, `Telegram/SourceFiles/mtproto/mtproto_dc_options.cpp`,
//! `kPublicRSAKeys` / `kTestPublicRSAKeys`, fetched 2026-09-11).
//!
//! These are Telegram's own published handshake keys — the constants
//! every official client embeds to verify the server during the
//! authorization-key DH handshake. They are public by nature (the
//! server proves itself with the matching private half). The PEM
//! bodies are decoded to `rsa.PublicKey` at **compile time** — no
//! hand-transcribed hex anywhere; a malformed vendor blob fails the
//! build instead of shipping a corrupt key.
//!
//! Overrides remain available: `td-keygen --pubkey <modulus.hex>` and
//! `DataCenters.connect(..., pubkeys, ...)` accept caller-provided keys
//! (e.g. if Telegram rotates keys or a custom server is tested).

const std = @import("std");
const rsa = @import("rsa.zig");

const production_pem_1 =
    \\-----BEGIN RSA PUBLIC KEY-----
    \\MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
    \\5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
    \\62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
    \\+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
    \\t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
    \\5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
    \\-----END RSA PUBLIC KEY-----
;

const test_pem_1 =
    \\-----BEGIN RSA PUBLIC KEY-----
    \\MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
    \\yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
    \\plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
    \\j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
    \\aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
    \\j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
    \\-----END RSA PUBLIC KEY-----
;

/// Decodes a PEM `RSAPUBLIC KEY` (PKCS#1: SEQUENCE { INTEGER modulus,
/// INTEGER e }) into a 2048-bit `rsa.PublicKey`. Compile-time only:
/// every structural mismatch is `unreachable`, so a bad vendored blob
/// is a build error, never a runtime surprise.
fn publicKeyFromPem(comptime pem: []const u8) rsa.PublicKey {
    comptime {
        // Collect the base64 body between the BEGIN/END markers.
        var b64: []const u8 = "";
        var in_body = false;
        var i: usize = 0;
        while (i < pem.len) {
            const end = std.mem.indexOfScalarPos(u8, pem, i, '\n') orelse pem.len;
            const line = std.mem.trim(u8, pem[i..end], " \t\r");
            if (std.mem.startsWith(u8, line, "-----BEGIN")) {
                in_body = true;
            } else if (std.mem.startsWith(u8, line, "-----END")) {
                break;
            } else if (in_body) {
                b64 = b64 ++ line;
            }
            i = end + 1;
        }

        var der: [std.base64.standard.Decoder.calcSizeForSlice(b64) catch unreachable]u8 = undefined;
        std.base64.standard.Decoder.decode(&der, b64) catch unreachable;

        // Locate the modulus INTEGER: type 0x02, long form length 0x82
        // 0x01 0x01 (257 bytes), leading 0x00 (positive sign marker).
        var j: usize = 0;
        while (j + 5 <= der.len) : (j += 1) {
            if (der[j] == 0x02 and der[j + 1] == 0x82 and
                der[j + 2] == 0x01 and der[j + 3] == 0x01 and der[j + 4] == 0x00) break;
        }
        if (j + 5 + 256 > der.len) unreachable; // modulus INTEGER not found

        var n: [256]u8 = undefined;
        @memcpy(&n, der[j + 5 ..][0..256]);

        // The exponent INTEGER must follow and must be 65537.
        const e = j + 5 + 256;
        if (e + 5 > der.len or
            der[e] != 0x02 or der[e + 1] != 0x03 or
            der[e + 2] != 0x01 or der[e + 3] != 0x00 or der[e + 4] != 0x01) unreachable;

        return .{ .n = n, .e = 65537 };
    }
}

/// Production-network handshake keys.
pub const production: []const rsa.PublicKey = &.{
    publicKeyFromPem(production_pem_1),
};

/// Test-network handshake keys.
pub const test_network: []const rsa.PublicKey = &.{
    publicKeyFromPem(test_pem_1),
};

test "vendored server keys decode with the documented fingerprints" {
    // The production key's fingerprint is published in the official
    // handshake sample (core.telegram.org/mtproto/samples-auth_key): the
    // live DCs offer it in every resPQ. Pinning it here catches both
    // fingerprint-formula and vendor-blob regressions.
    try std.testing.expectEqual(@as(u64, 0x85fd64de851d9dd0), production[0].fingerprint());
    try std.testing.expect(test_network[0].fingerprint() != production[0].fingerprint());
    for (test_network) |*k| {
        try std.testing.expect(k.fingerprint() != 0);
    }
}
