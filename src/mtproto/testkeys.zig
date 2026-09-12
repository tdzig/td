//! Test-only 2048-bit RSA keypair, generated once with OpenSSL for the
//! loopback handshake tests (`openssl genrsa 2048`). The private exponent
//! exists ONLY for the in-process mock server; it must never be used with
//! production keys.

pub const modulus_hex =
    "a97420536ccc7470299a1066be9dbffb6720c698a24434c5231336eb3469bb6d" ++
    "43808f760d2b18715482046610542ac7641deb2add2fb69c01dbca3f33492391" ++
    "b6ee6deb25736006b3825968f2070d38b09d65de0c48701b82a031e70cf62f43" ++
    "58eeaa424455946016815ab5ae8a2cb0833034149a2a34041978ec3233358ace" ++
    "14f391c786bb7a9f8f23f3927b68239c54d849788d0acd1c1566627c4c935eafe" ++
    "9c364c2a03599f205d5c69925d9c81c4df3466ad2c37158167b939202d97a75ba" ++
    "ef4b5a62649f3ddc1c421725f404958b715185bc47c45669433105e52f5bb223" ++
    "314941c2699a2eb493b5ef9dd37fff2daf4cab10e09b94615b2b0a3199d41b";

pub const private_exponent_hex =
    "1a4eaf88141f87c2340b3999a1e53ebd6a8cd19837b4ec1660f426360ccc8f6f" ++
    "0ea8425d7afce24e11e71f84b2eb463aef659fb16766756cb1f32bea74ed596a" ++
    "d16221c97c66759584bfeb5e9a18932a666d013820630c9890c68b08ca5fdc059" ++
    "224776553538ff5fcf8771b36ae37f2ed6309eadae64b6e098056f71231314bbd" ++
    "6b3fce553ccb911c3a6896b9a5cdff3d4176a11c122eb1051124b5678ceffe00" ++
    "0af9a03fb7fac62b0725d2b26a90c2b9f71ff4295f27ad810456f293217a1eaa5" ++
    "9068fc5d962b101e24419564a89b715e458f175a7c914b5c54800462bb8f626a3" ++
    "da99c322f4b858ffc0c9b893485c63ec4c1d20198dcb17405415d77efb8d";

pub const modulus_be: [256]u8 = blk: {
    var bytes: [256]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, modulus_hex) catch unreachable;
    break :blk bytes;
};

pub const d_be: [256]u8 = blk: {
    var bytes: [256]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, private_exponent_hex) catch unreachable;
    break :blk bytes;
};

const std = @import("std");

test "test key material decodes" {
    // Both values must be odd (RSA moduli and private exponents are).
    try std.testing.expect(modulus_be[255] & 1 == 1);
    try std.testing.expect(d_be[255] & 1 == 1);
}
