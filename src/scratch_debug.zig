const std = @import("std");
const inner = @import("mtproto/inner.zig");
const ige = @import("crypto/aes_ige.zig");

test "debug seal/open" {
    var prng = std.Random.DefaultPrng.init(9);
    const params = inner.tmpAesParams(&([_]u8{1} ** 32), &([_]u8{2} ** 16));

    const data = "inner data here";
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(data, &digest, .{});
    std.debug.print("sha1 prefix: {x}\n", .{digest});

    const sealed = try inner.sealInner(std.testing.allocator, params, data, prng.random());
    defer std.testing.allocator.free(sealed);
    std.debug.print("sealed len={d} first bytes: {x}\n", .{ sealed.len, sealed[0..24] });

    // raw IGE roundtrip sanity on the sealed buffer
    var copy: [64]u8 = undefined;
    @memcpy(copy[0..sealed.len], sealed);
    ige.decrypt256(params.key, params.iv, copy[0..sealed.len], copy[0..sealed.len]) catch unreachable;
    std.debug.print("decrypted first 24: {x}\n", .{copy[0..24]});
}
