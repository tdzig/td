"""Splice the extracted KAT values into src/mtproto/bigint.zig.

One-shot provenance tool: rebuilds the DH KAT test in bigint.zig from
kat_values.txt (produced by extract_kat.py) and writes the patched
source to stdout; the caller redirects it over the file.

    cd td && python3 patch_kat.py > src/mtproto/bigint.zig
"""

import sys

vals = {}
for line in open('kat_values.txt').read().splitlines():
    k, v = line.split('=', 1)
    vals[k] = v

src = open('src/mtproto/bigint.zig').read()

# Replace the whole DH KAT test with one built from the extracted values.
start = src.index('test "powmod official example: auth_key = g_a^b mod dh_prime"')
end = src.index('test "fromBytes/toBytes roundtrip with leading zeros"') if 'test "fromBytes/toBytes roundtrip with leading zeros"' in src else len(src)
# find end: next top-level 'fn ' or EOF
end = src.index('\nfn hexRightAlign') if '\nfn hexRightAlign' in src else len(src)

new_test = '''test "powmod official example: g_b and auth_key (external KAT)" {
    // External KAT from https://core.telegram.org/mtproto/samples-auth_key:
    // g_b = g^b mod dh_prime and auth_key = g_a^b mod dh_prime with the
    // example's b, g_a, dh_prime and expected outputs.
    const g_a_hex = "%s";
    const b_hex = "%s";
    const g_b_hex = "%s";
    const dh_prime_hex = "%s";
    const expect_hex = "%s";

    var g_a_buf = [_]u8{0} ** 256;
    var b_buf = [_]u8{0} ** 256;
    var prime_buf = [_]u8{0} ** 256;
    var expect_buf = [_]u8{0} ** 256;
    _ = std.fmt.hexToBytes(&g_a_buf, g_a_hex) catch unreachable;
    _ = std.fmt.hexToBytes(&b_buf, b_hex) catch unreachable;
    _ = std.fmt.hexToBytes(&prime_buf, dh_prime_hex) catch unreachable;
    _ = std.fmt.hexToBytes(&expect_buf, expect_hex) catch unreachable;

    // auth_key = g_a^b mod dh_prime
    var auth_key: [256]u8 = undefined;
    try powmod(std.testing.allocator, &g_a_buf, &b_buf, &prime_buf, &auth_key);
    try std.testing.expectEqualSlices(u8, &expect_buf, &auth_key);

    // g_b = 3^b mod dh_prime
    var g_b: [256]u8 = undefined;
    try powmod(std.testing.allocator, &.{3}, &b_buf, &prime_buf, &g_b);
    var g_b_expect = [_]u8{0} ** 256;
    _ = std.fmt.hexToBytes(&g_b_expect, g_b_hex) catch unreachable;
    try std.testing.expectEqualSlices(u8, &g_b_expect, &g_b);
}

''' % (vals['g_a'], vals['b'], vals['g_b'], vals['dh_prime'], vals['auth_key'])

sys.stdout.write(src[:start] + new_test + src[end:])
print('patched OK', file=sys.stderr)
