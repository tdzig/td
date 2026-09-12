# Vendored Telegram RPC error catalogs

One TSV per HTTP-style status code, format `id<TAB>message` with a header
row: the wire error identifier and its human description. An `_X` suffix
marks a parameterized error whose wire form carries a numeric suffix
(`FLOOD_WAIT_X` ← `FLOOD_WAIT_60`) and whose description contains a
`{value}` placeholder.

- Source: <https://github.com/mtgo-labs/mtgo/tree/master/compiler/errors_source>
  (itself inherited from gotd/td's error lists)
- Pinned commit: `8df3cb5cf8de1becb56cdb22e4bc8dd8fd4bd004`
- License: Apache-2.0 (data only, not linked code; td itself is MIT)

Lines whose id field does not match `^[A-Z0-9][A-Z0-9_]*$` are skipped by
the generator, matching mtgo's `cmd/errgen` behavior. The same id may
appear under several codes; the first file in sorted name order wins.

Regenerate `src/rpc/errors_gen.zig` from these files with `just errors`.
