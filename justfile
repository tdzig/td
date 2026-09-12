# td — task runner
#
# Zig is provided through nix (it is not on PATH in this environment);
# override with `just --set ZIG zig` when a system zig is available.

zig := "nix run nixpkgs#zig --"
default_schema := "schema/api.tl"

# List available recipes
default:
    @just --list

# Build the td demo binary and the td-gen code generator
build:
    {{zig}} build

# Run all tests (unit, integration, golden, official-schema codegen compile)
test:
    {{zig}} build test --summary all

# Run the demo binary
run: build
    ./zig-out/bin/td

# Generate Zig types from a TL schema (default: the official Telegram schema)
gen schema=default_schema out="generated.zig" extra="":
    ./zig-out/bin/td-gen {{schema}} {{out}} {{extra}}

# Regenerate the committed Telegram API layer, split into a tree —
# no monolith:
#   src/api/mod.zig        entry module (td.api surface, flat re-exports)
#   src/api/registry.zig   sorted wire-id -> name table
#   src/api/types/         unions + constructors by namespace/theme
#   src/api/functions/     request structs by namespace
# td-gen is self-hosting (built by `zig build gen` alone), so
# regeneration never requires the generated API to build first.
api:
    {{zig}} build gen
    rm -rf src/api
    ./zig-out/bin/td-gen schema/api.tl src/api --module ../root.zig --self-test --split

# Regenerate the committed core MTProto schema module
# (src/mtproto/schema_gen.zig) from the vendored Telegram Desktop
# `scheme/mtproto.tl`. Ids absent from the schema text are computed with
# the official canonical crc32 rule (the same one tdesktop's scheme
# generator uses). td-gen is self-hosting, so regeneration never
# requires the generated module to build first.
mtp:
    {{zig}} build gen
    ./zig-out/bin/td-gen schema/mtproto.tl src/mtproto/schema_gen.zig --module ../root.zig --self-test

# Regenerate the committed Telegram RPC error catalog
# (src/rpc/errors_gen.zig) from the vendored TSVs in
# tests/data/rpc_errors/ (mtgo/gotd error lists; see their README).
# td-errgen is self-hosting like td-gen, and the shell glob fixes the
# file order (sorted names) the dedupe rule depends on.
errors:
    {{zig}} build errgen
    ./zig-out/bin/td-errgen src/rpc/errors_gen.zig tests/data/rpc_errors/*.tsv

# Create an authorization key against a real Telegram DC (default: the
# production DC 2 bootstrap endpoint from src/dc/options.zig — must match
# the dc id keygen sends in the handshake). Uses the vendored official
# server keys; pass --pubkey <modulus.hex> for a custom key:
# `just keygen 149.154.167.51 --pubkey modulus.hex`
keygen host="149.154.167.51" *args: build
    ./zig-out/bin/td-keygen {{host}} {{args}} --port 443

# MTProto bot login + getMe smoke test against a production DC. Reads
# TD_BOT_TOKEN from the environment (api id/hash default to the public
# Telegram Desktop pair; override with TD_API_ID / TD_API_HASH):
#   TD_BOT_TOKEN=123456:AA... just bot
# Add TD_PFS=1 for perfect forward secrecy (bound temp auth keys):
#   TD_PFS=1 TD_BOT_TOKEN=123456:AA... just bot
bot: build
    ./zig-out/bin/example-bot-login

# Generate code for the full official schema and compile it with a
# self-test; also verify the committed error catalog is not stale
check-gen:
    {{zig}} build test --summary all
    ./zig-out/bin/td-errgen --check src/rpc/errors_gen.zig tests/data/rpc_errors/*.tsv

# Benchmark the client hot paths — crypto primitives, TL ser/de, frame
# encode/receive, RPC dispatch, socket echo, full-stack roundtrips,
# concurrent lanes, fleet scaling (100/1k/5k/10k sessions). Optional
# substring filter selects a section: `just bench tl`
bench filter="":
    {{zig}} build
    ./zig-out/bin/td-bench {{filter}}

# Coverage-guided fuzzing over every supported input path (TL parse/
# ser/de, generated decoders, encrypted frames, session loading,
# framing). Without --fuzz the same targets run their fixed corpora as
# plain tests inside `just test`.
fuzz *args="":
    {{zig}} build test --fuzz {{args}}

# Cross-compile release binaries for the supported target matrix into
# zig-out-dist/<triple>/ (td, td-gen, td-errgen, td-keygen, td-bench).
release:
    #!/usr/bin/env sh
    for t in x86_64-linux-gnu aarch64-linux-gnu x86_64-macos-none aarch64-macos-none x86_64-windows-gnu; do
        echo "== $t =="
        {{zig}} build -Doptimize=ReleaseFast -Dtarget="$t" --prefix "zig-out-dist/$t" || exit 1
    done

# Remove build artifacts
clean:
    rm -rf .zig-cache zig-out zig-out-dist generated.zig
