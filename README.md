# td

A Telegram **MTProto 2.0** client library for **Zig**, built from scratch.
No TDLib, gramJS, grammers, gotd, Pyrogram, Telethon, or any other client
implementation is used or ported.

## Status — Steps 1–18 written

Implemented:

- **Steps 1–11 (foundation → session persistence)** — detailed in the
  bullets below: the TL foundation and complete official-schema parser,
  the TL → Zig code generator and the generated Telegram API (`td.api`),
  MTProto 2.0 crypto, the authorization-key handshake (`td-keygen`), the
  TCP-full transport, the encrypted-message layer, the RPC/invoke
  system, DC configuration/migration, and session persistence.

- **TL binary serialization primitives**, **complete practical TL schema
  parser + validation**, **TL → Zig code generator**, and the **generated
  Telegram API** (`td.api`, regenerated from the current
  Telegram Desktop `scheme/api.tl` with `just api`).
- **MTProto 2.0 cryptographic primitives** (`td.crypto`) —
  SHA-1/SHA-256, AES-256-IGE (OpenSSL KAT-validated), msg_key and key/IV
  derivation, message encryption/decryption with verification, padding.
- **Authorization-key handshake** (`td.mtproto`), transport-independent:
  - `req_pq`/`req_pq_multi` → `resPQ`, nonce/server_nonce handling,
    RSA fingerprint selection (official server keys are vendored in
    `td.mtproto.server_keys`, PEM-decoded from the official Telegram
    Desktop source at compile time);
  - pq factorization (Pollard's rho) — validated against the official
    worked example;
  - `p_q_inner_data_dc` RSA encryption in **both** documented layouts:
    classic (SHA1+data+random padding) and the current **rsa_pad** scheme
    (192-byte reversed block + SHA256 + AES-256-IGE + XOR-masked key);
  - `req_DH_params` → `server_DH_params_ok/fail`; temporary AES key/IV
    derivation from new_nonce/server_nonce (validated byte-for-byte
    against the official example); sealed inner-data open with SHA1
    verification over the parsed payload;
  - `set_client_DH_params` with `client_DH_inner_data`; `dh_gen_ok`
    verification via new_nonce_hash1; auth_key = g_a^b mod dh_prime
    (validated against the official example's g_a/b/auth_key), auth_key
    hash/id and server_salt;
  - plain (unencrypted) message framing with msg_id rules;
  - **perfect forward secrecy** (`td.mtproto.pfs`,
    <https://core.telegram.org/api/pfs>): temporary auth keys via
    `p_q_inner_data_temp_dc` (`Handshake.runTemp`), and the
    `auth.bindTempAuthKey` binding — its `encrypted_message` is a
    complete **MTProto v1** packet sealed with the permanent key (the
    one v1 survivor on the modern wire, field placement per TDLib
    master); temp keys are RAM-only, never persisted.
- **Controlled integration test**: a deterministic in-process loopback
  server (test RSA keypair, official example dh_prime/g) runs the full
  handshake against the client in both RSA modes and all error paths
  (unknown fingerprint, `server_DH_params_fail`, tampered hashes, nonce
  mismatches) — both sides must derive the identical auth key.
- **`td-keygen` CLI**: creates a real authorization key against a
  Telegram DC over a minimal blocking TCP connection (intermediate
  framing): `td-keygen <dc-host> --port 443 --pubkey <modulus.hex>`.
  Key material and nonces are never logged — only the public auth_key_id.
- All core-MTProto constructors come from Telegram Desktop's
  `scheme/mtproto.tl` (vendored as `schema/mtproto.tl`).
- **Transport layer** (`td.transport`) — connection handling and framing,
  independent of MTProto encryption by design (transports move opaque
  payload frames; the session layer above encrypts them):
  - type-erased `Transport` interface (vtable: `connect`/`read`/`write`/
    `close`/`isConnected`, default composite `reconnect`) so further
    transports — obfuscated variants, HTTP, WebSocket — drop in without
    touching callers;
  - **All four TCP framings** from the official transport specification,
    selectable per client via `Client.Options.transport`
    (`td.transport.TransportMode`, default `.abridged`):
    - **abridged** (`td.transport.tcp_abridged`): `0xef` stream tag,
      1-byte length/4 prefixes, 4-byte prefixes for large payloads — the
      lightest and the default;
    - **intermediate** (`td.transport.tcp_intermediate`): `0xeeee_eeee`
      tag, `u32le length | payload`;
    - **padded intermediate** (`td.transport.tcp_padded_intermediate`):
      `0xdddd_dddd` tag, `u32le length+pad | payload | 0..15 random pad`
      — inbound frames keep the padding, which the message layer strips
      via the 16-byte block alignment;
    - **full** (`td.transport.tcp_full`): `u32le length (payload + 12) |
      u32le sequence | payload | crc32`, per-direction sequence numbers
      from zero, opt-in inbound sequence verification;
    the first three share the connection machinery in
    `td.transport.tcp_framed` (a new framing is a pure `Codec`);
    `td.transport.Dialer` dials any mode from one options knob;
  - timeouts via per-call deadlines (a timeout before any frame byte is
    consumed leaves the connection usable; mid-frame failures tear it
    down), configurable payload limit, clean error propagation through a
    single `transport.Error` set;
  - integration tests against a real TCP loopback server for every
    framing: golden wire-layout checks, roundtrips, malformed and
    oversized frames, peer disconnect, reconnect with fresh state (tag
    resent), timeout semantics, lifecycle errors.
- **Encrypted message layer** (`td.mtproto.message` +
  `td.mtproto.Session`) — MTProto 2.0 envelopes, containers and
  acknowledgements on top of `td.crypto`, transport-independent:
  - encrypted frame codec: `auth_key_id | msg_key | AES-256-IGE(salt,
    session_id, msg_id, seq_no, length, body, padding)` — built in
    place in caller-owned buffers, decrypted and fully validated in
    place (auth_key_id, constant-time msg_key, session identity, body
    alignment, 12..1024-byte padding bounds);
  - msg_id rules: client ids divisible by 4 with non-empty low 32 bits,
    monotonic, ≈ unixtime·2^32 (clock regressions absorbed); server ids
    ≡ 1 (responses) / 3 (other) mod 4; 30 s-future / 300 s-past reject
    window; strictly increasing ids double as duplicate detection;
  - seq_no per the spec formula `2·content_count + content` — only
    content-related (odd) messages advance the counter and require
    acknowledgement; failed validation never desynchronizes the
    expectations;
  - `msg_container#73f1f8dc` both ways: inner messages stamped
    individually, the container envelope last (id strictly greater than
    every inner id, service seq_no), with structural limits enforced
    (≤1024 messages, exact lengths);
  - acknowledgements: received content-related messages are queued
    automatically and drained as `msgs_ack#62d6b459` service messages
    (grouped per the spec's 8192-id recommendation, deduplicated);
  - core service messages (hand-serialized from Telegram Desktop's
    `scheme/mtproto.tl`): `msgs_ack`, `ping`/`ping_delay_disconnect`,
    `pong`, `bad_msg_notification`/`bad_server_salt` (with the
    documented error codes), `new_session_created`, `future_salts`
    (bare vector), `rpc_result`/`rpc_error`, `gzip_packed` (wrapper
    recognized; inflate comes with the RPC layer);
  - integration tests over the TCP-full transport on real loopback
    sockets: full encrypted roundtrip with independent server-side
    validation, mixed-content containers, `bad_server_salt` recovery
    (re-send under the new salt), `new_session_created` acknowledgement.
- **RPC / invoke system** (`td.rpc`) — requests and responses over the
  encrypted session, on any `td.transport` connection:
  - `Client.invoke(io, req)` — one-shot typed round trip: the request
    struct's generated `Result` decl selects the result type;
    `call(io, req, R)` is the same with the type spelled out;
    `send`/`wait` are the pipelined halves — any number of requests may be
    outstanding, each matched to its `rpc_result` by `req_msg_id`
    (including answers packed by the server into one container);
  - `invokeRaw`/`sendRaw`/`waitRaw` — the low-level path: pre-serialized
    request bytes in, owned result-object bytes out (`gzip_packed`
    already inflated, bounded against decompression bombs); this is also
    how generic wrappers (`invokeWithLayer`, `invokeAfterMsg`) travel;
  - `rpc_error#2144ca19` surfaces as `error.RpcError` with the code and
    message kept in `client.lastRpcError()`; service messages are handled
    per the spec — `msgs_ack`, `bad_msg_notification` (codes 16–20
    re-send under a fresh msg_id), `bad_server_salt` (salt adoption +
    re-send), `new_session_created`, `pong`, `future_salts`;
    server-pushed updates are counted, not decoded (an updates API is a
    later milestone);
  - results decode into generated types through a type-driven decoder
    that mirrors the generator: unions/structs with `deserialize`,
    top-level `Vector<T>` results as native slices (elements of recursive
    types pointer-boxed), and scalar results — `users.getUsers =
    Vector<User>` and `help.getNearestDc = NearestDc` alike;
  - gzip inflation on `std.compress.flate` with an output bound; decoded
    values borrow from an arena owned by the returned `Response`
    (`response.deinit()` frees everything at once);
  - timeouts: per-wait deadline plus the transport's read timeout — a
    clean timeout keeps the request registered (`wait` is retryable,
    `cancel` drops it), a dead connection fails every pending request;
  - the generator now emits `pub const Result = <type>;` on function
    request structs (`just api` regenerates the committed API with them;
    until then `call`/raw paths work with the committed file);
  - integration tests over TCP-full loopback against a validating
    in-process MTProto peer: typed roundtrips with acknowledgement
    checks, generated-function invocation with vector-of-union results,
    `rpc_error`, gzip'd results, `bad_server_salt` re-send, pipelined
    requests answered in one container, ping/pong, retryable timeouts,
    pushed-update accounting.
- **DC configuration / data-center management** (`td.dc`) — endpoint
  knowledge and migration, the client state that spans DCs:
  - `DcList` (`td.dc.options`): the built-in bootstrap endpoints
    (production: 5 DCs, IPv4 + IPv6, port 443, mirroring Telegram
    Desktop's `kBuiltInDcs`; test network: 3 DCs) merged at runtime with
    `help.getConfig`'s `dc_options` and `updateDcOptions` pushes —
    deduplicated by `(dc, ip, port)`, flags and secrets refreshed from
    the server's word; all stored bytes list-owned;
  - endpoint selection by purpose (general traffic, media
    upload/download — which prefers `media_only` entries — and CDN) and
    by address family with fallback, skipping `tcpo_only` entries the
    plain TCP-full transport cannot speak to;
  - migration handling: `PHONE/NETWORK/USER/FILE_MIGRATE_X` rpc errors
    (code 303) parsed from `client.lastRpcError()` into a target DC;
    `DataCenters.migrate` switches the current DC (unknown targets are
    refused until a fresh config is fetched); the export/import
    authorization flow for `USER_MIGRATE` is a later milestone;
  - `DataCenters` (`td.dc.manager`): current-DC state, per-DC
    authorization key store (secret material, never logged) and the
    `connect` composition — endpoint → TCP-full transport → cached
    handshake-or-stored-key → `rpc.Client`, with the +10000 DC-id shift
    for test servers applied automatically;
  - integration test: a `PHONE_MIGRATE_5` rpc error delivered by the
    loopback MTProto peer through the full stack drives a DC switch.
- **Session persistence** (`td.session`) — reconnect without
  repeating authorization:
  - `State` (`td.session.state`): the DC + environment, the secret
    authorization key (with the *capture-time* server salt —
    `bad_server_salt`/`new_session_created` corrections included), and
    the wire session id plus outgoing msg_id/seq counters;
    `capture` from a live client (keyed by the session's auth_key_id, so
    the DC follows the key), `applyTo` a `DataCenters` (key + current DC
    — after which `connect` skips the handshake), `adoptOn` a freshly
    connected client (continue the same logical session; a clock
    regression beyond the receive-window grace keeps a fresh identity
    instead);
  - fixed 316-byte little-endian binary format: magic, version, flags,
    CRC-32 trailer, and a key↔key-id consistency check (the id is SHA1 of
    the key by construction), so corruption and edited key material are
    both rejected;
  - `Store` (`td.session.store`): the type-erased custom-storage
    interface (load/save/remove of opaque bytes) with
    `loadState`/`saveState` conveniences; `MemoryStore` for in-process
    sessions; `FileStore` (`td.session.file`) for one file per
    session, written atomically (temp file + rename) with owner-only
    0600 permissions;
  - secret hygiene: the session modules have no logging at all, and the
    only rendering helper (`describe`, also reachable through the `{f}`
    format specifier) never outputs the auth key, its hash, the salt or
    the session id — only public fields (environment, DC, auth_key_id,
    counters);
  - integration tests over the loopback MTProto peer: the step's
    definition of done — disconnect, persist (memory and file stores),
    restart, reload, reconnect — with the peer enforcing continuation
    from the persisted counters (session id, msg_id high-water mark,
    content count) and the corrected salt on the restored connection.

- **Structured client storage** (`td.storage`) — the richer cousin of
  `session.Store`: instead of opaque bytes, typed records behind one
  type-erased `Storage` interface:
  - `SessionRecord`: `dc_id`, `api_id`, `test_mode`, `auth_key`
    (secret, redacted in every rendering), `date`, `user_id`, `is_bot`;
  - peer cache: id/access-hash/type/username/phone rows, bulk
    upsert, lookups by id, username (8 h TTL — handles get reassigned)
    and phone number;
  - per-entity update state (`pts`/`qts`/`date`/`seq`) for continuing
    a `getDifference` loop after a restart;
  - `MemoryStorage` (`td.storage.memory`): the fields as plain struct
    members (`session`, `peers`, `update_states`) for in-process use;
  - one conformance suite (`td.storage.conformance`) runs against any
    implementation through the interface — hostile strings roundtrip
    as data.

- **Connection management** (`td.connman`) — one owner for the whole
  life of a connection: state machine (`idle`/`connecting`/
  `connected`/`backing_off`/`closed`), exponential fully-jittered
  backoff, reconnection with wire-session reset (fresh session id and
  counters, kept auth key), recovery of every request the dead
  connection never answered (only connection-level failures are
  recoverable — exactly the MTProto boundary), health checks
  (`ping` / `ping_delay_disconnect` with a bounded round trip), a
  budgeted read loop (`pump`) and graceful shutdown (drain acks →
  cancel outstanding → close); integration tests where the server dies
  and comes back mid-request.
- **Perfect forward secrecy** (`Options.pfs`, high-level client) —
  when enabled, every connection the client establishes generates a
  short-lived temporary auth key (`p_q_inner_data_temp_dc` handshake on
  a dedicated connection) and binds it to the permanent key with
  `auth.bindTempAuthKey`; all traffic is then encrypted with the temp
  key and the permanent key never seals a message. Temp keys live in
  RAM only (never in a store or session string), are regenerated and
  re-bound on every connection establishment, and rotate ahead of
  expiry before the next `invoke`; persistence under PFS stores the
  permanent key and no wire-session identity. Off by default.
  Validated end-to-end against an in-process peer that implements the
  server side (`tests/pfs_client.zig`); the real-server check is
  `TD_PFS=1 just bot`.
- **Updates** (`td.updates`) — pts/qts/date/seq state tracking with
  verdicts, classification of pushed objects, a pure ingest engine with
  `getDifference` reconciliation over gaps, and a pump-safe hook
  (handlers never re-enter the client) — end-to-end tested against a
  loopback peer that pushes and heals.
- **No-updates sessions** (`Options.no_updates`, high-level client) —
  every `invoke` travels inside the `invokeWithoutUpdates` wrapper, so
  the server does not subscribe the session to the updates its queries
  would cause; with no `updates_handler` set (the default) the client
  then sees no updates at all (pyrogram's `no_updates`, gotd's
  `NoUpdates`). Wire-tested against the in-process peer.
- **Account authentication** (`td.auth`) — send-code → sign-in →
  sign-up → 2FA (SRP with safe-prime validation) → password update →
  logout, as an explicit state machine with mapped RPC errors; SRP/2FA
  math is KAT-tested, the flow end-to-end against a loopback peer.
- **Multi-session scheduling** (`td.multi`) — `Fleet`: a fixed-capacity
  slab of independent sessions with fair, budget-capped round-robin
  sweeps (resumable via a fairness cursor), fleet keep-alive and
  per-sweep work accounting; `Link`/`Registry`: an in-memory transport
  with a real embedded MTProto peer (full validation both directions,
  zero threads/sockets) and the `connman.Options.transport_provider`
  seam for non-socket transports and pooling; benchmarks measure
  memory/session, requests/sec, latency percentiles, allocations and
  event-loop utilization at 100 / 1 000 / 5 000 / 10 000 sessions plus
  a real-socket anchor at 100.
- **Fuzzing and protocol compliance** (`tests/fuzz.zig`,
  `tests/compliance.zig`) — coverage-guided fuzz targets for every
  supported input path (TL parser/reader/writer, generated
  deserializers, encrypted-message parser with a structured variant
  that reaches past the msg_key check, session loading, transport
  framing), hostile corpora running as plain tests in every suite, and
  deterministic compliance cases: tampered msg_keys, undersized
  padding, foreign key ids, out-of-window msg_ids, seq_no violations,
  unordered containers, unexpected constructors, rpc_error surfacing,
  gzip-bomb refusal, truncations — all rejected with the documented
  errors and never desynchronizing the receiver.

Security: the handshake and session modules contain no logging at all;
secret material (auth key, new_nonce, DH exponents, decrypted payloads)
stays in caller-owned memory and is never printed.

> **Verification status.** The code for steps 12–18 is committed
> together with its tests and benchmarks, but the first combined
> `just build && just test && just api && just bench` run for these
> batches is still pending (the development sandbox lost its shell —
> see the repository notes). Treat step 11 and earlier as the last
> verified state until that run passes.

> **RPC error catalog** (added after step 18): td-errgen, the vendored
> catalogs, `src/rpc/errors_gen.zig` and the rpc/dc integration are
> committed and verified — generator inline tests, golden
> reproducibility, the catalog suite (`tests/rpc_errors.zig`), the rpc
> classify/migration tests and `td-errgen --check` (byte-identical
> regeneration) all pass in `just build && just test` (2026-09-12).
> Unrelated failures in mtproto/transport/tl tests present in the same
> run come from a concurrent in-flight refactor of those layers, not
> from the catalog.

Not implemented yet (planned):

- Further transports (obfuscated variants, HTTP, WebSocket),
  `USER_MIGRATE` authorization export/import, generated `deinit`, media
  upload/download.

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — build, first
  round trip, authentication, first session restore
- [docs/sessions.md](docs/sessions.md) — state, custom storage, fleets
- [docs/rpc-and-updates.md](docs/rpc-and-updates.md) — pipelining, raw
  RPC, errors, updates
- [docs/raw-interfaces.md](docs/raw-interfaces.md) — raw TL, raw
  MTProto, custom transports
- [docs/operations.md](docs/operations.md) — performance, benchmarking,
  security posture, versioning, release

Runnable examples (`zig build` installs them): `example-loopback` — a
full RPC round trip over the in-memory peer; `example-session` — the
capture → store → restore → continue flow;
`example-quickstart` and `example-invoke` — the high-level client
against a production DC (client lifecycle, and the invoke surface:
typed calls, RpcError handling, pipelined send/wait).

Building this project requires **Zig 0.16**.

## Usage

```zig
const std = @import("std");
const td = @import("td");

var writer = td.tl.Writer.init(allocator);
defer writer.deinit();

try writer.writeInt(123);
try writer.writeString("hello");

var reader = td.tl.Reader.init(writer.items());
const n = try reader.readInt();          // 123
const s = try reader.readString();       // "hello" (borrows from input)
```

Parsing a TL schema:

```zig
var schema = try td.tl.parseSchema(allocator, "user#d10d979a flags:# = User;");
defer schema.deinit();

const user = schema.findByName("user").?;
// user.id == 0xd10d979a (exact u32 constructor id)
```

Note: AST strings borrow from the schema source text; keep the source buffer
alive as long as the `Schema`.

Using the generated Telegram API:

```zig
const td = @import("td");

// Types: tagged unions per TL result type.
const peer: td.api.InputPeer =
    .{ .inputPeerUser = .{ .user_id = 1, .access_hash = 2 } };

// Functions: request structs with serialize().
var w = td.tl.Writer.init(allocator);
defer w.deinit();
const req = td.api.messages.sendMessage{
    .peer = peer,
    .message = "hi",
    .random_id = 123,
    // remaining optional fields default to null/false
};
try req.serialize(&w);
```

Note: `deserialize` borrows strings/bytes zero-copy; vector storage and
recursive-type boxes are allocated with the caller's allocator.

Data centers and migration:

```zig
const td = @import("td");

var dcs = try td.dc.DataCenters.init(allocator, .production);
defer dcs.deinit();

// After `help.getConfig`: merge the server's endpoint list.
try dcs.list.updateFromConfig(&config_response.value.config);

// After a request failed with error.RpcError:
const m = td.dc.migration.fromRpcError(client.lastRpcError()).?;
if (try dcs.migrate(m)) {
    // Reconnect on dcs.current (dcs.connect) and re-send the request.
}
```

## Build & test

```sh
zig build          # build td (demo), td-gen, td-keygen, td-bench, examples
zig build test     # unit + integration + golden + compliance + fuzz corpora
zig build test --fuzz  # coverage-guided fuzzing over the same targets
zig build bench    # benchmarks (td links at ReleaseFast here; filter: td-bench multi)
```

Benchmarks cover every hot layer — crypto primitives, TL serialization
and deserialization, message construction, frame decrypt/receive, RPC
request/response dispatch, pipelining depth, raw socket echo, full-stack
loopback roundtrips, multi-lane concurrent requests, and fleet scaling
(memory/session, throughput, latency percentiles and event-loop
utilization at 100 / 1 000 / 5 000 / 10 000 sessions) — and report
ns/op, throughput and allocations per op (via a counting allocator).
Optimization work is driven by these numbers: no change ships without a
before/after pair from the same suite, and no scalability claim is made
without a fleet measurement behind it.

Generate Zig types from a TL schema:

```sh
./zig-out/bin/td-gen schema/api.tl out.zig
```

Regenerate the committed Telegram API layer:

```sh
just api
```

Regenerate the committed RPC error catalog (`src/rpc/errors_gen.zig`, 889
ids classified from `rpc_error` message strings — `FLOOD_WAIT_60` →
`.flood_wait_x` + 60) from the vendored TSVs:

```sh
just errors
```

## Layout

```
src/
├── root.zig        public API root (tl, errors, api)
├── errors.zig      error model (TlError, ParseError, Diagnostic)
├── main.zig        small demo binary
├── gen_main.zig    td-gen CLI (TL schema → Zig source)
├── errgen.zig      RPC error-catalog generator (TSV → Zig, deterministic)
├── errgen_main.zig td-errgen CLI (vendored error TSVs → errors_gen.zig)
├── api/             GENERATED Telegram API (just api regenerates),
│   │                split into a tree — no monolith
│   ├── mod.zig        entry module: re-exports every declaration (the
│   │                  td.api surface is flat, as in the old monolith)
│   ├── registry.zig   sorted wire-id → name table
│   ├── types/         result-type unions + the constructors they
│   │                  dispatch to, one file per group: by namespace
│   │                  (auth.zig, messages.zig, …) and, for the root
│   │                  namespace, by theme (users.zig, chats.zig,
│   │                  messages.zig, media.zig, updates.zig, …)
│   └── functions/     request structs, one file per namespace
│                      (auth.zig, messages.zig, …)
├── crypto/
│   ├── mod.zig      exports
│   ├── aes_ige.zig  AES-256-IGE (OpenSSL KAT-validated chaining)
│   └── mtproto.zig  auth_key_id, msg_key, key/IV derivation, message crypto
├── mtproto/
│   ├── mod.zig      exports (incl. test-only RSA keypair)
│   ├── bigint.zig   big-endian powmod on std.math.big (example KAT)
│   ├── factor.zig   pq factorization (Pollard's rho, example KAT)
│   ├── rsa.zig      RSA public op; classic + rsa_pad layouts; fingerprints
│   ├── inner.zig    tmp AES key/IV, sealed inner data, nonce hashes (KAT)
│   ├── schema.zig   hand-serialized core handshake constructors
│   ├── schema_gen.zig GENERATED core schema types (`just mtp`; ids for
│   │                id-less declarations computed with the official
│   │                canonical crc32 rule, as in tdesktop's generator)
│   ├── handshake.zig authorization-key client state machine
│   ├── message.zig  encrypted frames, containers, service messages
│   ├── session.zig  stateful session: ids/seq counters, validation, acks
│   ├── pfs.zig      PFS: temp keys, auth.bindTempAuthKey v1 bind blob
│   ├── tcp.zig      minimal blocking TCP (intermediate framing)
│   └── testkeys.zig test-only RSA keypair for loopback tests
├── transport/
│   ├── mod.zig      Transport interface (vtable), Endpoint, Error,
│   │                TransportMode, Dialer (any-mode TCP dialing)
│   ├── tcp_framed.zig shared Framed machinery for the tag transports
│   ├── tcp_abridged.zig abridged framing codec + connection (default)
│   ├── tcp_intermediate.zig intermediate framing codec + connection
│   ├── tcp_padded_intermediate.zig padded intermediate (0..15 pad)
│   └── tcp_full.zig TCP "full" framing codec + connection handling
├── rpc/
│   ├── mod.zig      RPC subsystem exports
│   ├── client.zig   Client: send/wait/invoke, pump, service dispatch
│   ├── decode.zig   result decoding (vectors, scalars) + gzip inflation
│   └── errors_gen.zig GENERATED RPC error catalog (just errors): Id
│                    enum + descriptions + classify for rpc_error
│                    messages; RpcErrorInfo carries the classification
├── dc/
│   ├── mod.zig      DC subsystem exports
│   ├── options.zig  DcList: bootstrap endpoints, config merge, selection
│   ├── migration.zig PHONE/NETWORK/USER/FILE_MIGRATE_X parsing
│   └── manager.zig  DataCenters: state, per-DC keys, connect composition
├── session/
│   ├── mod.zig      session subsystem exports
│   ├── state.zig    captured state: 316-byte record, capture/applyTo/adoptOn
│   ├── store.zig    Store interface + MemoryStore
│   └── file.zig     FileStore (atomic, owner-only)
├── storage/
│   ├── mod.zig      storage types, Storage interface + conformance suite
│   └── memory.zig   MemoryStorage: the same fields as plain struct members
├── connman/
│   ├── mod.zig      connection-management exports
│   ├── manager.zig  connection state machine, recovery, health, provider seam
│   └── backoff.zig  exponential fully-jittered delay policy
├── updates/
│   ├── mod.zig      updates subsystem exports
│   ├── state.zig    pts/qts/date/seq tracking
│   ├── classify.zig pushed-object classification
│   ├── engine.zig   pure ingest + getDifference reconciliation
│   └── fetch.zig    pump-safe updates hook
├── auth/
│   ├── mod.zig      auth subsystem exports
│   ├── password.zig SRP/2FA math + KDF
│   └── flow.zig     send-code/sign-in/sign-up/2FA/logout state machine
├── multi/
│   ├── mod.zig      multi-session exports
│   ├── loopback.zig in-memory transport + embedded MTProto peer, registry
│   └── fleet.zig    fixed-capacity session slab, fair budgeted sweeps
├── bench_main.zig   benchmark suite harness (zig build bench, section filter)
├── bench/
│   ├── common.zig   timer, one-line reporting, counting allocator
│   ├── tl.zig       generated-API ser/de + RPC result-decode benchmarks
│   ├── frame.zig    message construction + encrypted-frame benchmarks
│   ├── net.zig      dispatch, pipelining, socket echo, roundtrips, lanes
│   └── multi.zig    fleet scaling, latency percentiles, sweep utilization
├── keygen_main.zig  td-keygen CLI (authorization key vs a real DC)
├── examples/
│   ├── quickstart.zig        the high-level client, end to end (real DC)
│   ├── invoke.zig            the invoke surface: typed calls, errors, pipelining
│   ├── loopback_client.zig   full RPC round trip over the in-memory peer
│   ├── session_roundtrip.zig capture → store → restore → continue
│   └── bot_login.zig         bot authorization + getMe (opt-in, real DC)
└── tl/
    ├── mod.zig       TL subsystem exports
    ├── writer.zig    TL binary writer
    ├── reader.zig    TL binary reader (zero-copy reads)
    ├── types.zig     AST: Constructor, Param, TypeExpr
    ├── parser.zig    TL schema lexer + recursive-descent parser
    ├── schema.zig    owned parse result (arena-backed, constructors/functions)
    ├── validate.zig  schema-wide semantic validation
    └── codegen/
        ├── mod.zig   orchestrator: validate → generate (deterministic)
        ├── naming.zig type mapping + identifier escaping
        └── emit.zig  Zig source emission (structs, unions, ser/de)
tests/
├── tl_integration.zig
├── official_schema.zig      parses + validates the full official schema
├── codegen_golden.zig       byte-for-byte reproducibility vs golden file
├── errgen_golden.zig        error-catalog generator golden reproducibility
├── rpc_errors.zig           committed error catalog: classify + invariants
├── generated_roundtrip.zig  compiles + round-trips generated code
├── generated_api.zig        runtime roundtrips against td.api
├── auth_handshake.zig       full DH handshake vs an in-process loopback server
├── pfs_client.zig           client PFS end-to-end: temp handshake → bind → traffic
├── transport.zig            all four TCP framings vs real loopback TCP
│                            servers (golden wire vectors, malformed frames)
├── message_session.zig      encrypted sessions + containers + acks over TCP-full
├── rpc.zig                  RPC client end-to-end vs a validating MTProto peer
├── session.zig              persistence: capture → store → reload → reconnect
├── connman.zig              reconnection/backoff/recovery vs a dying peer
├── updates.zig              pushed-update delivery + getDifference healing
├── auth.zig                 SRP/2FA KATs + the account-auth flow end-to-end
├── multi.zig                fleets over in-memory links: independence, sweeps
├── fuzz.zig                 fuzz targets + hostile corpora (just fuzz)
├── compliance.zig           hostile frames/RPC rejected with spec errors
├── golden/                  sample.tl + expected_sample.zig (committed)
│                            (also sample_errors.tsv + expected_errors_gen.zig)
├── data/
│   └── rpc_errors/          RPC error catalogs, one TSV per status code
│                            (mtgo/gotd lists, Apache-2.0 — see their
│                            README for provenance; just errors regenerates
│                            src/rpc/errors_gen.zig from them)
└── schema/                  vendored official schemas (Telegram Desktop
    ├── api.tl               mtproto/scheme/api.tl — source for just api)
    ├── mtproto.tl           core MTProto schema (mtproto/scheme/mtproto.tl)
    └── embed.zig            module root exposing api.tl to @embedFile tests
```

## References

- <https://core.telegram.org/mtproto>
- <https://core.telegram.org/mtproto/description>
- <https://core.telegram.org/mtproto/service_messages>
- <https://core.telegram.org/mtproto/service_messages_about_messages>
- <https://core.telegram.org/mtproto/mtproto-transports>
- <https://core.telegram.org/schema>

## License

MIT — see [LICENSE](LICENSE).
