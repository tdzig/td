# Layout

Per-file map of the `td` source tree. Layering (each layer imports only
lower ones, and is independently testable):

`tl` → `crypto` → `mtproto` → `transport` → `rpc` → `dc` → `session` →
`connman` → `updates` → `auth` → `multi`

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
