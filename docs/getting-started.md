# Getting started

td is a Telegram **MTProto 2.0** client library for Zig 0.16. This
guide builds and runs a complete client round trip on your machine in
five minutes — no network, no phone number — and then points at the
real-network paths.

## Build

Zig comes through nix in this repository (see the `justfile`); any Zig
0.16 toolchain works:

```sh
just build          # td (demo), td-gen, td-keygen, td-bench, examples
just test           # unit + integration + golden + schema-codegen tests
```

Binaries land in `zig-out/bin/`: `td`, `td-gen`, `td-keygen`, `td-bench`,
`example-quickstart`, `example-loopback`, `example-session`.

## The high-level client (`td.Client`)

Most programs want exactly one object: [`td.Client`](../src/client.zig)
composes everything below — stored-session restore or fresh
authorization-key handshake, connection management, DC migration,
session persistence — behind `init` / `connect` / `invoke`:

```zig
var store = try td.session.FileStore.init(gpa, "session.bin");
defer store.deinit();

var client = try td.Client.init(gpa, .{
    .session_store = store.store(),
    .app = .{ .api_id = 12345 }, // your api_id from my.telegram.org
});
defer client.deinit(io);
try client.connect(io); // stored session or fresh handshake

const dc = try client.invoke(io, td.api.help.getNearestDc{});
defer dc.deinit(); // the response owns its arena
```

Every generated function (`td.api.*`) works through the same one
liner; `PHONE_MIGRATE`/`NETWORK_MIGRATE` redirects are followed
automatically (endpoint knowledge refreshed through `help.getConfig`
when the target is unknown), and rpc-level failures surface as
`error.RpcError` with code and message in `client.lastRpcError()`.
Also passed through: `call`/`send`/`wait` (typed + pipelined),
`invokeRaw` (pre-serialized bodies), `ping`, `saveSession`. Lifecycle:
`connect` is idempotent, `disconnect` drops the connection while
keeping the client usable, `close` is terminal (later calls fail with
`error.Closed`), `deinit` frees.
[`examples/quickstart.zig`](../examples/quickstart.zig) is a complete
runnable program. The sections below show what the facade is made of —
read them when you need a layer the facade does not cover.

### Portable session strings

Sessions move between clients as one base64url string
(`td.session.string`): data center, application id, authorization key
and signed-in identity, in the portable format used across the
ecosystem. `connect` imports it — no handshake, no sign-in — and
`exportSessionString` produces one again (identity included after a
sign-in that ran through `invoke`, or `setAuthorized`):

```zig
var client = try td.Client.init(gpa, .{
    .session_string = "AgAAB_...", // imported; overrides the store
    .app = .{ .api_id = 12345 }, // your api_id from my.telegram.org
});
defer client.deinit(io);
try client.connect(io);

// ... invoke, sign in ...

const str = try client.exportSessionString(gpa); // owned; a secret
defer gpa.free(str);
```

All three historical layouts of the format decode; encoding always
writes the current one. Bots and user sessions both import — the
identity fields decide. See [`session/string.zig`](../src/session/string.zig)
for the byte layouts and reference vectors.

## Your first round trip (no network)

[`examples/loopback_client.zig`](../examples/loopback_client.zig) is the
shortest complete program. The interesting part:

```zig
// An in-memory link: a real MTProto peer lives behind the transport —
// full encryption and envelope validation on both sides, no socket.
var link = td.multi.Link.init(gpa, &auth_key, salt);
defer link.deinit();
link.responder = .{ .ctx = undefined, .onBody = onBody };

var client = try td.rpc.Client.init(
    gpa,
    link.transport(),      // any td.transport.Transport works here
    &auth_key,
    salt,
    prng_state.random(),
    .{},
);
defer client.deinit();
try client.connect(io);

const answer = try client.invokeRaw(io, req.items()); // raw path
```

Run it with `./zig-out/bin/example-loopback`. Swap `link.transport()`
for a TCP-full transport (`td.transport.TcpFull`) and the same code
speaks to a real endpoint — the layers above the transport do not know
or care which one it is.

## The typed API

Requests are generated structs (`td.api.*`) with a `serialize` and a
`Result` decl; results decode into generated types:

```zig
const peer: td.api.InputPeer = .{ .inputPeerUser = .{ .user_id = 1, .access_hash = 2 } };
const resp = try manager.invoke(io, td.api.help.getNearestDc{});
defer resp.deinit(); // the response owns an arena the value borrows from
```

`manager` is a `td.connman.Manager` — it owns a connection, reconnects
with jittered backoff, recovers unanswered requests and health-checks
itself (`td.connman.Manager.invoke` runs one retry round automatically).

## Authentication (real DC)

1. **Authorization key**: `td-keygen <dc-host>` performs the DH
   handshake against a production DC using the official server keys
   vendored in `td.mtproto.server_keys` (decoded from the official
   Telegram Desktop source at compile time), and writes `auth_key.bin`.
   Pass `--pubkey <modulus.hex>` to use a custom key instead.
   In-process, `DataCenters.connect` runs the same handshake on first
   connect and caches the key.
2. **Bot smoke test** (fastest real-network check):
   `TD_BOT_TOKEN=… ./zig-out/bin/example-bot-login` — handshake (or
   stored-key reuse with real-server salt recovery), bot authorization,
   MTProto getMe (`users.getUsers` over `inputUserSelf`, decoded
   through `td.api.User`), and a second authorized RPC round trip. The
   token is read from the environment only; without it the example
   skips (CI-safe).
3. **Account auth** (phone number): `td.auth.flow` — sendCode, signIn,
   signUp, 2FA via SRP (`td.auth.password`), updatePassword, logOut.
   Everything is driven by you, one call at a time; there is no hidden
   worker thread.

Key material never appears in logs — the session modules have no
logging at all, and renderings are redacted by construction. Treat
`auth_key.bin` as a secret: it persists your authorization.

## Sessions across restarts

[`examples/session_roundtrip.zig`](../examples/session_roundtrip.zig)
shows the whole persistence loop:

```zig
const st = td.session.State.capture(&dcs, &client);   // from a live client
try store.store().saveState(io, st);                  // MemoryStore or FileStore
const restored = (try store.store().loadState(io, gpa)).?;
try restored.applyTo(&dcs2);                          // next connect skips the handshake
restored.adoptOn(&fresh_client, now_seconds);         // continue the same wire session
```

## Where to go next

- [sessions.md](sessions.md) — state details, custom storage, fleets
- [rpc-and-updates.md](rpc-and-updates.md) — pipelining, raw paths, updates
- [raw-interfaces.md](raw-interfaces.md) — raw TL, raw MTProto, custom transports
- [operations.md](operations.md) — performance, benchmarking, security, versioning
