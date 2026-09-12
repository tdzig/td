# Sessions

A *session* is everything that survives a disconnect: the secret
authorization key, the wire session id, the outgoing msg_id/seq
counters, and the DC it belongs to. td splits this into the state
itself (`td.session.State`) and where it is kept (`td.session.Store`).

## State

`td.session.State` captures, for one DC:

- the environment (production/test) and DC number;
- the secret authorization key with the **capture-time server salt**
  (later `bad_server_salt` / `new_session_created` corrections
  included);
- the wire session id and outgoing counters, so a restored client
  continues the same logical session instead of starting a new
  identity.

```zig
const st = td.session.State.capture(&dcs, &client) orelse ...; // from a live client
try st.applyTo(&dcs);           // restore the durable half (key + current DC)
st.adoptOn(&fresh_client, now); // restore the per-connection half
```

The binary form is a fixed 316-byte record: magic, version, flags,
CRC-32, and a key↔key-id consistency check (the id is SHA-1 of the key
by construction), so corruption *and* hand-edited key material are both
rejected. `deserialize` never partially trusts a record: every field is
range-checked before the value is returned.

Secret hygiene: the session modules contain no logging at all. The only
rendering helper (`describe`, reachable through the `{f}` format
specifier) never emits the key, its hash, the salt, or the session id.

## Storage

`td.session.Store` is a type-erased interface: opaque bytes in, opaque
bytes out. Two implementations ship:

- `td.session.MemoryStore` — one owned blob in process;
- `td.session.FileStore` — one file per session, replaced atomically
  (temp file + rename) with owner-only 0600 permissions.

```zig
var store = td.session.FileStore.init(gpa, "/var/lib/myapp/td");
defer store.deinit();
try store.store().saveState(io, st);
const st2 = (try store.store().loadState(io, gpa)) orelse ...;
```

**Custom storage**: implement the three vtable functions (`load`,
`save`, `remove`) over your database/KV store and hand `store()` to the
same call sites — nothing else in td touches storage, and the store
layer never inspects the bytes.

## Structured storage (session record, peer cache, update state)

When you want the store to hold *typed* data rather than opaque bytes —
a whole account's client-side state — `td.storage` is the layer.
Behind one type-erased interface it keeps three kinds of data:

- the **session record**: `dc_id`, `api_id`, `test_mode`, `auth_key`
  (secret, redacted in every rendering), `date`, `user_id`, `is_bot`;
- the **peer cache**: id / access hash / type / username / phone
  number, with lookups by id, username (8 h TTL — handles get
  reassigned) and phone;
- **update state** per entity (`pts`/`qts`/`date`/`seq`), so a
  restarted client continues its `getDifference` loop instead of
  refetching history.

```zig
var mem = td.storage.MemoryStorage.init(gpa);
defer mem.deinit();
const s = mem.storage();

try s.setSession(io, .{ .dc_id = 2, .api_id = 20350, .auth_key = &key,
                        .date = now, .user_id = uid, .is_bot = false });
try s.updatePeers(io, &.{.{ .id = peer_id, .type = .user,
                            .access_hash = hash, .username = "liber" }}, now);
const peer = (try s.getPeerByUsername(io, gpa, "liber", now)) orelse ...;
defer peer.deinit(gpa);
```

Backends implement the same `Storage` interface, and
`td.storage.conformance` runs the identical behavioral suite against
any implementation.

## Many sessions in one process

One `connman.Manager` is one connection. Independent accounts (or
independent sessions of one account) are independent managers, and
`td.multi.Fleet` schedules them:

```zig
var fleet = try td.multi.Fleet.init(gpa, .{
    .capacity = 10_000,
    .endpoint = .{ .host = "149.154.167.50", .port = 443 },
    .session = .{ /* per-session Manager options */ },
});
defer fleet.deinit(io);

const id = try fleet.addSession(&auth_key, salt);      // key bytes are copied
try (try fleet.session(id)).ensureConnected(io);

// One scheduler sweep: fair round-robin, budget-capped, resumable.
const sweep = fleet.pump(io, std.Io.Duration.fromMilliseconds(5));
// sweep.visited / sweep.frames / sweep.work_sessions — event-loop metrics
```

Design notes that matter at scale:

- **Slots are stable.** The fleet is a fixed-capacity slab; managers
  never move once created (their clients borrow their storage).
  `addSession`/`removeSession` are free-list operations.
- **Sessions are fully independent** — own key copy, wire session id,
  counters, backoff state. One session failing never disturbs another.
- **Scheduling is fair, not reactive.** There is no readiness API under
  the blocking `std.Io` model: a sweep visits sessions round-robin with
  `budget/live` each, and resumes from its cursor when the budget runs
  out. Sweeps are O(live sessions); what that costs per fleet size is
  measured, not guessed — see `just bench multi` and
  [operations.md](operations.md).

## Non-socket transports and pooling

`connman.Options.transport_provider` replaces the dial-TCP default with
any transport source — that is how `td.multi.Registry` runs fleets over
in-memory links, and how a pool would recycle connections:

```zig
.session = .{ .transport_provider = my_pool.provider() },
```

`acquire` must return a disconnected transport (the manager connects
it); `release` runs from `deinit`. The manager owns none of the
transport storage — only the vtable handle.
