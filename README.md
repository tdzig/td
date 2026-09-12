# td

> A Telegram **MTProto 2.0** client library for **Zig** — users and bots,
> built from scratch.

`td` is not a port and not a binding: no TDLib, gramJS, gotd, grammers,
Pyrogram or Telethon code is used. The entire stack is generated and
hand-written in Zig from the official TL schemas — **TL parsing →
codegen → crypto → handshake → transports → RPC → DC → sessions →
updates → auth → multi-session fleets** — with every layer independently
importable and tested. ("td" here is *this* library; TDLib is a
different project.)

Single-threaded by design: one connection is owned by one loop, `io` is
passed per call, and there are zero hidden threads or locks.
"Concurrency" means RPC pipelining and multi-session fleets, and is
measured, not claimed — the bench suite scales to 10 000 sessions.

## Status

Verified 2026-09-12: `just build` and `just test` pass with zero
failures; `just api` and `just mtp` regenerate the committed generated
code byte-identically; `just bench` completes. Real-network smoke tests
(`just keygen`, `just bot`) have passed against production DCs.

Still pending: production checks for PFS (`TD_PFS=1 just bot`) and
no-updates sessions; see [Roadmap](#roadmap) for what is not implemented.

## Quick start

Requires **Zig 0.16**.

```sh
zig build          # library, CLIs, and all examples
zig build test     # unit + integration + golden + compliance + fuzz corpora
```

The smallest real program — connect, one typed invoke, session
persisted for faster reruns (`TD_API_ID` from
[my.telegram.org](https://my.telegram.org); there are no embedded
defaults anywhere in this repository):

```zig
const std = @import("std");
const td = @import("td");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const api_id = try std.fmt.parseInt(
        i32,
        init.environ_map.get("TD_API_ID") orelse return error.NoApiId,
        10,
    );

    var store = try td.session.FileStore.init(gpa, "session.bin");
    defer store.deinit();

    var client = try td.Client.init(gpa, .{
        .session_store = store.store(),
        .app = .{ .api_id = api_id },
    });
    defer client.deinit(io);

    try client.connect(io); // stored session or fresh handshake

    var dc = try client.invoke(io, td.api.help.getNearestDc{});
    defer dc.deinit(); // the response owns its arena
    std.debug.print("nearest DC: {d}\n", .{dc.value.nearestDc.this_dc});
}
```

For a bot, set `TD_BOT_TOKEN` and run
[`zig build && ./zig-out/bin/example-bot-login`](examples/bot_login.zig) —
`auth.importBotAuthorization` + `users.getUsers` over the same client,
with optional PFS via `TD_PFS=1`.

## What's inside

- **Schema-driven API** — the vendored official `api.tl` / `mtproto.tl`
  compile through `td-gen` into the flat, typed `td.api` surface
  (tagged unions, request structs, zero-copy deserialization);
  regeneration is byte-reproducible (`just api`).
- **MTProto 2.0 core** — AES-256-IGE message crypto (OpenSSL
  KAT-validated), authorization-key handshake in both documented RSA
  layouts (classic + `rsa_pad`), msg_id/seq_no discipline, containers,
  acks, and all service messages.
- **Perfect forward secrecy** (opt-in) — temp auth keys generated,
  bound via `auth.bindTempAuthKey`, rotated ahead of expiry, never
  persisted.
- **All four TCP transports** — abridged (default), intermediate, padded
  intermediate, full — behind one vtable interface with golden wire
  vectors per framing; obfuscated/HTTP/WebSocket drop in later without
  touching callers.
- **RPC** — typed `invoke`, pipelined `send`/`wait` with any number of
  requests outstanding, raw pre-serialized paths, gzip results with
  decompression-bomb bounds, per-request timeouts.
- **Errors** — an 889-entry generated catalog classifies `rpc_error`
  messages (`FLOOD_WAIT_60` → typed id + parameter); DC migrations
  (`PHONE/NETWORK/FILE_MIGRATE_X`) are parsed and followed
  automatically.
- **Sessions & storage** — capture → store → restore → continue,
  portable session strings, atomic 0600 file store, custom storage
  interfaces, plus typed record storage (peer cache, per-entity update
  state).
- **Updates** — pts/qts/date/seq tracking, pushed-object classification,
  gap healing via `getDifference`; or `no_updates` sessions that never
  subscribe.
- **Auth** — bot import, send-code → sign-in → sign-up → 2FA (SRP) →
  logout as an explicit state machine with mapped RPC errors.
- **Fleets** — `td.multi.Fleet`: fixed-capacity independent sessions
  with fair, budget-capped sweeps; benchmarks measure memory/session,
  throughput, latency percentiles and event-loop utilization at
  100–10 000 sessions.

## Testing and security

Everything is tested against deterministic **in-process loopback peers**
— a real embedded MTProto server, a test RSA keypair, official
worked-example values — so `just test` needs no network. The protocol
edge is additionally covered by coverage-guided fuzzing (`just fuzz`)
and a compliance suite (tampered msg_keys, out-of-window msg_ids,
gzip bombs, truncations — all rejected with the documented errors,
never desynchronizing).

Cryptographic correctness comes from known-answer tests and the
official worked examples, not from "looks right". The handshake,
session and auth modules contain **no logging at all**; secret material
never leaves caller-owned memory, session files are written 0600
atomically, and `Session.State` has a redacted formatting mode. Real
network is strictly opt-in (`just keygen`, `just bot`).

## Documentation

| Document | Covers |
| --- | --- |
| [getting-started](docs/getting-started.md) | build, first round trip, auth, session restore |
| [rpc-and-updates](docs/rpc-and-updates.md) | pipelining, raw RPC, errors, updates |
| [sessions](docs/sessions.md) | state, custom storage, fleets |
| [raw-interfaces](docs/raw-interfaces.md) | raw TL, raw MTProto, custom transports |
| [operations](docs/operations.md) | performance, benchmarking, security posture, release |
| [layout](docs/layout.md) | per-file map of the source tree |

Runnable examples: `example-loopback` (in-memory peer round trip),
`example-session` (persist/restore), `example-quickstart` +
`example-invoke` (high-level client against a production DC),
`example-bot-login` (bot auth + getMe).

## Codegen

```sh
just api      # regenerate src/api/ from schema/api.tl (byte-reproducible)
just mtp      # regenerate src/mtproto/schema_gen.zig from schema/mtproto.tl
just errors   # regenerate src/rpc/errors_gen.zig from the vendored catalogs
just bench    # benchmark suite (filter: just bench multi)
just fuzz     # coverage-guided fuzzing (corpora also run in just test)
```

## Roadmap

Not implemented yet, planned in this order: media upload/download
(incl. CDN DCs), obfuscated transports + HTTP/WebSocket,
`USER_MIGRATE` authorization export/import, proxy support
(SOCKS5/MTProto), per-channel update state, generated `deinit`.

## Prior art

The design stands on the shoulders of the mature MTProto clients —
[TDLib](https://github.com/tdlib/td),
[Telethon](https://github.com/LonamiWebs/Telethon),
[Pyrogram](https://github.com/pyrogram/pyrogram),
[gotd](https://github.com/gotd/td),
[grammers](https://github.com/Lonami/grammers),
[gramJS](https://github.com/gram-js/gramjs) — studied for wire-format
ground truth and API shape, then rebuilt from zero in Zig.

## References

- [MTProto](https://core.telegram.org/mtproto) ·
  [description](https://core.telegram.org/mtproto/description) ·
  [service messages](https://core.telegram.org/mtproto/service_messages) ·
  [transports](https://core.telegram.org/mtproto/mtproto-transports) ·
  [schema](https://core.telegram.org/schema) ·
  [PFS](https://core.telegram.org/api/pfs)

## License

MIT — see [LICENSE](LICENSE).
