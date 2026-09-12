//! Updates subsystem: decoding, ordering and reconciling Telegram's
//! server-pushed updates, and delivering them to application callbacks.
//!
//!   * `state` — `State`: the `pts`/`qts`/`date`/`seq` counters and the
//!     pure apply/skip/gap verdicts for each sequencing rule.
//!   * `classify` — which common-stream counter (if any) a given
//!     `api.Update` advances.
//!   * `engine` — `Engine`: processes decoded `api.Updates` values in
//!     order, dedupes, detects gaps and — through a `Fetcher` — heals
//!     them with `updates.getDifference` / seeds pristine state with
//!     `updates.getState`, delivering `Event`s to the handler.
//!   * `fetch` — the RPC side: `RpcFetcher` (difference/state over an
//!     `rpc.Client`) and `hook` (the client callback glue that decodes
//!     raw pushed bodies and ingests them).
//!
//! The intended pump loop, with `Manager.updates_handler` attached:
//!
//!     client.pump(io, budget) catch ...;
//!     if (engine.needs_difference) try engine.reconcile(io);
//!
//! Reconciliation deliberately never runs inside the hook: it would
//! re-enter the client's read loop (see `fetch`).
//!
//! Not covered yet: channel-scoped updates (`updateChannel*` sequences
//! through `updates.getChannelDifference`), and persistence of the
//! update state across restarts (compose on top of `session.Store`).

pub const state = @import("state.zig");
pub const classify = @import("classify.zig");
pub const engine = @import("engine.zig");
pub const fetch = @import("fetch.zig");

pub const State = state.State;
pub const Sequencing = classify.Sequencing;
pub const Engine = engine.Engine;
pub const Event = engine.Event;
pub const Handler = engine.Handler;
pub const Fetcher = engine.Fetcher;
pub const Options = engine.Options;
pub const Outcome = engine.Outcome;
pub const GapKind = engine.GapKind;
pub const Stats = engine.Stats;
pub const RpcFetcher = fetch.RpcFetcher;
pub const hook = fetch.hook;

test {
    _ = @import("state.zig");
    _ = @import("classify.zig");
    _ = @import("engine.zig");
    _ = @import("fetch.zig");
}
