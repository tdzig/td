//! Multi-session support: running and scheduling many independent
//! Telegram sessions in one process, with the measurements to say what
//! "many" means.
//!
//!   * `loopback` — `Link`/`Registry`: an in-memory transport with a
//!     real MTProto peer embedded (full decrypt/validate/encrypt on the
//!     peer side). The whole stack runs against it, at zero threads and
//!     zero file descriptors — that is what makes fleet-scale tests and
//!     benchmarks practical, and it doubles as the demonstration of the
//!     `connman.Options.transport_provider` seam (non-socket transports,
//!     pooling).
//!   * `fleet` — `Fleet`: a fixed-capacity slab of `connman.Manager`
//!     sessions with fair, budget-capped round-robin scheduling
//!     (`pump`), fleet keep-alive (`maintainAll`), O(1) membership, and
//!     per-sweep work accounting (`Sweep`, `Totals`) for event-loop
//!     utilization.
//!
//! Sessions are fully independent — each keeps its own authorization
//! key, wire session id, endpoint and backoff state; the fleet shares
//! only the scheduler and the process allocator.
//!
//! Concurrency model (unchanged): single `std.Io`, single thread, `io`
//! passed per call. Thousands of sessions are multiplexed by
//! interleaving their operations on one thread, not by spawning per
//! session. Per-sweep cost is O(live sessions); the benchmarks in
//! `bench/multi.zig` measure what that costs at 100 / 1 000 / 5 000 /
//! 10 000 sessions — memory per session, requests per second, latency
//! percentiles, allocations and sweep utilization — and are the
//! authority on fleet sizing. No scalability claim is made without
//! them.

pub const loopback = @import("loopback.zig");
pub const fleet = @import("fleet.zig");

pub const Link = loopback.Link;
pub const Registry = loopback.Registry;
pub const Responder = loopback.Responder;
pub const Reply = loopback.Reply;
pub const Fleet = fleet.Fleet;
pub const FleetOptions = fleet.Options;

test {
    _ = @import("loopback.zig");
    _ = @import("fleet.zig");
}
