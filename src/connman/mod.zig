//! Connection management: robustness around one long-lived MTProto
//! connection. The step's definition of done — *the client survives
//! normal network interruptions and reconnects without corrupting MTProto
//! state* — is implemented here, on top of the transport, session and RPC
//! layers:
//!
//!   * `manager` — `Manager`: the connection state machine (`idle`,
//!     `connecting`, `connected`, `backing_off`, `closed`), automatic
//!     reconnection through an exponential fully-jittered backoff
//!     (`Backoff`), request recovery where the protocol permits
//!     (`rpc.Client.recoverFailed`: only requests the server never
//!     answered are re-sent, under fresh msg_ids, same handles), health
//!     checks (`maintain`: ping / ping_delay_disconnect with a bounded
//!     round trip), the read loop (`pump`), graceful shutdown (`close`:
//!     drain acks → cancel outstanding → close) and cancellation
//!     (`cancel`, plus stale-ping cleanup).
//!   * `backoff` — `Backoff`: pure delay policy, no clocks, no IO.
//!
//! Everything is instance state — the module has no globals and no
//! background threads; maintenance happens inside the operations, with
//! `std.Io` passed per call like everywhere in td. Wire-session
//! hygiene across reconnects is inherited from `mtproto.Session.reset`
//! (fresh session_id and counters, kept auth key and corrected salt), so
//! a surviving interruption looks to the server exactly like a client
//! that came back with a new session.

pub const manager = @import("manager.zig");
pub const backoff = @import("backoff.zig");

pub const Manager = manager.Manager;
pub const Options = manager.Options;
pub const TransportProvider = manager.TransportProvider;
pub const State = manager.State;
pub const Health = manager.Health;
pub const Error = manager.Error;
pub const Backoff = backoff.Backoff;

test {
    _ = @import("manager.zig");
    _ = @import("backoff.zig");
}
