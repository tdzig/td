//! Client-session subsystem: the state that survives a disconnect, and
//! where it is kept.
//!
//!   * `state` — `State`: DC + environment, the secret authorization key
//!     (with the capture-time server salt) and the wire-session id plus
//!     outgoing counters; fixed-size binary serialization with checksum
//!     and consistency validation; `capture` from a live client,
//!     `applyTo` a `DataCenters`, `adoptOn` a freshly connected client.
//!     Rendering is strictly redacted — secret material can never reach
//!     a log through this module.
//!   * `store` — `Store`: the type-erased custom-storage interface
//!     (load/save/remove of opaque bytes) with `loadState`/`saveState`
//!     conveniences, plus `MemoryStore` (in-process bytes).
//!   * `file` — `FileStore`: one file per session, atomically replaced,
//!     owner-only permissions.
//!   * `string` — portable session strings: the compact base64url form
//!     used across the client ecosystem (all three historical layouts
//!     in, the current one out).
//!
//! The reconnect flow this enables (the step's definition of done):
//!
//!     capture → serialize → Store.save
//!     ... restart ...
//!     Store.load → deserialize → applyTo(DataCenters) → connect
//!     (no handshake: the auth key is known) → adoptOn(client)
//!
//! Nothing here re-runs the authorization-key handshake unless the
//! stored key is gone.

pub const state = @import("state.zig");
pub const store = @import("store.zig");
pub const file = @import("file.zig");
pub const string = @import("string.zig");

pub const State = state.State;
pub const Store = store.Store;
pub const MemoryStore = store.MemoryStore;
pub const FileStore = file.FileStore;

test {
    _ = @import("state.zig");
    _ = @import("store.zig");
    _ = @import("file.zig");
    _ = @import("string.zig");
}
