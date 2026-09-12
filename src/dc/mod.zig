//! Data-center (DC) subsystem: endpoint knowledge, migration and the
//! client state that spans DCs.
//!
//!   * `options` — `DcList`: the built-in bootstrap addresses (production
//!     and test networks) merged with runtime `help.getConfig` /
//!     `updateDcOptions` data; endpoint selection by purpose (general /
//!     media / CDN) and address family (IPv4 / IPv6).
//!   * `migration` — the `PHONE/NETWORK/USER/FILE_MIGRATE_X` rpc-error
//!     family parsed into a target DC.
//!   * `manager` — `DataCenters`: current-DC state, per-DC authorization
//!     keys, and `connect` (endpoint → transport → key → RPC client).

pub const options = @import("options.zig");
pub const migration = @import("migration.zig");
pub const manager = @import("manager.zig");

pub const Environment = options.Environment;
pub const DcEndpoint = options.DcEndpoint;
pub const DcList = options.DcList;
pub const Purpose = options.Purpose;

pub const Migration = migration.Migration;
pub const MigrationKind = migration.Kind;

pub const DataCenters = manager.DataCenters;
pub const ConnectOptions = manager.ConnectOptions;
pub const Error = manager.Error;
pub const ConnectError = manager.ConnectError;

test {
    _ = @import("options.zig");
    _ = @import("migration.zig");
    _ = @import("manager.zig");
}
