//! The RPC side of the updates engine: a `Fetcher` implementation over
//! an `rpc.Client`, and the client-hook glue that feeds raw pushed
//! updates into an `Engine`.
//!
//! The split the engine mandates lives here: the hook only decodes and
//! ingests — pure, no client re-entry — while the getDifference/getState
//! calls happen inside `Engine.reconcile`, which the pump loop runs
//! after `pump` returns. A fetch from inside the hook would re-enter
//! the client's read loop: nested frames reuse the receive scratch the
//! outer dispatch is still reading from.
//!
//!     mgr.updates_handler = td.updates.fetch.hook(&engine);
//!     ... client.pump(io, budget) ...
//!     if (engine.needs_difference) try engine.reconcile(io);

const std = @import("std");
const api = @import("../api/mod.zig");
const rpc = @import("../rpc/mod.zig");
const Reader = @import("../tl/reader.zig").Reader;
const engine_mod = @import("engine.zig");

pub const Engine = engine_mod.Engine;

/// `updates.getDifference` / `updates.getState` over one rpc.Client.
/// The client is borrowed; the fetcher holds no state of its own.
pub const RpcFetcher = struct {
    client: *rpc.Client,

    pub fn init(client: *rpc.Client) RpcFetcher {
        return .{ .client = client };
    }

    /// The type-erased fetcher for the engine. `self` must outlive the
    /// engine's use of it.
    pub fn fetcher(self: *RpcFetcher) engine_mod.Fetcher {
        return .{
            .ctx = self,
            .getDifference = &getDifference,
            .getState = &getState,
        };
    }

    fn getDifference(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        req: api.updates.getDifference,
    ) anyerror!*engine_mod.DifferenceResponse {
        const self: *RpcFetcher = @ptrCast(@alignCast(ctx));
        const res = try allocator.create(engine_mod.DifferenceResponse);
        errdefer allocator.destroy(res);
        res.* = try self.client.call(io, req, api.updates.Difference);
        return res;
    }

    fn getState(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
    ) anyerror!*engine_mod.StateResponse {
        const self: *RpcFetcher = @ptrCast(@alignCast(ctx));
        const res = try allocator.create(engine_mod.StateResponse);
        errdefer allocator.destroy(res);
        res.* = try self.client.call(io, api.updates.getState{}, api.updates.state);
        return res;
    }
};

/// The rpc.Client hook for `engine`: decodes the raw pushed body as
/// `api.Updates` into a per-call arena (freed on return) and ingests
/// it. Failures are counted on the engine, never surfaced — a hook
/// cannot fail the pump. Delivery to the application handler happens
/// synchronously here; gap healing does not (set `needs_difference`,
/// reconcile after the pump).
pub fn hook(engine: *Engine) rpc.UpdatesHandler {
    return .{ .ctx = engine, .onUpdates = &onUpdates };
}

fn onUpdates(ctx: *anyopaque, io: std.Io, body: []const u8) void {
    _ = io;
    const engine: *Engine = @ptrCast(@alignCast(ctx));
    var arena = std.heap.ArenaAllocator.init(engine.allocator);
    defer arena.deinit();
    var r = Reader.init(body);
    const upds = api.Updates.deserialize(arena.allocator(), &r) catch {
        engine.stats.undecodable_bodies += 1;
        return;
    };
    _ = engine.handle(&upds);
}
