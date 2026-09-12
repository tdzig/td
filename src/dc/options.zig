//! Data-center endpoint knowledge: the built-in bootstrap addresses and
//! the runtime list learned from the server.
//!
//! Telegram clients reach the network through numbered data centers
//! (DCs). Before anything else a client needs at least one address to
//! connect to, so every client ships a small built-in list (`tdzig`'s
//! mirrors Telegram Desktop's `kBuiltInDcs`/`kBuiltInDcsTest`, all port
//! 443 — see `mtproto_dc_options.cpp`). After the first
//! `help.getConfig` the server hands back the current
//! `dc_options:Vector<DcOption>` — usually with more addresses per DC,
//! media-only and CDN entries — and `updateDcOptions` pushes later
//! changes. `DcList` merges all of those sources and answers the one
//! question every caller has: *where do I connect for DC X and this
//! purpose?*
//!
//! Endpoint selection follows tdesktop's rules, restricted to what the
//! plain TCP-full transport can speak:
//!
//!   * general connections never use `media_only` or `cdn` entries;
//!   * media (upload/download) connections prefer dedicated `media_only`
//!     entries and fall back to general ones;
//!   * CDN connections only use `cdn` entries;
//!   * `tcpo_only` entries require the obfuscated transport (a later
//!     milestone) and are skipped;
//!   * the requested address family (IPv4/IPv6) is preferred, the other
//!     one is the fallback.
//!
//! Ownership: a `DcList` owns copies of every address and secret it
//! stores (`init` seeds it, `deinit` frees everything), so a decoded
//! `config` response can be freed right after `updateFromConfig`.

const std = @import("std");
const transport = @import("../transport/mod.zig");
const api = @import("../api/mod.zig");

pub const Error = error{
    OutOfMemory,
};

/// Which Telegram network a client talks to. Affects the bootstrap list
/// and the DC id placed in the handshake's `p_q_inner_data_dc` (see
/// `manager.DataCenters.handshakeDcId`).
pub const Environment = enum {
    /// The production network.
    production,
    /// The test network (test phone numbers 99966X). Its servers expect
    /// handshake DC ids shifted by +10000. As of 2026 the test DCs no
    /// longer auto-provision accounts for those numbers.
    @"test",
};

/// What a connection will be used for — decides which endpoint flags are
/// acceptable (mirrors tdesktop's DcType).
pub const Purpose = enum {
    /// Regular API traffic: plain endpoints only (no `media_only`, no
    /// `cdn`).
    general,
    /// Upload/download traffic: dedicated `media_only` endpoints when the
    /// DC offers them, plain endpoints otherwise.
    media,
    /// CDN download traffic (`upload.fileCdnRedirect` targets): `cdn`
    /// endpoints only.
    cdn,
};

/// One DC endpoint, from the bootstrap list or a server `dcOption`. The
/// address and secret bytes are owned by the containing `DcList`.
pub const DcEndpoint = struct {
    /// Telegram data-center number (1..5 in production today).
    id: i32,
    /// IPv4 or IPv6 address, spelled exactly as the server does.
    ip_address: []u8,
    port: i32,
    /// Address family flag from the server; drives family selection.
    ipv6: bool = false,
    /// Upload/download connections only (see `Purpose.media`).
    media_only: bool = false,
    /// Requires the obfuscated transport; never selected here.
    tcpo_only: bool = false,
    /// CDN endpoint (carries its own secrets; see also `secret`).
    cdn: bool = false,
    /// Shipped with the client (bootstrap entries are always static).
    static: bool = false,
    /// Only this port speaks the given protocol.
    this_port_only: bool = false,
    /// Endpoint secret (obfuscated/CDN transports use it).
    secret: ?[]u8 = null,
};

/// The TCP port every built-in endpoint listens on.
pub const default_port: i32 = 443;

// ---------------------------------------------------------------- bootstrap

const Bootstrap = struct { id: i32, ip: []const u8 };

/// Built-in production endpoints, IPv4 — Telegram Desktop
/// `kBuiltInDcs` (dev branch, September 2026). DC 2 has a second
/// address; every entry is `static`.
const bootstrap_prod_v4 = [_]Bootstrap{
    .{ .id = 1, .ip = "149.154.175.50" }, // MIA
    .{ .id = 2, .ip = "149.154.167.51" }, // AMS
    .{ .id = 2, .ip = "95.161.76.100" }, // AMS (second address)
    .{ .id = 3, .ip = "149.154.175.100" }, // MIA
    .{ .id = 4, .ip = "149.154.167.91" }, // AMS
    .{ .id = 5, .ip = "149.154.171.5" }, // SIN
};

/// Built-in production endpoints, IPv6 — Telegram Desktop
/// `kBuiltInDcsIPv6`.
const bootstrap_prod_v6 = [_]Bootstrap{
    .{ .id = 1, .ip = "2001:b28:f23d:f001::a" },
    .{ .id = 2, .ip = "2001:67c:4e8:f002::a" },
    .{ .id = 3, .ip = "2001:b28:f23d:f003::a" },
    .{ .id = 4, .ip = "2001:67c:4e8:f004::a" },
    .{ .id = 5, .ip = "2001:b28:f23f:f005::a" },
};

/// Built-in test endpoints, IPv4 — Telegram Desktop `kBuiltInTestDcs`.
/// The test network has three DCs.
const bootstrap_test_v4 = [_]Bootstrap{
    .{ .id = 1, .ip = "149.154.175.10" },
    .{ .id = 2, .ip = "149.154.167.40" },
    .{ .id = 3, .ip = "149.154.175.117" },
};

/// Built-in test endpoints, IPv6 — Telegram Desktop
/// `kBuiltInTestDcsIPv6`.
const bootstrap_test_v6 = [_]Bootstrap{
    .{ .id = 1, .ip = "2001:b28:f23d:f001::e" },
    .{ .id = 2, .ip = "2001:67c:4e8:f002::e" },
    .{ .id = 3, .ip = "2001:b28:f23d:f003::e" },
};

// ------------------------------------------------------------------ DcList

/// The merged endpoint list. Bootstrap entries are seeded at `init`
/// unless `initEmpty` is used; server data merges in through
/// `addFromDcOption`/`updateFromOptions`/`updateFromConfig`, keyed by
/// `(dc id, address, port)` — a repeated entry refreshes its flags and
/// secret instead of duplicating.
pub const DcList = struct {
    allocator: std.mem.Allocator,
    environment: Environment,
    endpoints: std.ArrayList(DcEndpoint) = .empty,

    /// Seeds the built-in bootstrap list for `environment` (every entry
    /// static, port 443).
    pub fn init(allocator: std.mem.Allocator, environment: Environment) Error!DcList {
        var self: DcList = .{ .allocator = allocator, .environment = environment };
        errdefer self.deinit();
        const v4: []const Bootstrap = if (environment == .production)
            &bootstrap_prod_v4
        else
            &bootstrap_test_v4;
        const v6: []const Bootstrap = if (environment == .production)
            &bootstrap_prod_v6
        else
            &bootstrap_test_v6;
        for (v4) |b| try self.addBootstrap(b, false);
        for (v6) |b| try self.addBootstrap(b, true);
        return self;
    }

    /// An empty list for `environment` (no bootstrap entries) — for tests
    /// and for callers that learn everything from a stored `config`.
    pub fn initEmpty(allocator: std.mem.Allocator, environment: Environment) DcList {
        return .{ .allocator = allocator, .environment = environment };
    }

    pub fn deinit(self: *DcList) void {
        for (self.endpoints.items) |ep| {
            self.allocator.free(ep.ip_address);
            if (ep.secret) |s| self.allocator.free(s);
        }
        self.endpoints.deinit(self.allocator);
    }

    /// Number of stored endpoints (both families, all purposes).
    pub fn count(self: *const DcList) usize {
        return self.endpoints.items.len;
    }

    /// All endpoints, insertion order (bootstrap first).
    pub fn all(self: *const DcList) []const DcEndpoint {
        return self.endpoints.items;
    }

    /// Whether any endpoint for `dc` is known.
    pub fn hasDc(self: *const DcList, dc: i32) bool {
        for (self.endpoints.items) |ep| {
            if (ep.id == dc) return true;
        }
        return false;
    }

    /// Merges one server `dcOption` (or a hand-built one). An endpoint
    /// with the same `(id, ip, port)` keeps its place and has its flags
    /// and secret refreshed — the server's word wins.
    pub fn addFromDcOption(self: *DcList, opt: api.dcOption) Error!void {
        for (self.endpoints.items) |*ep| {
            if (ep.id != opt.id or ep.port != opt.port) continue;
            if (!std.mem.eql(u8, ep.ip_address, opt.ip_address)) continue;
            const new_secret: ?[]u8 = if (opt.secret) |s|
                (self.allocator.dupe(u8, s) catch return error.OutOfMemory)
            else
                null;
            ep.ipv6 = opt.ipv6;
            ep.media_only = opt.media_only;
            ep.tcpo_only = opt.tcpo_only;
            ep.cdn = opt.cdn;
            ep.static = opt.static;
            ep.this_port_only = opt.this_port_only;
            if (ep.secret) |old| self.allocator.free(old);
            ep.secret = new_secret;
            return;
        }
        const ip = self.allocator.dupe(u8, opt.ip_address) catch return error.OutOfMemory;
        const secret: ?[]u8 = if (opt.secret) |s|
            (self.allocator.dupe(u8, s) catch {
                self.allocator.free(ip);
                return error.OutOfMemory;
            })
        else
            null;
        self.endpoints.append(self.allocator, .{
            .id = opt.id,
            .ip_address = ip,
            .port = opt.port,
            .ipv6 = opt.ipv6,
            .media_only = opt.media_only,
            .tcpo_only = opt.tcpo_only,
            .cdn = opt.cdn,
            .static = opt.static,
            .this_port_only = opt.this_port_only,
            .secret = secret,
        }) catch {
            if (secret) |s| self.allocator.free(s);
            self.allocator.free(ip);
            return error.OutOfMemory;
        };
    }

    /// Merges an `updateDcOptions` payload (or any dcOption vector).
    pub fn updateFromOptions(self: *DcList, opts: []const api.DcOption) Error!void {
        for (opts) |opt| switch (opt) {
            .dcOption => |o| try self.addFromDcOption(o),
        };
    }

    /// Merges the endpoint list of a `help.getConfig` result. Only
    /// `dc_options` is read; the decoded response (and everything it
    /// borrows) can be freed right after the call.
    pub fn updateFromConfig(self: *DcList, cfg: *const api.config) Error!void {
        return self.updateFromOptions(cfg.dc_options);
    }

    /// Where to connect for `dc` and `purpose`. The preferred address
    /// family comes first, the other one is the fallback; `null` when the
    /// DC has no usable endpoint (unknown DC, or only `tcpo_only`
    /// entries). The returned `host` borrows this list's storage: valid
    /// until the next mutating call.
    pub fn endpointFor(
        self: *const DcList,
        dc: i32,
        purpose: Purpose,
        prefer_ipv6: bool,
    ) ?transport.Endpoint {
        const families = [2]bool{ prefer_ipv6, !prefer_ipv6 };
        if (purpose == .media) {
            // Dedicated upload/download endpoints win when offered.
            for (families) |want_ipv6| {
                if (self.endpointMatching(dc, .media, want_ipv6)) |ep| return ep;
            }
        }
        const match: Match = switch (purpose) {
            .general, .media => .plain,
            .cdn => .cdn,
        };
        for (families) |want_ipv6| {
            if (self.endpointMatching(dc, match, want_ipv6)) |ep| return ep;
        }
        return null;
    }

    /// Which flag combination a selection pass looks for.
    const Match = enum {
        /// No `media_only`, no `cdn`.
        plain,
        /// `media_only`, no `cdn`.
        media,
        /// `cdn`.
        cdn,
    };

    fn endpointMatching(self: *const DcList, dc: i32, match: Match, want_ipv6: bool) ?transport.Endpoint {
        for (self.endpoints.items) |ep| {
            if (ep.id != dc or ep.ipv6 != want_ipv6) continue;
            if (ep.port <= 0 or ep.port > std.math.maxInt(u16)) continue;
            // The plain TCP-full transport cannot speak to
            // obfuscation-only endpoints.
            if (ep.tcpo_only) continue;
            switch (match) {
                .plain => if (ep.media_only or ep.cdn) continue,
                .media => if (!ep.media_only or ep.cdn) continue,
                .cdn => if (!ep.cdn) continue,
            }
            return .{ .host = ep.ip_address, .port = @intCast(ep.port) };
        }
        return null;
    }

    fn addBootstrap(self: *DcList, b: Bootstrap, ipv6: bool) Error!void {
        const ip = self.allocator.dupe(u8, b.ip) catch return error.OutOfMemory;
        self.endpoints.append(self.allocator, .{
            .id = b.id,
            .ip_address = ip,
            .port = default_port,
            .ipv6 = ipv6,
            .static = true,
        }) catch {
            self.allocator.free(ip);
            return error.OutOfMemory;
        };
    }
};

// ---------------------------------------------------------------- tests

const tl = @import("../tl/mod.zig");
const Writer = tl.Writer;
const Reader = tl.Reader;

test "bootstrap lists seed production and test endpoints" {
    var list = try DcList.init(std.testing.allocator, .production);
    defer list.deinit();

    // 6 IPv4 entries (DC 2 has two addresses) + 5 IPv6 entries, all
    // static and on port 443.
    try std.testing.expectEqual(@as(usize, 11), list.count());
    for (list.all()) |ep| {
        try std.testing.expect(ep.static);
        try std.testing.expectEqual(@as(i32, 443), ep.port);
    }
    for (1..6) |dc| try std.testing.expect(list.hasDc(@intCast(dc)));
    try std.testing.expect(!list.hasDc(6));

    const v4 = list.endpointFor(2, .general, false).?;
    try std.testing.expectEqualStrings("149.154.167.51", v4.host);
    try std.testing.expectEqual(@as(u16, 443), v4.port);
    const v6 = list.endpointFor(2, .general, true).?;
    try std.testing.expectEqualStrings("2001:67c:4e8:f002::a", v6.host);

    // The test network: three DCs, six entries, no DC 4.
    var test_list = try DcList.init(std.testing.allocator, .@"test");
    defer test_list.deinit();
    try std.testing.expectEqual(@as(usize, 6), test_list.count());
    try std.testing.expect(!test_list.hasDc(4));
    const t1 = test_list.endpointFor(1, .general, false).?;
    try std.testing.expectEqualStrings("149.154.175.10", t1.host);
}

test "endpoint selection filters by purpose, family and flags" {
    var list = DcList.initEmpty(std.testing.allocator, .production);
    defer list.deinit();

    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.1", .port = 443 }); // plain v4
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.2", .port = 443, .media_only = true });
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10::1", .port = 443, .ipv6 = true });
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.3", .port = 443, .cdn = true });
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.4", .port = 443, .tcpo_only = true });

    // General: plain endpoints only, preferred family first.
    try std.testing.expectEqualStrings("10.0.0.1", list.endpointFor(1, .general, false).?.host);
    try std.testing.expectEqualStrings("10::1", list.endpointFor(1, .general, true).?.host);
    // Media prefers the dedicated endpoint regardless of family order.
    try std.testing.expectEqualStrings("10.0.0.2", list.endpointFor(1, .media, true).?.host);
    // CDN: cdn endpoints only.
    try std.testing.expectEqualStrings("10.0.0.3", list.endpointFor(1, .cdn, false).?.host);

    // A media-only-only DC serves media but not general traffic.
    try list.addFromDcOption(.{ .id = 2, .ip_address = "10.0.1.2", .port = 443, .media_only = true });
    try std.testing.expect(list.endpointFor(2, .general, false) == null);
    try std.testing.expectEqualStrings("10.0.1.2", list.endpointFor(2, .media, false).?.host);

    // Obfuscation-only endpoints are unreachable with plain transports.
    try list.addFromDcOption(.{ .id = 3, .ip_address = "10.0.2.3", .port = 443, .tcpo_only = true });
    try std.testing.expect(list.endpointFor(3, .general, false) == null);
    try std.testing.expect(list.endpointFor(3, .media, false) == null);

    // IPv4 preferred but only IPv6 exists: family fallback.
    try list.addFromDcOption(.{ .id = 4, .ip_address = "10::4", .port = 443, .ipv6 = true });
    try std.testing.expectEqualStrings("10::4", list.endpointFor(4, .general, false).?.host);
}

test "options update dedups by (id, ip, port) and refreshes flags" {
    var list = DcList.initEmpty(std.testing.allocator, .production);
    defer list.deinit();

    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.1", .port = 443 });
    const secret_bytes = "cafebabe";
    try list.addFromDcOption(.{
        .id = 1,
        .ip_address = "10.0.0.1",
        .port = 443,
        .media_only = true,
        .secret = secret_bytes,
    });
    try std.testing.expectEqual(@as(usize, 1), list.count());
    const ep = list.all()[0];
    try std.testing.expect(ep.media_only);
    try std.testing.expectEqualStrings("cafebabe", ep.secret.?);

    // A different port is a different endpoint.
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.1", .port = 80 });
    try std.testing.expectEqual(@as(usize, 2), list.count());
}

test "endpoints with unusable ports are never selected" {
    var list = DcList.initEmpty(std.testing.allocator, .production);
    defer list.deinit();

    // Ports outside the u16 range cannot name a TCP endpoint: zero,
    // negative and 65536+ entries are stored but never selected.
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.1", .port = 0 });
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.2", .port = -1 });
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.3", .port = 70000 });
    try std.testing.expect(list.endpointFor(1, .general, false) == null);
    try std.testing.expect(list.endpointFor(1, .media, false) == null);
    try std.testing.expect(list.endpointFor(1, .cdn, false) == null);
    // The DC is still known — only selection refuses it.
    try std.testing.expect(list.hasDc(1));

    // 65535 is the largest usable port.
    try list.addFromDcOption(.{ .id = 1, .ip_address = "10.0.0.4", .port = 65535 });
    const ep = list.endpointFor(1, .general, false).?;
    try std.testing.expectEqual(@as(u16, 65535), ep.port);
    try std.testing.expectEqualStrings("10.0.0.4", ep.host);

    // A DC with no entries at all.
    try std.testing.expect(list.endpointFor(9, .general, false) == null);
}

test "updateFromConfig merges wire-decoded dcOptions" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var list = DcList.initEmpty(std.testing.allocator, .production);
    defer list.deinit();

    // A config carrying two dcOptions, serialized and decoded back
    // through the generated types — exactly what a `help.getConfig`
    // round trip produces.
    const cfg = api.config{
        .date = 100,
        .expires = 200,
        .test_mode = false,
        .this_dc = 2,
        .dc_options = try arena.dupe(api.DcOption, &.{
            .{ .dcOption = .{ .id = 2, .ip_address = "149.154.167.51", .port = 443, .static = true } },
            .{ .dcOption = .{ .id = 5, .ip_address = "91.108.56.191", .port = 443, .static = true } },
        }),
        .dc_txt_domain_name = "experiments",
        .chat_size_max = 200,
        .megagroup_size_max = 10000,
        .forwarded_count_max = 100,
        .online_update_period_ms = 30000,
        .offline_blur_timeout_ms = 30000,
        .offline_idle_timeout_ms = 30000,
        .online_cloud_timeout_ms = 300000,
        .notify_cloud_delay_ms = 30000,
        .notify_default_delay_ms = 1500,
        .push_chat_period_ms = 60000,
        .push_chat_limit = 2,
        .edit_time_limit = 3600,
        .revoke_time_limit = 3600,
        .revoke_pm_time_limit = 3600,
        .rating_e_decay = 250000,
        .stickers_recent_limit = 200,
        .channels_read_media_period = 86400,
        .call_receive_timeout_ms = 20000,
        .call_ring_timeout_ms = 90000,
        .call_connect_timeout_ms = 30000,
        .call_packet_timeout_ms = 10000,
        .me_url_prefix = "https://t.me/",
        .caption_length_max = 1024,
        .message_length_max = 4096,
        .webfile_dc_id = 4,
    };
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try cfg.serialize(&w);

    var r = Reader.init(w.items());
    const decoded = try api.config.deserialize(arena, &r);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());

    try list.updateFromConfig(&decoded);
    try std.testing.expectEqual(@as(usize, 2), list.count());
    try std.testing.expect(list.hasDc(5));
    try std.testing.expectEqualStrings("91.108.56.191", list.endpointFor(5, .general, false).?.host);
}
