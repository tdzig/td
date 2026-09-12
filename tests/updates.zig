//! Updates-system tests: the ordering/reconciliation engine against the
//! real generated API, the client hook glue, and — over real loopback
//! sockets — pushed-update delivery from a live MTProto peer through
//! pump → hook → decode → engine → callback.
//!
//! The choreography follows `tests/connman.zig`: one thread, strict
//! alternation. Gap healing with real RPC round trips is not exercised
//! here (a synchronous `reconcile` cannot interleave with a server on
//! one thread); it is covered at the engine level with a scripted
//! fetcher, on top of the rpc.Client coverage in `tests/rpc.zig` and
//! `tests/connman.zig`.

const std = @import("std");
const net = std.Io.net;
const td = @import("td");

const api = td.api;
const Writer = td.tl.Writer;
const message = td.mtproto.message;
const Engine = td.updates.Engine;
const Event = td.updates.Event;

// ----------------------------------------------------------------- util

const Recorder = struct {
    tags: std.ArrayList([]const u8) = .empty,

    fn notify(ctx: *anyopaque, ev: Event) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        const t: []const u8 = switch (ev) {
            .update => |u| @tagName(u.*),
            .short_message => "short_message",
            .short_chat_message => "short_chat_message",
            .short_sent_message => "short_sent_message",
            .new_message => "new_message",
            .encrypted_message => "encrypted_message",
        };
        self.tags.append(std.testing.allocator, t) catch @panic("oom");
    }

    fn handler(self: *Recorder) td.updates.Handler {
        return .{ .ctx = self, .notify = &notify };
    }

    fn deinit(self: *Recorder) void {
        self.tags.deinit(std.testing.allocator);
    }
};

fn expectTags(expected: []const []const u8, rec: *const Recorder) !void {
    try std.testing.expectEqual(expected.len, rec.tags.items.len);
    for (expected, rec.tags.items) |e, a| try std.testing.expectEqualStrings(e, a);
}

/// Serializes one generated value to owned bytes (arena-freed).
fn serializeAlloc(arena: std.mem.Allocator, v: anytype) ![]u8 {
    var w = Writer.init(arena);
    try v.serialize(&w);
    return w.toOwnedSlice();
}

fn userStatusUpdate(user_id: i64) api.Update {
    return .{ .updateUserStatus = .{
        .user_id = user_id,
        .status = .{ .userStatusEmpty = .{} },
    } };
}

fn deleteMessagesUpdate(pts: i32, count: i32) api.Update {
    del_buf[0] = 1;
    del_buf[1] = 2;
    return .{ .updateDeleteMessages = .{
        .messages = del_buf[0..2],
        .pts = pts,
        .pts_count = count,
    } };
}
var del_buf = [_]i32{ 0, 0 };

/// Scripted fetcher: answers getDifference with pre-serialized
/// `api.updates.Difference` bodies (cycled), getState with built
/// states; can fail on demand.
const FakeFetcher = struct {
    script: []const []const u8 = &.{},
    state_script: []const api.updates.state = &.{},
    fail_with: ?anyerror = null,
    calls: usize = 0,
    state_calls: usize = 0,
    last_req: ?api.updates.getDifference = null,

    fn fetcher(self: *FakeFetcher) td.updates.Fetcher {
        return .{
            .ctx = self,
            .getDifference = &getDifferenceImpl,
            .getState = &getStateImpl,
        };
    }

    fn getDifferenceImpl(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        req: api.updates.getDifference,
    ) anyerror!*td.updates.engine.DifferenceResponse {
        _ = io;
        const self: *FakeFetcher = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.last_req = req;
        const res = try allocator.create(td.updates.engine.DifferenceResponse);
        errdefer allocator.destroy(res);
        if (self.fail_with) |e| return e;
        if (self.script.len == 0) return error.NoScript;
        const bytes = self.script[(self.calls - 1) % self.script.len];
        res.* = .{
            .arena_state = std.heap.ArenaAllocator.init(std.testing.allocator),
            .value = undefined,
        };
        res.value = try td.rpc.decode.decode(api.updates.Difference, res.arena_state.allocator(), bytes);
        return res;
    }

    fn getStateImpl(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
    ) anyerror!*td.updates.engine.StateResponse {
        _ = io;
        const self: *FakeFetcher = @ptrCast(@alignCast(ctx));
        self.state_calls += 1;
        const res = try allocator.create(td.updates.engine.StateResponse);
        errdefer allocator.destroy(res);
        if (self.fail_with) |e| return e;
        if (self.state_script.len == 0) return error.NoScript;
        res.* = .{
            .arena_state = std.heap.ArenaAllocator.init(std.testing.allocator),
            .value = self.state_script[(self.state_calls - 1) % self.state_script.len],
        };
        return res;
    }
};

// -------------------------------------------------- engine: containers

test "updates containers: in order, duplicate, then seq gap" {
    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();

    var seq1 = [_]api.Update{userStatusUpdate(7)};
    const first = api.Updates{ .updates_ = .{
        .updates = &seq1,
        .users = &.{},
        .chats = &.{},
        .date = 100,
        .seq = 1,
    } };
    var out = e.handle(&first);
    try std.testing.expectEqual(@as(usize, 1), out.delivered);
    try expectTags(&.{"updateUserStatus"}, &rec);
    try std.testing.expectEqual(@as(i32, 1), e.state.seq);
    try std.testing.expectEqual(@as(i32, 100), e.state.date);
    try std.testing.expect(!e.needs_difference);

    // seq 1 again: wholly stale, nothing delivered.
    out = e.handle(&first);
    try std.testing.expect(out.duplicate);
    try std.testing.expectEqual(@as(usize, 0), out.delivered);
    try std.testing.expectEqual(@as(usize, 1), e.stats.duplicates_skipped);

    // seq 3: skips ahead — a recorded gap, container discarded whole.
    var seq3 = [_]api.Update{userStatusUpdate(9)};
    const third = api.Updates{ .updates_ = .{
        .updates = &seq3,
        .users = &.{},
        .chats = &.{},
        .date = 105,
        .seq = 3,
    } };
    out = e.handle(&third);
    try std.testing.expectEqual(td.updates.GapKind.seq, out.gap.?);
    try std.testing.expectEqual(@as(usize, 0), out.delivered);
    try std.testing.expect(e.needs_difference);
    // The stale container did not move date or seq.
    try std.testing.expectEqual(@as(i32, 1), e.state.seq);
    try std.testing.expectEqual(@as(i32, 100), e.state.date);
}

test "pts updates inside a container: apply, duplicate, mid-container gap" {
    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();

    // From pristine (pts=0): delete at pts 3/3 applies exactly.
    var batch = [_]api.Update{ deleteMessagesUpdate(3, 3) };
    const c1 = api.Updates{ .updates_ = .{
        .updates = &batch,
        .users = &.{},
        .chats = &.{},
        .date = 10,
        .seq = 1,
    } };
    const out1 = e.handle(&c1);
    try std.testing.expectEqual(@as(usize, 1), out1.delivered);
    try std.testing.expectEqual(@as(i32, 3), e.state.pts);

    // Same pts again: duplicate inside a live container.
    const c2 = api.Updates{ .updates_ = .{
        .updates = &batch,
        .users = &.{},
        .chats = &.{},
        .date = 11,
        .seq = 2,
    } };
    const out2 = e.handle(&c2);
    try std.testing.expectEqual(@as(usize, 0), out2.delivered);
    try std.testing.expectEqual(@as(i32, 2), e.state.seq);

    // pts 8 (needs 6): a hole — gap recorded, but the container's date
    // and seq still advance (the heal will refill the hole).
    var ahead = [_]api.Update{deleteMessagesUpdate(8, 2)};
    const c3 = api.Updates{ .updates_ = .{
        .updates = &ahead,
        .users = &.{},
        .chats = &.{},
        .date = 12,
        .seq = 3,
    } };
    const out3 = e.handle(&c3);
    try std.testing.expectEqual(td.updates.GapKind.pts, out3.gap.?);
    try std.testing.expectEqual(@as(usize, 0), out3.delivered);
    try std.testing.expectEqual(@as(i32, 3), e.state.seq);
    try std.testing.expectEqual(@as(i32, 12), e.state.date);
    try std.testing.expect(e.needs_difference);
}

test "updatesCombined overlap delivers only the new parts" {
    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();
    e.state = .{ .pts = 10, .date = 50, .seq = 6 };

    // Batch covers seq 5..8: seq 5–6 are already applied, the rest new.
    var mixed = [_]api.Update{
        deleteMessagesUpdate(9, 1), // pts 9 <= 10: skip
        deleteMessagesUpdate(12, 2), // 12-2 == 10: applies
        userStatusUpdate(3), // unsequenced: always delivered
    };
    const c = api.Updates{ .updatesCombined = .{
        .updates = &mixed,
        .users = &.{},
        .chats = &.{},
        .date = 300,
        .seq_start = 5,
        .seq = 8,
    } };
    const out = e.handle(&c);
    try std.testing.expectEqual(@as(usize, 2), out.delivered);
    try expectTags(&.{ "updateDeleteMessages", "updateUserStatus" }, &rec);
    try std.testing.expectEqual(@as(i32, 12), e.state.pts);
    try std.testing.expectEqual(@as(i32, 8), e.state.seq);
    try std.testing.expectEqual(@as(i32, 300), e.state.date);
    try std.testing.expect(!e.needs_difference);
}

test "qts updates: apply, duplicate, gap" {
    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();
    e.state = .{ .qts = 4, .date = 10 };

    var enc = [_]api.Update{.{ .updateNewEncryptedMessage = .{
        .message = undefined, // classification and delivery read only the tag
        .qts = 5,
    } }};
    const c = api.Updates{ .updates_ = .{
        .updates = &enc,
        .users = &.{},
        .chats = &.{},
        .date = 20,
        .seq = 0,
    } };
    const out = e.handle(&c);
    try std.testing.expectEqual(@as(usize, 1), out.delivered);
    try std.testing.expectEqual(@as(i32, 5), e.state.qts);

    // qts 5 again, alone via updateShort: duplicate, undelivered.
    const again = api.Updates{ .updateShort = .{
        .update = enc[0],
        .date = 21,
    } };
    const out2 = e.handle(&again);
    try std.testing.expect(out2.duplicate);
    try std.testing.expectEqual(@as(usize, 0), out2.delivered);

    // qts 7 (needs 6): gap.
    var ahead = [_]api.Update{.{ .updateNewEncryptedMessage = .{
        .message = undefined,
        .qts = 7,
    } }};
    const c2 = api.Updates{ .updates_ = .{
        .updates = &ahead,
        .users = &.{},
        .chats = &.{},
        .date = 22,
        .seq = 0,
    } };
    const out3 = e.handle(&c2);
    try std.testing.expectEqual(td.updates.GapKind.qts, out3.gap.?);
    try std.testing.expect(e.needs_difference);
}

// --------------------------------------------- engine: short messages

test "updateShortMessage: apply, duplicate, gap" {
    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();
    e.state = .{ .pts = 10 };

    var msg = api.updateShortMessage{
        .id = 77,
        .user_id = 42,
        .message = "hi",
        .pts = 11,
        .pts_count = 1,
        .date = 500,
    };
    const u = api.Updates{ .updateShortMessage = msg };
    const out = e.handle(&u);
    try std.testing.expectEqual(@as(usize, 1), out.delivered);
    try expectTags(&.{"short_message"}, &rec);
    try std.testing.expectEqual(@as(i32, 11), e.state.pts);
    try std.testing.expectEqual(@as(i32, 500), e.state.date);

    // Same pts: duplicate.
    const upd2 = api.Updates{ .updateShortMessage = msg };
    const out2 = e.handle(&upd2);
    try std.testing.expect(out2.duplicate);

    // Beyond next: pts gap.
    msg.pts = 13;
    const upd3 = api.Updates{ .updateShortMessage = msg };
    const out3 = e.handle(&upd3);
    try std.testing.expectEqual(td.updates.GapKind.pts, out3.gap.?);
    try std.testing.expect(e.needs_difference);
}

test "updateShortChatMessage and updateShortSentMessage apply their pts" {
    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();

    const chat = api.Updates{ .updateShortChatMessage = .{
        .id = 1,
        .from_id = 5,
        .chat_id = 9,
        .message = "yo",
        .pts = 3,
        .pts_count = 1,
        .date = 60,
    } };
    _ = e.handle(&chat);
    try std.testing.expectEqual(@as(i32, 3), e.state.pts);

    const sent = api.Updates{ .updateShortSentMessage = .{
        .id = 2,
        .pts = 4,
        .pts_count = 1,
        .date = 61,
    } };
    const out = e.handle(&sent);
    try std.testing.expectEqual(@as(usize, 1), out.delivered);
    try expectTags(&.{ "short_chat_message", "short_sent_message" }, &rec);
    try std.testing.expectEqual(@as(i32, 4), e.state.pts);
}

test "updateShort delivers the wrapped update and merges date" {
    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();
    e.state = .{ .date = 100 };

    const wrapped = api.Updates{ .updateShort = .{
        .update = userStatusUpdate(11),
        .date = 90, // backwards: state keeps 100
    } };
    const out = e.handle(&wrapped);
    try std.testing.expectEqual(@as(usize, 1), out.delivered);
    try expectTags(&.{"updateUserStatus"}, &rec);
    try std.testing.expectEqual(@as(i32, 100), e.state.date);

    const forward = api.Updates{ .updateShort = .{
        .update = userStatusUpdate(12),
        .date = 140,
    } };
    _ = e.handle(&forward);
    try std.testing.expectEqual(@as(i32, 140), e.state.date);
}

// ---------------------------------------------- engine: reconciliation

test "reconcile heals a gap through scripted slices" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();
    e.state = .{ .pts = 100, .qts = 20, .date = 1000, .seq = 41 };

    // Trigger a too_long gap; the heal below runs the difference loop.
    const too_long = api.Updates{ .updatesTooLong = .{} };
    _ = e.handle(&too_long);
    try std.testing.expect(e.needs_difference);

    // Script: one intermediate slice (carrying a recovered message),
    // then the final difference.
    var msg1 = [_]api.Message{.{ .messageEmpty = .{ .id = 9 } }};
    var other1 = [_]api.Update{.{ .updateMessageID = .{ .id = 500, .random_id = 1 } }};
    var other2 = [_]api.Update{userStatusUpdate(1)};
    const slice1_bytes = try serializeAlloc(arena, api.updates.Difference{ .differenceSlice = .{
        .new_messages = &msg1,
        .new_encrypted_messages = &.{},
        .other_updates = &other1,
        .chats = &.{},
        .users = &.{},
        .intermediate_state = .{ .state = .{
            .pts = 110,
            .qts = 20,
            .date = 1001,
            .seq = 41,
            .unread_count = 2,
        } },
    } });
    const final_bytes = try serializeAlloc(arena, api.updates.Difference{ .difference = .{
        .new_messages = &.{},
        .new_encrypted_messages = &.{},
        .other_updates = &other2,
        .chats = &.{},
        .users = &.{},
        .state = .{ .state = .{
            .pts = 115,
            .qts = 22,
            .date = 1005,
            .seq = 42,
            .unread_count = 0,
        } },
    } });
    var script = [_][]const u8{ slice1_bytes, final_bytes };
    var ff = FakeFetcher{ .script = &script };
    e.fetcher = ff.fetcher();

    // The fetcher performs no IO; io is never touched on this path.
    try e.reconcile(undefined);

    // The recovered message is delivered first, then the slice's
    // auxiliary update, then the final difference's update.
    try expectTags(&.{ "new_message", "updateMessageID", "updateUserStatus" }, &rec);
    try std.testing.expectEqual(@as(i32, 115), e.state.pts);
    try std.testing.expectEqual(@as(i32, 22), e.state.qts);
    try std.testing.expectEqual(@as(i32, 42), e.state.seq);
    try std.testing.expectEqual(@as(i32, 1005), e.state.date);
    try std.testing.expect(!e.needs_difference);
    // The second request continued from the intermediate state.
    try std.testing.expectEqual(@as(usize, 2), ff.calls);
    try std.testing.expectEqual(@as(i32, 110), ff.last_req.?.pts);
    try std.testing.expectEqual(@as(usize, 2), e.stats.difference_rounds);
    try std.testing.expectEqual(@as(usize, 1), e.stats.gaps_healed);
}

test "reconcile on a pristine state seeds from updates.getState" {
    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();

    // Never initialized: any ahead-of-zero container is a gap...
    var far = [_]api.Update{userStatusUpdate(1)};
    const c = api.Updates{ .updates_ = .{
        .updates = &far,
        .users = &.{},
        .chats = &.{},
        .date = 900,
        .seq = 9,
    } };
    const out = e.handle(&c);
    try std.testing.expectEqual(td.updates.GapKind.seq, out.gap.?);

    var ff = FakeFetcher{};
    ff.state_script = &.{.{
        .pts = 500,
        .qts = 50,
        .date = 2000,
        .seq = 99,
        .unread_count = 3,
    }};
    e.fetcher = ff.fetcher();

    try e.reconcile(undefined);
    try std.testing.expectEqual(@as(i32, 500), e.state.pts);
    try std.testing.expectEqual(@as(i32, 99), e.state.seq);
    try std.testing.expectEqual(@as(i32, 3), e.state.unread_count);
    try std.testing.expectEqual(@as(usize, 0), rec.tags.items.len);
    try std.testing.expectEqual(@as(usize, 1), e.stats.resyncs);
    try std.testing.expect(!e.needs_difference);

    // ...and the adopted state now judges the old container stale.
    const out2 = e.handle(&c);
    try std.testing.expect(out2.duplicate);
}

test "differenceTooLong resets pts and reports the resync" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var e = Engine.init(std.testing.allocator);
    e.state = .{ .pts = 5, .date = 10 };
    e.needs_difference = true;

    const too_long_bytes = try serializeAlloc(arena, api.updates.Difference{ .differenceTooLong = .{
        .pts = 777,
    } });
    var script = [_][]const u8{too_long_bytes};
    var ff = FakeFetcher{ .script = &script };
    e.fetcher = ff.fetcher();

    try e.reconcile(undefined);
    try std.testing.expectEqual(@as(i32, 777), e.state.pts);
    try std.testing.expectEqual(@as(usize, 1), e.stats.resyncs);
    try std.testing.expect(!e.needs_difference);
}

test "slice loop past the limit fails without looping forever" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var e = Engine.init(std.testing.allocator);
    e.state = .{ .pts = 1, .date = 2 };
    e.opts.max_difference_slices = 3;
    e.needs_difference = true;

    var other = [_]api.Update{userStatusUpdate(1)};
    const endless = try serializeAlloc(arena, api.updates.Difference{ .differenceSlice = .{
        .new_messages = &.{},
        .new_encrypted_messages = &.{},
        .other_updates = &other,
        .chats = &.{},
        .users = &.{},
        .intermediate_state = .{ .state = .{
            .pts = 2,
            .qts = 0,
            .date = 3,
            .seq = 0,
            .unread_count = 0,
        } },
    } });
    var script = [_][]const u8{endless};
    var ff = FakeFetcher{ .script = &script };
    e.fetcher = ff.fetcher();

    try std.testing.expectError(error.SliceLimit, e.reconcile(undefined));
    try std.testing.expectEqual(@as(usize, 3), ff.calls);
    // The flag stays set: a later reconcile may get further.
    try std.testing.expect(e.needs_difference);
}

test "fetcher failure is mapped to FetchFailed with the cause retained" {
    var e = Engine.init(std.testing.allocator);
    e.state = .{ .pts = 1, .date = 2 };
    e.needs_difference = true;

    var ff = FakeFetcher{ .fail_with = error.ConnectionRefused };
    e.fetcher = ff.fetcher();

    try std.testing.expectError(error.FetchFailed, e.reconcile(undefined));
    try std.testing.expectEqual(anyerror.ConnectionRefused, e.last_fetch_error.?);
    try std.testing.expect(e.needs_difference);
}

// ----------------------------------------------------- hook wiring

test "hook decodes raw bodies and feeds the engine" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();
    // A container is only applied when its seq continues the local one;
    // prime the state so seq 4 is the expected next value.
    e.state = .{ .seq = 3, .date = 76 };

    var updates = [_]api.Update{userStatusUpdate(3)};
    const body = try serializeAlloc(arena, api.Updates{ .updates_ = .{
        .updates = &updates,
        .users = &.{},
        .chats = &.{},
        .date = 77,
        .seq = 4,
    } });

    const h = td.updates.hook(&e);
    h.onUpdates(h.ctx, undefined, body);

    try expectTags(&.{"updateUserStatus"}, &rec);
    try std.testing.expectEqual(@as(i32, 4), e.state.seq);
    try std.testing.expectEqual(@as(usize, 0), e.stats.undecodable_bodies);

    // Garbage counts as undecodable and delivers nothing.
    h.onUpdates(h.ctx, undefined, &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqual(@as(usize, 1), e.stats.undecodable_bodies);
    try std.testing.expectEqual(@as(usize, 1), rec.tags.items.len);
}

// ------------------------------------------- loopback: the real stack

// Shared authorization key (varied bytes so the per-direction auth_key
// windows genuinely differ) — same construction as tests/connman.zig.
const auth_key = blk: {
    var k: [256]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 97 +% 5);
    break :blk k;
};

fn writeAllRaw(io: std.Io, stream: *net.Stream, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, &.{bytes[sent..]}, 1);
        sent += n;
    }
}

fn readExactRaw(io: std.Io, stream: *net.Stream, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        var iovec = [1][]u8{buf[got..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &iovec);
        if (n == 0) return error.EndOfStream;
        got += n;
    }
}

fn serverReadFrame(io: std.Io, stream: *net.Stream, arena: std.mem.Allocator) ![]u8 {
    var head: [8]u8 = undefined;
    try readExactRaw(io, stream, &head);
    const parsed = td.transport.tcp_full.Codec.parseHeader(&head);
    if (parsed.length < td.transport.tcp_full.frame_overhead) return error.BadFrame;
    const payload = try arena.alloc(u8, parsed.length - td.transport.tcp_full.frame_overhead);
    try readExactRaw(io, stream, payload);
    var trailer: [4]u8 = undefined;
    try readExactRaw(io, stream, &trailer);
    if (td.transport.tcp_full.Codec.checksum(&head, payload) != std.mem.readInt(u32, &trailer, .little))
        return error.BadFrame;
    return payload;
}

/// Sends header+payload+trailer as one vectored write: three separate
/// small writes interact with Nagle + delayed ACK into ~40 ms stalls on
/// a request/response exchange.
fn sendFrameRaw(io: std.Io, stream: *net.Stream, h: []const u8, payload: []const u8, trailer: []const u8) !void {
    const parts = [3][]const u8{ h, payload, trailer };
    const total = h.len + payload.len + trailer.len;
    var sent: usize = 0;
    while (sent < total) {
        var iovecs: [3][]const u8 = undefined;
        var n_iov: usize = 0;
        var idx: usize = 0;
        var off: usize = sent;
        while (idx < parts.len) : (idx += 1) {
            if (off >= parts[idx].len) {
                off -= parts[idx].len;
                continue;
            }
            iovecs[n_iov] = parts[idx][off..];
            n_iov += 1;
            off = 0;
        }
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, &.{}, iovecs[0..n_iov], 1);
        if (n == 0) return error.IoFailed;
        sent += n;
    }
}

fn serverSendFrame(io: std.Io, stream: *net.Stream, payload: []const u8, out_seq: *u32) !void {
    const h = td.transport.tcp_full.Codec.header(payload.len, out_seq.*);
    const crc = td.transport.tcp_full.Codec.checksum(&h, payload);
    var trailer: [4]u8 = undefined;
    std.mem.writeInt(u32, &trailer, crc, .little);
    try sendFrameRaw(io, stream, &h, payload, &trailer);
    out_seq.* += 1;
}

fn nowBase(io: std.Io) i64 {
    const s = @divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s);
    return @as(i64, @intCast(s)) << 32;
}

/// Minimal MTProto peer able to push update frames to the client.
const TestServer = struct {
    session_id: i64,
    next_low: u32 = 1,
    content: u32 = 0,
    out_seq: u32 = 0,

    fn push(self: *TestServer, io: std.Io, stream: *net.Stream, arena: std.mem.Allocator, body: []const u8) !void {
        var prng = std.Random.DefaultPrng.init(0xabc);
        const buf = try arena.alloc(u8, message.frameLength(body.len));
        const id = nowBase(io) | self.next_low;
        self.next_low += 4;
        const seq: i32 = @intCast(2 * self.content + 1);
        self.content += 1;
        try message.writeEncrypted(&auth_key, .server_to_client, .{
            .salt = 0x51a1,
            .session_id = self.session_id,
            .msg_id = id,
            .seq_no = seq,
            .body = body,
        }, prng.random(), buf);
        try serverSendFrame(io, stream, buf, &self.out_seq);
    }
};

test "pushed updates flow through the real stack to the callback" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Listener + engine + rpc client, hook attached.
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var e = Engine.init(std.testing.allocator);
    var rec = Recorder{};
    defer rec.deinit();
    e.handler = rec.handler();
    // No fetcher: pushed gaps must be recordable without healing.

    var tcp = td.transport.TcpFull.init(
        .{ .host = "127.0.0.1", .port = server.socket.address.getPort() },
        .{ .read_timeout = std.Io.Duration.fromMilliseconds(40) },
    );
    try tcp.connect(io);
    errdefer tcp.close(io);
    var prng = std.Random.DefaultPrng.init(0x0dd11);
    var client = try td.rpc.Client.init(
        std.testing.allocator,
        tcp.transport(),
        &auth_key,
        0x51a1,
        prng.random(),
        .{ .response_timeout = std.Io.Duration.fromMilliseconds(250) },
    );
    defer client.deinit();

    var ts = TestServer{ .session_id = client.session.session_id };
    client.updates_handler = td.updates.hook(&e);

    var srv = try server.accept(io);
    defer srv.close(io);

    // Push one sequenced container with one unsequenced update.
    var updates = [_]api.Update{userStatusUpdate(21)};
    const body = try serializeAlloc(arena, api.Updates{ .updates_ = .{
        .updates = &updates,
        .users = &.{},
        .chats = &.{},
        .date = 4242,
        .seq = 1,
    } });
    try ts.push(io, &srv, arena, body);

    // Pump a short budget: the frame is dispatched, then the budget (or
    // the idle read timeout) ends the pump with error.TimedOut.
    try std.testing.expectError(
        error.TimedOut,
        client.pump(io, std.Io.Duration.fromMilliseconds(30)),
    );

    try expectTags(&.{"updateUserStatus"}, &rec);
    try std.testing.expectEqual(@as(i32, 1), e.state.seq);
    try std.testing.expectEqual(@as(i32, 4242), e.state.date);
    try std.testing.expectEqual(@as(usize, 1), client.updates_seen);
    try std.testing.expect(!e.needs_difference);

    // Push updatesTooLong: the hook records a gap for reconcile.
    try ts.push(io, &srv, arena, try serializeAlloc(arena, api.Updates{ .updatesTooLong = .{} }));
    try std.testing.expectError(
        error.TimedOut,
        client.pump(io, std.Io.Duration.fromMilliseconds(30)),
    );
    try std.testing.expectEqual(@as(usize, 2), client.updates_seen);
    try std.testing.expect(e.needs_difference);
    // Without a fetcher the flag survives reconcile untouched.
    try e.reconcile(io);
    try std.testing.expect(e.needs_difference);

    tcp.close(io);
}
