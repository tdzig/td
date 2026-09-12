//! Per-update sequencing classification: which common-stream counter an
//! `api.Update` advances, if any.
//!
//! The `Update` union has ~165 constructors; only a handful move the
//! common `pts`/`qts` streams — the rest (typing indicators, config and
//! DC-option changes, channel-scoped updates, ...) are unsequenced and
//! always deliverable. Classification is deliberately conservative:
//! anything not positively known to move a counter is `none`. A
//! misclassified sequenced update would be re-delivered on overlap
//! (harmless duplicates) rather than dropped (lost data), which is the
//! safe failure direction.
//!
//! Channel updates (`updateChannel*`) are intentionally `none`: channels
//! sequence through their own pts and `updates.getChannelDifference`,
//! which is a later milestone on top of this engine.

const api = @import("../api/mod.zig");

/// What a single `api.Update` does to the common update state.
pub const Sequencing = union(enum) {
    /// Advances `pts` by `count` (`pts_count`; 1 where the schema has
    /// no count field).
    pts: Pts,
    /// Advances `qts` by exactly one (secret-chat updates).
    qts: i32,
    /// No common-stream counter: always deliverable.
    none,

    pub const Pts = struct { pts: i32, count: i32 };
};

/// Classifies one update. Borrows nothing; returns values only.
pub fn classify(u: *const api.Update) Sequencing {
    return switch (u.*) {
        .updateNewMessage => |v| .{ .pts = .{ .pts = v.pts, .count = v.pts_count } },
        .updateEditMessage => |v| .{ .pts = .{ .pts = v.pts, .count = v.pts_count } },
        .updateDeleteMessages => |v| .{ .pts = .{ .pts = v.pts, .count = v.pts_count } },
        .updateReadHistoryInbox => |v| .{ .pts = .{ .pts = v.pts, .count = v.pts_count } },
        .updateReadHistoryOutbox => |v| .{ .pts = .{ .pts = v.pts, .count = v.pts_count } },
        .updateReadMessagesContents => |v| .{ .pts = .{ .pts = v.pts, .count = v.pts_count } },
        .updateWebPage => |v| .{ .pts = .{ .pts = v.pts, .count = v.pts_count } },
        .updateNewEncryptedMessage => |v| .{ .qts = v.qts },
        else => .none,
    };
}

// ---------------------------------------------------------------- tests

const std = @import("std");
const testing = std.testing;

const updateDeleteMessages = api.updateDeleteMessages;
const updateNewEncryptedMessage = api.updateNewEncryptedMessage;

test "pts-bearing updates classify with their pts and count" {
    var msgs = [_]i32{ 1, 2, 3 };
    const u = api.Update{ .updateDeleteMessages = .{
        .messages = &msgs,
        .pts = 42,
        .pts_count = 3,
    } };
    const s = classify(&u);
    try testing.expect(s == .pts);
    try testing.expectEqual(@as(i32, 42), s.pts.pts);
    try testing.expectEqual(@as(i32, 3), s.pts.count);
}

test "updateWebPage carries pts in this layer (no qts)" {
    const u = api.Update{ .updateWebPage = .{
        .webpage = undefined, // never touched by classification
        .pts = 7,
        .pts_count = 1,
    } };
    const s = classify(&u);
    try testing.expect(s == .pts);
    try testing.expectEqual(@as(i32, 7), s.pts.pts);
}

test "qts-bearing update classifies as qts" {
    const u = api.Update{ .updateNewEncryptedMessage = .{
        .message = undefined, // never touched by classification
        .qts = 9,
    } };
    const s = classify(&u);
    try testing.expect(s == .qts);
    try testing.expectEqual(@as(i32, 9), s.qts);
}

test "unsequenced updates classify as none" {
    const status = api.Update{ .updateUserStatus = .{
        .user_id = 1,
        .status = .{ .userStatusEmpty = .{} },
    } };
    try testing.expect(classify(&status) == .none);

    const msg_id = api.Update{ .updateMessageID = .{ .id = 1, .random_id = 2 } };
    try testing.expect(classify(&msg_id) == .none);

    const channel = api.Update{ .updateChannelTooLong = .{ .channel_id = 1 } };
    try testing.expect(classify(&channel) == .none);
}
