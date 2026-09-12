//! Consistency check: the constructor ids pinned in the hand-written
//! MTProto modules (`mtproto.schema`, `mtproto.message`, `mtproto.pfs`)
//! must match the vendored official schema (`schema/mtproto.tl`), and the
//! generated module (`mtproto.schema_gen`) must serialize wire-identically
//! to the hand-written types. The handshake code is KAT-verified against
//! the official worked examples, so any divergence here — a schema
//! refresh, an edited constant, a generator regression — is a bug.

const std = @import("std");
const td = @import("td");
const schema_file = @import("schema");

const mp = td.mtproto;

/// Pinned ids whose declarations the parser sees in schema/mtproto.tl.
const parsed_pins = [_]struct { name: []const u8, id: u32 }{
    // Handshake key creation (mtproto/schema.zig).
    .{ .name = "req_pq", .id = mp.schema.req_pq_id },
    .{ .name = "req_pq_multi", .id = mp.schema.req_pq_multi_id },
    .{ .name = "resPQ", .id = mp.schema.resPQ_id },
    .{ .name = "p_q_inner_data_dc", .id = mp.schema.p_q_inner_data_dc_id },
    .{ .name = "p_q_inner_data_temp_dc", .id = mp.schema.p_q_inner_data_temp_dc_id },
    .{ .name = "req_DH_params", .id = mp.schema.req_DH_params_id },
    .{ .name = "server_DH_params_fail", .id = mp.schema.server_DH_params_fail_id },
    .{ .name = "server_DH_params_ok", .id = mp.schema.server_DH_params_ok_id },
    .{ .name = "server_DH_inner_data", .id = mp.schema.server_DH_inner_data_id },
    .{ .name = "client_DH_inner_data", .id = mp.schema.client_DH_inner_data_id },
    .{ .name = "set_client_DH_params", .id = mp.schema.set_client_DH_params_id },
    .{ .name = "dh_gen_ok", .id = mp.schema.dh_gen_ok_id },
    .{ .name = "dh_gen_retry", .id = mp.schema.dh_gen_retry_id },
    .{ .name = "dh_gen_fail", .id = mp.schema.dh_gen_fail_id },
    // Perfect forward secrecy (mtproto/pfs.zig).
    .{ .name = "bind_auth_key_inner", .id = mp.pfs.bind_auth_key_inner_id },
    // Service messages (mtproto/message.zig); the "parsed manually"
    // framing types are checked separately below.
    .{ .name = "msgs_ack", .id = mp.message.msgs_ack_id },
    .{ .name = "bad_msg_notification", .id = mp.message.bad_msg_notification_id },
    .{ .name = "bad_server_salt", .id = mp.message.bad_server_salt_id },
    .{ .name = "new_session_created", .id = mp.message.new_session_created_id },
    .{ .name = "pong", .id = mp.message.pong_id },
    .{ .name = "ping", .id = mp.message.ping_id },
    .{ .name = "ping_delay_disconnect", .id = mp.message.ping_delay_disconnect_id },
    .{ .name = "future_salt", .id = mp.message.future_salt_id },
    .{ .name = "future_salts", .id = mp.message.future_salts_id },
    .{ .name = "get_future_salts", .id = mp.message.get_future_salts_id },
    .{ .name = "rpc_error", .id = mp.message.rpc_error_id },
};

/// Framing types commented out in the schema ("parsed manually"
/// upstream) — their ids only exist in the raw schema text.
const commented_pins = [_]struct { name: []const u8, id: u32 }{
    .{ .name = "msg_container", .id = mp.message.msg_container_id },
    .{ .name = "rpc_result", .id = mp.message.rpc_result_id },
    .{ .name = "gzip_packed", .id = mp.message.gzip_packed_id },
};

test "pinned MTProto ids match the vendored schema" {
    var parsed = try td.tl.parseSchema(std.testing.allocator, schema_file.mtproto_tl);
    defer parsed.deinit();

    for (parsed_pins) |pin| {
        const decl = parsed.findByName(pin.name) orelse {
            std.debug.print("schema/mtproto.tl is missing pinned declaration `{s}`\n", .{pin.name});
            return error.TestUnexpectedResult;
        };
        if (decl.id != pin.id) {
            std.debug.print(
                "pinned `{s}` id is 0x{x:0>8} but schema/mtproto.tl says 0x{x:0>8}\n",
                .{ pin.name, pin.id, decl.id },
            );
            return error.TestUnexpectedResult;
        }
    }

    for (commented_pins) |pin| {
        try expectCommentedId(schema_file.mtproto_tl, pin.name, pin.id);
    }
}

/// Finds `name#hex` in the raw schema text and compares the id.
fn expectCommentedId(text: []const u8, name: []const u8, want: u32) !void {
    const marker = try std.fmt.allocPrint(std.testing.allocator, "{s}#", .{name});
    defer std.testing.allocator.free(marker);
    const idx = std.mem.indexOf(u8, text, marker) orelse {
        std.debug.print("schema text has no declaration `{s}#...`\n", .{name});
        return error.TestUnexpectedResult;
    };
    const hex_start = idx + marker.len;
    var hex_len: usize = 0;
    while (hex_len < 8 and std.ascii.isHex(text[hex_start + hex_len])) : (hex_len += 1) {}
    const got = try std.fmt.parseInt(u32, text[hex_start .. hex_start + hex_len], 16);
    try std.testing.expectEqual(want, got);
}

test "generated module matches hand-written serialization" {
    const a = std.testing.allocator;
    var nonce: [16]u8 = undefined;
    for (&nonce, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);

    // Function: generated req_pq vs hand-written ReqPq.
    {
        var w_gen = td.tl.Writer.init(a);
        defer w_gen.deinit();
        const gen_req: mp.schema_gen.req_pq = .{ .nonce = nonce };
        try gen_req.serialize(&w_gen);

        var w_hand = td.tl.Writer.init(a);
        defer w_hand.deinit();
        const hand_req: mp.schema.ReqPq = .{ .nonce = nonce };
        try hand_req.serialize(&w_hand);

        try std.testing.expectEqualSlices(u8, w_hand.items(), w_gen.items());
    }

    // Type with a bare-vector field: the generated resPQ serializes to
    // bytes the hand-written deserialize accepts, with identical fields
    // (vectors are arena-allocated, like in the generated-API tests).
    {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();

        var w = td.tl.Writer.init(a);
        defer w.deinit();
        try w.writeUInt(mp.schema.resPQ_id);
        const gen: mp.schema_gen.resPQ = .{
            .nonce = nonce,
            .server_nonce = nonce,
            .pq = "pq-value",
            .server_public_key_fingerprints = @constCast(&[_]i64{ 0x1111_2222_3333_4444, 5 }),
        };
        try gen.serialize(&w);

        var r = td.tl.Reader.init(w.items());
        const got = try mp.schema.ResPQ.deserialize(arena.allocator(), &r);

        try std.testing.expectEqual(gen.nonce, got.nonce);
        try std.testing.expectEqualStrings(gen.pq, got.pq);
        try std.testing.expectEqual(gen.server_public_key_fingerprints.len, got.server_public_key_fingerprints.len);
        try std.testing.expectEqual(gen.server_public_key_fingerprints[0], got.server_public_key_fingerprints[0]);
    }
}
