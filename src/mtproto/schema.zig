//! Hand-serialized TL types for the MTProto authorization-key handshake.
//!
//! These constructors live in the *core* MTProto schema
//! (schema/mtproto.tl, from Telegram Desktop's `scheme/mtproto.tl`)
//! — not the API schema — so they are encoded with the low-level
//! `tl.Writer`/`tl.Reader` primitives here. Constructor ids are exact
//! unsigned 32-bit values from that schema.

const std = @import("std");
const tl = @import("../tl/mod.zig");
const Writer = tl.Writer;
const Reader = tl.Reader;
const TlError = @import("../errors.zig").TlError;

pub const req_pq_id: u32 = 0x60469778;
pub const req_pq_multi_id: u32 = 0xbe7e8ef1;
pub const resPQ_id: u32 = 0x05162463;
pub const p_q_inner_data_dc_id: u32 = 0xa9f55f95;
pub const p_q_inner_data_temp_dc_id: u32 = 0x56fddf88;
pub const req_DH_params_id: u32 = 0xd712e4be;
pub const server_DH_params_fail_id: u32 = 0x79cb045d;
pub const server_DH_params_ok_id: u32 = 0xd0e8075c;
pub const server_DH_inner_data_id: u32 = 0xb5890dba;
pub const client_DH_inner_data_id: u32 = 0x6643b654;
pub const set_client_DH_params_id: u32 = 0xf5045f1f;
pub const dh_gen_ok_id: u32 = 0x3bcbf734;
pub const dh_gen_retry_id: u32 = 0x46dc1fb9;
pub const dh_gen_fail_id: u32 = 0xa69dae02;

pub const ReqPq = struct {
    nonce: [16]u8,
    multi: bool = false,

    pub fn serialize(self: *const ReqPq, w: *Writer) TlError!void {
        try w.writeConstructorId(if (self.multi) req_pq_multi_id else req_pq_id);
        try w.writeInt128(self.nonce);
    }
};

pub const ResPQ = struct {
    nonce: [16]u8,
    server_nonce: [16]u8,
    /// pq as a big-endian minimal byte string (borrowed).
    pq: []const u8,
    /// Allocated with the caller's allocator.
    server_public_key_fingerprints: []i64,

    pub fn deserialize(allocator: std.mem.Allocator, r: *Reader) TlError!ResPQ {
        if ((try r.readConstructorId()) != resPQ_id) return error.InvalidValue;
        var self: ResPQ = undefined;
        self.nonce = try r.readInt128();
        self.server_nonce = try r.readInt128();
        self.pq = try r.readString();
        self.server_public_key_fingerprints = try r.readVectorOfLong(allocator);
        return self;
    }
};

/// p_q_inner_data_dc (the variant used when connecting to a specific DC).
pub const PQInnerDataDc = struct {
    pq: []const u8,
    p: []const u8,
    q: []const u8,
    nonce: [16]u8,
    server_nonce: [16]u8,
    new_nonce: [32]u8,
    dc: i32,

    pub fn serialize(self: *const PQInnerDataDc, w: *Writer) TlError!void {
        try w.writeConstructorId(p_q_inner_data_dc_id);
        try w.writeBytes(self.pq);
        try w.writeBytes(self.p);
        try w.writeBytes(self.q);
        try w.writeInt128(self.nonce);
        try w.writeInt128(self.server_nonce);
        try w.writeInt256(self.new_nonce);
        try w.writeInt(self.dc);
    }
};

/// p_q_inner_data_temp_dc — the PFS variant: yields a temporary key the
/// server invalidates at `server_time + expires_in` (see
/// https://core.telegram.org/api/pfs).
pub const PQInnerDataTempDc = struct {
    pq: []const u8,
    p: []const u8,
    q: []const u8,
    nonce: [16]u8,
    server_nonce: [16]u8,
    new_nonce: [32]u8,
    dc: i32,
    expires_in: i32,

    pub fn serialize(self: *const PQInnerDataTempDc, w: *Writer) TlError!void {
        try w.writeConstructorId(p_q_inner_data_temp_dc_id);
        try w.writeBytes(self.pq);
        try w.writeBytes(self.p);
        try w.writeBytes(self.q);
        try w.writeInt128(self.nonce);
        try w.writeInt128(self.server_nonce);
        try w.writeInt256(self.new_nonce);
        try w.writeInt(self.dc);
        try w.writeInt(self.expires_in);
    }
};

pub const ReqDhParams = struct {
    nonce: [16]u8,
    server_nonce: [16]u8,
    p: []const u8,
    q: []const u8,
    public_key_fingerprint: i64,
    encrypted_data: []const u8,

    pub fn serialize(self: *const ReqDhParams, w: *Writer) TlError!void {
        try w.writeConstructorId(req_DH_params_id);
        try w.writeInt128(self.nonce);
        try w.writeInt128(self.server_nonce);
        try w.writeBytes(self.p);
        try w.writeBytes(self.q);
        try w.writeLong(self.public_key_fingerprint);
        try w.writeBytes(self.encrypted_data);
    }
};

pub const ServerDhFail = struct {
    nonce: [16]u8,
    server_nonce: [16]u8,
    new_nonce_hash: [16]u8,
};

pub const ServerDhOk = struct {
    nonce: [16]u8,
    server_nonce: [16]u8,
    encrypted_answer: []const u8, // borrowed
};

pub const ServerDhParams = union(enum) {
    fail: ServerDhFail,
    ok: ServerDhOk,

    pub fn deserialize(r: *Reader) TlError!ServerDhParams {
        const id = try r.readConstructorId();
        switch (id) {
            server_DH_params_fail_id => {
                var self: ServerDhFail = undefined;
                self.nonce = try r.readInt128();
                self.server_nonce = try r.readInt128();
                self.new_nonce_hash = try r.readInt128();
                return .{ .fail = self };
            },
            server_DH_params_ok_id => {
                var self: ServerDhOk = undefined;
                self.nonce = try r.readInt128();
                self.server_nonce = try r.readInt128();
                self.encrypted_answer = try r.readString();
                return .{ .ok = self };
            },
            else => return error.InvalidValue,
        }
    }
};

pub const ServerDhInnerData = struct {
    nonce: [16]u8,
    server_nonce: [16]u8,
    g: i32,
    dh_prime: []const u8, // borrowed
    g_a: []const u8, // borrowed
    server_time: i32,

    pub fn serialize(self: *const ServerDhInnerData, w: *Writer) TlError!void {
        try w.writeConstructorId(server_DH_inner_data_id);
        try w.writeInt128(self.nonce);
        try w.writeInt128(self.server_nonce);
        try w.writeInt(self.g);
        try w.writeBytes(self.dh_prime);
        try w.writeBytes(self.g_a);
        try w.writeInt(self.server_time);
    }

    pub fn deserialize(r: *Reader) TlError!ServerDhInnerData {
        if ((try r.readConstructorId()) != server_DH_inner_data_id) return error.InvalidValue;
        var self: ServerDhInnerData = undefined;
        self.nonce = try r.readInt128();
        self.server_nonce = try r.readInt128();
        self.g = try r.readInt();
        self.dh_prime = try r.readString();
        self.g_a = try r.readString();
        self.server_time = try r.readInt();
        return self;
    }
};

pub const ClientDhInnerData = struct {
    nonce: [16]u8,
    server_nonce: [16]u8,
    retry_id: i64,
    g_b: []const u8,

    pub fn serialize(self: *const ClientDhInnerData, w: *Writer) TlError!void {
        try w.writeConstructorId(client_DH_inner_data_id);
        try w.writeInt128(self.nonce);
        try w.writeInt128(self.server_nonce);
        try w.writeLong(self.retry_id);
        try w.writeBytes(self.g_b);
    }
};

pub const SetClientDhParams = struct {
    nonce: [16]u8,
    server_nonce: [16]u8,
    encrypted_data: []const u8,

    pub fn serialize(self: *const SetClientDhParams, w: *Writer) TlError!void {
        try w.writeConstructorId(set_client_DH_params_id);
        try w.writeInt128(self.nonce);
        try w.writeInt128(self.server_nonce);
        try w.writeBytes(self.encrypted_data);
    }
};

pub const DhGenAnswer = union(enum) {
    ok: struct {
        nonce: [16]u8,
        server_nonce: [16]u8,
        new_nonce_hash1: [16]u8,
    },
    retry: struct {
        nonce: [16]u8,
        server_nonce: [16]u8,
        new_nonce_hash2: [16]u8,
    },
    fail: struct {
        nonce: [16]u8,
        server_nonce: [16]u8,
        new_nonce_hash3: [16]u8,
    },

    pub fn deserialize(r: *Reader) TlError!DhGenAnswer {
        const id = try r.readConstructorId();
        const nonce: [16]u8 = try r.readInt128();
        const server_nonce: [16]u8 = try r.readInt128();
        const hash: [16]u8 = try r.readInt128();
        switch (id) {
            dh_gen_ok_id => return .{ .ok = .{ .nonce = nonce, .server_nonce = server_nonce, .new_nonce_hash1 = hash } },
            dh_gen_retry_id => return .{ .retry = .{ .nonce = nonce, .server_nonce = server_nonce, .new_nonce_hash2 = hash } },
            dh_gen_fail_id => return .{ .fail = .{ .nonce = nonce, .server_nonce = server_nonce, .new_nonce_hash3 = hash } },
            else => return error.InvalidValue,
        }
    }
};

/// Serializes any handshake message with a `serialize(*Writer)` method into
/// a freshly allocated byte string.
pub fn serializeAlloc(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var w = Writer.init(allocator);
    errdefer w.deinit();
    try value.serialize(&w);
    return w.toOwnedSlice();
}

// ---------------------------------------------------------------- tests

test "req_pq / resPQ roundtrip" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const nonce = [_]u8{0x11} ** 16;
    const body = try serializeAlloc(arena, &ReqPq{ .nonce = nonce, .multi = true });
    try std.testing.expectEqual(req_pq_multi_id, std.mem.readInt(u32, body[0..4], .little));

    // server side
    var w = Writer.init(arena);
    try w.writeConstructorId(resPQ_id);
    try w.writeInt128(nonce);
    try w.writeInt128([_]u8{0x22} ** 16);
    try w.writeBytes(&[_]u8{ 0x0d, 0xef, 0xbe, 0xff }); // pq
    try w.writeVectorOfLong(&.{@bitCast(@as(u64, 0x85fd64de851d9dd0))});

    var r = Reader.init(w.items());
    const res = try ResPQ.deserialize(arena, &r);
    try std.testing.expectEqualSlices(u8, &nonce, &res.nonce);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0d, 0xef, 0xbe, 0xff }, res.pq);
    try std.testing.expectEqual(@as(i64, @bitCast(@as(u64, 0x85fd64de851d9dd0))), res.server_public_key_fingerprints[0]);
}

test "p_q_inner_data_dc serialization matches the official example" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var nonce: [16]u8 = undefined;
    var server_nonce: [16]u8 = undefined;
    var new_nonce: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&nonce, "51A1143FC7A3666BE4BE54D6890A02DC") catch unreachable;
    _ = std.fmt.hexToBytes(&server_nonce, "63248F6748214EAB8A2F4CC876E11974") catch unreachable;
    _ = std.fmt.hexToBytes(&new_nonce, "BF8CB5BD9C5B4FE7CF24D64D281F89311576D53C0DA65A83267E57315414C9A6") catch unreachable;

    const inner = PQInnerDataDc{
        .pq = &.{ 0x2E, 0x9C, 0xDB, 0x98, 0xC8, 0x0C, 0xDA, 0x4B },
        .p = &.{ 0x6A, 0x79, 0x42, 0x59 },
        .q = &.{ 0x70, 0x12, 0xC5, 0x43 },
        .nonce = nonce,
        .server_nonce = server_nonce,
        .new_nonce = new_nonce,
        .dc = 2,
    };
    const data = try serializeAlloc(arena, &inner);

    const expect_hex = "955FF5A9082E9CDB98C80CDA4B000000046A794259000000047012C54300000051A1143FC7A3666BE4BE54D6890A02DC63248F6748214EAB8A2F4CC876E11974BF8CB5BD9C5B4FE7CF24D64D281F89311576D53C0DA65A83267E57315414C9A602000000";
    const expect = try arena.alloc(u8, expect_hex.len / 2);
    _ = std.fmt.hexToBytes(expect, expect_hex) catch unreachable;
    try std.testing.expectEqualSlices(u8, expect, data);
}
