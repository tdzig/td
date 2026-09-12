# Raw interfaces

td is usable as a low-level MTProto/TL framework without its client
conveniences. Every layer is independently importable and tested; the
high-level pieces are thin compositions over them.

## Layering

    TL  →  generated API  →  MTProto  →  transport  →  client

No layer reaches around another; there are no circular imports.

## Raw TL (`td.tl`)

```zig
// Binary writer/reader (TLserializer format):
var w = td.tl.Writer.init(allocator);
defer w.deinit();
try w.writeInt(123);
try w.writeString("hello");
try w.writeConstructorId(0x12345678);

var r = td.tl.Reader.init(w.items());
const n = try r.readInt();       // bounds-checked, error-union
const s = try r.readString();    // borrows from the input: zero-copy
```

All reads are borrowing — vectors allocate only their slice storage,
and a vector count larger than the remaining input is refused before
allocating (the same OOM-guard `rpc.decode` applies).

```zig
// Schema parser → AST → code generator:
var schema = try td.tl.parseSchema(allocator, source_text);
defer schema.deinit();
// AST strings borrow from source_text; keep the buffer alive.

const zig_source = try td.tl.codegen.generate(allocator, &schema, .{});
```

The generator is deterministic: the same schema always produces the
same bytes (checked by golden tests), which is what makes the committed
`src/api` tree auditable in review — a schema change shows up as a
readable diff, never a reshuffle. Regenerate with `just api`.

## Raw MTProto (`td.mtproto`)

`message` is the stateless half — envelopes, containers, acks, the
service-message constructors — all composable with caller-owned
buffers:

```zig
// Build an encrypted frame into your own buffer:
const frame = try alloc(u8, message.frameLength(body.len));
const sent = try session.encode(now_seconds, content_related, body, frame);

// Parse and validate (in place; the body borrows from the buffer):
const dec = try message.readEncrypted(&auth_key, .server_to_client, expected_session_id, frame);
```

`Session` owns the stateful half: msg_id generation and monotonicity,
the receive window (30 s future / 300 s past), strict seq_no counters,
container id ordering, pending-ack queueing. Failed validation commits
nothing — a rejected frame cannot desynchronize later expectations.

Crypto (`td.crypto`) is std.crypto only: SHA-1/SHA-256, AES-256-IGE
(OpenSSL KAT-validated), msg_key and key/IV derivation. Nothing is
improvised.

## Transport

A transport moves complete payload frames; framing is entirely its
business, encryption is never its business. Implement the five-function
vtable and the whole stack runs on it:

```zig
pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        connect:    *const fn (ctx, io) Error!void,
        close:      *const fn (ctx, io) void,
        write:      *const fn (ctx, io, payload: []const u8) Error!void,  // one frame
        read:       *const fn (ctx, io, allocator) Error![]u8,            // one frame
        isConnected: *const fn (ctx) bool,
    };
};
```

Shipped implementations: `td.transport.TcpFull` (the reference framing:
length/seq/crc32) and `td.multi.Link` (in-memory, with a real embedded
peer). A `connman.Options.transport_provider` hands transports to
managers from your own pool. Contract details that implementations must
honor — `AlreadyConnected`, idle `TimedOut` before any frame byte,
mid-frame failures closing the connection — are documented in
`src/transport/mod.zig`.

## Testing your layer

`tests/compliance.zig` shows the harness patterns: hand-crafted frames
through `Session.receive` asserting exact spec errors, and hostile RPC
payloads through a `Client` over a loopback link. `tests/fuzz.zig`
registers the same surfaces as coverage-guided fuzz targets
(`just fuzz`).
