//! Module root so tests can `@import("schema")` the vendored official
//! API schema — `@embedFile` cannot escape a module's root directory,
//! and the official-schema test module is rooted at `tests/`.

pub const api_tl = @embedFile("api.tl");
pub const mtproto_tl = @embedFile("mtproto.tl");
