//! Public error model for tdzig.
//!
//! Malformed input (bad TL binary data, bad schema text) is always reported
//! through Zig error unions — never through @panic. Components that benefit
//! from extra context (e.g. the schema parser) keep a `Diagnostic` describing
//! the last failure.

/// Errors raised while reading or writing the TL binary format.
pub const TlError = error{
    /// Input ended before a complete value could be read.
    EndOfStream,
    /// A length prefix exceeds the remaining input (or the format's maximum).
    InvalidLength,
    /// A value was syntactically readable but not a valid TL value
    /// (e.g. an unknown boolean constructor id).
    InvalidValue,
    OutOfMemory,
};

/// Errors raised while parsing TL schema source text.
pub const ParseError = error{
    /// Syntax error (missing '#', ':', '=', ';', bad identifier, ...).
    InvalidSchema,
    /// Constructor id was not a valid 1..8 digit hexadecimal number.
    InvalidConstructorId,
    /// Syntactically valid TL that this milestone does not support yet
    /// (e.g. generic combinator definitions with `{X:Type}` bindings).
    UnsupportedSyntax,
    OutOfMemory,
};

/// Human-oriented context for the last parse failure.
/// All strings are static literals; nothing is allocated.
pub const Diagnostic = struct {
    /// 1-based line number, or 0 when unknown.
    line: usize = 0,
    /// 1-based column number, or 0 when unknown.
    column: usize = 0,
    /// Static description of the failure.
    message: []const u8 = "",
};
