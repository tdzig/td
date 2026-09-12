const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const td = b.addModule("td", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "td",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    b.installArtifact(exe);

    // td-gen: TL schema → Zig source generator. Self-hosting on purpose:
    // it imports only the tl subsystem, never the td module, so
    // `zig build gen` works even when the generated src/api/ tree is
    // missing or stale — which is how `just api` bootstraps a full
    // regeneration.
    const gen_exe = b.addExecutable(.{
        .name = "td-gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/gen_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const gen_install = b.addInstallArtifact(gen_exe, .{});
    b.getInstallStep().dependOn(&gen_install.step);
    const gen_step = b.step("gen", "Build and install td-gen only (bootstrap for `just api`)");
    gen_step.dependOn(&gen_install.step);

    // td-errgen: Telegram RPC error catalogs (TSV) → generated Zig
    // module. Self-hosting like td-gen: it imports only std (via
    // src/errgen.zig), never the td module, so `zig build errgen` works
    // even when the generated catalog is missing or stale.
    const errgen_exe = b.addExecutable(.{
        .name = "td-errgen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/errgen_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const errgen_install = b.addInstallArtifact(errgen_exe, .{});
    b.getInstallStep().dependOn(&errgen_install.step);
    const errgen_step = b.step("errgen", "Build and install td-errgen only (bootstrap for `just errors`)");
    errgen_step.dependOn(&errgen_install.step);

    // td-keygen: create an authorization key against a real Telegram DC
    // (plain TCP-full transport from td.transport).
    const keygen_exe = b.addExecutable(.{
        .name = "td-keygen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/keygen_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    b.installArtifact(keygen_exe);

    // Benchmarks for the client hot paths (`zig build bench`). The td
    // module is instantiated a second time here at ReleaseFast:
    // benchmarks must measure optimized library code, while the shared
    // `td` module follows the build's optimize flag (Debug by default,
    // which is what the tests want).
    const td_bench = b.addModule("td", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    const bench_exe = b.addExecutable(.{
        .name = "td-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench_main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "td", .module = td_bench },
            },
        }),
    });
    const bench_run = b.addRunArtifact(bench_exe);
    // Installed by the default step (not just the `bench` run step) so
    // `just bench` can exec zig-out/bin/td-bench directly with its
    // section-filter argument.
    b.installArtifact(bench_exe);
    const bench_step = b.step("bench", "Benchmark the client hot paths");
    bench_step.dependOn(&bench_run.step);

    // Examples: runnable, network-free demonstrations of the public API
    // (a full round trip over the in-memory loopback peer, and the
    // session capture → store → restore → continue flow). Built by the
    // default step so they can never rot.
    const Example = struct {
        name: []const u8,
        file: []const u8,
    };
    const examples = [_]Example{
        // The high-level client: init / connect / invoke, with session
        // persistence. Talks to the real network (no credentials
        // needed). See examples/quickstart.zig.
        .{ .name = "example-quickstart", .file = "examples/quickstart.zig" },
        .{ .name = "example-loopback", .file = "examples/loopback_client.zig" },
        .{ .name = "example-session", .file = "examples/session_roundtrip.zig" },
        // The invoke surface: plain/argument invokes, RpcError handling,
        // pipelined send/wait. Talks to the real network (no credentials
        // needed). See examples/invoke.zig.
        .{ .name = "example-invoke", .file = "examples/invoke.zig" },
        // Real-network smoke test: skips (exit 0) unless TD_BOT_TOKEN
        // is set. See examples/bot_login.zig.
        .{ .name = "example-bot-login", .file = "examples/bot_login.zig" },
    };
    for (examples) |ex| {
        const example_exe = b.addExecutable(.{
            .name = ex.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(ex.file),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "td", .module = td },
                },
            }),
        });
        b.installArtifact(example_exe);
    }

    // Unit tests: the td module itself is the test root, so every
    // inline `test` declaration in its files is collected.
    const unit_tests = b.addTest(.{ .root_module = td });
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/tl_integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    const official_schema_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/official_schema.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
                .{ .name = "schema", .module = b.createModule(.{
                    .root_source_file = b.path("schema/embed.zig"),
                }) },
            },
        }),
    });
    const mtproto_schema_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/mtproto_schema.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
                .{ .name = "schema", .module = b.createModule(.{
                    .root_source_file = b.path("schema/embed.zig"),
                }) },
            },
        }),
    });
    const codegen_golden_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/codegen_golden.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Golden test for the error-catalog generator (td-errgen): output
    // for the sample TSV must match the committed expected file.
    const errgen_golden_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/errgen_golden.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // The committed generated error catalog (src/rpc/errors_gen.zig,
    // exposed as td.rpc.errors_gen): classification, parameterized
    // normalization, table invariants, rpc/dc integration.
    const rpc_errors_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rpc_errors.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    const generated_roundtrip_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/generated_roundtrip.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Runtime tests against the committed generated Telegram API
    // (src/api/telegram.zig, exposed as td.api).
    const generated_api_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/generated_api.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Authorization-key handshake: full loopback integration against an
    // in-process server, plus official-example KATs.
    const auth_handshake_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/auth_handshake.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Client-level PFS: the full temp-handshake -> bindTempAuthKey ->
    // traffic-under-temp-key choreography against an in-process peer.
    const pfs_client_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/pfs_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Transport layer: TCP-full framing over real loopback sockets
    // (connect/read/write/close/reconnect, timeouts, framing violations).
    const transport_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/transport.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Encrypted-message session layer over the TCP-full transport on real
    // loopback sockets (envelopes, containers, acks, salt recovery).
    const message_session_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/message_session.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // RPC layer: invoke/send/wait over the full stack against an
    // in-process MTProto peer (rpc_result matching, rpc_error, gzip,
    // pipelining, salt recovery, ping, timeouts).
    const rpc_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rpc.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Session persistence: capture → store → reload → reconnect over the
    // full stack against an in-process MTProto peer (memory and file
    // stores, counter/salt/session-id continuation).
    const session_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/session.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Connection management: state machine, backoff, automatic
    // reconnection and request recovery over real loopback sockets —
    // the server dies and comes back mid-request.
    const connman_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/connman.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Updates: ordering/reconciliation engine over the generated API
    // plus end-to-end pushed-update delivery and getDifference healing
    // against an in-process MTProto peer on real loopback sockets.
    const updates_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/updates.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Authentication: SRP/2FA math KATs and the send-code → sign-in →
    // 2FA → logout flow over the full stack against an in-process
    // MTProto peer on real loopback sockets, plus session capture.
    const auth_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/auth.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Multi-session: a fleet of independent managers over in-memory
    // loopback links — wire-identity independence, scheduler sweeps,
    // error isolation, slot recycling.
    const multi_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/multi.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Fuzz targets over every supported input path (TL parse/ser/de,
    // generated decoders, encrypted frames, session loading, framing);
    // the fixed corpora run as plain tests, the same bodies run under
    // the coverage-guided fuzzer with `zig build test --fuzz`.
    const fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Protocol compliance: hostile frames and RPC payloads (tampered
    // msg_keys, undersized padding, unordered containers, rpc_error,
    // gzip bombs, truncations) rejected with the documented errors
    // without desynchronizing the receiver.
    const compliance_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/compliance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    // Generated-code compilation check: run td-gen on the full official
    // Telegram schema (with a built-in self-test that forces analysis of
    // every generated declaration) and compile the result.
    const gen_official = b.addRunArtifact(gen_exe);
    gen_official.addFileArg(b.path("schema/api.tl"));
    gen_official.addArg("--self-test");
    const generated_official = gen_official.addOutputFileArg("telegram_api_gen.zig");
    const gen_compile_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = generated_official,
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    const run_gen_compile_test = b.addRunArtifact(gen_compile_test);

    // Same check for the core MTProto schema (its dialect exercises the
    // id-less declarations, the `?` bare types and bare `vector<T>`).
    const gen_mtproto = b.addRunArtifact(gen_exe);
    gen_mtproto.addFileArg(b.path("schema/mtproto.tl"));
    gen_mtproto.addArg("--self-test");
    const generated_mtproto = gen_mtproto.addOutputFileArg("mtproto_gen.zig");
    const gen_mtproto_compile_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = generated_mtproto,
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "td", .module = td },
            },
        }),
    });
    const run_gen_mtproto_compile_test = b.addRunArtifact(gen_mtproto_compile_test);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const run_integration_tests = b.addRunArtifact(integration_tests);
    const run_official_schema_tests = b.addRunArtifact(official_schema_tests);
    const run_mtproto_schema_tests = b.addRunArtifact(mtproto_schema_tests);
    const run_codegen_golden_tests = b.addRunArtifact(codegen_golden_tests);
    const run_errgen_golden_tests = b.addRunArtifact(errgen_golden_tests);
    const run_rpc_errors_tests = b.addRunArtifact(rpc_errors_tests);
    const run_generated_roundtrip_tests = b.addRunArtifact(generated_roundtrip_tests);
    const run_generated_api_tests = b.addRunArtifact(generated_api_tests);
    const run_auth_handshake_tests = b.addRunArtifact(auth_handshake_tests);
    const run_pfs_client_tests = b.addRunArtifact(pfs_client_tests);
    const run_transport_tests = b.addRunArtifact(transport_tests);
    const run_message_session_tests = b.addRunArtifact(message_session_tests);
    const run_rpc_tests = b.addRunArtifact(rpc_tests);
    const run_session_tests = b.addRunArtifact(session_tests);
    const run_connman_tests = b.addRunArtifact(connman_tests);
    const run_updates_tests = b.addRunArtifact(updates_tests);
    const run_auth_tests = b.addRunArtifact(auth_tests);
    const run_multi_tests = b.addRunArtifact(multi_tests);
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    const run_compliance_tests = b.addRunArtifact(compliance_tests);

    const test_step = b.step("test", "Run unit and integration tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_official_schema_tests.step);
    test_step.dependOn(&run_mtproto_schema_tests.step);
    test_step.dependOn(&run_codegen_golden_tests.step);
    test_step.dependOn(&run_errgen_golden_tests.step);
    test_step.dependOn(&run_rpc_errors_tests.step);
    test_step.dependOn(&run_generated_roundtrip_tests.step);
    test_step.dependOn(&run_generated_api_tests.step);
    test_step.dependOn(&run_auth_handshake_tests.step);
    test_step.dependOn(&run_pfs_client_tests.step);
    test_step.dependOn(&run_transport_tests.step);
    test_step.dependOn(&run_message_session_tests.step);
    test_step.dependOn(&run_rpc_tests.step);
    test_step.dependOn(&run_session_tests.step);
    test_step.dependOn(&run_connman_tests.step);
    test_step.dependOn(&run_updates_tests.step);
    test_step.dependOn(&run_auth_tests.step);
    test_step.dependOn(&run_multi_tests.step);
    test_step.dependOn(&run_fuzz_tests.step);
    test_step.dependOn(&run_compliance_tests.step);
    test_step.dependOn(&run_gen_compile_test.step);
    test_step.dependOn(&run_gen_mtproto_compile_test.step);
}
