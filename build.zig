const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSmall,
    });

    const wasm = b.addExecutable(.{
        .name = "autodoc",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
            .cpu_features_add = std.Target.wasm.featureSet(&.{
                .atomics,
                .bulk_memory,
                // .extended_const, not supported by Safari
                .multivalue,
                .mutable_globals,
                .nontrapping_fptoint,
                .reference_types,
                //.relaxed_simd, not supported by Firefox or Safari
                .sign_ext,
                // observed to cause Error occured during wast conversion :
                // Unknown operator: 0xfd058 in Firefox 117
                //.simd128,
                // .tail_call, not supported by Safari
            }),
        }),
        .optimize = optimize,
    });
    // It would be nice if Zig could just use the exact list of functions that
    // are exported in `wasm`.
    wasm.root_module.export_symbol_names = &.{
        "alloc",
        "categorize_decl",
        "decl_docs_html",
        "decl_fqn",
        "decl_name",
        "decl_parent",
        "decl_type_html",
        "find_decl",
        "find_package_root",
        "get_aliasee",
        "namespace_members",
        "package_name",
        "query_begin",
        "query_exec",
        "set_input_string",
        "unpack",
    };
    wasm.entry = .disabled;

    b.getInstallStep().dependOn(&b.addInstallFile(wasm.getEmittedBin(), "main.wasm").step);

    b.installDirectory(.{
        .source_dir = .{ .path = "lib" },
        .install_dir = .prefix,
        .install_subdir = "",
    });

    const exe_unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
