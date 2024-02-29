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
        }),
        .optimize = optimize,
    });
    // It would be nice if Zig could just use the exact list of functions that
    // are exported in `wasm`.
    wasm.root_module.export_symbol_names = &.{
        "unpack",
        "alloc",
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
