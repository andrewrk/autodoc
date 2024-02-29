var files: std.StringArrayHashMapUnmanaged([]u8) = .{};
const gpa = std.heap.wasm_allocator;

const std = @import("std");
const log = std.log;
const assert = std.debug.assert;

const js = struct {
    extern "js" fn log(ptr: [*]const u8, len: usize) void;
    extern "js" fn panic(ptr: [*]const u8, len: usize) noreturn;
};

pub const std_options: std.Options = .{
    .logFn = logFn,
    //.log_level = .debug,
};

pub fn panic(msg: []const u8, st: ?*std.builtin.StackTrace, addr: ?usize) noreturn {
    _ = st;
    _ = addr;
    log.err("panic: {s}", .{msg});
    @trap();
}

fn logFn(
    comptime message_level: log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const level_txt = comptime message_level.asText();
    const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    var buf: [500]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, level_txt ++ prefix2 ++ format, args) catch l: {
        buf[buf.len - 3 ..][0..3].* = "...".*;
        break :l &buf;
    };
    js.log(line.ptr, line.len);
}

export fn alloc(n: usize) [*]u8 {
    const slice = gpa.alloc(u8, n) catch @panic("OOM");
    return slice.ptr;
}

export fn unpack(tar_ptr: [*]u8, tar_len: usize) void {
    const tar_bytes = tar_ptr[0..tar_len];
    //log.debug("received {d} bytes of tar file", .{tar_bytes.len});

    unpack_inner(tar_bytes) catch |err| {
        fatal("unable to unpack tar: {s}", .{@errorName(err)});
    };
}

fn unpack_inner(tar_bytes: []u8) !void {
    var fbs = std.io.fixedBufferStream(tar_bytes);
    var it = std.tar.iterator(fbs.reader(), null);
    while (try it.next()) |file| {
        switch (file.kind) {
            .normal => {
                if (file.size == 0 and file.name.len == 0) break;
                if (std.mem.endsWith(u8, file.name, ".zig")) {
                    log.debug("found file: '{s}'", .{file.name});
                    const file_name = try gpa.dupe(u8, file.name);
                    const file_bytes = tar_bytes[fbs.pos..][0..@intCast(file.size)];
                    try files.put(gpa, file_name, file_bytes);
                } else {
                    log.warn("skipping: '{s}' - the tar creation should have done that", .{
                        file.name,
                    });
                }
                try file.skip();
            },
            else => continue,
        }
    }

    for (files.keys(), files.values()) |path, source| {
        log.debug("parsing file: '{s}'", .{path});
        try parse(source);
    }
}

fn parse(source: []u8) !void {
    // Require every source file to end with a newline so that Zig's tokenizer
    // can continue to require null termination and Autodoc implementation can
    // avoid copying source bytes from the decompressed tar file buffer.
    if (source.len == 0) return;
    assert(source[source.len - 1] == '\n');
    source[source.len - 1] = 0;
    const adjusted_source = source[0 .. source.len - 1 :0];

    var tree = try std.zig.Ast.parse(gpa, adjusted_source, .zig);
    defer tree.deinit(gpa);
}

fn wrapError(x: anyerror!void) u32 {
    if (x) |_| {
        return 0;
    } else |err| {
        return @intFromError(err);
    }
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const line = std.fmt.allocPrint(gpa, format, args) catch @panic("OOM");
    defer gpa.free(line);
    js.panic(line.ptr, line.len);
}
