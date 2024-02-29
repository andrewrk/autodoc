const std = @import("std");
const gpa = std.heap.wasm_allocator;
const log = std.log;

const js = struct {
    extern "js" fn log(ptr: [*]const u8, len: usize) void;
    extern "js" fn panic(ptr: [*]const u8, len: usize) noreturn;
};

pub const std_options: std.Options = .{
    .logFn = logFn,
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
    const line = std.fmt.allocPrint(gpa, level_txt ++ prefix2 ++ format, args) catch @panic("OOM");
    defer gpa.free(line);
    js.log(line.ptr, line.len);
}

export fn parse(
    source_index: u32,
    source_len: u32,
) u32 {
    const source_ptr: [*:0]u8 = @ptrFromInt(source_index);
    const source_code = source_ptr[0..source_len :0];

    return wrapError(parse_inner(source_code));
}

export fn alloc(n: usize) [*]u8 {
    const slice = gpa.alloc(u8, n) catch @panic("OOM");
    return slice.ptr;
}

export fn unpack(tar_ptr: [*]const u8, tar_len: usize) void {
    const tar_bytes = tar_ptr[0..tar_len];
    log.debug("received {d} bytes of tar file", .{tar_bytes.len});

    unpack_inner(tar_bytes) catch |err| {
        fatal("unable to unpack tar: {s}", .{@errorName(err)});
    };
}

fn unpack_inner(tar_bytes: []const u8) !void {
    var fbs = std.io.fixedBufferStream(tar_bytes);
    var it = std.tar.iterator(fbs.reader(), null);
    while (try it.next()) |file| {
        switch (file.kind) {
            .normal => {
                if (file.size == 0 and file.name.len == 0) break;
                log.debug("found file: '{s}'", .{file.name});
                try file.skip();
            },
            else => continue,
        }
    }
}

fn parse_inner(source_code: [:0]const u8) !void {
    var tree = try std.zig.Ast.parse(gpa, source_code, .zig);
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
