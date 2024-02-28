const std = @import("std");
const gpa = std.heap.wasm_allocator;

export fn parse(
    source_index: u32,
    source_len: u32,
) u32 {
    const source_ptr: [*:0]u8 = @ptrFromInt(source_index);
    const source_code = source_ptr[0..source_len :0];

    return wrapError(parse_inner(source_code));
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
