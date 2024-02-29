var files: std.StringArrayHashMapUnmanaged(std.zig.Ast) = .{};
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

var query_string: std.ArrayListUnmanaged(u8) = .{};
var query_results: std.ArrayListUnmanaged(GlobalAstNode) = .{};

/// Resizes the query string to be the correct length; returns the pointer to
/// the query string.
export fn query_begin(query_string_len: usize) [*]u8 {
    query_string.resize(gpa, query_string_len) catch @panic("OOM");
    return query_string.items.ptr;
}

/// Executes the query. Returns the pointer to the query results which is an
/// array of u32.
/// The first element is the length of the array.
/// Subsequent elements are GlobalAstNode values which are all public
/// declarations.
export fn query_exec(ignore_case: bool) [*]GlobalAstNode {
    const query = query_string.items;
    log.debug("querying '{s}'", .{query});
    query_exec_fallible(query, ignore_case) catch |err| switch (err) {
        error.OutOfMemory => @panic("OOM"),
    };
    query_results.items[0] = @enumFromInt(query_results.items.len - 1);
    return query_results.items.ptr;
}

const max_matched_items = 2000;

fn query_exec_fallible(query: []const u8, ignore_case: bool) !void {
    const g = struct {
        var full_path_search_text: std.ArrayListUnmanaged(u8) = .{};
        var full_path_search_text_lower: std.ArrayListUnmanaged(u8) = .{};
        var doc_search_text: std.ArrayListUnmanaged(u8) = .{};
        /// Each element matches a corresponding query_results element.
        var points: std.ArrayListUnmanaged(u32) = .{};
    };

    // First element stores the size of the list.
    try query_results.resize(gpa, 1);
    // Corresponding point value is meaningless and therefore undefined.
    try g.points.resize(gpa, 1);

    var total_node_index: usize = 0;
    for (files.keys(), files.values()) |file_path, *ast| {
        const token_tags = ast.tokens.items(.tag);
        const node_tags = ast.nodes.items(.tag);
        const main_tokens = ast.nodes.items(.main_token);
        decl_loop: for (node_tags, main_tokens, 0..) |tag, main_token, node_index| {
            const global_node: GlobalAstNode = @enumFromInt(total_node_index + node_index);
            const decl_name = switch (tag) {
                .global_var_decl,
                .local_var_decl,
                .simple_var_decl,
                .aligned_var_decl,
                => n: {
                    if (main_token == 0) continue;
                    const is_pub = token_tags[main_token - 1] == .keyword_pub;
                    if (!is_pub) continue;
                    const name_token = main_token + 1;
                    assert(token_tags[name_token] == .identifier);
                    const ident_name = ast.tokenSlice(name_token);
                    break :n ident_name;
                },
                else => continue,
            };
            g.full_path_search_text.clearRetainingCapacity();
            try g.full_path_search_text.ensureUnusedCapacity(gpa, file_path.len + 1 + decl_name.len);
            g.full_path_search_text.appendSliceAssumeCapacity(file_path);
            g.full_path_search_text.appendAssumeCapacity('.');
            // TODO we need to walk the tree to make this take into account
            // namespace nesting.
            g.full_path_search_text.appendSliceAssumeCapacity(decl_name);

            try g.full_path_search_text_lower.resize(gpa, g.full_path_search_text.items.len);
            @memcpy(g.full_path_search_text_lower.items, g.full_path_search_text.items);

            // TODO doc comment finding
            try g.doc_search_text.resize(gpa, 0);

            if (ignore_case) {
                ascii_lower(g.full_path_search_text_lower.items);
                ascii_lower(g.doc_search_text.items);
            }

            var it = std.mem.tokenizeScalar(u8, query, ' ');
            var points: u32 = 0;
            while (it.next()) |term| {
                // exact, case sensitive match of full decl path
                if (std.mem.eql(u8, g.full_path_search_text.items, term)) {
                    points += 4;
                    continue;
                }
                // exact, case sensitive match of just decl name
                if (std.mem.eql(u8, decl_name, term)) {
                    points += 3;
                    continue;
                }
                // substring, case insensitive match of full decl path
                if (std.mem.indexOf(u8, g.full_path_search_text_lower.items, term) != null) {
                    points += 2;
                    continue;
                }
                if (std.mem.indexOf(u8, g.doc_search_text.items, term) != null) {
                    points += 1;
                    continue;
                }
                continue :decl_loop;
            }
            if (query_results.items.len < max_matched_items or points >= 3) {
                try query_results.append(gpa, global_node);
                try g.points.append(gpa, points);
            }
        }
        total_node_index += ast.nodes.len;
    }

    const sort_context: struct {
        pub fn swap(sc: @This(), a_index: usize, b_index: usize) void {
            _ = sc;
            std.mem.swap(u32, &g.points.items[a_index], &g.points.items[b_index]);
            std.mem.swap(GlobalAstNode, &query_results.items[a_index], &query_results.items[b_index]);
        }

        pub fn lessThan(sc: @This(), a_index: usize, b_index: usize) bool {
            _ = sc;
            if (g.points.items[b_index] < g.points.items[a_index]) {
                return true;
            } else if (g.points.items[b_index] > g.points.items[a_index]) {
                return false;
            } else {
                const a_global_node = query_results.items[a_index];
                const b_global_node = query_results.items[b_index];
                const a_file_path = a_global_node.file_path();
                const b_file_path = b_global_node.file_path();
                // TODO Also check the local namespace  inside the file
                return std.mem.lessThan(u8, b_file_path, a_file_path);
            }
        }
    } = .{};

    std.mem.sortUnstableContext(1, query_results.items.len, sort_context);

    if (query_results.items.len > max_matched_items)
        query_results.shrinkRetainingCapacity(max_matched_items);
}

var fqn_buffer: std.ArrayListUnmanaged(u8) = .{};

const String = packed struct(u64) {
    ptr: u32,
    len: u32,

    fn init(s: []const u8) String {
        return .{
            .ptr = @intFromPtr(s.ptr),
            .len = s.len,
        };
    }
};

export fn fully_qualified_name(node: GlobalAstNode) String {
    fully_qualified_name_fallible(node) catch |err| switch (err) {
        error.OutOfMemory => @panic("OOM"),
    };
    return String.init(fqn_buffer.items);
}

fn fully_qualified_name_fallible(node: GlobalAstNode) !void {
    fqn_buffer.clearRetainingCapacity();
    try fqn_buffer.appendSlice(gpa, node.file_path());
    try fqn_buffer.append(gpa, '.');
    try fqn_buffer.appendSlice(gpa, "TODO_decl_name_here");
}

/// Uniquely identifies an AST node across all files.
const GlobalAstNode = enum(u32) {
    _,

    fn file_path(n: GlobalAstNode) []const u8 {
        var total_node_index: usize = 0;
        for (files.keys(), files.values()) |path, *ast| {
            total_node_index += ast.nodes.len;
            if (total_node_index > @intFromEnum(n)) {
                return path;
            }
        }
        unreachable;
    }
};
/// Uniquely identifies a source token across all files.
const GlobalToken = enum(u32) { _ };

fn unpack_inner(tar_bytes: []u8) !void {
    var fbs = std.io.fixedBufferStream(tar_bytes);
    var file_name_buffer: [1024]u8 = undefined;
    var link_name_buffer: [1024]u8 = undefined;
    var it = std.tar.iterator(fbs.reader(), .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });
    while (try it.next()) |file| {
        switch (file.kind) {
            .normal => {
                if (file.size == 0 and file.name.len == 0) break;
                if (std.mem.endsWith(u8, file.name, ".zig")) {
                    log.debug("found file: '{s}'", .{file.name});
                    const file_name = try gpa.dupe(u8, file.name);
                    const file_bytes = tar_bytes[fbs.pos..][0..@intCast(file.size)];
                    const tree = try parse(file_bytes);
                    try files.put(gpa, file_name, tree);
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
}

fn parse(source: []u8) !std.zig.Ast {
    // Require every source file to end with a newline so that Zig's tokenizer
    // can continue to require null termination and Autodoc implementation can
    // avoid copying source bytes from the decompressed tar file buffer.
    const adjusted_source: [:0]const u8 = s: {
        if (source.len == 0)
            break :s "";

        assert(source[source.len - 1] == '\n');
        source[source.len - 1] = 0;
        break :s source[0 .. source.len - 1 :0];
    };

    return std.zig.Ast.parse(gpa, adjusted_source, .zig);
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    const line = std.fmt.allocPrint(gpa, format, args) catch @panic("OOM");
    defer gpa.free(line);
    js.panic(line.ptr, line.len);
}

fn ascii_lower(bytes: []u8) void {
    for (bytes) |*b| b.* = std.ascii.toLower(b.*);
}
