var files: std.StringArrayHashMapUnmanaged(Ast) = .{};
var decls: std.ArrayListUnmanaged(Decl) = .{};
var packages: std.StringArrayHashMapUnmanaged(FileIndex) = .{};
const gpa = std.heap.wasm_allocator;

const std = @import("std");
const log = std.log;
const assert = std.debug.assert;
const Ast = std.zig.Ast;

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
var query_results: std.ArrayListUnmanaged(Decl.Index) = .{};

/// Resizes the query string to be the correct length; returns the pointer to
/// the query string.
export fn query_begin(query_string_len: usize) [*]u8 {
    query_string.resize(gpa, query_string_len) catch @panic("OOM");
    return query_string.items.ptr;
}

/// Executes the query. Returns the pointer to the query results which is an
/// array of u32.
/// The first element is the length of the array.
/// Subsequent elements are Decl.Index values which are all public
/// declarations.
export fn query_exec(ignore_case: bool) [*]Decl.Index {
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

    decl_loop: for (decls.items, 0..) |*decl, decl_index| {
        const info = decl.extra_info();
        if (!info.is_pub) continue;
        const file_path = decl.file_path();

        try reset_with_file_path(&g.full_path_search_text, file_path);
        if (decl.parent != .none)
            try append_parent_ns(&g.full_path_search_text, decl.parent);
        try g.full_path_search_text.appendSlice(gpa, info.name);

        try g.full_path_search_text_lower.resize(gpa, g.full_path_search_text.items.len);
        @memcpy(g.full_path_search_text_lower.items, g.full_path_search_text.items);

        const ast = &files.values()[@intFromEnum(decl.file)];
        try collect_docs(&g.doc_search_text, ast, info.first_doc_comment);

        if (ignore_case) {
            ascii_lower(g.full_path_search_text_lower.items);
            ascii_lower(g.doc_search_text.items);
        }

        var it = std.mem.tokenizeScalar(u8, query, ' ');
        var points: u32 = 0;
        var bypass_limit = false;
        while (it.next()) |term| {
            // exact, case sensitive match of full decl path
            if (std.mem.eql(u8, g.full_path_search_text.items, term)) {
                points += 4;
                bypass_limit = true;
                continue;
            }
            // exact, case sensitive match of just decl name
            if (std.mem.eql(u8, info.name, term)) {
                points += 3;
                bypass_limit = true;
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

        if (query_results.items.len < max_matched_items or bypass_limit) {
            try query_results.append(gpa, @enumFromInt(decl_index));
            try g.points.append(gpa, points);
        }
    }

    const sort_context: struct {
        pub fn swap(sc: @This(), a_index: usize, b_index: usize) void {
            _ = sc;
            std.mem.swap(u32, &g.points.items[a_index], &g.points.items[b_index]);
            std.mem.swap(Decl.Index, &query_results.items[a_index], &query_results.items[b_index]);
        }

        pub fn lessThan(sc: @This(), a_index: usize, b_index: usize) bool {
            _ = sc;
            if (g.points.items[b_index] < g.points.items[a_index]) {
                return true;
            } else if (g.points.items[b_index] > g.points.items[a_index]) {
                return false;
            } else {
                const a_decl = query_results.items[a_index];
                const b_decl = query_results.items[b_index];
                const a_file_path = decls.items[@intFromEnum(a_decl)].file_path();
                const b_file_path = decls.items[@intFromEnum(b_decl)].file_path();
                // TODO Also check the local namespace  inside the file
                return std.mem.lessThan(u8, b_file_path, a_file_path);
            }
        }
    } = .{};

    std.mem.sortUnstableContext(1, query_results.items.len, sort_context);

    if (query_results.items.len > max_matched_items)
        query_results.shrinkRetainingCapacity(max_matched_items);
}

fn append_parent_ns(list: *std.ArrayListUnmanaged(u8), parent: Decl.Index) Oom!void {
    assert(parent != .none);
    const decl = &decls.items[@intFromEnum(parent)];
    if (decl.parent != .none) {
        try append_parent_ns(list, decl.parent);
        try list.append(gpa, '.');
    }
}

const String = Slice(u8);

fn Slice(T: type) type {
    return packed struct(u64) {
        ptr: u32,
        len: u32,

        fn init(s: []const T) @This() {
            return .{
                .ptr = @intFromPtr(s.ptr),
                .len = s.len,
            };
        }
    };
}

var string_result: std.ArrayListUnmanaged(u8) = .{};

export fn decl_fqn(decl_index: Decl.Index) String {
    const decl = &decls.items[@intFromEnum(decl_index)];
    decl_fqn_list(&string_result, decl) catch @panic("OOM");
    return String.init(string_result.items);
}

fn decl_fqn_list(list: *std.ArrayListUnmanaged(u8), decl: *const Decl) Oom!void {
    try reset_with_file_path(list, decl.file_path());
    if (decl.parent != .none) {
        try append_parent_ns(list, decl.parent);
        try list.appendSlice(gpa, decl.extra_info().name);
    } else {
        list.items.len -= 1; // remove the trailing '.'
    }
}

export fn decl_parent(decl_index: Decl.Index) Decl.Index {
    const decl = &decls.items[@intFromEnum(decl_index)];
    return decl.parent;
}

export fn decl_name(decl_index: Decl.Index) String {
    const decl = &decls.items[@intFromEnum(decl_index)];
    string_result.clearRetainingCapacity();
    const name = n: {
        if (decl.parent == .none) {
            // Then it is the root struct of a file.
            const file_path = files.keys()[@intFromEnum(decl.file)];
            break :n std.fs.path.stem(file_path);
        }
        break :n decl.extra_info().name;
    };
    string_result.appendSlice(gpa, name) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_docs_html(decl_index: Decl.Index, short: bool) String {
    const g = struct {
        var markdown_input: std.ArrayListUnmanaged(u8) = .{};
    };
    const decl = &decls.items[@intFromEnum(decl_index)];
    const ast = &files.values()[@intFromEnum(decl.file)];
    collect_docs(&g.markdown_input, ast, decl.extra_info().first_doc_comment) catch @panic("OOM");
    const chomped = c: {
        const s = g.markdown_input.items;
        if (!short) break :c s;
        const nl = std.mem.indexOfScalar(u8, s, '\n') orelse s.len;
        break :c s[0..nl];
    };
    render_markdown(&string_result, chomped) catch @panic("OOM");
    return String.init(string_result.items);
}

fn collect_docs(
    list: *std.ArrayListUnmanaged(u8),
    ast: *const Ast,
    first_doc_comment: Ast.TokenIndex,
) Oom!void {
    const token_tags = ast.tokens.items(.tag);
    list.clearRetainingCapacity();
    var it = first_doc_comment;
    while (token_tags[it] == .doc_comment) : (it += 1) {
        const line = std.mem.trim(u8, ast.tokenSlice(it)[3..], " \t\r");
        try list.appendSlice(gpa, line);
    }
}

export fn decl_type_html(decl_index: Decl.Index) String {
    const decl = &decls.items[@intFromEnum(decl_index)];
    const ast = &files.values()[@intFromEnum(decl.file)];
    string_result.clearRetainingCapacity();
    _ = ast; // TODO
    string_result.appendSlice(gpa, "TODO_type_here") catch @panic("OOM");
    return String.init(string_result.items);
}

fn reset_with_file_path(list: *std.ArrayListUnmanaged(u8), file_path: []const u8) Oom!void {
    list.clearRetainingCapacity();
    try list.ensureUnusedCapacity(gpa, file_path.len + 1);
    list.appendSliceAssumeCapacity(file_path);
    for (list.items) |*byte| switch (byte.*) {
        '/' => byte.* = '.',
        else => continue,
    };
    if (std.mem.endsWith(u8, list.items, ".zig")) {
        list.items.len -= 3;
    } else {
        list.appendAssumeCapacity('.');
    }
}

const FileIndex = enum(u32) {
    _,

    fn findRootDecl(file_index: FileIndex) Decl.Index {
        for (decls.items, 0..) |*decl, i| {
            if (decl.file == file_index and decl.ast_node == 0)
                return @enumFromInt(i);
        }
        return .none;
    }
};

const PackageIndex = enum(u32) {
    _,
};

const Decl = struct {
    ast_node: Ast.Node.Index,
    file: FileIndex,
    /// The decl whose namespace this is in.
    parent: Index,

    const ExtraInfo = struct {
        is_pub: bool,
        name: []const u8,
        /// This might not be a doc_comment token in which case there are no doc comments.
        first_doc_comment: Ast.TokenIndex,
    };

    const Index = enum(u32) {
        none = std.math.maxInt(u32),
        _,
    };

    fn add(d: Decl) !Index {
        try decls.append(gpa, d);
        return @enumFromInt(decls.items.len - 1);
    }

    fn extra_info(d: *const Decl) ExtraInfo {
        const ast = &files.values()[@intFromEnum(d.file)];
        const token_tags = ast.tokens.items(.tag);
        const node_tags = ast.nodes.items(.tag);
        switch (node_tags[d.ast_node]) {
            .root => return .{
                .name = "",
                .is_pub = true,
                .first_doc_comment = 0,
            },

            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const var_decl = ast.fullVarDecl(d.ast_node).?;
                const name_token = var_decl.ast.mut_token + 1;
                assert(token_tags[name_token] == .identifier);
                const ident_name = ast.tokenSlice(name_token);
                return .{
                    .name = ident_name,
                    .is_pub = var_decl.visib_token != null,
                    .first_doc_comment = findFirstDocComment(ast, var_decl.firstToken()),
                };
            },

            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => {
                var buf: [1]Ast.Node.Index = undefined;
                const fn_proto = ast.fullFnProto(&buf, d.ast_node).?;
                const name_token = fn_proto.name_token.?;
                assert(token_tags[name_token] == .identifier);
                const ident_name = ast.tokenSlice(name_token);
                return .{
                    .name = ident_name,
                    .is_pub = fn_proto.visib_token != null,
                    .first_doc_comment = findFirstDocComment(ast, fn_proto.firstToken()),
                };
            },

            else => |t| {
                log.debug("hit '{s}'", .{@tagName(t)});
                unreachable;
            },
        }
    }

    fn file_path(d: *const Decl) []const u8 {
        return files.keys()[@intFromEnum(d.file)];
    }
};

fn findFirstDocComment(ast: *const Ast, token: Ast.TokenIndex) Ast.TokenIndex {
    const token_tags = ast.tokens.items(.tag);
    var it = token;
    while (it > 0) {
        it -= 1;
        if (token_tags[it] != .doc_comment) {
            return it + 1;
        }
    }
    return it;
}

const Oom = error{OutOfMemory};

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
                    if (std.mem.indexOfScalar(u8, file_name, '/')) |pkg_name_end| {
                        const pkg_name = file_name[0..pkg_name_end];
                        const gop = try packages.getOrPut(gpa, pkg_name);
                        const file_index: FileIndex = @enumFromInt(files.entries.len);
                        if (!gop.found_existing or
                            std.mem.eql(u8, file_name[pkg_name_end..], "/root.zig") or
                            std.mem.eql(u8, file_name[pkg_name_end + 1 .. file_name.len - ".zig".len], pkg_name))
                        {
                            gop.value_ptr.* = file_index;
                        }
                        const file_bytes = tar_bytes[fbs.pos..][0..@intCast(file.size)];
                        const tree = try parse(file_bytes);
                        try files.put(gpa, file_name, tree);
                        try index_file(file_index);
                    }
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

fn parse(source: []u8) Oom!Ast {
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

    return Ast.parse(gpa, adjusted_source, .zig);
}

fn index_file(file_index: FileIndex) Oom!void {
    const ast = &files.values()[@intFromEnum(file_index)];

    if (ast.errors.len > 0) {
        // TODO: expose this in the UI
        log.err("can't index '{s}' because it has syntax errors", .{
            files.keys()[@intFromEnum(file_index)],
        });
        return;
    }

    const root = ast.containerDeclRoot();
    const decl_index = try Decl.add(.{
        .ast_node = 0,
        .file = file_index,
        .parent = .none,
    });
    try index_namespace(file_index, decl_index, root);
}

fn index_namespace(
    file_index: FileIndex,
    parent_decl: Decl.Index,
    container_decl: Ast.full.ContainerDecl,
) Oom!void {
    const ast = &files.values()[@intFromEnum(file_index)];
    const node_tags = ast.nodes.items(.tag);

    for (container_decl.ast.members) |member| {
        switch (node_tags[member]) {
            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => {
                const decl_index = try Decl.add(.{
                    .ast_node = member,
                    .file = file_index,
                    .parent = parent_decl,
                });
                _ = decl_index;
            },

            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const decl_index = try Decl.add(.{
                    .ast_node = member,
                    .file = file_index,
                    .parent = parent_decl,
                });
                const var_decl = ast.fullVarDecl(member).?;
                try index_expr(file_index, decl_index, var_decl.ast.init_node);
            },

            .test_decl => {
                // TODO look for doctests
            },

            else => continue,
        }
    }
}

fn index_expr(file_index: FileIndex, parent_decl: Decl.Index, node: Ast.Node.Index) Oom!void {
    const ast = &files.values()[@intFromEnum(file_index)];
    const node_tags = ast.nodes.items(.tag);
    switch (node_tags[node]) {
        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            try index_namespace(file_index, parent_decl, ast.fullContainerDecl(&buf, node).?);
        },

        else => return,
    }
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    var buf: [500]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, format, args) catch l: {
        buf[buf.len - 3 ..][0..3].* = "...".*;
        break :l &buf;
    };
    js.panic(line.ptr, line.len);
}

fn ascii_lower(bytes: []u8) void {
    for (bytes) |*b| b.* = std.ascii.toLower(b.*);
}

export fn package_name(index: u32) String {
    const names = packages.keys();
    return String.init(if (index >= names.len) "" else names[index]);
}

export fn find_package_root(pkg: PackageIndex) Decl.Index {
    const root_file = packages.values()[@intFromEnum(pkg)];
    const result = root_file.findRootDecl();
    assert(result != .none);
    return result;
}

/// Set by `set_input_string`.
var input_string: std.ArrayListUnmanaged(u8) = .{};

export fn set_input_string(len: usize) [*]u8 {
    input_string.resize(gpa, len) catch @panic("OOM");
    return input_string.items.ptr;
}

/// Uses `input_string`.
export fn find_decl() Decl.Index {
    const g = struct {
        var match_fqn: std.ArrayListUnmanaged(u8) = .{};
    };
    for (decls.items, 0..) |*decl, decl_index| {
        decl_fqn_list(&g.match_fqn, decl) catch @panic("OOM");
        if (std.mem.eql(u8, g.match_fqn.items, input_string.items)) {
            return @enumFromInt(decl_index);
        }
    }
    return .none;
}

/// keep in sync with "CAT_" constants in main.js
const Category = enum(u8) {
    namespace,
    global_variable,
    function,
    type,
    error_set,
    global_const,
    primitive_true,
    primitive_false,
    primitive_null,
    alias,
};

export fn categorize_decl(decl_index: Decl.Index) Category {
    global_aliasee = .none;
    const decl = &decls.items[@intFromEnum(decl_index)];
    const file_index: FileIndex = decl.file;
    const ast = &files.values()[@intFromEnum(file_index)];
    const node_tags = ast.nodes.items(.tag);
    const token_tags = ast.tokens.items(.tag);
    switch (node_tags[decl.ast_node]) {
        .root => return .namespace,

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = ast.fullVarDecl(decl.ast_node).?;
            if (token_tags[var_decl.ast.mut_token] == .keyword_var)
                return .global_variable;

            return categorize_expr(file_index, var_decl.ast.init_node);
        },

        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => return .function,

        else => unreachable,
    }
}

fn categorize_expr(file_index: FileIndex, node: Ast.Node.Index) Category {
    const ast = &files.values()[@intFromEnum(file_index)];
    const node_tags = ast.nodes.items(.tag);
    const node_datas = ast.nodes.items(.data);
    return switch (node_tags[node]) {
        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => .namespace,

        .error_set_decl,
        => .error_set,

        .identifier => {
            const name_token = ast.nodes.items(.main_token)[node];
            const ident_name = ast.tokenSlice(name_token);
            if (std.mem.eql(u8, ident_name, "true")) {
                return .primitive_true;
            } else if (std.mem.eql(u8, ident_name, "false")) {
                return .primitive_false;
            } else if (std.mem.eql(u8, ident_name, "null")) {
                return .primitive_null;
            } else if (std.zig.primitives.isPrimitive(ident_name)) {
                return .type;
            }
            // TODO:
            //return .alias;
            return .global_const;
        },

        .builtin_call_two, .builtin_call_two_comma => {
            if (node_datas[node].lhs == 0) {
                const params = [_]Ast.Node.Index{};
                return categorize_builtin_call(file_index, node, &params);
            } else if (node_datas[node].rhs == 0) {
                const params = [_]Ast.Node.Index{node_datas[node].lhs};
                return categorize_builtin_call(file_index, node, &params);
            } else {
                const params = [_]Ast.Node.Index{ node_datas[node].lhs, node_datas[node].rhs };
                return categorize_builtin_call(file_index, node, &params);
            }
        },
        .builtin_call, .builtin_call_comma => {
            const params = ast.extra_data[node_datas[node].lhs..node_datas[node].rhs];
            return categorize_builtin_call(file_index, node, params);
        },

        else => .global_const,
    };
}

/// Set only by `categorize_decl`; read only by `get_aliasee`, valid only
/// when `categorize_decl` returns `.alias`.
var global_aliasee: Decl.Index = .none;

export fn get_aliasee() Decl.Index {
    return global_aliasee;
}

fn categorize_builtin_call(
    file_index: FileIndex,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
) Category {
    const ast = &files.values()[@intFromEnum(file_index)];
    const main_tokens = ast.nodes.items(.main_token);
    const builtin_token = main_tokens[node];
    const builtin_name = ast.tokenSlice(builtin_token);
    if (std.mem.eql(u8, builtin_name, "@import")) {
        const str_lit_token = main_tokens[params[0]];
        const str_bytes = ast.tokenSlice(str_lit_token);
        const file_path = std.zig.string_literal.parseAlloc(gpa, str_bytes) catch @panic("OOM");
        defer gpa.free(file_path);
        const base_path = files.keys()[@intFromEnum(file_index)];
        const resolved_path = std.fs.path.resolvePosix(gpa, &.{
            base_path, "..", file_path,
        }) catch @panic("OOM");
        defer gpa.free(resolved_path);
        log.debug("from '{s}' @import '{s}' resolved='{s}'", .{
            base_path, file_path, resolved_path,
        });
        if (files.getIndex(resolved_path)) |imported_file_index| {
            global_aliasee = FileIndex.findRootDecl(@enumFromInt(imported_file_index));
            assert(global_aliasee != .none);
            return .alias;
        } else {
            log.warn("import target '{s}' did not resolve to any file", .{resolved_path});
        }
    }

    return .global_const;
}

export fn namespace_members(parent: Decl.Index, include_private: bool) Slice(Decl.Index) {
    const g = struct {
        var members: std.ArrayListUnmanaged(Decl.Index) = .{};
    };

    g.members.clearRetainingCapacity();

    for (decls.items, 0..) |*decl, i| {
        if (decl.parent == parent) {
            assert(!include_private); // TODO implement this
            g.members.append(gpa, @enumFromInt(i)) catch @panic("OOM");
        }
    }

    return Slice(Decl.Index).init(g.members.items);
}

fn render_markdown(dest: *std.ArrayListUnmanaged(u8), input: []const u8) !void {
    // TODO implement a custom markdown renderer
    // resist urge to use a third party implementation
    // this implementation will have zig specific tweaks such as inserting links
    // syntax highlighting, recognizing identifiers even outside of backticks, etc.
    dest.clearRetainingCapacity();
    for (input) |c| {
        try dest.ensureUnusedCapacity(gpa, 6);
        switch (c) {
            '&' => dest.appendSliceAssumeCapacity("&amp;"),
            '<' => dest.appendSliceAssumeCapacity("&lt;"),
            '>' => dest.appendSliceAssumeCapacity("&gt;"),
            '"' => dest.appendSliceAssumeCapacity("&quot;"),
            else => dest.appendAssumeCapacity(c),
        }
    }
}

fn writeEscaped(out: anytype, input: []const u8) !void {
    for (input) |c| {
        try switch (c) {
            '&' => out.writeAll("&amp;"),
            '<' => out.writeAll("&lt;"),
            '>' => out.writeAll("&gt;"),
            '"' => out.writeAll("&quot;"),
            else => out.writeByte(c),
        };
    }
}
