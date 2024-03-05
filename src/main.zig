var files: std.StringArrayHashMapUnmanaged(Ast) = .{};
var decls: std.ArrayListUnmanaged(Decl) = .{};
var packages: std.StringArrayHashMapUnmanaged(FileIndex) = .{};
const gpa = std.heap.wasm_allocator;

const std = @import("std");
const log = std.log;
const assert = std.debug.assert;
const Ast = std.zig.Ast;
const Walk = @import("Walk.zig");
const markdown = @import("markdown.zig");

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
    const Score = packed struct(u32) {
        points: u16,
        segments: u16,
    };
    const g = struct {
        var full_path_search_text: std.ArrayListUnmanaged(u8) = .{};
        var full_path_search_text_lower: std.ArrayListUnmanaged(u8) = .{};
        var doc_search_text: std.ArrayListUnmanaged(u8) = .{};
        /// Each element matches a corresponding query_results element.
        var scores: std.ArrayListUnmanaged(Score) = .{};
    };

    // First element stores the size of the list.
    try query_results.resize(gpa, 1);
    // Corresponding point value is meaningless and therefore undefined.
    try g.scores.resize(gpa, 1);

    decl_loop: for (decls.items, 0..) |*decl, decl_index| {
        const info = decl.extra_info();
        if (!info.is_pub) continue;

        try reset_with_decl_path(&g.full_path_search_text, decl);
        if (decl.parent != .none)
            try Decl.append_parent_ns(&g.full_path_search_text, decl.parent);
        try g.full_path_search_text.appendSlice(gpa, info.name);

        try g.full_path_search_text_lower.resize(gpa, g.full_path_search_text.items.len);
        @memcpy(g.full_path_search_text_lower.items, g.full_path_search_text.items);

        const ast = decl.file.ast();
        try collect_docs(&g.doc_search_text, ast, info.first_doc_comment);

        if (ignore_case) {
            ascii_lower(g.full_path_search_text_lower.items);
            ascii_lower(g.doc_search_text.items);
        }

        var it = std.mem.tokenizeScalar(u8, query, ' ');
        var points: u16 = 0;
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
            try g.scores.append(gpa, .{
                .points = points,
                .segments = @intCast(count_scalar(g.full_path_search_text.items, '.')),
            });
        }
    }

    const sort_context: struct {
        pub fn swap(sc: @This(), a_index: usize, b_index: usize) void {
            _ = sc;
            std.mem.swap(Score, &g.scores.items[a_index], &g.scores.items[b_index]);
            std.mem.swap(Decl.Index, &query_results.items[a_index], &query_results.items[b_index]);
        }

        pub fn lessThan(sc: @This(), a_index: usize, b_index: usize) bool {
            _ = sc;
            const a_score = g.scores.items[a_index];
            const b_score = g.scores.items[b_index];
            if (b_score.points < a_score.points) {
                return true;
            } else if (b_score.points > a_score.points) {
                return false;
            } else if (a_score.segments < b_score.segments) {
                return true;
            } else if (a_score.segments > b_score.segments) {
                return false;
            } else {
                const a_decl = query_results.items[a_index];
                const b_decl = query_results.items[b_index];
                const a_file_path = a_decl.get().file.path();
                const b_file_path = b_decl.get().file.path();
                // TODO Also check the local namespace  inside the file
                return std.mem.lessThan(u8, b_file_path, a_file_path);
            }
        }
    } = .{};

    std.mem.sortUnstableContext(1, query_results.items.len, sort_context);

    if (query_results.items.len > max_matched_items)
        query_results.shrinkRetainingCapacity(max_matched_items);
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

export fn decl_fields(decl_index: Decl.Index) Slice(Ast.Node.Index) {
    return Slice(Ast.Node.Index).init(decl_fields_fallible(decl_index) catch @panic("OOM"));
}

fn decl_fields_fallible(decl_index: Decl.Index) ![]Ast.Node.Index {
    const g = struct {
        var result: std.ArrayListUnmanaged(Ast.Node.Index) = .{};
    };
    g.result.clearRetainingCapacity();
    const decl = decl_index.get();
    const ast = decl.file.ast();
    const node_tags = ast.nodes.items(.tag);
    const value_node = decl.value_node() orelse return &.{};
    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = ast.fullContainerDecl(&buf, value_node) orelse return &.{};
    for (container_decl.ast.members) |member_node| switch (node_tags[member_node]) {
        .container_field_init,
        .container_field_align,
        .container_field,
        => try g.result.append(gpa, member_node),

        else => continue,
    };
    return g.result.items;
}

export fn decl_field_html(decl_index: Decl.Index, field_node: Ast.Node.Index) String {
    string_result.clearRetainingCapacity();
    decl_field_html_fallible(&string_result, decl_index, field_node) catch @panic("OOM");
    return String.init(string_result.items);
}

fn decl_field_html_fallible(
    out: *std.ArrayListUnmanaged(u8),
    decl_index: Decl.Index,
    field_node: Ast.Node.Index,
) !void {
    const decl = decl_index.get();
    const ast = decl.file.ast();
    try out.appendSlice(gpa, "<pre><code>");
    try decl.file.source_html(out, field_node);
    try out.appendSlice(gpa, "</code></pre>");

    const field = ast.fullContainerField(field_node).?;
    const first_doc_comment = findFirstDocComment(ast, field.firstToken());

    if (ast.tokens.items(.tag)[first_doc_comment] == .doc_comment) {
        try out.appendSlice(gpa, "<div class=\"fieldDocs\">");
        try render_docs(out, ast, first_doc_comment, false);
        try out.appendSlice(gpa, "</div>");
    }
}

export fn decl_fn_proto_html(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    const ast = decl.file.ast();
    const node_tags = ast.nodes.items(.tag);
    const node_datas = ast.nodes.items(.data);
    const proto_node = switch (node_tags[decl.ast_node]) {
        .fn_decl => node_datas[decl.ast_node].lhs,

        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        => decl.ast_node,

        else => unreachable,
    };

    string_result.clearRetainingCapacity();
    decl.file.source_html(&string_result, proto_node) catch |err| {
        fatal("unable to render source: {s}", .{@errorName(err)});
    };
    return String.init(string_result.items);
}

export fn decl_source_html(decl_index: Decl.Index) String {
    const decl = decl_index.get();

    string_result.clearRetainingCapacity();
    decl.file.source_html(&string_result, decl.ast_node) catch |err| {
        fatal("unable to render source: {s}", .{@errorName(err)});
    };
    return String.init(string_result.items);
}

export fn decl_doctest_html(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    const walk = decl.file.walk() catch |err| {
        log.err("failed to walk: {s}", .{@errorName(err)});
        return String.init("");
    };
    const doctest_ast_node = walk.doctests.get(decl.ast_node) orelse
        return String.init("");

    string_result.clearRetainingCapacity();
    decl.file.source_html(&string_result, doctest_ast_node) catch |err| {
        fatal("unable to render source: {s}", .{@errorName(err)});
    };
    return String.init(string_result.items);
}

export fn decl_fqn(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    decl.fqn(&string_result) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_parent(decl_index: Decl.Index) Decl.Index {
    const decl = decl_index.get();
    return decl.parent;
}

export fn decl_file_path(decl_index: Decl.Index) String {
    string_result.clearRetainingCapacity();
    string_result.appendSlice(gpa, decl_index.get().file.path()) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_category_name(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    const ast = decl.file.ast();
    const token_tags = ast.tokens.items(.tag);
    const name = switch (decl.categorize()) {
        .namespace => |node| {
            const node_tags = ast.nodes.items(.tag);
            if (node_tags[decl.ast_node] == .root)
                return String.init("struct");
            string_result.clearRetainingCapacity();
            var buf: [2]Ast.Node.Index = undefined;
            const container_decl = ast.fullContainerDecl(&buf, node).?;
            if (container_decl.layout_token) |t| {
                if (token_tags[t] == .keyword_extern) {
                    string_result.appendSlice(gpa, "extern ") catch @panic("OOM");
                }
            }
            const main_token_tag = token_tags[container_decl.ast.main_token];
            string_result.appendSlice(gpa, main_token_tag.lexeme().?) catch @panic("OOM");
            return String.init(string_result.items);
        },
        .global_variable => "Global Variable",
        .function => "Function",
        .type => "Type",
        .error_set => "Error Set",
        .global_const => "Constant",
        .primitive => "Primitive Value",
        .alias => "Alias",
    };
    return String.init(name);
}

export fn decl_name(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    string_result.clearRetainingCapacity();
    const name = n: {
        if (decl.parent == .none) {
            // Then it is the root struct of a file.
            break :n std.fs.path.stem(decl.file.path());
        }
        break :n decl.extra_info().name;
    };
    string_result.appendSlice(gpa, name) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_docs_html(decl_index: Decl.Index, short: bool) String {
    const decl = decl_index.get();
    const ast = decl.file.ast();
    string_result.clearRetainingCapacity();
    render_docs(&string_result, ast, decl.extra_info().first_doc_comment, short) catch @panic("OOM");
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
    while (true) : (it += 1) switch (token_tags[it]) {
        .doc_comment, .container_doc_comment => {
            // It is tempting to trim this string but think carefully about how
            // that will affect the markdown parser.
            const line = ast.tokenSlice(it)[3..];
            try list.appendSlice(gpa, line);
        },
        else => break,
    };
}

fn render_docs(
    out: *std.ArrayListUnmanaged(u8),
    ast: *const Ast,
    first_doc_comment: Ast.TokenIndex,
    short: bool,
) Oom!void {
    const token_tags = ast.tokens.items(.tag);

    var parser = try markdown.Parser.init(gpa);
    defer parser.deinit();
    var it = first_doc_comment;
    while (true) : (it += 1) switch (token_tags[it]) {
        .doc_comment, .container_doc_comment => {
            const line = ast.tokenSlice(it)[3..];
            if (short and line.len == 0) break;
            try parser.feedLine(line);
        },
        else => break,
    };

    var parsed_doc = try parser.endInput();
    defer parsed_doc.deinit(gpa);

    const Writer = std.ArrayListUnmanaged(u8).Writer;
    const Renderer = markdown.Renderer(Writer, void);
    const renderer: Renderer = .{
        .context = {},
        .renderFn = struct {
            fn render(
                r: Renderer,
                doc: markdown.Document,
                node: markdown.Document.Node.Index,
                writer: Writer,
            ) !void {
                const data = doc.nodes.items(.data)[@intFromEnum(node)];
                switch (doc.nodes.items(.tag)[@intFromEnum(node)]) {
                    // TODO: detect identifier references (dotted paths) in
                    // these three node types and render them appropriately.
                    // Also, syntax highlighting can be applied in code blocks
                    // unless the tag says otherwise.
                    .code_block => {
                        const tag = doc.string(data.code_block.tag);
                        _ = tag;
                        const content = doc.string(data.code_block.content);
                        try writer.print("<pre><code>{}</code></pre>\n", .{markdown.fmtHtml(content)});
                    },
                    .code_span => {
                        const content = doc.string(data.text.content);
                        try writer.print("<code>{}</code>", .{markdown.fmtHtml(content)});
                    },
                    .text => {
                        const content = doc.string(data.text.content);
                        try writer.print("{}", .{markdown.fmtHtml(content)});
                    },

                    else => try Renderer.renderDefault(r, doc, node, writer),
                }
            }
        }.render,
    };
    try renderer.render(parsed_doc, out.writer(gpa));
}

export fn decl_type_html(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    const ast = decl.file.ast();
    string_result.clearRetainingCapacity();
    _ = ast; // TODO
    string_result.appendSlice(gpa, "TODO_type_here") catch @panic("OOM");
    return String.init(string_result.items);
}

fn reset_with_decl_path(list: *std.ArrayListUnmanaged(u8), decl: *const Decl) Oom!void {
    list.clearRetainingCapacity();

    // Prefer the package name alias.
    for (packages.keys(), packages.values()) |pkg_name, pkg_file| {
        if (pkg_file == decl.file) {
            try list.ensureUnusedCapacity(gpa, pkg_name.len + 1);
            list.appendSliceAssumeCapacity(pkg_name);
            list.appendAssumeCapacity('.');
            return;
        }
    }

    const file_path = decl.file.path();
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

pub const FileIndex = enum(u32) {
    _,

    fn path(i: FileIndex) []const u8 {
        return files.keys()[@intFromEnum(i)];
    }

    fn ast(i: FileIndex) *Ast {
        return &files.values()[@intFromEnum(i)];
    }

    fn findRootDecl(file_index: FileIndex) Decl.Index {
        for (decls.items, 0..) |*decl, i| {
            if (decl.file == file_index and decl.ast_node == 0)
                return @enumFromInt(i);
        }
        return .none;
    }

    fn source_html(
        file: FileIndex,
        out: *std.ArrayListUnmanaged(u8),
        root_node: Ast.Node.Index,
    ) !void {
        const w = try file.walk();
        return Decl.walk_source_html(w, out, root_node);
    }

    fn walk(file: FileIndex) !*const Walk {
        const g = struct {
            var prev_walk: ?Walk = null;
            var arena_instance: std.heap.ArenaAllocator = undefined;
        };

        if (g.prev_walk) |*prev_walk| {
            if (prev_walk.file == file) {
                return prev_walk;
            }
            g.arena_instance.deinit();
        }

        g.arena_instance = std.heap.ArenaAllocator.init(gpa);

        g.prev_walk = .{
            .arena = g.arena_instance.allocator(),
            .token_links = .{},
            .token_parents = .{},
            .doctests = .{},
            .file = file,
            .ast = file.ast(),
        };
        const w = &g.prev_walk.?;
        try w.root();
        return w;
    }
};

const PackageIndex = enum(u32) {
    _,
};

pub const Decl = struct {
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

        fn get(i: Index) *Decl {
            return &decls.items[@intFromEnum(i)];
        }
    };

    fn add(d: Decl) !Index {
        try decls.append(gpa, d);
        return @enumFromInt(decls.items.len - 1);
    }

    fn is_pub(d: *const Decl) bool {
        return d.extra_info().is_pub;
    }

    fn extra_info(d: *const Decl) ExtraInfo {
        const ast = d.file.ast();
        const token_tags = ast.tokens.items(.tag);
        const node_tags = ast.nodes.items(.tag);
        switch (node_tags[d.ast_node]) {
            .root => return .{
                .name = "",
                .is_pub = true,
                .first_doc_comment = if (token_tags[0] == .container_doc_comment)
                    0
                else
                    token_tags.len - 1,
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

    fn value_node(d: *const Decl) ?Ast.Node.Index {
        const ast = d.file.ast();
        const node_tags = ast.nodes.items(.tag);
        const token_tags = ast.tokens.items(.tag);
        return switch (node_tags[d.ast_node]) {
            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            .root,
            => d.ast_node,

            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const var_decl = ast.fullVarDecl(d.ast_node).?;
                if (token_tags[var_decl.ast.mut_token] == .keyword_const)
                    return var_decl.ast.init_node;

                return null;
            },

            else => null,
        };
    }

    fn walk_source_html(
        walk: *const Walk,
        out: *std.ArrayListUnmanaged(u8),
        root_node: Ast.Node.Index,
    ) !void {
        const ast = walk.file.ast();

        const g = struct {
            var field_access_buffer: std.ArrayListUnmanaged(u8) = .{};
        };

        const token_tags = ast.tokens.items(.tag);
        const token_starts = ast.tokens.items(.start);

        const start_token = ast.firstToken(root_node);
        const end_token = ast.lastToken(root_node) + 1;

        var cursor: usize = token_starts[start_token];

        for (
            token_tags[start_token..end_token],
            token_starts[start_token..end_token],
            start_token..,
        ) |tag, start, token_index| {
            const between = ast.source[cursor..start];
            try appendEscaped(out, between);
            if (tag == .eof) break;
            const slice = ast.tokenSlice(token_index);
            cursor = start + slice.len;
            switch (tag) {
                .eof => unreachable,

                .keyword_addrspace,
                .keyword_align,
                .keyword_and,
                .keyword_asm,
                .keyword_async,
                .keyword_await,
                .keyword_break,
                .keyword_catch,
                .keyword_comptime,
                .keyword_const,
                .keyword_continue,
                .keyword_defer,
                .keyword_else,
                .keyword_enum,
                .keyword_errdefer,
                .keyword_error,
                .keyword_export,
                .keyword_extern,
                .keyword_for,
                .keyword_if,
                .keyword_inline,
                .keyword_noalias,
                .keyword_noinline,
                .keyword_nosuspend,
                .keyword_opaque,
                .keyword_or,
                .keyword_orelse,
                .keyword_packed,
                .keyword_anyframe,
                .keyword_pub,
                .keyword_resume,
                .keyword_return,
                .keyword_linksection,
                .keyword_callconv,
                .keyword_struct,
                .keyword_suspend,
                .keyword_switch,
                .keyword_test,
                .keyword_threadlocal,
                .keyword_try,
                .keyword_union,
                .keyword_unreachable,
                .keyword_usingnamespace,
                .keyword_var,
                .keyword_volatile,
                .keyword_allowzero,
                .keyword_while,
                .keyword_anytype,
                .keyword_fn,
                => {
                    try out.appendSlice(gpa, "<span class=\"tok-kw\">");
                    try appendEscaped(out, slice);
                    try out.appendSlice(gpa, "</span>");
                },

                .string_literal,
                .char_literal,
                .multiline_string_literal_line,
                => {
                    try out.appendSlice(gpa, "<span class=\"tok-str\">");
                    try appendEscaped(out, slice);
                    try out.appendSlice(gpa, "</span>");
                },

                .builtin => {
                    try out.appendSlice(gpa, "<span class=\"tok-builtin\">");
                    try appendEscaped(out, slice);
                    try out.appendSlice(gpa, "</span>");
                },

                .doc_comment,
                .container_doc_comment,
                => {
                    try out.appendSlice(gpa, "<span class=\"tok-comment\">");
                    try appendEscaped(out, slice);
                    try out.appendSlice(gpa, "</span>");
                },

                .identifier => {
                    if (std.mem.eql(u8, slice, "undefined") or
                        std.mem.eql(u8, slice, "null") or
                        std.mem.eql(u8, slice, "true") or
                        std.mem.eql(u8, slice, "false"))
                    {
                        try out.appendSlice(gpa, "<span class=\"tok-null\">");
                        try appendEscaped(out, slice);
                        try out.appendSlice(gpa, "</span>");
                    } else if (std.zig.primitives.isPrimitive(slice)) {
                        try out.appendSlice(gpa, "<span class=\"tok-type\">");
                        try appendEscaped(out, slice);
                        try out.appendSlice(gpa, "</span>");
                    } else if (walk.token_links.get(token_index)) |var_node| {
                        g.field_access_buffer.clearRetainingCapacity();
                        try resolve_var_link(walk, &g.field_access_buffer, var_node);
                        try out.appendSlice(gpa, "<a href=\"#");
                        try out.appendSlice(gpa, g.field_access_buffer.items); // TODO url escape
                        try out.appendSlice(gpa, "\">");
                        try appendEscaped(out, slice);
                        try out.appendSlice(gpa, "</a>");
                    } else if (walk.token_parents.get(token_index)) |field_access_node| {
                        g.field_access_buffer.clearRetainingCapacity();
                        try walk_field_accesses(walk, &g.field_access_buffer, field_access_node);
                        if (g.field_access_buffer.items.len > 0) {
                            try out.appendSlice(gpa, "<a href=\"#");
                            try out.appendSlice(gpa, g.field_access_buffer.items); // TODO url escape
                            try out.appendSlice(gpa, "\">");
                            try appendEscaped(out, slice);
                            try out.appendSlice(gpa, "</a>");
                        } else {
                            try appendEscaped(out, slice);
                        }
                    } else {
                        try appendEscaped(out, slice);
                    }
                },

                .number_literal => {
                    try out.appendSlice(gpa, "<span class=\"tok-number\">");
                    try appendEscaped(out, slice);
                    try out.appendSlice(gpa, "</span>");
                },

                .bang,
                .pipe,
                .pipe_pipe,
                .pipe_equal,
                .equal,
                .equal_equal,
                .equal_angle_bracket_right,
                .bang_equal,
                .l_paren,
                .r_paren,
                .semicolon,
                .percent,
                .percent_equal,
                .l_brace,
                .r_brace,
                .l_bracket,
                .r_bracket,
                .period,
                .period_asterisk,
                .ellipsis2,
                .ellipsis3,
                .caret,
                .caret_equal,
                .plus,
                .plus_plus,
                .plus_equal,
                .plus_percent,
                .plus_percent_equal,
                .plus_pipe,
                .plus_pipe_equal,
                .minus,
                .minus_equal,
                .minus_percent,
                .minus_percent_equal,
                .minus_pipe,
                .minus_pipe_equal,
                .asterisk,
                .asterisk_equal,
                .asterisk_asterisk,
                .asterisk_percent,
                .asterisk_percent_equal,
                .asterisk_pipe,
                .asterisk_pipe_equal,
                .arrow,
                .colon,
                .slash,
                .slash_equal,
                .comma,
                .ampersand,
                .ampersand_equal,
                .question_mark,
                .angle_bracket_left,
                .angle_bracket_left_equal,
                .angle_bracket_angle_bracket_left,
                .angle_bracket_angle_bracket_left_equal,
                .angle_bracket_angle_bracket_left_pipe,
                .angle_bracket_angle_bracket_left_pipe_equal,
                .angle_bracket_right,
                .angle_bracket_right_equal,
                .angle_bracket_angle_bracket_right,
                .angle_bracket_angle_bracket_right_equal,
                .tilde,
                => try appendEscaped(out, slice),

                .invalid, .invalid_periodasterisks => return error.InvalidToken,
            }
        }
    }

    fn resolve_var_link(
        w: *const Walk,
        out: *std.ArrayListUnmanaged(u8),
        node: Ast.Node.Index,
    ) Oom!void {
        const file_index = w.file;
        const ast = w.ast;
        //const main_tokens = ast.nodes.items(.main_token);
        if (ast.fullVarDecl(node)) |vd| switch (categorize_expr(file_index, vd.ast.init_node)) {
            .alias => |decl_index| {
                try decl_index.get().fqn(out);
            },
            else => {
                try out.writer(gpa).print("src/{s}#N{d}", .{
                    file_index.path(), node,
                });
                //const name_token = main_tokens[node] + 1;
                //const name = ast.tokenSlice(name_token);
                //try out.appendSlice(gpa, name);
            },
        } else {
            log.debug("TODO resolve_var_link fn decl", .{});
        }
    }

    fn walk_field_accesses(
        w: *const Walk,
        out: *std.ArrayListUnmanaged(u8),
        node: Ast.Node.Index,
    ) Oom!void {
        const ast = w.ast;
        const node_tags = ast.nodes.items(.tag);
        assert(node_tags[node] == .field_access);
        const node_datas = ast.nodes.items(.data);
        const main_tokens = ast.nodes.items(.main_token);
        const object_node = node_datas[node].lhs;
        const dot_token = main_tokens[node];
        const field_ident = dot_token + 1;
        switch (node_tags[object_node]) {
            .identifier => {
                const lhs_ident = main_tokens[object_node];
                if (w.token_links.get(lhs_ident)) |var_node| {
                    try resolve_var_link(w, out, var_node);
                }
            },
            .field_access => {
                try walk_field_accesses(w, out, object_node);
            },
            else => {},
        }
        if (out.items.len > 0) {
            try out.append(gpa, '.');
            try out.appendSlice(gpa, ast.tokenSlice(field_ident));
        }
    }

    /// keep in sync with "CAT_" constants in main.js
    const Category = union(enum(u8)) {
        namespace: Ast.Node.Index,
        global_variable: Ast.Node.Index,
        function: Ast.Node.Index,
        primitive: Ast.Node.Index,
        error_set: Ast.Node.Index,
        global_const: Ast.Node.Index,
        alias: Decl.Index,
        type,

        const Tag = @typeInfo(Category).Union.tag_type.?;
    };

    fn categorize(decl: *const Decl) Category {
        const file_index: FileIndex = decl.file;
        const ast = file_index.ast();
        const node_tags = ast.nodes.items(.tag);
        const token_tags = ast.tokens.items(.tag);
        switch (node_tags[decl.ast_node]) {
            .root => return .{ .namespace = decl.ast_node },

            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const var_decl = ast.fullVarDecl(decl.ast_node).?;
                if (token_tags[var_decl.ast.mut_token] == .keyword_var)
                    return .{ .global_variable = decl.ast_node };

                return categorize_expr(file_index, var_decl.ast.init_node);
            },

            .fn_proto,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto_simple,
            .fn_decl,
            => return .{ .function = decl.ast_node },

            else => unreachable,
        }
    }

    fn categorize_expr(file_index: FileIndex, node: Ast.Node.Index) Category {
        const ast = file_index.ast();
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
            => .{ .namespace = node },

            .error_set_decl,
            => .{ .error_set = node },

            .identifier => {
                const name_token = ast.nodes.items(.main_token)[node];
                const ident_name = ast.tokenSlice(name_token);
                if (std.zig.primitives.isPrimitive(ident_name)) {
                    return .{ .primitive = node };
                }
                // TODO:
                //return .alias;
                return .{ .global_const = node };
            },

            .field_access => {
                // TODO:
                //return .alias;
                return .{ .global_const = node };
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

            else => .{ .global_const = node },
        };
    }

    fn categorize_builtin_call(
        file_index: FileIndex,
        node: Ast.Node.Index,
        params: []const Ast.Node.Index,
    ) Category {
        const ast = file_index.ast();
        const main_tokens = ast.nodes.items(.main_token);
        const builtin_token = main_tokens[node];
        const builtin_name = ast.tokenSlice(builtin_token);
        if (std.mem.eql(u8, builtin_name, "@import")) {
            const str_lit_token = main_tokens[params[0]];
            const str_bytes = ast.tokenSlice(str_lit_token);
            const file_path = std.zig.string_literal.parseAlloc(gpa, str_bytes) catch @panic("OOM");
            defer gpa.free(file_path);
            const base_path = file_index.path();
            const resolved_path = std.fs.path.resolvePosix(gpa, &.{
                base_path, "..", file_path,
            }) catch @panic("OOM");
            defer gpa.free(resolved_path);
            log.debug("from '{s}' @import '{s}' resolved='{s}'", .{
                base_path, file_path, resolved_path,
            });
            if (files.getIndex(resolved_path)) |imported_file_index| {
                return .{ .alias = FileIndex.findRootDecl(@enumFromInt(imported_file_index)) };
            } else {
                log.warn("import target '{s}' did not resolve to any file", .{resolved_path});
            }
        }

        return .{ .global_const = node };
    }

    fn fqn(decl: *const Decl, out: *std.ArrayListUnmanaged(u8)) Oom!void {
        try reset_with_decl_path(out, decl);
        if (decl.parent != .none) {
            try append_parent_ns(out, decl.parent);
            try out.appendSlice(gpa, decl.extra_info().name);
        } else {
            out.items.len -= 1; // remove the trailing '.'
        }
    }

    fn append_parent_ns(list: *std.ArrayListUnmanaged(u8), parent: Decl.Index) Oom!void {
        assert(parent != .none);
        const decl = parent.get();
        if (decl.parent != .none) {
            try append_parent_ns(list, decl.parent);
            try list.appendSlice(gpa, decl.extra_info().name);
            try list.append(gpa, '.');
        }
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
    const ast = file_index.ast();

    if (ast.errors.len > 0) {
        // TODO: expose this in the UI
        log.err("can't index '{s}' because it has syntax errors", .{file_index.path()});
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
    const ast = file_index.ast();
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

            else => continue,
        }
    }
}

fn index_expr(file_index: FileIndex, parent_decl: Decl.Index, node: Ast.Node.Index) Oom!void {
    const ast = file_index.ast();
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

/// Looks up the root struct decl corresponding to a file by path.
/// Uses `input_string`.
export fn find_file_root() Decl.Index {
    const file: FileIndex = @enumFromInt(files.getIndex(input_string.items) orelse return .none);
    return file.findRootDecl();
}

/// Uses `input_string`.
export fn find_decl() Decl.Index {
    const g = struct {
        var match_fqn: std.ArrayListUnmanaged(u8) = .{};
    };
    for (decls.items, 0..) |*decl, decl_index| {
        decl.fqn(&g.match_fqn) catch @panic("OOM");
        if (std.mem.eql(u8, g.match_fqn.items, input_string.items)) {
            //const path = @as(Decl.Index, @enumFromInt(decl_index)).get().file.path();
            //log.debug("find_decl '{s}' found in {s}", .{ input_string.items, path });
            return @enumFromInt(decl_index);
        }
    }
    return .none;
}

/// Set only by `categorize_decl`; read only by `get_aliasee`, valid only
/// when `categorize_decl` returns `.alias`.
var global_aliasee: Decl.Index = .none;

export fn get_aliasee() Decl.Index {
    return global_aliasee;
}
export fn categorize_decl(decl_index: Decl.Index, resolve_alias_count: usize) Decl.Category.Tag {
    global_aliasee = .none;
    var chase_alias_n = resolve_alias_count;
    var decl = decl_index.get();
    while (true) {
        const result = decl.categorize();
        switch (decl.categorize()) {
            .alias => |new_index| {
                assert(new_index != .none);
                global_aliasee = new_index;
                if (chase_alias_n > 0) {
                    chase_alias_n -= 1;
                    decl = new_index.get();
                    continue;
                }
            },
            else => {},
        }
        return result;
    }
}

export fn namespace_members(parent: Decl.Index, include_private: bool) Slice(Decl.Index) {
    const g = struct {
        var members: std.ArrayListUnmanaged(Decl.Index) = .{};
    };

    g.members.clearRetainingCapacity();

    for (decls.items, 0..) |*decl, i| {
        if (decl.parent == parent) {
            if (include_private or decl.is_pub()) {
                g.members.append(gpa, @enumFromInt(i)) catch @panic("OOM");
            }
        }
    }

    return Slice(Decl.Index).init(g.members.items);
}

fn appendEscaped(out: *std.ArrayListUnmanaged(u8), s: []const u8) !void {
    for (s) |c| {
        try out.ensureUnusedCapacity(gpa, 6);
        switch (c) {
            '&' => out.appendSliceAssumeCapacity("&amp;"),
            '<' => out.appendSliceAssumeCapacity("&lt;"),
            '>' => out.appendSliceAssumeCapacity("&gt;"),
            '"' => out.appendSliceAssumeCapacity("&quot;"),
            else => out.appendAssumeCapacity(c),
        }
    }
}

fn count_scalar(haystack: []const u8, needle: u8) usize {
    var total: usize = 0;
    for (haystack) |elem| {
        if (elem == needle)
            total += 1;
    }
    return total;
}
