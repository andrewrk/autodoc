//! Find and annotate identifiers with links to their declarations.

arena: std.mem.Allocator,
token_links: std.AutoArrayHashMapUnmanaged(Ast.TokenIndex, Ast.Node.Index),
token_parents: std.AutoArrayHashMapUnmanaged(Ast.TokenIndex, Ast.Node.Index),
decl: *const @import("main.zig").Decl,
ast: *const Ast,

pub fn root(w: *Walk) !void {
    var scope: Scope = .{ .tag = .top };
    try struct_decl(w, &scope, w.ast.containerDeclRoot());
}

const Scope = struct {
    tag: Tag,

    const Tag = enum { top, local, namespace };

    const Local = struct {
        base: Scope = .{ .tag = .local },
        parent: *Scope,
        var_node: Ast.Node.Index,
    };

    const Namespace = struct {
        base: Scope = .{ .tag = .namespace },
        parent: *Scope,
        names: std.StringArrayHashMapUnmanaged(Ast.Node.Index) = .{},
    };

    fn lookup(start_scope: *Scope, ast: *const Ast, name: []const u8) ?Ast.Node.Index {
        const main_tokens = ast.nodes.items(.main_token);
        var it: *Scope = start_scope;
        while (true) switch (it.tag) {
            .top => break,
            .local => {
                const local = @fieldParentPtr(Local, "base", it);
                const name_token = main_tokens[local.var_node] + 1;
                const ident_name = ast.tokenSlice(name_token);
                if (std.mem.eql(u8, ident_name, name)) {
                    return local.var_node;
                }
                it = local.parent;
            },
            .namespace => {
                const namespace = @fieldParentPtr(Namespace, "base", it);
                if (namespace.names.get(name)) |node| {
                    return node;
                }
                it = namespace.parent;
            },
        };
        return null;
    }
};

const Oom = error{OutOfMemory};

fn struct_decl(
    w: *Walk,
    scope: *Scope,
    container_decl: Ast.full.ContainerDecl,
) Oom!void {
    const ast = w.ast;
    const node_tags = ast.nodes.items(.tag);
    const node_datas = ast.nodes.items(.data);

    var namespace: Scope.Namespace = .{
        .parent = scope,
    };
    try w.scanDecls(&namespace, container_decl.ast.members);

    for (container_decl.ast.members) |member| switch (node_tags[member]) {
        .container_field_init,
        .container_field_align,
        .container_field,
        => try w.container_field(&namespace.base, ast.fullContainerField(member).?),

        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const full = ast.fullFnProto(&buf, member).?;
            const body = if (node_tags[member] == .fn_decl) node_datas[member].rhs else 0;
            try w.fn_decl(&namespace.base, body, full);
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => try w.global_var_decl(&namespace.base, ast.fullVarDecl(member).?),

        .@"comptime",
        .@"usingnamespace",
        => try w.expr(&namespace.base, node_datas[member].lhs),

        .test_decl => try w.expr(&namespace.base, node_datas[member].rhs),

        else => unreachable,
    };
}

fn comptime_decl(
    w: *Walk,
    scope: *Scope,
    full: Ast.full.VarDecl,
) Oom!void {
    try w.expr(scope, full.ast.type_node);
    try w.maybe_expr(scope, full.ast.align_node);
    try w.maybe_expr(scope, full.ast.addrspace_node);
    try w.maybe_expr(scope, full.ast.section_node);
    try w.expr(scope, full.ast.init_node);
}

fn global_var_decl(
    w: *Walk,
    scope: *Scope,
    full: Ast.full.VarDecl,
) Oom!void {
    try w.maybe_expr(scope, full.ast.type_node);
    try w.maybe_expr(scope, full.ast.align_node);
    try w.maybe_expr(scope, full.ast.addrspace_node);
    try w.maybe_expr(scope, full.ast.section_node);
    try w.expr(scope, full.ast.init_node);
}

fn container_field(
    w: *Walk,
    scope: *Scope,
    full: Ast.full.ContainerField,
) Oom!void {
    try w.maybe_expr(scope, full.ast.type_expr);
    try w.maybe_expr(scope, full.ast.align_expr);
    try w.maybe_expr(scope, full.ast.value_expr);
}

fn fn_decl(
    w: *Walk,
    scope: *Scope,
    body: Ast.Node.Index,
    full: Ast.full.FnProto,
) Oom!void {
    for (full.ast.params) |param| {
        try expr(w, scope, param);
    }
    try expr(w, scope, full.ast.return_type);
    try maybe_expr(w, scope, full.ast.align_expr);
    try maybe_expr(w, scope, full.ast.addrspace_expr);
    try maybe_expr(w, scope, full.ast.section_expr);
    try maybe_expr(w, scope, full.ast.callconv_expr);
    try maybe_expr(w, scope, body);
}

fn maybe_expr(w: *Walk, scope: *Scope, node: Ast.Node.Index) Oom!void {
    if (node != 0) return expr(w, scope, node);
}

fn expr(w: *Walk, scope: *Scope, node: Ast.Node.Index) Oom!void {
    assert(node != 0);
    const arena = w.arena;
    const ast = w.ast;
    const node_tags = ast.nodes.items(.tag);
    const node_datas = ast.nodes.items(.data);
    const main_tokens = ast.nodes.items(.main_token);
    switch (node_tags[node]) {
        .root => unreachable, // Top-level declaration.
        .@"usingnamespace" => unreachable, // Top-level declaration.
        .test_decl => unreachable, // Top-level declaration.
        .container_field_init => unreachable, // Top-level declaration.
        .container_field_align => unreachable, // Top-level declaration.
        .container_field => unreachable, // Top-level declaration.
        .fn_decl => unreachable, // Top-level declaration.

        .global_var_decl => unreachable, // Handled in `block`.
        .local_var_decl => unreachable, // Handled in `block`.
        .simple_var_decl => unreachable, // Handled in `block`.
        .aligned_var_decl => unreachable, // Handled in `block`.
        .@"defer" => unreachable, // Handled in `block`.
        .@"errdefer" => unreachable, // Handled in `block`.

        .switch_case => unreachable, // Handled in `switchExpr`.
        .switch_case_inline => unreachable, // Handled in `switchExpr`.
        .switch_case_one => unreachable, // Handled in `switchExpr`.
        .switch_case_inline_one => unreachable, // Handled in `switchExpr`.
        .switch_range => unreachable, // Handled in `switchExpr`.

        .asm_output => unreachable, // Handled in `asmExpr`.
        .asm_input => unreachable, // Handled in `asmExpr`.

        .for_range => unreachable, // Handled in `forExpr`.

        .assign,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_or,
        .assign_bit_xor,
        .assign_div,
        .assign_sub,
        .assign_sub_wrap,
        .assign_sub_sat,
        .assign_mod,
        .assign_add,
        .assign_add_wrap,
        .assign_add_sat,
        .assign_mul,
        .assign_mul_wrap,
        .assign_mul_sat,
        .shl,
        .shr,
        .add,
        .add_wrap,
        .add_sat,
        .sub,
        .sub_wrap,
        .sub_sat,
        .mul,
        .mul_wrap,
        .mul_sat,
        .div,
        .mod,
        .shl_sat,

        .bit_and,
        .bit_or,
        .bit_xor,
        .bang_equal,
        .equal_equal,
        .greater_than,
        .greater_or_equal,
        .less_than,
        .less_or_equal,
        .array_cat,

        .array_mult,
        .error_union,
        .merge_error_sets,
        .bool_and,
        .bool_or,
        .@"catch",
        .@"orelse",
        .array_type,
        .array_access,
        => {
            try expr(w, scope, node_datas[node].lhs);
            try expr(w, scope, node_datas[node].rhs);
        },

        .assign_destructure => {
            const extra_index = node_datas[node].lhs;
            const lhs_count = ast.extra_data[extra_index];
            const lhs_nodes: []const Ast.Node.Index = @ptrCast(ast.extra_data[extra_index + 1 ..][0..lhs_count]);
            const rhs = node_datas[node].rhs;
            for (lhs_nodes) |lhs_node| try expr(w, scope, lhs_node);
            _ = try expr(w, scope, rhs);
        },

        .bool_not,
        .bit_not,
        .negation,
        .negation_wrap,
        .@"return",
        .deref,
        .address_of,
        .optional_type,
        .unwrap_optional,
        .grouped_expression,
        .@"comptime",
        .@"nosuspend",
        .@"suspend",
        .@"await",
        .@"resume",
        .@"try",
        => try maybe_expr(w, scope, node_datas[node].lhs),

        .anyframe_type,
        .@"break",
        => try maybe_expr(w, scope, node_datas[node].rhs),

        .identifier => {
            const ident_token = main_tokens[node];
            const ident_name = ast.tokenSlice(ident_token);
            if (scope.lookup(ast, ident_name)) |var_node| {
                try w.token_links.put(arena, ident_token, var_node);
            }
        },
        .field_access => {
            const object_node = node_datas[node].lhs;
            const dot_token = main_tokens[node];
            const field_ident = dot_token + 1;
            try w.token_parents.put(arena, field_ident, node);
            // This will populate the left-most field object if it is an
            // identifier, allowing rendering code to piece together the link.
            try expr(w, scope, object_node);
        },

        .string_literal,
        .multiline_string_literal,
        .number_literal,
        .unreachable_literal,
        .enum_literal,
        .error_value,
        .anyframe_literal,
        .@"continue",
        .char_literal,
        .error_set_decl,
        => {},

        .asm_simple,
        .@"asm",
        => {
            const full = ast.fullAsm(node).?;
            for (full.ast.items) |n| {
                // TODO handle .asm_input, .asm_output
                _ = n;
            }
            try expr(w, scope, full.ast.template);
        },

        .builtin_call_two, .builtin_call_two_comma => {
            if (node_datas[node].lhs == 0) {
                const params = [_]Ast.Node.Index{};
                return builtin_call(w, scope, &params);
            } else if (node_datas[node].rhs == 0) {
                const params = [_]Ast.Node.Index{node_datas[node].lhs};
                return builtin_call(w, scope, &params);
            } else {
                const params = [_]Ast.Node.Index{ node_datas[node].lhs, node_datas[node].rhs };
                return builtin_call(w, scope, &params);
            }
        },
        .builtin_call, .builtin_call_comma => {
            const params = ast.extra_data[node_datas[node].lhs..node_datas[node].rhs];
            return builtin_call(w, scope, params);
        },

        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const full = ast.fullCall(&buf, node).?;
            try expr(w, scope, full.ast.fn_expr);
            for (full.ast.params) |param| {
                try expr(w, scope, param);
            }
        },

        .if_simple,
        .@"if",
        => {
            const full = ast.fullIf(node).?;
            try expr(w, scope, full.ast.cond_expr);
            try expr(w, scope, full.ast.then_expr);
            try maybe_expr(w, scope, full.ast.else_expr);
        },

        .while_simple,
        .while_cont,
        .@"while",
        => {
            try while_expr(w, scope, ast.fullWhile(node).?);
        },

        .for_simple, .@"for" => {
            const full = ast.fullFor(node).?;
            for (full.ast.inputs) |input| {
                if (node_tags[input] == .for_range) {
                    try expr(w, scope, node_datas[input].lhs);
                    try maybe_expr(w, scope, node_datas[input].rhs);
                } else {
                    try expr(w, scope, input);
                }
            }
            try expr(w, scope, full.ast.then_expr);
            try maybe_expr(w, scope, full.ast.else_expr);
        },

        .slice => return slice(w, scope, ast.slice(node)),
        .slice_open => return slice(w, scope, ast.sliceOpen(node)),
        .slice_sentinel => return slice(w, scope, ast.sliceSentinel(node)),

        .block_two, .block_two_semicolon => {
            const statements = [2]Ast.Node.Index{ node_datas[node].lhs, node_datas[node].rhs };
            if (node_datas[node].lhs == 0) {
                return block(w, scope, statements[0..0]);
            } else if (node_datas[node].rhs == 0) {
                return block(w, scope, statements[0..1]);
            } else {
                return block(w, scope, statements[0..2]);
            }
        },
        .block, .block_semicolon => {
            const statements = ast.extra_data[node_datas[node].lhs..node_datas[node].rhs];
            return block(w, scope, statements);
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => {
            const full = ast.fullPtrType(node).?;
            try maybe_expr(w, scope, full.ast.align_node);
            try maybe_expr(w, scope, full.ast.addrspace_node);
            try maybe_expr(w, scope, full.ast.sentinel);
            try maybe_expr(w, scope, full.ast.bit_range_start);
            try maybe_expr(w, scope, full.ast.bit_range_end);
            try expr(w, scope, full.ast.child_type);
        },

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
            return struct_decl(w, scope, ast.fullContainerDecl(&buf, node).?);
        },

        .array_type_sentinel => {
            const extra = ast.extraData(node_datas[node].rhs, Ast.Node.ArrayTypeSentinel);
            try expr(w, scope, node_datas[node].lhs);
            try expr(w, scope, extra.elem_type);
            try expr(w, scope, extra.sentinel);
        },
        .@"switch", .switch_comma => {
            const operand_node = node_datas[node].lhs;
            try expr(w, scope, operand_node);
            const extra = ast.extraData(node_datas[node].rhs, Ast.Node.SubRange);
            const case_nodes = ast.extra_data[extra.start..extra.end];
            for (case_nodes) |case_node| {
                const case = ast.fullSwitchCase(case_node).?;
                for (case.ast.values) |value_node| {
                    try expr(w, scope, value_node);
                }
                try expr(w, scope, case.ast.target_expr);
            }
        },

        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const full = ast.fullArrayInit(&buf, node).?;
            try maybe_expr(w, scope, full.ast.type_expr);
            for (full.ast.elements) |elem| {
                try expr(w, scope, elem);
            }
        },

        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const full = ast.fullStructInit(&buf, node).?;
            try maybe_expr(w, scope, full.ast.type_expr);
            for (full.ast.fields) |field| {
                try expr(w, scope, field);
            }
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            return fn_decl(w, scope, 0, ast.fullFnProto(&buf, node).?);
        },
    }
}

fn slice(w: *Walk, scope: *Scope, full: Ast.full.Slice) Oom!void {
    try expr(w, scope, full.ast.sliced);
    try expr(w, scope, full.ast.start);
    try maybe_expr(w, scope, full.ast.end);
    try maybe_expr(w, scope, full.ast.sentinel);
}

fn builtin_call(w: *Walk, scope: *Scope, params: []const Ast.Node.Index) Oom!void {
    for (params) |node| {
        try expr(w, scope, node);
    }
}

fn block(w: *Walk, parent_scope: *Scope, statements: []const Ast.Node.Index) Oom!void {
    const ast = w.ast;
    const arena = w.arena;
    const node_tags = ast.nodes.items(.tag);
    const node_datas = ast.nodes.items(.data);

    var scope = parent_scope;

    for (statements) |node| {
        switch (node_tags[node]) {
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const full = ast.fullVarDecl(node).?;
                try global_var_decl(w, scope, full);
                const local = try arena.create(Scope.Local);
                local.* = .{
                    .parent = scope,
                    .var_node = node,
                };
                scope = &local.base;
            },

            .assign_destructure => {
                // TODO
            },

            .grouped_expression => try expr(w, scope, node_datas[node].lhs),

            .@"defer",
            .@"errdefer",
            => try expr(w, scope, node_datas[node].rhs),

            else => try expr(w, scope, node),
        }
    }
}

fn local_var_decl(
    w: *Walk,
    scope: *Scope,
    node: Ast.Node.Index,
    full: Ast.full.VarDecl,
) Oom!*Scope {
    try global_var_decl(w, scope, full);
    var local: Scope.Local = .{
        .parent = scope,
        .var_node = node,
    };
    return &local.base;
}

fn while_expr(w: *Walk, scope: *Scope, full: Ast.full.While) Oom!void {
    try expr(w, scope, full.ast.cond_expr);
    try maybe_expr(w, scope, full.ast.cont_expr);
    try expr(w, scope, full.ast.then_expr);
    try maybe_expr(w, scope, full.ast.else_expr);
}

fn scanDecls(w: *Walk, namespace: *Scope.Namespace, members: []const Ast.Node.Index) Oom!void {
    const arena = w.arena;
    const ast = w.ast;
    const node_tags = ast.nodes.items(.tag);
    const main_tokens = ast.nodes.items(.main_token);
    const token_tags = ast.tokens.items(.tag);

    for (members) |member_node| {
        const name_token = switch (node_tags[member_node]) {
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => main_tokens[member_node] + 1,

            .fn_proto_simple,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto,
            .fn_decl,
            => blk: {
                const ident = main_tokens[member_node] + 1;
                if (token_tags[ident] != .identifier) continue;
                break :blk ident;
            },

            else => continue,
        };

        const token_bytes = ast.tokenSlice(name_token);
        try namespace.names.put(arena, token_bytes, member_node);
    }
}

//test {
//    const gpa = std.testing.allocator;
//
//    var arena_instance = std.heap.ArenaAllocator.init(gpa);
//    defer arena_instance.deinit();
//    const arena = arena_instance.allocator();
//
//    // example test command:
//    // zig test --dep input.zig -Mroot=src/Walk.zig -Minput.zig=/home/andy/dev/zig/lib/std/fs/File.zig
//    var ast = try Ast.parse(gpa, @embedFile("input.zig"), .zig);
//    defer ast.deinit(gpa);
//
//    var w: Walk = .{
//        .arena = arena,
//        .token_links = .{},
//        .ast = &ast,
//    };
//
//    try w.root();
//}

const Walk = @This();
const std = @import("std");
const Ast = std.zig.Ast;
const assert = std.debug.assert;
