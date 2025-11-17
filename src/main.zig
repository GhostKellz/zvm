//! ZVM CLI - Execute ZVM bytecode from command line

const std = @import("std");
const zvm = @import("root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("╔════════════════════════════════════════════╗\n", .{});
    std.debug.print("║  ZVM - The Zig Virtual Machine v1.0.0     ║\n", .{});
    std.debug.print("║  Zero dependencies, maximum performance   ║\n", .{});
    std.debug.print("╚════════════════════════════════════════════╝\n\n", .{});

    // Demo: Simple arithmetic
    std.debug.print("Demo: Simple Arithmetic (42 + 8)\n", .{});
    std.debug.print("────────────────────────────────────────────\n", .{});

    // Bytecode: PUSH1 42, PUSH1 8, ADD, HALT
    const bytecode = [_]u8{
        @intFromEnum(zvm.Opcode.PUSH1), 42,
        @intFromEnum(zvm.Opcode.PUSH1), 8,
        @intFromEnum(zvm.Opcode.ADD),
        @intFromEnum(zvm.Opcode.HALT),
    };

    std.debug.print("Bytecode: ", .{});
    for (bytecode) |byte| {
        std.debug.print("{X:0>2} ", .{byte});
    }
    std.debug.print("\n\n", .{});

    // Initialize storage
    var state = zvm.JournaledState.init(allocator);
    defer state.deinit();
    var transient_storage = zvm.TransientStorageImpl.init(allocator);
    defer transient_storage.deinit();

    var vm = zvm.VM.init(allocator, 1_000_000, state.asStorage(), transient_storage.asTransientStorage(), null);
    defer vm.deinit();

    vm.loadBytecode(&bytecode);

    std.debug.print("Executing...\n", .{});
    const result = try vm.execute();

    std.debug.print("\n✓ Execution completed successfully!\n", .{});
    std.debug.print("  Gas used: {d}\n", .{result.gas_used});
    std.debug.print("  Stack depth: {d}\n", .{vm.stack.depth()});

    if (vm.stack.depth() > 0) {
        const top = try vm.stack.peek(0);
        std.debug.print("  Result: {d}\n", .{top.toU64()});
    }

    std.debug.print("\n════════════════════════════════════════════\n", .{});
    std.debug.print("ZVM is ready for KALIX compilation!\n", .{});
    std.debug.print("════════════════════════════════════════════\n", .{});
}
