//! Example: Simple Storage Counter Contract
//! Demonstrates persistent storage, transient storage, and checkpoint/rollback

const std = @import("std");
const zvm = @import("zvm");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n╔════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║  ZVM Storage Demo - Counter Contract                  ║\n", .{});
    std.debug.print("╚════════════════════════════════════════════════════════╝\n\n", .{});

    // Initialize storage backends
    var state = zvm.JournaledState.init(allocator);
    defer state.deinit();
    var transient_storage = zvm.TransientStorageImpl.init(allocator);
    defer transient_storage.deinit();

    // Counter contract bytecode:
    // Load counter from slot 0, add 1, store back
    // PUSH1 0, SLOAD, PUSH1 1, ADD, PUSH1 0, SSTORE, HALT
    const counter_bytecode = [_]u8{
        @intFromEnum(zvm.Opcode.PUSH1), 0,    // Push key (slot 0)
        @intFromEnum(zvm.Opcode.SLOAD),       // Load current counter value
        @intFromEnum(zvm.Opcode.PUSH1), 1,    // Push 1
        @intFromEnum(zvm.Opcode.ADD),         // Increment counter
        @intFromEnum(zvm.Opcode.PUSH1), 0,    // Push key (slot 0) for storage
        @intFromEnum(zvm.Opcode.SSTORE),      // Store new counter value
        @intFromEnum(zvm.Opcode.HALT),
    };

    std.debug.print("Contract: Simple Counter\n", .{});
    std.debug.print("  - Stores counter in slot 0\n", .{});
    std.debug.print("  - Increments by 1 each call\n", .{});
    std.debug.print("  - Demonstrates persistent storage\n\n", .{});

    std.debug.print("Bytecode: ", .{});
    for (counter_bytecode) |byte| {
        std.debug.print("{X:0>2} ", .{byte});
    }
    std.debug.print("\n\n", .{});

    // Execute contract 5 times
    std.debug.print("Executing contract 5 times...\n", .{});
    std.debug.print("────────────────────────────────────────────────────────\n", .{});

    for (0..5) |i| {
        var vm = zvm.VM.init(allocator, 100000, state.asStorage(), transient_storage.asTransientStorage(), null);
        defer vm.deinit();

        vm.loadBytecode(&counter_bytecode);
        const result = try vm.execute();

        std.debug.print("Call #{d}: Gas used = {d:>5}, Counter = ", .{ i + 1, result.gas_used });

        // Read the counter value from storage
        const storage = state.asStorage();
        const addr = zvm.Address.zero();
        const counter_value = storage.load(addr, zvm.U256.fromU64(0));
        std.debug.print("{d}\n", .{counter_value.toU64()});
    }

    std.debug.print("\n╔════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║  Demonstrating Checkpoint/Rollback                    ║\n", .{});
    std.debug.print("╚════════════════════════════════════════════════════════╝\n\n", .{});

    const storage = state.asStorage();
    const addr = zvm.Address.zero();

    std.debug.print("Current counter value: {d}\n\n", .{storage.load(addr, zvm.U256.fromU64(0)).toU64()});

    // Create checkpoint and modify
    std.debug.print("Creating checkpoint...\n", .{});
    storage.checkpoint();

    // Execute contract twice with checkpoint
    std.debug.print("Executing contract 2 more times (in checkpoint)...\n", .{});
    for (0..2) |_| {
        var vm = zvm.VM.init(allocator, 100000, state.asStorage(), transient_storage.asTransientStorage(), null);
        defer vm.deinit();
        vm.loadBytecode(&counter_bytecode);
        _ = try vm.execute();
    }

    std.debug.print("Counter in checkpoint: {d}\n\n", .{storage.load(addr, zvm.U256.fromU64(0)).toU64()});

    // Rollback the checkpoint
    std.debug.print("Rolling back checkpoint...\n", .{});
    storage.rollback();

    std.debug.print("Counter after rollback: {d}\n", .{storage.load(addr, zvm.U256.fromU64(0)).toU64()});
    std.debug.print("  (Changes reverted successfully!)\n\n", .{});

    // Demonstrate transient storage
    std.debug.print("╔════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║  Demonstrating Transient Storage (EIP-1153)           ║\n", .{});
    std.debug.print("╚════════════════════════════════════════════════════════╝\n\n", .{});

    // Transient storage example: PUSH1 99, PUSH1 5, TSTORE, PUSH1 5, TLOAD
    const transient_bytecode = [_]u8{
        @intFromEnum(zvm.Opcode.PUSH1), 99,   // Value to store
        @intFromEnum(zvm.Opcode.PUSH1), 5,    // Key
        @intFromEnum(zvm.Opcode.TSTORE),      // Store in transient storage
        @intFromEnum(zvm.Opcode.PUSH1), 5,    // Key
        @intFromEnum(zvm.Opcode.TLOAD),       // Load from transient storage
        @intFromEnum(zvm.Opcode.HALT),
    };

    std.debug.print("Storing value 99 in transient slot 5...\n", .{});
    var vm_trans = zvm.VM.init(allocator, 100000, state.asStorage(), transient_storage.asTransientStorage(), null);
    defer vm_trans.deinit();
    vm_trans.loadBytecode(&transient_bytecode);
    _ = try vm_trans.execute();

    const loaded_value = try vm_trans.stack.peek(0);
    std.debug.print("Loaded value: {d}\n\n", .{loaded_value.toU64()});

    // Clear transient storage (simulating end of transaction)
    std.debug.print("Clearing transient storage (end of transaction)...\n", .{});
    const ts = transient_storage.asTransientStorage();
    ts.clear();

    const cleared_value = ts.load(addr, zvm.U256.fromU64(5));
    std.debug.print("Value after clear: {d}\n", .{cleared_value.toU64()});
    std.debug.print("  (Transient storage cleared successfully!)\n\n", .{});

    std.debug.print("════════════════════════════════════════════════════════\n", .{});
    std.debug.print("Storage Phase 2 Complete!\n", .{});
    std.debug.print("  ✓ Persistent storage with SLOAD/SSTORE\n", .{});
    std.debug.print("  ✓ Transient storage with TLOAD/TSTORE (EIP-1153)\n", .{});
    std.debug.print("  ✓ Checkpoint/commit/rollback for nested calls\n", .{});
    std.debug.print("  ✓ Cold/warm gas accounting (EIP-2929)\n", .{});
    std.debug.print("════════════════════════════════════════════════════════\n", .{});
}
