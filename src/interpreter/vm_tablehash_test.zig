//! Comprehensive tests for TABLEHASH opcode
//! Used by KALIX for structured storage (tables with typed keys)

const std = @import("std");
const testing = std.testing;

const VM = @import("vm.zig").VM;
const Opcode = @import("../bytecode/opcode.zig").Opcode;
const U256 = @import("../primitives/types.zig").U256;

const journaled = @import("../state/journaled.zig");
const transient = @import("../state/transient.zig");

// =============================================================================
// TABLEHASH Tests
// =============================================================================

test "TABLEHASH basic operation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    var vm = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm.deinit();

    // Bytecode: PUSH32 key, PUSH32 table_slot, TABLEHASH, HALT
    const table_slot = U256.fromU64(42);
    const key = U256.fromU64(123);

    var slot_bytes = table_slot.toBytes();
    var key_bytes = key.toBytes();

    const bytecode = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode);
    const result = try vm.execute();

    try testing.expect(result.success);

    // Stack should contain hashed key
    const hashed_key = try vm.stack.peek(0);
    try testing.expect(!hashed_key.isZero());

    // Verify it's different from both inputs
    try testing.expect(!hashed_key.eql(table_slot));
    try testing.expect(!hashed_key.eql(key));
}

test "TABLEHASH deterministic hashing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    const table_slot = U256.fromU64(1);
    const key = U256.fromU64(100);

    var slot_bytes = table_slot.toBytes();
    var key_bytes = key.toBytes();

    const bytecode = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    // Execute twice with same inputs
    var vm1 = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm1.deinit();
    vm1.loadBytecode(&bytecode);
    _ = try vm1.execute();
    const hash1 = try vm1.stack.peek(0);

    var vm2 = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm2.deinit();
    vm2.loadBytecode(&bytecode);
    _ = try vm2.execute();
    const hash2 = try vm2.stack.peek(0);

    // Same inputs should produce same hash
    try testing.expect(hash1.eql(hash2));
}

test "TABLEHASH different keys produce different hashes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    const table_slot = U256.fromU64(1);
    const key1 = U256.fromU64(100);
    const key2 = U256.fromU64(101);

    var slot_bytes = table_slot.toBytes();
    var key1_bytes = key1.toBytes();
    var key2_bytes = key2.toBytes();

    // Test with key1
    const bytecode1 = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key1_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    var vm1 = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm1.deinit();
    vm1.loadBytecode(&bytecode1);
    _ = try vm1.execute();
    const hash1 = try vm1.stack.peek(0);

    // Test with key2
    const bytecode2 = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key2_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    var vm2 = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm2.deinit();
    vm2.loadBytecode(&bytecode2);
    _ = try vm2.execute();
    const hash2 = try vm2.stack.peek(0);

    // Different keys should produce different hashes
    try testing.expect(!hash1.eql(hash2));
}

test "TABLEHASH different table slots produce different hashes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    const slot1 = U256.fromU64(1);
    const slot2 = U256.fromU64(2);
    const key = U256.fromU64(100);

    var slot1_bytes = slot1.toBytes();
    var slot2_bytes = slot2.toBytes();
    var key_bytes = key.toBytes();

    // Test with slot1
    const bytecode1 = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot1_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    var vm1 = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm1.deinit();
    vm1.loadBytecode(&bytecode1);
    _ = try vm1.execute();
    const hash1 = try vm1.stack.peek(0);

    // Test with slot2
    const bytecode2 = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot2_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    var vm2 = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm2.deinit();
    vm2.loadBytecode(&bytecode2);
    _ = try vm2.execute();
    const hash2 = try vm2.stack.peek(0);

    // Different table slots should produce different hashes
    try testing.expect(!hash1.eql(hash2));
}

test "TABLEHASH with SSTORE and SLOAD" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    var vm = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm.deinit();

    const table_slot = U256.fromU64(5);
    const key = U256.fromU64(42);
    const value = U256.fromU64(9999);

    var slot_bytes = table_slot.toBytes();
    var key_bytes = key.toBytes();
    var value_bytes = value.toBytes();

    // Bytecode:
    // PUSH value, PUSH key, PUSH table_slot, TABLEHASH, SSTORE  (store)
    // PUSH key, PUSH table_slot, TABLEHASH, SLOAD               (load)
    // HALT
    const bytecode = [_]u8{
        // Store phase
        @intFromEnum(Opcode.PUSH32),
    } ++ value_bytes ++ [_]u8{
        @intFromEnum(Opcode.PUSH32),
    } ++ key_bytes ++ [_]u8{
        @intFromEnum(Opcode.PUSH32),
    } ++ slot_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.SSTORE),
        // Load phase
        @intFromEnum(Opcode.PUSH32),
    } ++ key_bytes ++ [_]u8{
        @intFromEnum(Opcode.PUSH32),
    } ++ slot_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.SLOAD),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode);
    const result = try vm.execute();

    try testing.expect(result.success);

    // Stack should contain loaded value
    const loaded = try vm.stack.peek(0);
    try testing.expect(loaded.eql(value));
}

test "TABLEHASH gas cost" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    var vm = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm.deinit();

    const table_slot = U256.fromU64(1);
    const key = U256.fromU64(1);

    var slot_bytes = table_slot.toBytes();
    var key_bytes = key.toBytes();

    const bytecode = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode);
    const result = try vm.execute();

    try testing.expect(result.success);

    // Gas should include: 2x PUSH32 (6 gas) + TABLEHASH (30 gas) = 36 gas minimum
    try testing.expect(result.gas_used >= 36);
}

test "TABLEHASH with large values" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    var vm = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm.deinit();

    // Use maximum U256 values
    const table_slot = U256.fromU64(std.math.maxInt(u64));
    const key = U256.fromU64(std.math.maxInt(u64));

    var slot_bytes = table_slot.toBytes();
    var key_bytes = key.toBytes();

    const bytecode = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode);
    const result = try vm.execute();

    try testing.expect(result.success);

    const hashed_key = try vm.stack.peek(0);
    try testing.expect(!hashed_key.isZero());
}

test "TABLEHASH collision resistance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    // Test that (slot=1, key=2) != (slot=2, key=1)
    const slot1 = U256.fromU64(1);
    const key1 = U256.fromU64(2);
    const slot2 = U256.fromU64(2);
    const key2 = U256.fromU64(1);

    var slot1_bytes = slot1.toBytes();
    var key1_bytes = key1.toBytes();
    var slot2_bytes = slot2.toBytes();
    var key2_bytes = key2.toBytes();

    // First combination
    const bytecode1 = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key1_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot1_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    var vm1 = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm1.deinit();
    vm1.loadBytecode(&bytecode1);
    _ = try vm1.execute();
    const hash1 = try vm1.stack.peek(0);

    // Second combination (swapped)
    const bytecode2 = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ key2_bytes ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ slot2_bytes ++ [_]u8{
        @intFromEnum(Opcode.TABLEHASH),
        @intFromEnum(Opcode.HALT),
    };

    var vm2 = VM.init(allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm2.deinit();
    vm2.loadBytecode(&bytecode2);
    _ = try vm2.execute();
    const hash2 = try vm2.stack.peek(0);

    // Swapped parameters should produce different hashes (collision resistance)
    try testing.expect(!hash1.eql(hash2));
}
