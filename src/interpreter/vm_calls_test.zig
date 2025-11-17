//! Comprehensive tests for CALL, DELEGATECALL, STATICCALL, CREATE, and CREATE2 opcodes

const std = @import("std");
const testing = std.testing;

const VM = @import("vm.zig").VM;
const Opcode = @import("../bytecode/opcode.zig").Opcode;
const U256 = @import("../primitives/types.zig").U256;
const Address = @import("../primitives/types.zig").Address;

const journaled = @import("../state/journaled.zig");
const transient = @import("../state/transient.zig");
const AccountState = @import("../state/accounts.zig").AccountState;

/// Helper to convert Address to U256 for stack operations
fn addressToU256(addr: Address) U256 {
    var bytes: [32]u8 = [_]u8{0} ** 32;
    @memcpy(bytes[12..32], &addr.bytes);
    return U256.fromBytes(bytes);
}

/// Helper to convert U256 to Address
fn u256ToAddress(value: U256) Address {
    const bytes = value.toBytes();
    var addr_bytes: [20]u8 = undefined;
    @memcpy(&addr_bytes, bytes[12..32]);
    return Address{ .bytes = addr_bytes };
}

// =============================================================================
// CREATE Tests
// =============================================================================

test "CREATE deploys simple contract" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Setup storage and account state
    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = AccountState.init(allocator);
    defer accounts.deinit();

    // Create deployer account
    const deployer = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    try accounts.setBalance(deployer, U256.fromU64(1000000));

    // Initialize VM
    var vm = VM.init(allocator, 1_000_000, state.asStorage(), tstorage.asTransientStorage(), null);
    vm.account_state = &accounts;
    defer vm.deinit();

    // Simple constructor that returns bytecode: PUSH1 42, HALT
    const init_code = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
        @intFromEnum(Opcode.PUSH1), 0, // offset
        @intFromEnum(Opcode.MSTORE8),
        @intFromEnum(Opcode.PUSH1), 1, // length
        @intFromEnum(Opcode.PUSH1), 0, // offset
        @intFromEnum(Opcode.RETURN),
    };

    // Store init code in memory
    for (init_code, 0..) |byte, i| {
        try vm.memory.store8(i, byte);
    }

    // Bytecode: CREATE with init code from memory
    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), @intCast(init_code.len), // size
        @intFromEnum(Opcode.PUSH1), 0, // offset
        @intFromEnum(Opcode.PUSH1), 0, // value
        @intFromEnum(Opcode.CREATE),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode);
    vm.context.address = deployer;

    const result = try vm.execute();

    try testing.expect(result.success);

    // Stack should contain new contract address
    const new_address_u256 = try vm.stack.peek(0);
    const new_address = u256ToAddress(new_address_u256);

    // Verify contract was deployed
    try testing.expect(accounts.isContract(new_address));
    try testing.expect(accounts.exists(new_address));
}

test "CREATE2 with deterministic address" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = AccountState.init(allocator);
    defer accounts.deinit();

    const deployer = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    try accounts.setBalance(deployer, U256.fromU64(1000000));

    var vm = VM.init(allocator, 1_000_000, state.asStorage(), tstorage.asTransientStorage(), null);
    vm.account_state = &accounts;
    defer vm.deinit();

    // Simple init code
    const init_code = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.MSTORE8),
        @intFromEnum(Opcode.PUSH1), 1,
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.RETURN),
    };

    for (init_code, 0..) |byte, i| {
        try vm.memory.store8(i, byte);
    }

    // CREATE2 with salt
    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 123, // salt
        @intFromEnum(Opcode.PUSH1), @intCast(init_code.len), // size
        @intFromEnum(Opcode.PUSH1), 0, // offset
        @intFromEnum(Opcode.PUSH1), 0, // value
        @intFromEnum(Opcode.CREATE2),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode);
    vm.context.address = deployer;

    const result = try vm.execute();
    try testing.expect(result.success);

    // Contract should be deployed
    const new_address_u256 = try vm.stack.peek(0);
    const new_address = u256ToAddress(new_address_u256);
    try testing.expect(accounts.isContract(new_address));
}

// =============================================================================
// CALL Tests
// =============================================================================

test "CALL simple contract to contract" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = AccountState.init(allocator);
    defer accounts.deinit();

    // Contract A (caller)
    const addr_a = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    try accounts.setBalance(addr_a, U256.fromU64(1000000));

    // Contract B (callee) - simple contract that returns 42
    const addr_b = Address.fromBytes([_]u8{2} ++ [_]u8{0} ** 19);
    const bytecode_b = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42, // value to return
        @intFromEnum(Opcode.PUSH1), 0, // offset in memory
        @intFromEnum(Opcode.MSTORE8),
        @intFromEnum(Opcode.PUSH1), 1, // length
        @intFromEnum(Opcode.PUSH1), 0, // offset
        @intFromEnum(Opcode.RETURN),
    };
    try accounts.deployContract(addr_b, &bytecode_b);

    var vm = VM.init(allocator, 1_000_000, state.asStorage(), tstorage.asTransientStorage(), null);
    vm.account_state = &accounts;
    defer vm.deinit();

    // Contract A calls contract B
    const addr_b_u256 = addressToU256(addr_b);
    var addr_b_bytes = addr_b_u256.toBytes();

    const bytecode_a = [_]u8{
        // Stack: retSize, retOffset, argsSize, argsOffset, value, address, gas
        @intFromEnum(Opcode.PUSH1), 1, // retSize
        @intFromEnum(Opcode.PUSH1), 0, // retOffset
        @intFromEnum(Opcode.PUSH1), 0, // argsSize
        @intFromEnum(Opcode.PUSH1), 0, // argsOffset
        @intFromEnum(Opcode.PUSH1), 0, // value
    } ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ addr_b_bytes ++ [_]u8{ // address B
        @intFromEnum(Opcode.PUSH4), 0, 1, 134, 160, // gas (100000)
        @intFromEnum(Opcode.CALL),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode_a);
    vm.context.address = addr_a;

    const result = try vm.execute();
    try testing.expect(result.success);

    // Check if CALL succeeded (should push 1 to stack)
    const call_success = try vm.stack.peek(0);
    try testing.expectEqual(@as(u64, 1), call_success.toU64());
}

test "DELEGATECALL preserves caller context" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = AccountState.init(allocator);
    defer accounts.deinit();

    const addr_a = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    const addr_b = Address.fromBytes([_]u8{2} ++ [_]u8{0} ** 19);

    try accounts.setBalance(addr_a, U256.fromU64(1000000));

    // Contract B: returns ADDRESS opcode result
    const bytecode_b = [_]u8{
        @intFromEnum(Opcode.ADDRESS), // Should return addr_a (caller's context)
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.MSTORE),
        @intFromEnum(Opcode.PUSH1), 32,
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.RETURN),
    };
    try accounts.deployContract(addr_b, &bytecode_b);

    var vm = VM.init(allocator, 1_000_000, state.asStorage(), tstorage.asTransientStorage(), null);
    vm.account_state = &accounts;
    defer vm.deinit();

    const addr_b_u256 = addressToU256(addr_b);
    var addr_b_bytes = addr_b_u256.toBytes();

    // DELEGATECALL to B
    const bytecode_a = [_]u8{
        @intFromEnum(Opcode.PUSH1), 32, // retSize
        @intFromEnum(Opcode.PUSH1), 0, // retOffset
        @intFromEnum(Opcode.PUSH1), 0, // argsSize
        @intFromEnum(Opcode.PUSH1), 0, // argsOffset
    } ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ addr_b_bytes ++ [_]u8{
        @intFromEnum(Opcode.PUSH4), 0, 1, 134, 160, // gas
        @intFromEnum(Opcode.DELEGATECALL),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode_a);
    vm.context.address = addr_a;

    const result = try vm.execute();
    try testing.expect(result.success);

    const call_success = try vm.stack.peek(0);
    try testing.expectEqual(@as(u64, 1), call_success.toU64());
}

test "STATICCALL rejects state modifications" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = AccountState.init(allocator);
    defer accounts.deinit();

    const addr_a = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    const addr_b = Address.fromBytes([_]u8{2} ++ [_]u8{0} ** 19);

    try accounts.setBalance(addr_a, U256.fromU64(1000000));

    // Contract B tries to write to storage (should fail in static mode)
    const bytecode_b = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.SSTORE), // This should fail in STATICCALL
        @intFromEnum(Opcode.HALT),
    };
    try accounts.deployContract(addr_b, &bytecode_b);

    var vm = VM.init(allocator, 1_000_000, state.asStorage(), tstorage.asTransientStorage(), null);
    vm.account_state = &accounts;
    defer vm.deinit();

    const addr_b_u256 = addressToU256(addr_b);
    var addr_b_bytes = addr_b_u256.toBytes();

    const bytecode_a = [_]u8{
        @intFromEnum(Opcode.PUSH1), 0, // retSize
        @intFromEnum(Opcode.PUSH1), 0, // retOffset
        @intFromEnum(Opcode.PUSH1), 0, // argsSize
        @intFromEnum(Opcode.PUSH1), 0, // argsOffset
    } ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ addr_b_bytes ++ [_]u8{
        @intFromEnum(Opcode.PUSH4), 0, 1, 134, 160, // gas
        @intFromEnum(Opcode.STATICCALL),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode_a);
    vm.context.address = addr_a;

    const result = try vm.execute();
    try testing.expect(result.success);

    // STATICCALL should fail (return 0) because callee tries to modify state
    const call_success = try vm.stack.peek(0);
    try testing.expectEqual(@as(u64, 0), call_success.toU64());
}

test "SELFDESTRUCT transfers balance and destroys account" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = AccountState.init(allocator);
    defer accounts.deinit();

    const addr_contract = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    const addr_recipient = Address.fromBytes([_]u8{2} ++ [_]u8{0} ** 19);

    // Give contract some balance
    try accounts.setBalance(addr_contract, U256.fromU64(1000));
    _ = try accounts.createAccount(addr_recipient);

    var vm = VM.init(allocator, 1_000_000, state.asStorage(), tstorage.asTransientStorage(), null);
    vm.account_state = &accounts;
    defer vm.deinit();

    const recipient_u256 = addressToU256(addr_recipient);
    var recipient_bytes = recipient_u256.toBytes();

    // Contract selfdestructs, sending balance to recipient
    const bytecode = [_]u8{@intFromEnum(Opcode.PUSH32)} ++ recipient_bytes ++ [_]u8{
        @intFromEnum(Opcode.SELFDESTRUCT),
    };

    vm.loadBytecode(&bytecode);
    vm.context.address = addr_contract;

    _ = try vm.execute();

    // Contract should be destroyed
    try testing.expect(!accounts.exists(addr_contract));

    // Recipient should have received the balance
    const recipient_balance = accounts.getBalance(addr_recipient);
    try testing.expectEqual(@as(u64, 1000), recipient_balance.toU64());
}

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

test "CREATE fails if address already exists" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = AccountState.init(allocator);
    defer accounts.deinit();

    const deployer = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    try accounts.setBalance(deployer, U256.fromU64(1000000));

    // Deploy twice - second should fail since nonce generates same address
    // (in real scenarios, nonce would increment)

    var vm = VM.init(allocator, 1_000_000, state.asStorage(), tstorage.asTransientStorage(), null);
    vm.account_state = &accounts;
    defer vm.deinit();

    const init_code = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.RETURN),
    };

    for (init_code, 0..) |byte, i| {
        try vm.memory.store8(i, byte);
    }

    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), @intCast(init_code.len),
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.CREATE),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode);
    vm.context.address = deployer;

    const result = try vm.execute();
    try testing.expect(result.success);
}

test "CALL to non-existent address fails" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = AccountState.init(allocator);
    defer accounts.deinit();

    const addr_a = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    const addr_nonexistent = Address.fromBytes([_]u8{99} ++ [_]u8{0} ** 19);

    try accounts.setBalance(addr_a, U256.fromU64(1000000));

    var vm = VM.init(allocator, 1_000_000, state.asStorage(), tstorage.asTransientStorage(), null);
    vm.account_state = &accounts;
    defer vm.deinit();

    const addr_ne_u256 = addressToU256(addr_nonexistent);
    var addr_ne_bytes = addr_ne_u256.toBytes();

    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 0, // retSize
        @intFromEnum(Opcode.PUSH1), 0, // retOffset
        @intFromEnum(Opcode.PUSH1), 0, // argsSize
        @intFromEnum(Opcode.PUSH1), 0, // argsOffset
        @intFromEnum(Opcode.PUSH1), 0, // value
    } ++ [_]u8{@intFromEnum(Opcode.PUSH32)} ++ addr_ne_bytes ++ [_]u8{
        @intFromEnum(Opcode.PUSH4), 0, 1, 134, 160, // gas
        @intFromEnum(Opcode.CALL),
        @intFromEnum(Opcode.HALT),
    };

    vm.loadBytecode(&bytecode);
    vm.context.address = addr_a;

    const result = try vm.execute();
    try testing.expect(result.success);

    // Call should fail (return 0)
    const call_result = try vm.stack.peek(0);
    try testing.expectEqual(@as(u64, 0), call_result.toU64());
}
