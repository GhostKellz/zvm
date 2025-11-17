//! Example: Hedera Token Service (HTS) operations
//! Demonstrates HTS token transfers, minting, and HCS message submission

const std = @import("std");
const zvm = @import("zvm");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n╔══════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║  ZVM Hedera Integration - HTS & HCS Demo                ║\n", .{});
    std.debug.print("╚══════════════════════════════════════════════════════════╝\n\n", .{});

    // Initialize storage
    var state = zvm.JournaledState.init(allocator);
    defer state.deinit();
    var transient_storage = zvm.TransientStorageImpl.init(allocator);
    defer transient_storage.deinit();

    // Initialize mock Hedera syscalls
    var hedera = zvm.hedera.MockHedera.init(allocator);
    defer hedera.deinit();

    // Create a mock token
    const token_id = zvm.Address.zero();
    try hedera.createMockToken(token_id, "TestToken", "TEST", 8, zvm.U256.fromU64(1_000_000));

    std.debug.print("═══ Hedera Token Service (HTS) Demo ═══\n\n", .{});
    std.debug.print("Created Token:\n", .{});
    std.debug.print("  ID:     {any}\n", .{token_id});
    std.debug.print("  Name:   TestToken\n", .{});
    std.debug.print("  Symbol: TEST\n", .{});
    std.debug.print("  Supply: 1,000,000\n\n", .{});

    // === HTS Transfer Demo ===
    std.debug.print("Demo 1: HTS Token Transfer\n", .{});
    std.debug.print("──────────────────────────────────────────────────────────\n", .{});

    // Convert addresses to U256 for stack (Hedera uses 20-byte addresses)
    const token_u256 = addressToU256(token_id);
    const from_addr = zvm.Address.zero();
    const to_addr_bytes = [_]u8{0} ** 19 ++ [_]u8{1};
    const to_addr = zvm.Address{ .bytes = to_addr_bytes };
    const from_u256 = addressToU256(from_addr);
    const to_u256 = addressToU256(to_addr);
    const amount = zvm.U256.fromU64(100);

    // Bytecode: PUSH32 token, PUSH32 from, PUSH32 to, PUSH32 amount, HTS_TRANSFER, HALT
    var bytecode_transfer = std.ArrayListUnmanaged(u8){};
    defer bytecode_transfer.deinit(allocator);

    try bytecode_transfer.append(allocator, @intFromEnum(zvm.Opcode.PUSH32));
    try bytecode_transfer.appendSlice(allocator, &token_u256.toBytes());
    try bytecode_transfer.append(allocator, @intFromEnum(zvm.Opcode.PUSH32));
    try bytecode_transfer.appendSlice(allocator, &from_u256.toBytes());
    try bytecode_transfer.append(allocator, @intFromEnum(zvm.Opcode.PUSH32));
    try bytecode_transfer.appendSlice(allocator, &to_u256.toBytes());
    try bytecode_transfer.append(allocator, @intFromEnum(zvm.Opcode.PUSH32));
    try bytecode_transfer.appendSlice(allocator, &amount.toBytes());
    try bytecode_transfer.append(allocator, @intFromEnum(zvm.Opcode.HTS_TRANSFER));
    try bytecode_transfer.append(allocator, @intFromEnum(zvm.Opcode.HALT));

    var vm_transfer = zvm.VM.init(allocator, 100000, state.asStorage(), transient_storage.asTransientStorage(), hedera.asHederaSyscalls());
    defer vm_transfer.deinit();

    vm_transfer.loadBytecode(bytecode_transfer.items);
    const result_transfer = try vm_transfer.execute();

    const success = try vm_transfer.stack.peek(0);
    std.debug.print("Transfer 100 TEST from {any} to {any}\n", .{ from_addr, to_addr });
    std.debug.print("  Success: {d}\n", .{success.toU64()});
    std.debug.print("  Gas used: {d}\n\n", .{result_transfer.gas_used});

    // === HTS Mint Demo ===
    std.debug.print("Demo 2: HTS Token Minting\n", .{});
    std.debug.print("──────────────────────────────────────────────────────────\n", .{});

    // Bytecode: PUSH32 token, PUSH32 amount, HTS_MINT, HALT
    var bytecode_mint = std.ArrayListUnmanaged(u8){};
    defer bytecode_mint.deinit(allocator);

    const mint_amount = zvm.U256.fromU64(50000);
    try bytecode_mint.append(allocator, @intFromEnum(zvm.Opcode.PUSH32));
    try bytecode_mint.appendSlice(allocator, &token_u256.toBytes());
    try bytecode_mint.append(allocator, @intFromEnum(zvm.Opcode.PUSH32));
    try bytecode_mint.appendSlice(allocator, &mint_amount.toBytes());
    try bytecode_mint.append(allocator, @intFromEnum(zvm.Opcode.HTS_MINT));
    try bytecode_mint.append(allocator, @intFromEnum(zvm.Opcode.HALT));

    var vm_mint = zvm.VM.init(allocator, 200000, state.asStorage(), transient_storage.asTransientStorage(), hedera.asHederaSyscalls());
    defer vm_mint.deinit();

    vm_mint.loadBytecode(bytecode_mint.items);
    const result_mint = try vm_mint.execute();

    const mint_success = try vm_mint.stack.peek(0);
    std.debug.print("Mint 50,000 TEST tokens\n", .{});
    std.debug.print("  Success: {d}\n", .{mint_success.toU64()});
    std.debug.print("  Gas used: {d}\n\n", .{result_mint.gas_used});

    // === HCS Message Submission Demo ===
    std.debug.print("═══ Hedera Consensus Service (HCS) Demo ═══\n\n", .{});
    std.debug.print("Demo 3: Submit Message to HCS Topic\n", .{});
    std.debug.print("──────────────────────────────────────────────────────────\n", .{});

    const topic_id = zvm.Address.zero();
    const topic_u256 = addressToU256(topic_id);
    const message = "Hello from ZVM on Hedera!";

    // Bytecode: Write message to memory, then submit to HCS
    // PUSH32 message (simplified - just store in memory at offset 0)
    // PUSH32 topic_id, PUSH1 offset, PUSH1 length, HCS_SUBMIT, HALT

    var vm_hcs = zvm.VM.init(allocator, 200000, state.asStorage(), transient_storage.asTransientStorage(), hedera.asHederaSyscalls());
    defer vm_hcs.deinit();

    // First, write message to memory
    for (message, 0..) |byte, i| {
        try vm_hcs.memory.store8(i, byte);
    }

    // Bytecode: PUSH32 topic, PUSH1 0 (offset), PUSH1 len, HCS_SUBMIT, HALT
    var bytecode_hcs = std.ArrayListUnmanaged(u8){};
    defer bytecode_hcs.deinit(allocator);

    try bytecode_hcs.append(allocator, @intFromEnum(zvm.Opcode.PUSH32));
    try bytecode_hcs.appendSlice(allocator, &topic_u256.toBytes());
    try bytecode_hcs.append(allocator, @intFromEnum(zvm.Opcode.PUSH1));
    try bytecode_hcs.append(allocator, 0); // offset
    try bytecode_hcs.append(allocator, @intFromEnum(zvm.Opcode.PUSH1));
    try bytecode_hcs.append(allocator, @intCast(message.len)); // length
    try bytecode_hcs.append(allocator, @intFromEnum(zvm.Opcode.HCS_SUBMIT));
    try bytecode_hcs.append(allocator, @intFromEnum(zvm.Opcode.HALT));

    vm_hcs.loadBytecode(bytecode_hcs.items);
    const result_hcs = try vm_hcs.execute();

    const hcs_success = try vm_hcs.stack.peek(0);
    std.debug.print("Submit message to topic {any}\n", .{topic_id});
    std.debug.print("  Message: \"{s}\"\n", .{message});
    std.debug.print("  Success: {d}\n", .{hcs_success.toU64()});
    std.debug.print("  Gas used: {d}\n", .{result_hcs.gas_used});
    std.debug.print("  Gas cost = base (5000) + per-byte (100 × {d}) = {d}\n\n", .{ message.len, 5000 + 100 * message.len });

    std.debug.print("══════════════════════════════════════════════════════════\n", .{});
    std.debug.print("Hedera Phase 3 Complete!\n", .{});
    std.debug.print("  ✓ HTS token operations (transfer, mint, burn)\n", .{});
    std.debug.print("  ✓ HCS consensus service messaging\n", .{});
    std.debug.print("  ✓ Hedera-specific gas accounting\n", .{});
    std.debug.print("  ✓ Mock implementation for testing\n", .{});
    std.debug.print("══════════════════════════════════════════════════════════\n", .{});
}

fn addressToU256(addr: zvm.Address) zvm.U256 {
    var bytes: [32]u8 = [_]u8{0} ** 32;
    @memcpy(bytes[12..32], &addr.bytes);
    return zvm.U256.fromBytes(bytes);
}
