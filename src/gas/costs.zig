//! ZVM Gas Cost Catalog
//! Exported for compiler integration (KALIX, etc.)
//!
//! This module provides authoritative gas costs for all ZVM opcodes and operations.
//! Compilers can import this module to ensure accurate gas estimation.

const std = @import("std");
const opcode = @import("../bytecode/opcode.zig");
const Opcode = opcode.Opcode;

/// Get gas cost for a specific opcode
/// Returns the base gas cost (dynamic costs calculated separately)
pub fn getOpcodeCost(op: Opcode) u64 {
    return op.gasCost();
}

/// Opcode gas costs as a constant lookup table
/// Indexed by opcode value (0-255)
pub const OPCODE_COSTS: [256]u64 = blk: {
    @setEvalBranchQuota(10000);
    var costs: [256]u64 = [_]u64{0} ** 256;

    // Populate with actual opcode costs
    costs[@intFromEnum(Opcode.HALT)] = 0;
    costs[@intFromEnum(Opcode.NOP)] = 0;

    // Stack operations
    costs[@intFromEnum(Opcode.POP)] = 2;
    costs[@intFromEnum(Opcode.PUSH1)] = 3;
    costs[@intFromEnum(Opcode.PUSH2)] = 3;
    costs[@intFromEnum(Opcode.PUSH4)] = 3;
    costs[@intFromEnum(Opcode.PUSH8)] = 3;
    costs[@intFromEnum(Opcode.PUSH16)] = 3;
    costs[@intFromEnum(Opcode.PUSH32)] = 3;
    costs[@intFromEnum(Opcode.DUP1)] = 3;
    costs[@intFromEnum(Opcode.DUP2)] = 3;
    costs[@intFromEnum(Opcode.DUP3)] = 3;
    costs[@intFromEnum(Opcode.DUP4)] = 3;
    costs[@intFromEnum(Opcode.SWAP1)] = 3;
    costs[@intFromEnum(Opcode.SWAP2)] = 3;
    costs[@intFromEnum(Opcode.SWAP3)] = 3;
    costs[@intFromEnum(Opcode.SWAP4)] = 3;

    // Arithmetic
    costs[@intFromEnum(Opcode.ADD)] = 3;
    costs[@intFromEnum(Opcode.SUB)] = 3;
    costs[@intFromEnum(Opcode.MUL)] = 5;
    costs[@intFromEnum(Opcode.DIV)] = 5;
    costs[@intFromEnum(Opcode.SDIV)] = 5;
    costs[@intFromEnum(Opcode.MOD)] = 5;
    costs[@intFromEnum(Opcode.SMOD)] = 5;
    costs[@intFromEnum(Opcode.ADDMOD)] = 8;
    costs[@intFromEnum(Opcode.MULMOD)] = 8;
    costs[@intFromEnum(Opcode.EXP)] = 10;
    costs[@intFromEnum(Opcode.SIGNEXTEND)] = 5;

    // Comparison & Bitwise
    costs[@intFromEnum(Opcode.LT)] = 3;
    costs[@intFromEnum(Opcode.GT)] = 3;
    costs[@intFromEnum(Opcode.SLT)] = 3;
    costs[@intFromEnum(Opcode.SGT)] = 3;
    costs[@intFromEnum(Opcode.EQ)] = 3;
    costs[@intFromEnum(Opcode.ISZERO)] = 3;
    costs[@intFromEnum(Opcode.AND)] = 3;
    costs[@intFromEnum(Opcode.OR)] = 3;
    costs[@intFromEnum(Opcode.XOR)] = 3;
    costs[@intFromEnum(Opcode.NOT)] = 3;
    costs[@intFromEnum(Opcode.BYTE)] = 3;
    costs[@intFromEnum(Opcode.SHL)] = 8;
    costs[@intFromEnum(Opcode.SHR)] = 8;
    costs[@intFromEnum(Opcode.SAR)] = 8;

    // Cryptographic
    costs[@intFromEnum(Opcode.KECCAK256)] = 30;
    costs[@intFromEnum(Opcode.SHA256)] = 60;
    costs[@intFromEnum(Opcode.RIPEMD160)] = 600;
    costs[@intFromEnum(Opcode.BLAKE2B)] = 30;

    // Memory
    costs[@intFromEnum(Opcode.MLOAD)] = 3;
    costs[@intFromEnum(Opcode.MSTORE)] = 3;
    costs[@intFromEnum(Opcode.MSTORE8)] = 3;
    costs[@intFromEnum(Opcode.MSIZE)] = 3;

    // Storage
    costs[@intFromEnum(Opcode.SLOAD)] = 100;
    costs[@intFromEnum(Opcode.SSTORE)] = 100;
    costs[@intFromEnum(Opcode.TLOAD)] = 100;
    costs[@intFromEnum(Opcode.TSTORE)] = 100;

    // Storage utilities
    costs[@intFromEnum(Opcode.TABLEHASH)] = 30;

    // Control flow
    costs[@intFromEnum(Opcode.JUMP)] = 8;
    costs[@intFromEnum(Opcode.JUMPI)] = 10;
    costs[@intFromEnum(Opcode.PC)] = 3;
    costs[@intFromEnum(Opcode.JUMPDEST)] = 1;
    costs[@intFromEnum(Opcode.RETURN)] = 0;
    costs[@intFromEnum(Opcode.REVERT)] = 0;
    costs[@intFromEnum(Opcode.SELFDESTRUCT)] = 5000;

    // Calls
    costs[@intFromEnum(Opcode.CALL)] = 100;
    costs[@intFromEnum(Opcode.CALLCODE)] = 100;
    costs[@intFromEnum(Opcode.DELEGATECALL)] = 100;
    costs[@intFromEnum(Opcode.STATICCALL)] = 100;
    costs[@intFromEnum(Opcode.CREATE)] = 32000;
    costs[@intFromEnum(Opcode.CREATE2)] = 32000;

    // Context
    costs[@intFromEnum(Opcode.ADDRESS)] = 2;
    costs[@intFromEnum(Opcode.BALANCE)] = 2;
    costs[@intFromEnum(Opcode.ORIGIN)] = 2;
    costs[@intFromEnum(Opcode.CALLER)] = 2;
    costs[@intFromEnum(Opcode.CALLVALUE)] = 2;
    costs[@intFromEnum(Opcode.CALLDATALOAD)] = 3;
    costs[@intFromEnum(Opcode.CALLDATASIZE)] = 2;
    costs[@intFromEnum(Opcode.CALLDATACOPY)] = 3;
    costs[@intFromEnum(Opcode.CODESIZE)] = 2;
    costs[@intFromEnum(Opcode.CODECOPY)] = 3;
    costs[@intFromEnum(Opcode.GASPRICE)] = 2;
    costs[@intFromEnum(Opcode.EXTCODESIZE)] = 100;
    costs[@intFromEnum(Opcode.EXTCODECOPY)] = 3;
    costs[@intFromEnum(Opcode.RETURNDATASIZE)] = 2;
    costs[@intFromEnum(Opcode.RETURNDATACOPY)] = 3;
    costs[@intFromEnum(Opcode.EXTCODEHASH)] = 100;

    // Block info
    costs[@intFromEnum(Opcode.BLOCKHASH)] = 20;
    costs[@intFromEnum(Opcode.COINBASE)] = 2;
    costs[@intFromEnum(Opcode.TIMESTAMP)] = 2;
    costs[@intFromEnum(Opcode.NUMBER)] = 2;
    costs[@intFromEnum(Opcode.DIFFICULTY)] = 2;
    costs[@intFromEnum(Opcode.PREVRANDAO)] = 2;
    costs[@intFromEnum(Opcode.GASLIMIT)] = 2;
    costs[@intFromEnum(Opcode.CHAINID)] = 2;
    costs[@intFromEnum(Opcode.SELFBALANCE)] = 2;
    costs[@intFromEnum(Opcode.BASEFEE)] = 2;

    // Logging
    costs[@intFromEnum(Opcode.LOG0)] = 375;
    costs[@intFromEnum(Opcode.LOG1)] = 750;
    costs[@intFromEnum(Opcode.LOG2)] = 1125;
    costs[@intFromEnum(Opcode.LOG3)] = 1500;
    costs[@intFromEnum(Opcode.LOG4)] = 1875;

    // Hedera HTS
    costs[@intFromEnum(Opcode.HTS_TRANSFER)] = 50;
    costs[@intFromEnum(Opcode.HTS_MINT)] = 100;
    costs[@intFromEnum(Opcode.HTS_BURN)] = 100;
    costs[@intFromEnum(Opcode.HTS_ASSOCIATE)] = 50;
    costs[@intFromEnum(Opcode.HTS_DISSOCIATE)] = 50;
    costs[@intFromEnum(Opcode.HTS_APPROVE)] = 50;
    costs[@intFromEnum(Opcode.HTS_CREATE)] = 500;

    // Hedera HCS
    costs[@intFromEnum(Opcode.HCS_SUBMIT)] = 50;
    costs[@intFromEnum(Opcode.HCS_CREATE_TOPIC)] = 200;
    costs[@intFromEnum(Opcode.HCS_UPDATE_TOPIC)] = 100;
    costs[@intFromEnum(Opcode.HCS_DELETE_TOPIC)] = 100;

    // Hedera context
    costs[@intFromEnum(Opcode.HEDERA_ACCOUNT_ID)] = 2;
    costs[@intFromEnum(Opcode.HEDERA_TIMESTAMP)] = 2;

    break :blk costs;
};

/// Storage operation gas costs (dynamic based on state)
pub const Storage = struct {
    /// Base cost for warm storage access
    pub const warm = 100;

    /// Cost for cold storage access (first access in transaction)
    pub const cold = 2100;

    /// Cost for setting storage from zero to non-zero
    pub const set = 20000;

    /// Cost for clearing storage (non-zero to zero) - also provides refund
    pub const clear = 2900;

    /// Refund for clearing storage
    pub const clear_refund = 15000;

    /// Refund for SELFDESTRUCT
    pub const selfdestruct_refund = 24000;
};

/// Memory expansion gas cost formula
/// Cost = 3 * words + (words^2 / 512)
/// where words = (new_size + 31) / 32
pub fn memoryExpansion(current_size: usize, new_size: usize) u64 {
    if (new_size <= current_size) return 0;

    const current_words = (current_size + 31) / 32;
    const new_words = (new_size + 31) / 32;

    const current_cost = 3 * current_words + (current_words * current_words) / 512;
    const new_cost = 3 * new_words + (new_words * new_words) / 512;

    return @intCast(new_cost - current_cost);
}

/// Call operation additional costs
pub const Call = struct {
    /// Base cost for CALL/CALLCODE
    pub const base = 100;

    /// Additional cost when transferring value
    pub const value_transfer = 9000;

    /// Additional cost when creating new account
    pub const new_account = 25000;

    /// Stipend provided when value is transferred
    pub const stipend = 2300;
};

/// CREATE operation costs
pub const Create = struct {
    /// Base cost for CREATE/CREATE2
    pub const base = 32000;

    /// Cost per byte for code deposit
    pub const code_deposit = 200;

    /// Minimum size for initcode
    pub const min_initcode_size = 0;

    /// Maximum size for initcode (EIP-3860)
    pub const max_initcode_size = 49152;
};

/// Copy operation costs
/// Cost = base + 3 * words
pub fn copyCost(size: usize) u64 {
    const words = (size + 31) / 32;
    return 3 + @as(u64, @intCast(3 * words));
}

/// KECCAK256 dynamic cost
/// Cost = 30 + 6 * words
pub fn keccak256Cost(size: usize) u64 {
    const words = (size + 31) / 32;
    return 30 + @as(u64, @intCast(6 * words));
}

/// LOG operation cost
/// Cost = base + 375 * topics + 8 * size
pub fn logCost(topics: u8, size: usize) u64 {
    const base: u64 = 375;
    const topic_cost = @as(u64, topics) * 375;
    const data_cost = @as(u64, @intCast(size)) * 8;
    return base + topic_cost + data_cost;
}

/// EXP dynamic cost
/// Cost = 10 + 50 * byte_length(exponent)
pub fn expCost(exponent: u256) u64 {
    // Calculate byte length of exponent
    var exp = exponent;
    var byte_len: u64 = 0;
    while (exp > 0) : (exp >>= 8) {
        byte_len += 1;
    }
    if (byte_len == 0) byte_len = 1;
    return 10 + 50 * byte_len;
}

// =============================================================================
// Tests
// =============================================================================

test "opcode cost lookup" {
    const testing = std.testing;

    // Verify critical opcodes
    try testing.expectEqual(@as(u64, 3), OPCODE_COSTS[@intFromEnum(Opcode.ADD)]);
    try testing.expectEqual(@as(u64, 100), OPCODE_COSTS[@intFromEnum(Opcode.SLOAD)]);
    try testing.expectEqual(@as(u64, 30), OPCODE_COSTS[@intFromEnum(Opcode.KECCAK256)]);
    try testing.expectEqual(@as(u64, 30), OPCODE_COSTS[@intFromEnum(Opcode.TABLEHASH)]);
    try testing.expectEqual(@as(u64, 32000), OPCODE_COSTS[@intFromEnum(Opcode.CREATE)]);
}

test "memory expansion cost" {
    const testing = std.testing;

    // No expansion
    try testing.expectEqual(@as(u64, 0), memoryExpansion(0, 0));
    try testing.expectEqual(@as(u64, 0), memoryExpansion(32, 32));

    // Expansion from 0 to 32 bytes (1 word)
    // Cost = 3 * 1 + (1 * 1) / 512 = 3 + 0 = 3
    try testing.expectEqual(@as(u64, 3), memoryExpansion(0, 32));

    // Expansion from 0 to 64 bytes (2 words)
    // Cost = 3 * 2 + (2 * 2) / 512 = 6 + 0 = 6
    try testing.expectEqual(@as(u64, 6), memoryExpansion(0, 64));
}

test "copy cost" {
    const testing = std.testing;

    // 32 bytes (1 word): 3 + 3 * 1 = 6
    try testing.expectEqual(@as(u64, 6), copyCost(32));

    // 64 bytes (2 words): 3 + 3 * 2 = 9
    try testing.expectEqual(@as(u64, 9), copyCost(64));

    // 0 bytes: 3 + 3 * 0 = 3
    try testing.expectEqual(@as(u64, 3), copyCost(0));
}

test "keccak256 cost" {
    const testing = std.testing;

    // 32 bytes (1 word): 30 + 6 * 1 = 36
    try testing.expectEqual(@as(u64, 36), keccak256Cost(32));

    // 64 bytes (2 words): 30 + 6 * 2 = 42
    try testing.expectEqual(@as(u64, 42), keccak256Cost(64));
}

test "log cost" {
    const testing = std.testing;

    // LOG0 with 32 bytes: 375 + 0 + 256 = 631
    try testing.expectEqual(@as(u64, 631), logCost(0, 32));

    // LOG1 with 32 bytes: 375 + 375 + 256 = 1006
    try testing.expectEqual(@as(u64, 1006), logCost(1, 32));
}
