//! ZVM Opcode definitions
//! Multi-chain VM supporting Hedera, EVM, and Soroban compatibility

const std = @import("std");

/// ZVM Opcodes
/// Organized by category with reserved ranges for future expansion
pub const Opcode = enum(u8) {
    // === Control Flow (0x00-0x0F) ===
    HALT = 0x00, // Stop execution
    NOP = 0x01, // No operation

    // === Stack Operations (0x10-0x2F) ===
    POP = 0x10, // Remove top stack item
    PUSH1 = 0x11, // Push 1-byte value
    PUSH2 = 0x12, // Push 2-byte value
    PUSH4 = 0x13, // Push 4-byte value
    PUSH8 = 0x14, // Push 8-byte value
    PUSH16 = 0x15, // Push 16-byte value
    PUSH32 = 0x16, // Push 32-byte value (full U256)
    DUP1 = 0x17, // Duplicate 1st stack item
    DUP2 = 0x18, // Duplicate 2nd stack item
    DUP3 = 0x19, // Duplicate 3rd stack item
    DUP4 = 0x1A, // Duplicate 4th stack item
    SWAP1 = 0x1B, // Swap top with 2nd item
    SWAP2 = 0x1C, // Swap top with 3rd item
    SWAP3 = 0x1D, // Swap top with 4th item
    SWAP4 = 0x1E, // Swap top with 5th item

    // === Arithmetic Operations (0x30-0x4F) ===
    ADD = 0x30, // Addition
    SUB = 0x31, // Subtraction
    MUL = 0x32, // Multiplication
    DIV = 0x33, // Division
    SDIV = 0x34, // Signed division
    MOD = 0x35, // Modulo
    SMOD = 0x36, // Signed modulo
    ADDMOD = 0x37, // (a + b) % N
    MULMOD = 0x38, // (a * b) % N
    EXP = 0x39, // Exponentiation
    SIGNEXTEND = 0x3A, // Sign extension

    // === Comparison & Bitwise (0x50-0x6F) ===
    LT = 0x50, // Less than
    GT = 0x51, // Greater than
    SLT = 0x52, // Signed less than
    SGT = 0x53, // Signed greater than
    EQ = 0x54, // Equality
    ISZERO = 0x55, // Is zero
    AND = 0x56, // Bitwise AND
    OR = 0x57, // Bitwise OR
    XOR = 0x58, // Bitwise XOR
    NOT = 0x59, // Bitwise NOT
    BYTE = 0x5A, // Retrieve single byte
    SHL = 0x5B, // Shift left
    SHR = 0x5C, // Logical shift right
    SAR = 0x5D, // Arithmetic shift right

    // === Cryptographic Operations (0x70-0x7F) ===
    KECCAK256 = 0x70, // Keccak-256 hash
    SHA256 = 0x71, // SHA-256 hash
    RIPEMD160 = 0x72, // RIPEMD-160 hash
    BLAKE2B = 0x73, // Blake2b hash

    // === Memory Operations (0x80-0x8F) ===
    MLOAD = 0x80, // Load word from memory
    MSTORE = 0x81, // Store word to memory
    MSTORE8 = 0x82, // Store byte to memory
    MSIZE = 0x83, // Get memory size

    // === Storage Operations (0x90-0x9F) ===
    SLOAD = 0x90, // Load from storage
    SSTORE = 0x91, // Store to storage
    TLOAD = 0x92, // Load from transient storage
    TSTORE = 0x93, // Store to transient storage

    // === Control Flow & Jumps (0xA0-0xAF) ===
    JUMP = 0xA0, // Unconditional jump
    JUMPI = 0xA1, // Conditional jump
    PC = 0xA2, // Program counter
    JUMPDEST = 0xA3, // Jump destination marker
    CALL = 0xA4, // Call contract
    CALLCODE = 0xA5, // Call with alternative code
    DELEGATECALL = 0xA6, // Delegate call
    STATICCALL = 0xA7, // Static call (read-only)
    RETURN = 0xA8, // Return from call
    REVERT = 0xA9, // Revert state changes
    SELFDESTRUCT = 0xAA, // Destroy contract

    // === Context Information (0xB0-0xCF) ===
    ADDRESS = 0xB0, // Current contract address
    BALANCE = 0xB1, // Account balance
    ORIGIN = 0xB2, // Transaction origin
    CALLER = 0xB3, // Message caller
    CALLVALUE = 0xB4, // Call value (amount sent)
    CALLDATALOAD = 0xB5, // Load call data
    CALLDATASIZE = 0xB6, // Size of call data
    CALLDATACOPY = 0xB7, // Copy call data to memory
    CODESIZE = 0xB8, // Size of code
    CODECOPY = 0xB9, // Copy code to memory
    GASPRICE = 0xBA, // Gas price
    EXTCODESIZE = 0xBB, // External code size
    EXTCODECOPY = 0xBC, // Copy external code
    RETURNDATASIZE = 0xBD, // Size of return data
    RETURNDATACOPY = 0xBE, // Copy return data
    EXTCODEHASH = 0xBF, // External code hash

    // === Block Information (0xC0-0xCF) ===
    BLOCKHASH = 0xC0, // Block hash
    COINBASE = 0xC1, // Block beneficiary
    TIMESTAMP = 0xC2, // Block timestamp
    NUMBER = 0xC3, // Block number
    DIFFICULTY = 0xC4, // Block difficulty (deprecated)
    PREVRANDAO = 0xC5, // Previous RANDAO value
    GASLIMIT = 0xC6, // Block gas limit
    CHAINID = 0xC7, // Chain ID
    SELFBALANCE = 0xC8, // Contract's own balance
    BASEFEE = 0xC9, // Base fee

    // === Hedera-Specific Syscalls (0xE0-0xEF) ===
    // HTS (Hedera Token Service)
    HTS_TRANSFER = 0xE0, // Transfer tokens
    HTS_MINT = 0xE1, // Mint tokens
    HTS_BURN = 0xE2, // Burn tokens
    HTS_ASSOCIATE = 0xE3, // Associate token with account
    HTS_DISSOCIATE = 0xE4, // Dissociate token
    HTS_APPROVE = 0xE5, // Approve token spending
    HTS_CREATE = 0xE6, // Create new token

    // HCS (Hedera Consensus Service)
    HCS_SUBMIT = 0xE7, // Submit message to topic
    HCS_CREATE_TOPIC = 0xE8, // Create new topic
    HCS_UPDATE_TOPIC = 0xE9, // Update topic
    HCS_DELETE_TOPIC = 0xEA, // Delete topic

    // Hedera Account & Context
    HEDERA_ACCOUNT_ID = 0xEB, // Get Hedera account ID
    HEDERA_TIMESTAMP = 0xEC, // Get consensus timestamp

    // === Post-Quantum Cryptography (0xF0-0xF7) ===
    PQ_VERIFY_DILITHIUM = 0xF0, // Verify Dilithium signature
    PQ_VERIFY_FALCON = 0xF1, // Verify Falcon signature
    PQ_VERIFY_SPHINCS = 0xF2, // Verify SPHINCS+ signature
    PQ_KEYGEN = 0xF3, // Generate PQ key pair

    // === Logging & Events (0xF8-0xFF) ===
    LOG0 = 0xF8, // Log with 0 topics
    LOG1 = 0xF9, // Log with 1 topic
    LOG2 = 0xFA, // Log with 2 topics
    LOG3 = 0xFB, // Log with 3 topics
    LOG4 = 0xFC, // Log with 4 topics

    /// Get gas cost for this opcode
    /// Returns base gas cost (dynamic costs calculated separately)
    pub fn gasCost(self: Opcode) u64 {
        return switch (self) {
            // Free operations
            .HALT, .NOP => 0,

            // Very cheap operations (3 gas)
            .ADD, .SUB, .NOT, .LT, .GT, .SLT, .SGT, .EQ, .ISZERO, .AND, .OR, .XOR, .BYTE, .CALLDATALOAD, .MLOAD, .MSTORE, .MSTORE8, .PC, .MSIZE => 3,

            // Cheap operations (5 gas)
            .MUL, .DIV, .SDIV, .MOD, .SMOD, .SIGNEXTEND => 5,

            // Medium operations (8 gas)
            .ADDMOD, .MULMOD, .SHL, .SHR, .SAR => 8,

            // Stack operations (3 gas)
            .POP => 2,
            .PUSH1, .PUSH2, .PUSH4, .PUSH8, .PUSH16, .PUSH32 => 3,
            .DUP1, .DUP2, .DUP3, .DUP4 => 3,
            .SWAP1, .SWAP2, .SWAP3, .SWAP4 => 3,

            // Expensive operations
            .EXP => 10, // Base cost, +50 per byte
            .KECCAK256 => 30, // Base cost, +6 per word
            .SHA256 => 60,
            .RIPEMD160 => 600,
            .BLAKE2B => 30,

            // Storage (very expensive)
            .SLOAD => 100, // Warm: 100, Cold: 2100
            .SSTORE => 100, // Complex: 20000 for setting non-zero from zero
            .TLOAD => 100,
            .TSTORE => 100,

            // Context operations
            .ADDRESS, .BALANCE, .ORIGIN, .CALLER, .CALLVALUE, .CALLDATASIZE, .CODESIZE, .GASPRICE, .RETURNDATASIZE, .CHAINID, .SELFBALANCE, .BASEFEE => 2,

            .EXTCODESIZE, .EXTCODEHASH => 100, // Warm, +2600 if cold
            .BLOCKHASH => 20,
            .COINBASE, .TIMESTAMP, .NUMBER, .DIFFICULTY, .PREVRANDAO, .GASLIMIT => 2,

            // Copy operations (dynamic cost based on size)
            .CALLDATACOPY, .CODECOPY, .RETURNDATACOPY, .EXTCODECOPY => 3, // Base + 3 per word

            // Control flow
            .JUMP => 8,
            .JUMPI => 10,
            .JUMPDEST => 1,

            // Calls (base cost, dynamic cost calculated separately)
            .CALL, .CALLCODE, .DELEGATECALL, .STATICCALL => 100, // Base, +many dynamic costs
            .RETURN, .REVERT => 0,
            .SELFDESTRUCT => 5000, // + refund

            // Hedera syscalls (estimated costs)
            .HTS_TRANSFER => 50,
            .HTS_MINT, .HTS_BURN => 100,
            .HTS_ASSOCIATE, .HTS_DISSOCIATE => 50,
            .HTS_APPROVE => 50,
            .HTS_CREATE => 500,
            .HCS_SUBMIT => 50,
            .HCS_CREATE_TOPIC => 200,
            .HCS_UPDATE_TOPIC, .HCS_DELETE_TOPIC => 100,
            .HEDERA_ACCOUNT_ID, .HEDERA_TIMESTAMP => 2,

            // Post-quantum crypto (expensive)
            .PQ_VERIFY_DILITHIUM => 1000,
            .PQ_VERIFY_FALCON => 800,
            .PQ_VERIFY_SPHINCS => 2000,
            .PQ_KEYGEN => 5000,

            // Logging (dynamic cost based on data size)
            .LOG0 => 375,
            .LOG1 => 750,
            .LOG2 => 1125,
            .LOG3 => 1500,
            .LOG4 => 1875,
        };
    }

    /// Check if this opcode modifies state
    pub fn isStateModifying(self: Opcode) bool {
        return switch (self) {
            .SSTORE, .TSTORE, .CALL, .CALLCODE, .DELEGATECALL, .SELFDESTRUCT, .HTS_TRANSFER, .HTS_MINT, .HTS_BURN, .HTS_ASSOCIATE, .HTS_DISSOCIATE, .HTS_APPROVE, .HTS_CREATE, .HCS_SUBMIT, .HCS_CREATE_TOPIC, .HCS_UPDATE_TOPIC, .HCS_DELETE_TOPIC, .LOG0, .LOG1, .LOG2, .LOG3, .LOG4 => true,
            else => false,
        };
    }

    /// Check if this opcode is valid in static context (STATICCALL)
    pub fn isStaticValid(self: Opcode) bool {
        return !self.isStateModifying();
    }

    /// Get number of items this opcode pops from stack
    pub fn stackPops(self: Opcode) u8 {
        return switch (self) {
            .HALT, .NOP, .PC, .MSIZE, .ADDRESS, .BALANCE, .ORIGIN, .CALLER, .CALLVALUE, .CALLDATASIZE, .CODESIZE, .GASPRICE, .COINBASE, .TIMESTAMP, .NUMBER, .DIFFICULTY, .PREVRANDAO, .GASLIMIT, .CHAINID, .SELFBALANCE, .BASEFEE, .RETURNDATASIZE, .HEDERA_ACCOUNT_ID, .HEDERA_TIMESTAMP => 0,

            .PUSH1, .PUSH2, .PUSH4, .PUSH8, .PUSH16, .PUSH32, .DUP1, .DUP2, .DUP3, .DUP4 => 0,

            .POP, .ISZERO, .NOT, .MLOAD, .SLOAD, .TLOAD, .JUMP, .EXTCODESIZE, .EXTCODEHASH, .BLOCKHASH => 1,

            .ADD, .SUB, .MUL, .DIV, .SDIV, .MOD, .SMOD, .EXP, .SIGNEXTEND, .LT, .GT, .SLT, .SGT, .EQ, .AND, .OR, .XOR, .BYTE, .SHL, .SHR, .SAR, .KECCAK256, .MSTORE, .MSTORE8, .SSTORE, .TSTORE, .JUMPI, .RETURN, .REVERT, .SWAP1, .SWAP2, .SWAP3, .SWAP4, .CALLDATALOAD => 2,

            .ADDMOD, .MULMOD, .CALLDATACOPY, .CODECOPY, .RETURNDATACOPY => 3,

            .EXTCODECOPY => 4,

            .CALL, .CALLCODE => 7,
            .DELEGATECALL, .STATICCALL => 6,

            .LOG0 => 2,
            .LOG1 => 3,
            .LOG2 => 4,
            .LOG3 => 5,
            .LOG4 => 6,

            // Hedera opcodes (simplified)
            .HTS_TRANSFER => 3, // token_id, to, amount
            .HTS_MINT, .HTS_BURN => 2,
            .HTS_ASSOCIATE, .HTS_DISSOCIATE => 1,

            else => 0,
        };
    }

    /// Get number of items this opcode pushes to stack
    pub fn stackPushes(self: Opcode) u8 {
        return switch (self) {
            .HALT, .NOP, .POP, .JUMP, .JUMPDEST, .RETURN, .REVERT, .MSTORE, .MSTORE8, .SSTORE, .TSTORE, .SELFDESTRUCT, .LOG0, .LOG1, .LOG2, .LOG3, .LOG4, .CALLDATACOPY, .CODECOPY, .RETURNDATACOPY, .EXTCODECOPY => 0,

            // Most operations push 1 result
            else => 1,
        };
    }

    /// Format opcode for debugging
    pub fn format(
        self: Opcode,
        comptime _: []const u8,
        _: anytype,
        writer: anytype,
    ) !void {
        try writer.print("{s}", .{@tagName(self)});
    }
};

// Tests
test "opcode gas costs" {
    try std.testing.expectEqual(@as(u64, 3), Opcode.ADD.gasCost());
    try std.testing.expectEqual(@as(u64, 100), Opcode.SLOAD.gasCost());
    try std.testing.expectEqual(@as(u64, 30), Opcode.KECCAK256.gasCost());
}

test "opcode state modification" {
    try std.testing.expect(Opcode.SSTORE.isStateModifying());
    try std.testing.expect(!Opcode.SLOAD.isStateModifying());
    try std.testing.expect(Opcode.HTS_TRANSFER.isStateModifying());
}

test "opcode stack effects" {
    try std.testing.expectEqual(@as(u8, 2), Opcode.ADD.stackPops());
    try std.testing.expectEqual(@as(u8, 1), Opcode.ADD.stackPushes());

    try std.testing.expectEqual(@as(u8, 0), Opcode.PUSH32.stackPops());
    try std.testing.expectEqual(@as(u8, 1), Opcode.PUSH32.stackPushes());
}
