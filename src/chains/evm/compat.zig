//! EVM Compatibility Layer
//! Translates EVM bytecode to ZVM bytecode for Solidity contract execution

const std = @import("std");
const Opcode = @import("../../bytecode/opcode.zig").Opcode;
const BytecodeContainer = @import("../../bytecode/container.zig").BytecodeContainer;

pub const EvmCompatError = error{
    UnsupportedOpcode,
    InvalidBytecode,
    UnsupportedPrecompile,
} || std.mem.Allocator.Error;

/// EVM to ZVM opcode mapping
pub const EvmOpcodeMap = struct {
    /// Map EVM opcode to ZVM opcode (1:1 mapping for most opcodes)
    pub fn map(evm_opcode: u8) !Opcode {
        return switch (evm_opcode) {
            // Stop and Arithmetic
            0x00 => Opcode.HALT,
            0x01 => Opcode.ADD,
            0x02 => Opcode.MUL,
            0x03 => Opcode.SUB,
            0x04 => Opcode.DIV,
            0x05 => Opcode.SDIV,
            0x06 => Opcode.MOD,
            0x07 => Opcode.SMOD,
            0x08 => Opcode.ADDMOD,
            0x09 => Opcode.MULMOD,
            0x0A => Opcode.EXP,
            0x0B => Opcode.SIGNEXTEND,

            // Comparison & Bitwise
            0x10 => Opcode.LT,
            0x11 => Opcode.GT,
            0x12 => Opcode.SLT,
            0x13 => Opcode.SGT,
            0x14 => Opcode.EQ,
            0x15 => Opcode.ISZERO,
            0x16 => Opcode.AND,
            0x17 => Opcode.OR,
            0x18 => Opcode.XOR,
            0x19 => Opcode.NOT,
            0x1A => Opcode.BYTE,
            0x1B => Opcode.SHL,
            0x1C => Opcode.SHR,
            0x1D => Opcode.SAR,

            // Crypto
            0x20 => Opcode.KECCAK256,

            // Block Info
            0x40 => Opcode.BLOCKHASH,
            0x41 => Opcode.COINBASE,
            0x42 => Opcode.TIMESTAMP,
            0x43 => Opcode.NUMBER,
            0x44 => Opcode.DIFFICULTY,
            0x45 => Opcode.GASLIMIT,
            0x46 => Opcode.CHAINID,
            0x47 => Opcode.SELFBALANCE,
            0x48 => Opcode.BASEFEE,

            // Stack, Memory, Storage
            0x50 => Opcode.POP,
            0x51 => Opcode.MLOAD,
            0x52 => Opcode.MSTORE,
            0x53 => Opcode.MSTORE8,
            0x54 => Opcode.SLOAD,
            0x55 => Opcode.SSTORE,
            0x56 => Opcode.JUMP,
            0x57 => Opcode.JUMPI,
            0x58 => Opcode.PC,
            0x59 => Opcode.MSIZE,
            0x5A => Opcode.GAS,
            0x5B => Opcode.JUMPDEST,
            0x5C => Opcode.TLOAD,
            0x5D => Opcode.TSTORE,

            // Push operations (0x60-0x7F)
            0x60 => Opcode.PUSH1,
            0x61 => Opcode.PUSH2,
            0x62 => Opcode.PUSH2, // PUSH3 -> PUSH2 (we use powers of 2)
            0x63 => Opcode.PUSH4,
            0x64 => Opcode.PUSH4, // PUSH5-7 -> PUSH4
            0x65 => Opcode.PUSH4,
            0x66 => Opcode.PUSH4,
            0x67 => Opcode.PUSH4,
            0x68 => Opcode.PUSH8,
            0x69 => Opcode.PUSH8, // PUSH9-15 -> PUSH8
            0x6A => Opcode.PUSH8,
            0x6B => Opcode.PUSH8,
            0x6C => Opcode.PUSH8,
            0x6D => Opcode.PUSH8,
            0x6E => Opcode.PUSH8,
            0x6F => Opcode.PUSH8,
            0x70 => Opcode.PUSH16,
            0x71 => Opcode.PUSH16, // PUSH17-31 -> PUSH16
            0x72 => Opcode.PUSH16,
            0x73 => Opcode.PUSH16,
            0x74 => Opcode.PUSH16,
            0x75 => Opcode.PUSH16,
            0x76 => Opcode.PUSH16,
            0x77 => Opcode.PUSH16,
            0x78 => Opcode.PUSH16,
            0x79 => Opcode.PUSH16,
            0x7A => Opcode.PUSH16,
            0x7B => Opcode.PUSH16,
            0x7C => Opcode.PUSH16,
            0x7D => Opcode.PUSH16,
            0x7E => Opcode.PUSH16,
            0x7F => Opcode.PUSH32,

            // Dup operations (0x80-0x8F)
            0x80 => Opcode.DUP1,
            0x81 => Opcode.DUP2,
            0x82 => Opcode.DUP3,
            0x83 => Opcode.DUP4,
            0x84 => Opcode.DUP4, // DUP5-16 -> DUP4 (max we support)
            0x85 => Opcode.DUP4,
            0x86 => Opcode.DUP4,
            0x87 => Opcode.DUP4,
            0x88 => Opcode.DUP4,
            0x89 => Opcode.DUP4,
            0x8A => Opcode.DUP4,
            0x8B => Opcode.DUP4,
            0x8C => Opcode.DUP4,
            0x8D => Opcode.DUP4,
            0x8E => Opcode.DUP4,
            0x8F => Opcode.DUP4,

            // Swap operations (0x90-0x9F)
            0x90 => Opcode.SWAP1,
            0x91 => Opcode.SWAP2,
            0x92 => Opcode.SWAP3,
            0x93 => Opcode.SWAP4,
            0x94 => Opcode.SWAP4, // SWAP5-16 -> SWAP4 (max we support)
            0x95 => Opcode.SWAP4,
            0x96 => Opcode.SWAP4,
            0x97 => Opcode.SWAP4,
            0x98 => Opcode.SWAP4,
            0x99 => Opcode.SWAP4,
            0x9A => Opcode.SWAP4,
            0x9B => Opcode.SWAP4,
            0x9C => Opcode.SWAP4,
            0x9D => Opcode.SWAP4,
            0x9E => Opcode.SWAP4,
            0x9F => Opcode.SWAP4,

            // Log operations (0xA0-0xA4)
            0xA0 => Opcode.LOG0,
            0xA1 => Opcode.LOG1,
            0xA2 => Opcode.LOG2,
            0xA3 => Opcode.LOG3,
            0xA4 => Opcode.LOG4,

            // System operations
            0xF0 => Opcode.CREATE,
            0xF1 => Opcode.CALL,
            0xF2 => Opcode.CALLCODE,
            0xF3 => Opcode.RETURN,
            0xF4 => Opcode.DELEGATECALL,
            0xF5 => Opcode.CREATE2,
            0xFA => Opcode.STATICCALL,
            0xFD => Opcode.REVERT,
            0xFF => Opcode.SELFDESTRUCT,

            // Context operations
            0x30 => Opcode.ADDRESS,
            0x31 => Opcode.BALANCE,
            0x32 => Opcode.ORIGIN,
            0x33 => Opcode.CALLER,
            0x34 => Opcode.CALLVALUE,
            0x35 => Opcode.CALLDATALOAD,
            0x36 => Opcode.CALLDATASIZE,
            0x37 => Opcode.CALLDATACOPY,
            0x38 => Opcode.CODESIZE,
            0x39 => Opcode.CODECOPY,
            0x3A => Opcode.GASPRICE,
            0x3B => Opcode.EXTCODESIZE,
            0x3C => Opcode.EXTCODECOPY,
            0x3D => Opcode.RETURNDATASIZE,
            0x3E => Opcode.RETURNDATACOPY,
            0x3F => Opcode.EXTCODEHASH,

            else => error.UnsupportedOpcode,
        };
    }

    /// Get push data size for EVM opcode
    pub fn getPushSize(evm_opcode: u8) u8 {
        if (evm_opcode >= 0x60 and evm_opcode <= 0x7F) {
            return evm_opcode - 0x5F; // PUSH1=1, PUSH2=2, ..., PUSH32=32
        }
        return 0;
    }
};

/// EVM bytecode translator
pub const EvmCompat = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) EvmCompat {
        return .{ .allocator = allocator };
    }

    /// Translate EVM bytecode to ZVM bytecode
    pub fn translate(self: *EvmCompat, evm_bytecode: []const u8) ![]u8 {
        var zvm_bytecode = std.ArrayList(u8).init(self.allocator);
        errdefer zvm_bytecode.deinit();

        var i: usize = 0;
        while (i < evm_bytecode.len) {
            const evm_op = evm_bytecode[i];

            // Map opcode
            const zvm_op = try EvmOpcodeMap.map(evm_op);
            try zvm_bytecode.append(@intFromEnum(zvm_op));

            // Handle PUSH data
            const push_size = EvmOpcodeMap.getPushSize(evm_op);
            if (push_size > 0) {
                i += 1;
                const end = @min(i + push_size, evm_bytecode.len);
                const push_data = evm_bytecode[i..end];

                // Pad to ZVM push size if needed
                const zvm_push_size = self.getZvmPushSize(zvm_op);
                if (push_data.len < zvm_push_size) {
                    // Left-pad with zeros
                    const padding = zvm_push_size - push_data.len;
                    try zvm_bytecode.appendNTimes(0, padding);
                }
                try zvm_bytecode.appendSlice(push_data);

                i += push_size - 1; // -1 because loop increments
            }

            i += 1;
        }

        return try zvm_bytecode.toOwnedSlice();
    }

    /// Translate EVM bytecode and wrap in ZVMC container
    pub fn translateToContainer(self: *EvmCompat, evm_bytecode: []const u8) !BytecodeContainer {
        const zvm_bytecode = try self.translate(evm_bytecode);
        errdefer self.allocator.free(zvm_bytecode);

        return try BytecodeContainer.create(
            self.allocator,
            zvm_bytecode,
            &[_]u8{}, // No ABI for translated EVM contracts
            .evm_compat,
        );
    }

    fn getZvmPushSize(self: *EvmCompat, op: Opcode) usize {
        _ = self;
        return switch (op) {
            .PUSH1 => 1,
            .PUSH2 => 2,
            .PUSH4 => 4,
            .PUSH8 => 8,
            .PUSH16 => 16,
            .PUSH32 => 32,
            else => 0,
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "EVM opcode mapping" {
    const testing = std.testing;

    // Test basic arithmetic
    try testing.expectEqual(Opcode.ADD, try EvmOpcodeMap.map(0x01));
    try testing.expectEqual(Opcode.MUL, try EvmOpcodeMap.map(0x02));
    try testing.expectEqual(Opcode.SUB, try EvmOpcodeMap.map(0x03));

    // Test PUSH opcodes
    try testing.expectEqual(Opcode.PUSH1, try EvmOpcodeMap.map(0x60));
    try testing.expectEqual(Opcode.PUSH32, try EvmOpcodeMap.map(0x7F));

    // Test DUP/SWAP
    try testing.expectEqual(Opcode.DUP1, try EvmOpcodeMap.map(0x80));
    try testing.expectEqual(Opcode.SWAP1, try EvmOpcodeMap.map(0x90));
}

test "EVM push size" {
    const testing = std.testing;

    try testing.expectEqual(@as(u8, 1), EvmOpcodeMap.getPushSize(0x60));
    try testing.expectEqual(@as(u8, 2), EvmOpcodeMap.getPushSize(0x61));
    try testing.expectEqual(@as(u8, 32), EvmOpcodeMap.getPushSize(0x7F));
    try testing.expectEqual(@as(u8, 0), EvmOpcodeMap.getPushSize(0x01)); // ADD
}

test "EVM bytecode translation" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var compat = EvmCompat.init(allocator);

    // Solidity: return 42 + 8
    const evm_bytecode = [_]u8{
        0x60, 0x2A, // PUSH1 42
        0x60, 0x08, // PUSH1 8
        0x01, // ADD
        0x00, // HALT
    };

    const zvm_bytecode = try compat.translate(&evm_bytecode);
    defer allocator.free(zvm_bytecode);

    // Verify translation
    try testing.expectEqual(@as(usize, 6), zvm_bytecode.len);
    try testing.expectEqual(@intFromEnum(Opcode.PUSH1), zvm_bytecode[0]);
    try testing.expectEqual(@as(u8, 0x2A), zvm_bytecode[1]);
    try testing.expectEqual(@intFromEnum(Opcode.PUSH1), zvm_bytecode[2]);
    try testing.expectEqual(@as(u8, 0x08), zvm_bytecode[3]);
    try testing.expectEqual(@intFromEnum(Opcode.ADD), zvm_bytecode[4]);
    try testing.expectEqual(@intFromEnum(Opcode.HALT), zvm_bytecode[5]);
}

test "EVM to container" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var compat = EvmCompat.init(allocator);

    const evm_bytecode = [_]u8{ 0x60, 0x01, 0x00 }; // PUSH1 1, HALT

    var container = try compat.translateToContainer(&evm_bytecode);
    defer container.deinit(allocator);

    try testing.expectEqual(BytecodeContainer.Target.evm_compat, container.target);
    try testing.expect(container.code.len > 0);
}
