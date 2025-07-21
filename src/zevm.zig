//! ZEVM - Ethereum Virtual Machine compatibility layer for ZVM
//! Maps Ethereum opcodes to ZVM native equivalents
const std = @import("std");
const zvm = @import("zvm.zig");
const contract = @import("contract.zig");
const runtime = @import("runtime.zig");

/// Ethereum-compatible opcodes (subset)
pub const EvmOpcode = enum(u8) {
    // Stop and Arithmetic Operations
    STOP = 0x00,
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,
    SDIV = 0x05,
    MOD = 0x06,
    SMOD = 0x07,
    ADDMOD = 0x08,
    MULMOD = 0x09,
    EXP = 0x0a,
    SIGNEXTEND = 0x0b,

    // Comparison & Bitwise Logic Operations
    LT = 0x10,
    GT = 0x11,
    SLT = 0x12,
    SGT = 0x13,
    EQ = 0x14,
    ISZERO = 0x15,
    AND = 0x16,
    OR = 0x17,
    XOR = 0x18,
    NOT = 0x19,
    BYTE = 0x1a,
    SHL = 0x1b,
    SHR = 0x1c,
    SAR = 0x1d,

    // Keccak256
    KECCAK256 = 0x20,

    // Environmental Information
    ADDRESS = 0x30,
    BALANCE = 0x31,
    ORIGIN = 0x32,
    CALLER = 0x33,
    CALLVALUE = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE = 0x38,
    CODECOPY = 0x39,
    GASPRICE = 0x3a,
    EXTCODESIZE = 0x3b,
    EXTCODECOPY = 0x3c,
    RETURNDATASIZE = 0x3d,
    RETURNDATACOPY = 0x3e,
    EXTCODEHASH = 0x3f,

    // Block Information
    BLOCKHASH = 0x40,
    COINBASE = 0x41,
    TIMESTAMP = 0x42,
    NUMBER = 0x43,
    DIFFICULTY = 0x44,
    GASLIMIT = 0x45,
    CHAINID = 0x46,
    SELFBALANCE = 0x47,

    // Stack, Memory, Storage and Flow Operations
    POP = 0x50,
    MLOAD = 0x51,
    MSTORE = 0x52,
    MSTORE8 = 0x53,
    SLOAD = 0x54,
    SSTORE = 0x55,
    JUMP = 0x56,
    JUMPI = 0x57,
    PC = 0x58,
    MSIZE = 0x59,
    GAS = 0x5a,
    JUMPDEST = 0x5b,

    // Push Operations
    PUSH1 = 0x60,
    PUSH2 = 0x61,
    PUSH3 = 0x62,
    PUSH4 = 0x63,
    PUSH5 = 0x64,
    PUSH6 = 0x65,
    PUSH7 = 0x66,
    PUSH8 = 0x67,
    PUSH9 = 0x68,
    PUSH10 = 0x69,
    PUSH11 = 0x6a,
    PUSH12 = 0x6b,
    PUSH13 = 0x6c,
    PUSH14 = 0x6d,
    PUSH15 = 0x6e,
    PUSH16 = 0x6f,
    PUSH17 = 0x70,
    PUSH18 = 0x71,
    PUSH19 = 0x72,
    PUSH20 = 0x73,
    PUSH21 = 0x74,
    PUSH22 = 0x75,
    PUSH23 = 0x76,
    PUSH24 = 0x77,
    PUSH25 = 0x78,
    PUSH26 = 0x79,
    PUSH27 = 0x7a,
    PUSH28 = 0x7b,
    PUSH29 = 0x7c,
    PUSH30 = 0x7d,
    PUSH31 = 0x7e,
    PUSH32 = 0x7f,

    // Duplication Operations
    DUP1 = 0x80,
    DUP2 = 0x81,
    DUP3 = 0x82,
    DUP4 = 0x83,
    DUP5 = 0x84,
    DUP6 = 0x85,
    DUP7 = 0x86,
    DUP8 = 0x87,
    DUP9 = 0x88,
    DUP10 = 0x89,
    DUP11 = 0x8a,
    DUP12 = 0x8b,
    DUP13 = 0x8c,
    DUP14 = 0x8d,
    DUP15 = 0x8e,
    DUP16 = 0x8f,

    // Exchange Operations
    SWAP1 = 0x90,
    SWAP2 = 0x91,
    SWAP3 = 0x92,
    SWAP4 = 0x93,
    SWAP5 = 0x94,
    SWAP6 = 0x95,
    SWAP7 = 0x96,
    SWAP8 = 0x97,
    SWAP9 = 0x98,
    SWAP10 = 0x99,
    SWAP11 = 0x9a,
    SWAP12 = 0x9b,
    SWAP13 = 0x9c,
    SWAP14 = 0x9d,
    SWAP15 = 0x9e,
    SWAP16 = 0x9f,

    // Logging Operations
    LOG0 = 0xa0,
    LOG1 = 0xa1,
    LOG2 = 0xa2,
    LOG3 = 0xa3,
    LOG4 = 0xa4,

    // System Operations
    CREATE = 0xf0,
    CALL = 0xf1,
    CALLCODE = 0xf2,
    RETURN = 0xf3,
    DELEGATECALL = 0xf4,
    CREATE2 = 0xf5,
    STATICCALL = 0xfa,
    REVERT = 0xfd,
    INVALID = 0xfe,
    SELFDESTRUCT = 0xff,

    _,
};

/// Ethereum gas costs
pub const EvmGasCost = struct {
    pub const ZERO = 0;
    pub const BASE = 2;
    pub const VERYLOW = 3;
    pub const LOW = 5;
    pub const MID = 8;
    pub const HIGH = 10;
    pub const EXTCODE = 700;
    pub const BALANCE = 700;
    pub const SLOAD = 800;
    pub const SSTORE_SET = 20000;
    pub const SSTORE_RESET = 5000;
    pub const SSTORE_CLEAR = 15000;
    pub const JUMPDEST = 1;
    pub const CREATE = 32000;
    pub const CALL = 700;
    pub const MEMORY = 3;
    pub const KECCAK256_WORD = 6;
    pub const LOG_BASE = 375;
    pub const LOG_DATA = 8;
    pub const LOG_TOPIC = 375;
};

/// Enhanced VM with Ethereum compatibility
pub const EvmVM = struct {
    vm: zvm.VM,
    context: contract.ContractContext,
    return_data: []const u8,
    logs: std.ArrayList(EvmLog),

    const EvmLog = struct {
        address: contract.Address,
        topics: []const [32]u8,
        data: []const u8,
    };

    pub fn init(context: contract.ContractContext, allocator: std.mem.Allocator) EvmVM {
        return EvmVM{
            .vm = zvm.VM.init(),
            .context = context,
            .return_data = &[_]u8{},
            .logs = std.ArrayList(EvmLog).init(allocator),
        };
    }

    pub fn deinit(self: *EvmVM) void {
        self.logs.deinit();
    }

    /// Execute EVM bytecode
    pub fn execute(self: *EvmVM, bytecode: []const u8) zvm.VMError!contract.ExecutionResult {
        self.vm.load_bytecode(bytecode, self.context.gas_limit);

        while (self.vm.running) {
            try self.execute_evm_step();
        }

        return contract.ExecutionResult{
            .success = true,
            .gas_used = self.vm.gas_used(),
            .return_data = self.return_data,
            .error_msg = null,
            .contract_address = self.context.address,
        };
    }

    /// Execute one EVM instruction
    fn execute_evm_step(self: *EvmVM) zvm.VMError!void {
        const is_running = self.vm.running;
        const pc = self.vm.pc;
        const bytecode_len = self.vm.bytecode.len;

        if (!is_running or pc >= bytecode_len) {
            self.vm.running = false;
            return;
        }

        const opcode_byte = self.vm.bytecode[pc];
        const evm_opcode: EvmOpcode = @enumFromInt(opcode_byte);

        switch (evm_opcode) {
            .STOP => {
                self.vm.running = false;
                try self.vm.gas.consume(EvmGasCost.ZERO);
            },
            .ADD => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(a +% b);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .MUL => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(a *% b);
                try self.vm.gas.consume(EvmGasCost.LOW);
            },
            .SUB => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(a -% b);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .DIV => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                if (b == 0) {
                    try self.vm.stack.push(0);
                } else {
                    try self.vm.stack.push(a / b);
                }
                try self.vm.gas.consume(EvmGasCost.LOW);
            },
            .MOD => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                if (b == 0) {
                    try self.vm.stack.push(0);
                } else {
                    try self.vm.stack.push(a % b);
                }
                try self.vm.gas.consume(EvmGasCost.LOW);
            },
            .EQ => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(if (a == b) 1 else 0);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .LT => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(if (a < b) 1 else 0);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .GT => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(if (a > b) 1 else 0);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .ISZERO => {
                const a = try self.vm.stack.pop();
                try self.vm.stack.push(if (a == 0) 1 else 0);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .AND => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(a & b);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .OR => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(a | b);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .XOR => {
                const a = try self.vm.stack.pop();
                const b = try self.vm.stack.pop();
                try self.vm.stack.push(a ^ b);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .NOT => {
                const a = try self.vm.stack.pop();
                try self.vm.stack.push(~a);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .KECCAK256 => {
                const offset = try self.vm.stack.pop();
                const length = try self.vm.stack.pop();

                // Get data from memory (simplified)
                _ = offset;
                _ = length;
                const data = &[_]u8{0x42}; // Placeholder

                const hash = runtime.Crypto.keccak256(data);

                // Convert hash to u256
                var result: u256 = 0;
                for (hash) |byte| {
                    result = (result << 8) | byte;
                }
                try self.vm.stack.push(result);

                const gas_cost = EvmGasCost.HIGH + (data.len + 31) / 32 * EvmGasCost.KECCAK256_WORD;
                try self.vm.gas.consume(gas_cost);
            },
            .ADDRESS => {
                // Push current contract address
                var addr_u256: u256 = 0;
                for (self.context.address) |byte| {
                    addr_u256 = (addr_u256 << 8) | byte;
                }
                try self.vm.stack.push(addr_u256);
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            .BALANCE => {
                const addr_u256 = try self.vm.stack.pop();

                // Convert u256 to address (simplified)
                _ = addr_u256;
                const balance: u256 = 1000000; // Mock balance
                try self.vm.stack.push(balance);
                try self.vm.gas.consume(EvmGasCost.BALANCE);
            },
            .CALLER => {
                // Push caller address
                var caller_u256: u256 = 0;
                for (self.context.sender) |byte| {
                    caller_u256 = (caller_u256 << 8) | byte;
                }
                try self.vm.stack.push(caller_u256);
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            .CALLVALUE => {
                try self.vm.stack.push(self.context.value);
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            .CALLDATASIZE => {
                try self.vm.stack.push(self.context.input.len);
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            .TIMESTAMP => {
                try self.vm.stack.push(self.context.block_timestamp);
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            .NUMBER => {
                try self.vm.stack.push(self.context.block_number);
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            .POP => {
                _ = try self.vm.stack.pop();
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            .MLOAD => {
                const offset = try self.vm.stack.pop();
                // Load 32 bytes from memory (simplified)
                _ = offset;
                try self.vm.stack.push(0x1234567890abcdef); // Placeholder
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .MSTORE => {
                const offset = try self.vm.stack.pop();
                const value = try self.vm.stack.pop();
                // Store 32 bytes to memory (simplified)
                _ = offset;
                _ = value;
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .SLOAD => {
                const key = try self.vm.stack.pop();
                const value = self.context.storage.load(key);
                try self.vm.stack.push(value);
                try self.vm.gas.consume(EvmGasCost.SLOAD);
            },
            .SSTORE => {
                const key = try self.vm.stack.pop();
                const value = try self.vm.stack.pop();
                self.context.storage.store(key, value);
                try self.vm.gas.consume(EvmGasCost.SSTORE_SET); // Simplified
            },
            .JUMP => {
                const dest = try self.vm.stack.pop();
                if (dest >= self.vm.bytecode.len) return zvm.VMError.InvalidJump;

                // Check if destination is JUMPDEST
                if (self.vm.bytecode[@intCast(dest)] != @intFromEnum(EvmOpcode.JUMPDEST)) {
                    return zvm.VMError.InvalidJump;
                }

                self.vm.pc = @intCast(dest);
                try self.vm.gas.consume(EvmGasCost.MID);
                return; // Don't increment PC
            },
            .JUMPI => {
                const dest = try self.vm.stack.pop();
                const condition = try self.vm.stack.pop();

                if (condition != 0) {
                    if (dest >= self.vm.bytecode.len) return zvm.VMError.InvalidJump;

                    // Check if destination is JUMPDEST
                    if (self.vm.bytecode[@intCast(dest)] != @intFromEnum(EvmOpcode.JUMPDEST)) {
                        return zvm.VMError.InvalidJump;
                    }

                    self.vm.pc = @intCast(dest);
                    try self.vm.gas.consume(EvmGasCost.HIGH);
                    return; // Don't increment PC
                }
                try self.vm.gas.consume(EvmGasCost.HIGH);
            },
            .JUMPDEST => {
                try self.vm.gas.consume(EvmGasCost.JUMPDEST);
            },
            .PC => {
                try self.vm.stack.push(self.vm.pc);
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            .GAS => {
                try self.vm.stack.push(self.vm.gas.remaining());
                try self.vm.gas.consume(EvmGasCost.BASE);
            },
            // Push operations
            .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8, .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16, .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24, .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32 => {
                const push_size = @intFromEnum(evm_opcode) - @intFromEnum(EvmOpcode.PUSH1) + 1;

                if (self.vm.pc + push_size >= self.vm.bytecode.len) {
                    return zvm.VMError.InvalidOpcode;
                }

                var value: u256 = 0;
                for (1..push_size + 1) |i| {
                    value = (value << 8) | self.vm.bytecode[self.vm.pc + i];
                }

                try self.vm.stack.push(value);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
                self.vm.pc += push_size;
            },
            // Dup operations
            .DUP1, .DUP2, .DUP3, .DUP4, .DUP5, .DUP6, .DUP7, .DUP8, .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14, .DUP15, .DUP16 => {
                const dup_depth = @intFromEnum(evm_opcode) - @intFromEnum(EvmOpcode.DUP1);
                try self.vm.stack.dup(dup_depth);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            // Swap operations
            .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8, .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16 => {
                const swap_depth = @intFromEnum(evm_opcode) - @intFromEnum(EvmOpcode.SWAP1) + 1;
                try self.vm.stack.swap(swap_depth);
                try self.vm.gas.consume(EvmGasCost.VERYLOW);
            },
            .RETURN => {
                const offset = try self.vm.stack.pop();
                const length = try self.vm.stack.pop();

                // Set return data (simplified)
                _ = offset;
                _ = length;
                self.return_data = &[_]u8{0x42}; // Placeholder

                self.vm.running = false;
                try self.vm.gas.consume(EvmGasCost.ZERO);
            },
            .REVERT => {
                const offset = try self.vm.stack.pop();
                const length = try self.vm.stack.pop();

                // Set return data (simplified)
                _ = offset;
                _ = length;
                self.return_data = &[_]u8{0x42}; // Placeholder

                self.vm.running = false;
                return zvm.VMError.ExecutionReverted;
            },
            else => {
                return zvm.VMError.InvalidOpcode;
            },
        }

        self.vm.pc += 1;
    }
};

/// ZEVM runtime that uses EVM-compatible execution
pub const ZevmRuntime = struct {
    allocator: std.mem.Allocator,
    registry: contract.ContractRegistry,
    default_storage: contract.Storage,

    pub fn init(allocator: std.mem.Allocator) ZevmRuntime {
        return ZevmRuntime{
            .allocator = allocator,
            .registry = contract.ContractRegistry.init(allocator),
            .default_storage = contract.Storage.init(allocator),
        };
    }

    pub fn deinit(self: *ZevmRuntime) void {
        self.registry.deinit();
        self.default_storage.deinit();
    }

    /// Execute EVM bytecode
    pub fn execute_evm(self: *ZevmRuntime, bytecode: []const u8, caller: contract.Address, value: u256, input: []const u8, gas_limit: u64) !contract.ExecutionResult {
        const context = contract.ContractContext.init(
            contract.AddressUtils.zero(), // Contract address
            caller,
            value,
            input,
            gas_limit,
            12345, // Block number
            @intCast(std.time.timestamp()),
            &self.default_storage,
        );

        var evm = EvmVM.init(context, self.allocator);
        defer evm.deinit();

        return evm.execute(bytecode);
    }
};

// Tests
test "EVM opcode execution" {
    var zevm_runtime = ZevmRuntime.init(std.testing.allocator);
    defer zevm_runtime.deinit();

    // Simple EVM bytecode: PUSH1 42, PUSH1 8, ADD, STOP
    const bytecode = [_]u8{ @intFromEnum(EvmOpcode.PUSH1), 42, @intFromEnum(EvmOpcode.PUSH1), 8, @intFromEnum(EvmOpcode.ADD), @intFromEnum(EvmOpcode.STOP) };

    const result = try zevm_runtime.execute_evm(&bytecode, contract.AddressUtils.zero(), 0, &[_]u8{}, 100000);

    try std.testing.expect(result.success);
}

test "EVM gas consumption" {
    var zevm_runtime = ZevmRuntime.init(std.testing.allocator);
    defer zevm_runtime.deinit();

    const bytecode = [_]u8{ @intFromEnum(EvmOpcode.PUSH1), 1, @intFromEnum(EvmOpcode.PUSH1), 2, @intFromEnum(EvmOpcode.ADD), @intFromEnum(EvmOpcode.STOP) };

    const result = try zevm_runtime.execute_evm(&bytecode, contract.AddressUtils.zero(), 0, &[_]u8{}, 100000);

    try std.testing.expect(result.success);
    try std.testing.expect(result.gas_used > 0);
}
