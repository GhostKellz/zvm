//! ZVM Core - Bytecode interpreter, stack machine, memory management
const std = @import("std");

/// ZVM Error types
pub const VMError = error{
    StackOverflow,
    StackUnderflow,
    InvalidOpcode,
    OutOfGas,
    InvalidMemoryAccess,
    InvalidJump,
    ExecutionReverted,
    InvalidContract,
};

/// ZVM Opcodes - Native instruction set
pub const Opcode = enum(u8) {
    // Stack operations
    PUSH1 = 0x01,
    PUSH2 = 0x02,
    PUSH4 = 0x03,
    PUSH8 = 0x04,
    POP = 0x05,
    DUP = 0x06,
    SWAP = 0x07,

    // Arithmetic
    ADD = 0x10,
    SUB = 0x11,
    MUL = 0x12,
    DIV = 0x13,
    MOD = 0x14,

    // Comparison
    LT = 0x20,
    GT = 0x21,
    EQ = 0x22,
    NOT = 0x23,
    AND = 0x24,
    OR = 0x25,
    XOR = 0x26,

    // Memory operations
    MLOAD = 0x30,
    MSTORE = 0x31,
    MSIZE = 0x32,

    // Storage operations
    SLOAD = 0x40,
    SSTORE = 0x41,

    // Control flow
    JUMP = 0x50,
    JUMPI = 0x51,
    JUMPDEST = 0x52,

    // System operations
    CALL = 0x60,
    RETURN = 0x61,
    REVERT = 0x62,
    HALT = 0x63,

    // Contract operations
    CALLER = 0x70,
    CALLVALUE = 0x71,
    CALLDATALOAD = 0x72,
    CALLDATASIZE = 0x73,

    // Crypto operations (via zcrypto)
    KECCAK256 = 0x80,
    ECRECOVER = 0x81,
    ED25519_VERIFY = 0x82,
    SHA256 = 0x83,
    BLAKE3 = 0x84,
    
    // Post-quantum crypto operations
    ML_DSA_VERIFY = 0x90,
    ML_KEM_ENCAPSULATE = 0x91,
    ML_KEM_DECAPSULATE = 0x92,
    SCHNORR_VERIFY = 0x93,
    
    // Multi-signature operations
    MULTISIG_VERIFY = 0xA0,
    THRESHOLD_VERIFY = 0xA1,
    AGGREGATE_VERIFY = 0xA2,
    RING_VERIFY = 0xA3,

    _,
};

/// Gas costs for opcodes
pub const GasCost = struct {
    pub const BASE = 1;
    pub const VERYLOW = 3;
    pub const LOW = 5;
    pub const MID = 8;
    pub const HIGH = 10;
    pub const EXTCODE = 700;
    pub const BALANCE = 700;
    pub const SLOAD = 800;
    pub const SSTORE = 20000;
    pub const JUMPDEST = 1;
    pub const CREATE = 32000;
    pub const CALL = 700;
    pub const MEMORY = 3;
    
    // Crypto operation costs
    pub const KECCAK256_BASE = 30;
    pub const KECCAK256_WORD = 6;
    pub const SHA256_BASE = 60;
    pub const SHA256_WORD = 12;
    pub const BLAKE3_BASE = 20;
    pub const BLAKE3_WORD = 4;
    pub const ECRECOVER = 3000;
    pub const ED25519_VERIFY = 2000;
    
    // Post-quantum crypto costs (higher due to computational complexity)
    pub const ML_DSA_VERIFY = 8000;
    pub const ML_KEM_ENCAPSULATE = 5000;
    pub const ML_KEM_DECAPSULATE = 5000;
    pub const SCHNORR_VERIFY = 2500;
    
    // Multi-signature costs (scale with number of signatures)
    pub const MULTISIG_VERIFY_BASE = 1000;
    pub const MULTISIG_VERIFY_PER_SIG = 2000;
    pub const THRESHOLD_VERIFY_BASE = 1500;
    pub const THRESHOLD_VERIFY_PER_KEY = 500;
    pub const AGGREGATE_VERIFY_BASE = 2000;
    pub const AGGREGATE_VERIFY_PER_SIG = 1000;
    pub const RING_VERIFY_BASE = 3000;
    pub const RING_VERIFY_PER_KEY = 200;
};

/// VM execution stack (max 1024 items)
pub const Stack = struct {
    const MAX_DEPTH = 1024;

    items: [MAX_DEPTH]u256,
    len: usize,

    pub fn init() Stack {
        return Stack{
            .items = [_]u256{0} ** MAX_DEPTH,
            .len = 0,
        };
    }

    pub fn push(self: *Stack, value: u256) VMError!void {
        if (self.len >= MAX_DEPTH) return VMError.StackOverflow;
        self.items[self.len] = value;
        self.len += 1;
    }

    pub fn pop(self: *Stack) VMError!u256 {
        if (self.len == 0) return VMError.StackUnderflow;
        self.len -= 1;
        return self.items[self.len];
    }

    pub fn peek(self: *Stack, offset: usize) VMError!u256 {
        if (offset >= self.len) return VMError.StackUnderflow;
        return self.items[self.len - 1 - offset];
    }

    pub fn swap(self: *Stack, depth: usize) VMError!void {
        if (depth >= self.len) return VMError.StackUnderflow;
        const tmp = self.items[self.len - 1];
        self.items[self.len - 1] = self.items[self.len - 1 - depth];
        self.items[self.len - 1 - depth] = tmp;
    }

    pub fn dup(self: *Stack, depth: usize) VMError!void {
        if (depth >= self.len) return VMError.StackUnderflow;
        const value = self.items[self.len - 1 - depth];
        try self.push(value);
    }
};

/// VM Memory model - expandable byte array
pub const Memory = struct {
    data: []u8,
    size: usize,

    pub fn init() Memory {
        return Memory{
            .data = &[_]u8{},
            .size = 0,
        };
    }

    pub fn expand(self: *Memory, new_size: usize) VMError!void {
        if (new_size <= self.size) return;
        // In a real implementation, this would use an allocator
        // For now, we'll simulate with a fixed buffer
        self.size = new_size;
    }

    pub fn store(self: *Memory, offset: usize, data: []const u8) VMError!void {
        if (offset + data.len > self.size) {
            try self.expand(offset + data.len);
        }
        // Bounds check for safety
        if (offset + data.len > self.data.len) return VMError.InvalidMemoryAccess;
        @memcpy(self.data[offset .. offset + data.len], data);
    }

    pub fn load(self: *Memory, offset: usize, length: usize) VMError![]const u8 {
        if (offset + length > self.size) return VMError.InvalidMemoryAccess;
        return self.data[offset .. offset + length];
    }
};

/// Gas meter for deterministic execution costs
pub const GasMeter = struct {
    limit: u64,
    used: u64,

    pub fn init(limit: u64) GasMeter {
        return GasMeter{
            .limit = limit,
            .used = 0,
        };
    }

    pub fn consume(self: *GasMeter, cost: u64) VMError!void {
        if (self.used + cost > self.limit) return VMError.OutOfGas;
        self.used += cost;
    }

    pub fn remaining(self: *GasMeter) u64 {
        return self.limit - self.used;
    }
};

/// Core VM state
pub const VM = struct {
    stack: Stack,
    memory: Memory,
    gas: GasMeter,
    pc: usize, // Program counter
    running: bool,
    bytecode: []const u8,

    pub fn init() VM {
        return VM{
            .stack = Stack.init(),
            .memory = Memory.init(),
            .gas = GasMeter.init(0),
            .pc = 0,
            .running = false,
            .bytecode = &[_]u8{},
        };
    }

    pub fn load_bytecode(self: *VM, code: []const u8, limit: u64) void {
        self.bytecode = code;
        self.gas = GasMeter.init(limit);
        self.pc = 0;
        self.running = true;
        self.stack = Stack.init();
        self.memory = Memory.init();
    }

    /// Execute one instruction
    pub fn step(self: *VM) VMError!void {
        const is_running = self.running;
        const pc = self.pc;
        const bytecode_len = self.bytecode.len;

        if (!is_running or pc >= bytecode_len) {
            self.running = false;
            return;
        }

        const opcode_byte = self.bytecode[pc];
        const opcode: Opcode = @enumFromInt(opcode_byte);

        // Consume base gas
        try self.gas.consume(GasCost.BASE);

        switch (opcode) {
            .PUSH1 => {
                self.pc += 1;
                if (self.pc >= self.bytecode.len) return VMError.InvalidOpcode;
                try self.stack.push(self.bytecode[self.pc]);
            },
            .PUSH2 => {
                self.pc += 1;
                if (self.pc + 1 >= self.bytecode.len) return VMError.InvalidOpcode;
                const value = (@as(u256, self.bytecode[self.pc]) << 8) | self.bytecode[self.pc + 1];
                try self.stack.push(value);
                self.pc += 1;
            },
            .PUSH4 => {
                self.pc += 1;
                if (self.pc + 3 >= self.bytecode.len) return VMError.InvalidOpcode;
                var value: u256 = 0;
                for (0..4) |i| {
                    value = (value << 8) | self.bytecode[self.pc + i];
                }
                try self.stack.push(value);
                self.pc += 3;
            },
            .POP => {
                _ = try self.stack.pop();
            },
            .ADD => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a +% b); // Wrapping add
            },
            .SUB => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a -% b); // Wrapping sub
            },
            .MUL => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a *% b); // Wrapping mul
            },
            .DIV => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                if (b == 0) {
                    try self.stack.push(0);
                } else {
                    try self.stack.push(a / b);
                }
            },
            .EQ => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(if (a == b) 1 else 0);
            },
            .LT => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(if (a < b) 1 else 0);
            },
            .DUP => {
                try self.stack.dup(0); // Duplicate top
            },
            .SWAP => {
                try self.stack.swap(1); // Swap top two
            },
            .JUMP => {
                const dest = try self.stack.pop();
                if (dest >= self.bytecode.len) return VMError.InvalidJump;
                self.pc = @intCast(dest);
                return; // Don't increment PC
            },
            .JUMPI => {
                const dest = try self.stack.pop();
                const condition = try self.stack.pop();
                if (condition != 0) {
                    if (dest >= self.bytecode.len) return VMError.InvalidJump;
                    self.pc = @intCast(dest);
                    return; // Don't increment PC
                }
            },
            .HALT => {
                self.running = false;
                return;
            },
            .RETURN => {
                // In a full implementation, this would return data
                self.running = false;
                return;
            },
            .REVERT => {
                self.running = false;
                return VMError.ExecutionReverted;
            },
            else => {
                return VMError.InvalidOpcode;
            },
        }

        self.pc += 1;
    }

    /// Execute until completion or error
    pub fn run(self: *VM) VMError!void {
        while (self.running) {
            try self.step();
        }
    }

    pub fn gas_limit(self: *VM) u64 {
        return self.gas.limit;
    }

    pub fn gas_used(self: *VM) u64 {
        return self.gas.used;
    }
};

// Tests
test "VM initialization" {
    const vm = VM.init();
    try std.testing.expect(vm.gas.limit == 0);
    try std.testing.expect(!vm.running);
}

test "Stack operations" {
    var stack = Stack.init();
    try stack.push(42);
    try stack.push(100);

    try std.testing.expect(try stack.pop() == 100);
    try std.testing.expect(try stack.pop() == 42);
}

test "Basic bytecode execution" {
    var vm = VM.init();

    // Simple bytecode: PUSH1 42, PUSH1 8, ADD, HALT
    const bytecode = [_]u8{ @intFromEnum(Opcode.PUSH1), 42, @intFromEnum(Opcode.PUSH1), 8, @intFromEnum(Opcode.ADD), @intFromEnum(Opcode.HALT) };

    vm.load_bytecode(&bytecode, 1000);
    try vm.run();

    try std.testing.expect(vm.stack.len == 1);
    try std.testing.expect(try vm.stack.peek(0) == 50); // 42 + 8
}

test "Gas consumption" {
    var vm = VM.init();

    const bytecode = [_]u8{ @intFromEnum(Opcode.PUSH1), 1, @intFromEnum(Opcode.HALT) };

    vm.load_bytecode(&bytecode, 10);
    try vm.run();

    try std.testing.expect(vm.gas_used() >= 2); // At least base costs
}
