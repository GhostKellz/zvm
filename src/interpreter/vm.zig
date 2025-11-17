//! ZVM Core Interpreter
//! Zero-dependency virtual machine for multi-chain smart contract execution

const std = @import("std");
const types = @import("../primitives/types.zig");
const opcode = @import("../bytecode/opcode.zig");
const Stack = @import("stack.zig").Stack;
const Memory = @import("memory.zig").Memory;
const Gas = @import("../gas/meter.zig").Gas;
const storage_mod = @import("../state/storage.zig");

const U256 = types.U256;
const Address = types.Address;
const Hash = types.Hash;
const Opcode = opcode.Opcode;
const Storage = storage_mod.Storage;
const TransientStorage = storage_mod.TransientStorage;
const StorageAccess = storage_mod.StorageAccess;

// Hedera syscalls (optional)
const hedera_mod = @import("../chains/hedera/syscalls.zig");
const HederaSyscalls = hedera_mod.HederaSyscalls;
const HederaGas = hedera_mod.HederaGas;
const HTSOperation = hedera_mod.HTSOperation;
const HCSOperation = hedera_mod.HCSOperation;

pub const VMError = error{
    OutOfGas,
    StackOverflow,
    StackUnderflow,
    InvalidJumpDestination,
    InvalidOpcode,
    Revert,
    OutOfMemory,
    InvalidOffset,
    DivisionByZero,
    Halted,
} || std.mem.Allocator.Error;

/// Execution context for the VM
pub const ExecutionContext = struct {
    /// Address of the contract being executed
    address: Address,
    /// Address of the caller
    caller: Address,
    /// Transaction origin
    origin: Address,
    /// Value sent with the call
    value: U256,
    /// Gas price
    gas_price: u64,
    /// Input data (calldata)
    calldata: []const u8,
    /// Block number
    block_number: u64,
    /// Block timestamp
    timestamp: u64,
    /// Chain ID
    chain_id: u64,

    pub fn init() ExecutionContext {
        return .{
            .address = Address.zero(),
            .caller = Address.zero(),
            .origin = Address.zero(),
            .value = U256.zero(),
            .gas_price = 0,
            .calldata = &[_]u8{},
            .block_number = 0,
            .timestamp = 0,
            .chain_id = 1, // Default to mainnet
        };
    }
};

/// Result of contract execution
pub const ExecutionResult = struct {
    success: bool,
    gas_used: u64,
    return_data: []const u8,
    logs: []const Log,

    pub const Log = struct {
        address: Address,
        topics: []const Hash,
        data: []const u8,
    };
};

/// Core VM state
pub const VM = struct {
    /// Stack for operands
    stack: Stack,
    /// Memory for temporary storage
    memory: Memory,
    /// Gas meter
    gas: Gas,
    /// Program counter
    pc: usize,
    /// Bytecode being executed
    bytecode: []const u8,
    /// Execution context
    context: ExecutionContext,
    /// Return data buffer
    return_data: std.ArrayListUnmanaged(u8),
    /// Logs emitted during execution
    logs: std.ArrayListUnmanaged(ExecutionResult.Log),
    /// Persistent storage
    storage: Storage,
    /// Transient storage (cleared after transaction)
    transient_storage: TransientStorage,
    /// Hedera syscalls (optional, null if not on Hedera)
    hedera_syscalls: ?HederaSyscalls,
    /// Allocator
    allocator: std.mem.Allocator,
    /// Halted flag
    halted: bool,
    /// PC modified flag (for jumps)
    pc_modified: bool,

    pub fn init(allocator: std.mem.Allocator, gas_limit: u64, storage: Storage, transient_storage: TransientStorage, hedera_syscalls: ?HederaSyscalls) VM {
        return .{
            .stack = Stack.init(),
            .memory = Memory.init(allocator),
            .gas = Gas.init(gas_limit),
            .pc = 0,
            .bytecode = &[_]u8{},
            .context = ExecutionContext.init(),
            .return_data = .{},
            .logs = .{},
            .storage = storage,
            .transient_storage = transient_storage,
            .hedera_syscalls = hedera_syscalls,
            .allocator = allocator,
            .halted = false,
            .pc_modified = false,
        };
    }

    pub fn deinit(self: *VM) void {
        self.memory.deinit();
        self.return_data.deinit(self.allocator);
        // Clean up logs
        for (self.logs.items) |log| {
            self.allocator.free(log.topics);
            self.allocator.free(log.data);
        }
        self.logs.deinit(self.allocator);
    }

    /// Load bytecode and prepare for execution
    pub fn loadBytecode(self: *VM, bytecode: []const u8) void {
        self.bytecode = bytecode;
        self.pc = 0;
        self.halted = false;
        self.stack.clear();
        self.memory.clear();
        self.return_data.clearRetainingCapacity();
    }

    /// Execute bytecode
    pub fn execute(self: *VM) !ExecutionResult {
        while (!self.halted and self.pc < self.bytecode.len) {
            try self.step();
        }

        const gas_used = self.gas.finalUsed();

        return ExecutionResult{
            .success = !self.halted, // TODO: Track execution status properly
            .gas_used = gas_used,
            .return_data = self.return_data.items,
            .logs = self.logs.items,
        };
    }

    /// Execute single instruction
    fn step(self: *VM) !void {
        // Fetch opcode
        const op = @as(Opcode, @enumFromInt(self.bytecode[self.pc]));

        // Charge gas
        try self.gas.charge(op.gasCost());

        // Reset PC modified flag
        self.pc_modified = false;

        // Execute opcode
        try self.executeOpcode(op);

        // Advance PC (unless opcode modified it)
        if (!self.pc_modified) {
            self.pc += 1;
        }
    }

    /// Execute single opcode
    fn executeOpcode(self: *VM, op: Opcode) !void {
        switch (op) {
            // === Control Flow ===
            .HALT => {
                self.halted = true;
                return;
            },

            .NOP => {}, // Do nothing

            // === Stack Operations ===
            .POP => {
                _ = try self.stack.pop();
            },

            .PUSH1 => {
                self.pc += 1;
                const value = self.bytecode[self.pc];
                try self.stack.push(U256.fromU64(value));
            },

            .PUSH2 => {
                self.pc += 1;
                const high = self.bytecode[self.pc];
                self.pc += 1;
                const low = self.bytecode[self.pc];
                const value: u16 = (@as(u16, high) << 8) | low;
                try self.stack.push(U256.fromU64(value));
            },

            .PUSH4 => {
                self.pc += 1;
                var value: u32 = 0;
                for (0..4) |i| {
                    value = (value << 8) | self.bytecode[self.pc + i];
                }
                self.pc += 3;
                try self.stack.push(U256.fromU64(value));
            },

            .PUSH32 => {
                self.pc += 1;
                var bytes: [32]u8 = undefined;
                @memcpy(&bytes, self.bytecode[self.pc .. self.pc + 32]);
                self.pc += 31;
                try self.stack.push(U256.fromBytes(bytes));
            },

            .DUP1 => try self.stack.dup(0),
            .DUP2 => try self.stack.dup(1),
            .DUP3 => try self.stack.dup(2),
            .DUP4 => try self.stack.dup(3),

            .SWAP1 => try self.stack.swap(1),
            .SWAP2 => try self.stack.swap(2),
            .SWAP3 => try self.stack.swap(3),
            .SWAP4 => try self.stack.swap(4),

            // === Arithmetic ===
            .ADD => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a.add(b));
            },

            .SUB => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a.sub(b));
            },

            .MUL => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a.mul(b));
            },

            .DIV => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                if (b.isZero()) {
                    try self.stack.push(U256.zero());
                } else {
                    try self.stack.push(a.div(b));
                }
            },

            .MOD => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                if (b.isZero()) {
                    try self.stack.push(U256.zero());
                } else {
                    try self.stack.push(a.mod(b));
                }
            },

            // === Comparison & Bitwise ===
            .LT => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(if (a.lt(b)) U256.one() else U256.zero());
            },

            .GT => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(if (a.gt(b)) U256.one() else U256.zero());
            },

            .EQ => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(if (a.eql(b)) U256.one() else U256.zero());
            },

            .ISZERO => {
                const a = try self.stack.pop();
                try self.stack.push(if (a.isZero()) U256.one() else U256.zero());
            },

            .AND => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a.bitAnd(b));
            },

            .OR => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a.bitOr(b));
            },

            .XOR => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a.bitXor(b));
            },

            .NOT => {
                const a = try self.stack.pop();
                try self.stack.push(a.bitNot());
            },

            .SHL => {
                const shift = try self.stack.pop();
                const value = try self.stack.pop();
                try self.stack.push(value.shl(shift));
            },

            .SHR => {
                const shift = try self.stack.pop();
                const value = try self.stack.pop();
                try self.stack.push(value.shr(shift));
            },

            // === Additional EVM Arithmetic ===
            .ADDMOD => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                const n = try self.stack.pop();
                if (n.isZero()) {
                    try self.stack.push(U256.zero());
                } else {
                    const sum = a.add(b);
                    try self.stack.push(sum.mod(n));
                }
            },

            .MULMOD => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                const n = try self.stack.pop();
                if (n.isZero()) {
                    try self.stack.push(U256.zero());
                } else {
                    const product = a.mul(b);
                    try self.stack.push(product.mod(n));
                }
            },

            .EXP => {
                const base = try self.stack.pop();
                const exponent = try self.stack.pop();

                // Simplified exponentiation (real implementation would handle overflow better)
                var result = U256.one();
                var exp = exponent.toU64(); // Simplified - only handle small exponents
                var b = base;

                while (exp > 0) {
                    if (exp & 1 == 1) {
                        result = result.mul(b);
                    }
                    b = b.mul(b);
                    exp >>= 1;
                }

                try self.stack.push(result);
            },

            .BYTE => {
                const i = try self.stack.pop();
                const x = try self.stack.pop();

                const byte_index = i.toU64();
                if (byte_index >= 32) {
                    try self.stack.push(U256.zero());
                } else {
                    const bytes = x.toBytes();
                    const byte_val = bytes[@intCast(byte_index)];
                    try self.stack.push(U256.fromU64(byte_val));
                }
            },

            // === Memory ===
            .MLOAD => {
                const offset = try self.stack.pop();
                const offset_usize = offset.toUsize();

                // Charge for memory expansion
                const expansion_cost = Memory.expansionCost(self.memory.size(), offset_usize + 32);
                try self.gas.charge(expansion_cost);

                const value = try self.memory.load(offset_usize);
                try self.stack.push(value);
            },

            .MSTORE => {
                const offset = try self.stack.pop();
                const value = try self.stack.pop();
                const offset_usize = offset.toUsize();

                // Charge for memory expansion
                const expansion_cost = Memory.expansionCost(self.memory.size(), offset_usize + 32);
                try self.gas.charge(expansion_cost);

                try self.memory.store(offset_usize, value);
            },

            .MSTORE8 => {
                const offset = try self.stack.pop();
                const value = try self.stack.pop();
                const offset_usize = offset.toUsize();

                // Charge for memory expansion
                const expansion_cost = Memory.expansionCost(self.memory.size(), offset_usize + 1);
                try self.gas.charge(expansion_cost);

                const byte: u8 = @intCast(value.toU64() & 0xFF);
                try self.memory.store8(offset_usize, byte);
            },

            .MSIZE => {
                const size = self.memory.size();
                try self.stack.push(U256.fromU64(@intCast(size)));
            },

            // === Control Flow ===
            .JUMP => {
                const dest = try self.stack.pop();
                self.pc = dest.toUsize();
                self.pc_modified = true;
            },

            .JUMPI => {
                const dest = try self.stack.pop();
                const condition = try self.stack.pop();

                if (!condition.isZero()) {
                    self.pc = dest.toUsize();
                    self.pc_modified = true;
                }
            },

            .PC => {
                try self.stack.push(U256.fromU64(@intCast(self.pc)));
            },

            .JUMPDEST => {
                // Valid jump destination, no-op
            },

            .RETURN => {
                const offset = try self.stack.pop();
                const length = try self.stack.pop();

                const offset_usize = offset.toUsize();
                const length_usize = length.toUsize();

                if (length_usize > 0) {
                    const data = try self.memory.slice(offset_usize, length_usize);
                    try self.return_data.appendSlice(self.allocator, data);
                }

                self.halted = true;
            },

            .REVERT => {
                const offset = try self.stack.pop();
                const length = try self.stack.pop();

                const offset_usize = offset.toUsize();
                const length_usize = length.toUsize();

                if (length_usize > 0) {
                    const data = try self.memory.slice(offset_usize, length_usize);
                    try self.return_data.appendSlice(self.allocator, data);
                }

                return error.Revert;
            },

            // === Context ===
            .ADDRESS => {
                try self.stack.push(addressToU256(self.context.address));
            },

            .CALLER => {
                try self.stack.push(addressToU256(self.context.caller));
            },

            .ORIGIN => {
                try self.stack.push(addressToU256(self.context.origin));
            },

            .CALLVALUE => {
                try self.stack.push(self.context.value);
            },

            .CALLDATALOAD => {
                const offset = try self.stack.pop();
                const offset_usize = offset.toUsize();

                var data: [32]u8 = [_]u8{0} ** 32;
                const available = if (offset_usize < self.context.calldata.len)
                    self.context.calldata.len - offset_usize
                else
                    0;

                if (available > 0) {
                    const to_copy = @min(32, available);
                    @memcpy(data[0..to_copy], self.context.calldata[offset_usize .. offset_usize + to_copy]);
                }

                try self.stack.push(U256.fromBytes(data));
            },

            .CALLDATASIZE => {
                try self.stack.push(U256.fromU64(@intCast(self.context.calldata.len)));
            },

            .TIMESTAMP => {
                try self.stack.push(U256.fromU64(self.context.timestamp));
            },

            .NUMBER => {
                try self.stack.push(U256.fromU64(self.context.block_number));
            },

            .CHAINID => {
                try self.stack.push(U256.fromU64(self.context.chain_id));
            },

            .GASPRICE => {
                try self.stack.push(U256.fromU64(self.context.gas_price));
            },

            .GASLIMIT => {
                // Return a reasonable gas limit
                try self.stack.push(U256.fromU64(30_000_000));
            },

            .COINBASE => {
                // Mock coinbase (would be actual block beneficiary)
                try self.stack.push(addressToU256(Address.zero()));
            },

            .BLOCKHASH => {
                const block_number = try self.stack.pop();
                _ = block_number; // Simplified - would look up actual block hash
                // Return mock block hash
                const mock_hash = Hash{ .bytes = [_]u8{0xAB} ** 32 };
                try self.stack.push(U256.fromBytes(mock_hash.bytes));
            },

            // === Logging ===
            .LOG0 => {
                const offset = try self.stack.pop();
                const length = try self.stack.pop();

                const offset_usize = offset.toUsize();
                const length_usize = length.toUsize();
                const data = try self.memory.slice(offset_usize, length_usize);

                // Create log with 0 topics
                const log = ExecutionResult.Log{
                    .address = self.context.address,
                    .topics = &[_]Hash{},
                    .data = data,
                };
                try self.logs.append(self.allocator, log);
            },

            .LOG1 => {
                const offset = try self.stack.pop();
                const length = try self.stack.pop();
                const topic1_u256 = try self.stack.pop();

                const offset_usize = offset.toUsize();
                const length_usize = length.toUsize();
                const data = try self.memory.slice(offset_usize, length_usize);

                var topics = try self.allocator.alloc(Hash, 1);
                const topic1_bytes = topic1_u256.toBytes();
                topics[0] = Hash{ .bytes = topic1_bytes };

                const log = ExecutionResult.Log{
                    .address = self.context.address,
                    .topics = topics,
                    .data = data,
                };
                try self.logs.append(self.allocator, log);
            },

            .LOG2 => {
                const offset = try self.stack.pop();
                const length = try self.stack.pop();
                const topic1_u256 = try self.stack.pop();
                const topic2_u256 = try self.stack.pop();

                const offset_usize = offset.toUsize();
                const length_usize = length.toUsize();
                const data = try self.memory.slice(offset_usize, length_usize);

                var topics = try self.allocator.alloc(Hash, 2);
                topics[0] = Hash{ .bytes = topic1_u256.toBytes() };
                topics[1] = Hash{ .bytes = topic2_u256.toBytes() };

                const log = ExecutionResult.Log{
                    .address = self.context.address,
                    .topics = topics,
                    .data = data,
                };
                try self.logs.append(self.allocator, log);
            },

            // === Crypto ===
            .KECCAK256 => {
                const offset = try self.stack.pop();
                const length = try self.stack.pop();

                const offset_usize = offset.toUsize();
                const length_usize = length.toUsize();

                const data = try self.memory.slice(offset_usize, length_usize);

                var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
                hasher.update(data);
                var hash: [32]u8 = undefined;
                hasher.final(&hash);

                try self.stack.push(U256.fromBytes(hash));
            },

            // === Storage ===
            .SLOAD => {
                const key = try self.stack.pop();

                // Charge dynamic gas based on access pattern
                const access = self.storage.accessPattern(self.context.address, key);
                const dynamic_gas: u64 = switch (access) {
                    .cold => 2100, // Cold SLOAD (EIP-2929)
                    .warm => 100,  // Warm SLOAD
                };
                try self.gas.charge(dynamic_gas);

                const value = self.storage.load(self.context.address, key);
                try self.stack.push(value);
            },

            .SSTORE => {
                const key = try self.stack.pop();
                const value = try self.stack.pop();

                // Get current and original values for gas calculation
                const current = self.storage.load(self.context.address, key);
                const access = self.storage.accessPattern(self.context.address, key);

                // Calculate dynamic gas cost (simplified EIP-2200/EIP-2929)
                const dynamic_gas: u64 = if (value.eql(current))
                    100  // No change
                else if (current.isZero())
                    20000  // Storage creation
                else if (value.isZero())
                    2900  // Storage deletion (with refund)
                else switch (access) {
                    .cold => 2200,  // Cold storage modification
                    .warm => 100,   // Warm storage modification
                };

                try self.gas.charge(dynamic_gas);

                // Refund gas for storage deletion
                if (!current.isZero() and value.isZero()) {
                    self.gas.refund(15000);
                }

                self.storage.store(self.context.address, key, value);
            },

            .TLOAD => {
                const key = try self.stack.pop();
                const value = self.transient_storage.load(self.context.address, key);
                try self.stack.push(value);
            },

            .TSTORE => {
                const key = try self.stack.pop();
                const value = try self.stack.pop();
                self.transient_storage.store(self.context.address, key, value);
            },

            // === Hedera Token Service (HTS) ===
            .HTS_TRANSFER => {
                if (self.hedera_syscalls) |hedera| {
                    try self.gas.charge(HederaGas.htsGasCost(.TRANSFER));

                    // Stack: token_id, from, to, amount
                    const token_id_u256 = try self.stack.pop();
                    const from_u256 = try self.stack.pop();
                    const to_u256 = try self.stack.pop();
                    const amount = try self.stack.pop();

                    const token_id = u256ToAddress(token_id_u256);
                    const from = u256ToAddress(from_u256);
                    const to = u256ToAddress(to_u256);

                    // Encode parameters (simplified - would use proper encoding in production)
                    var data: [128]u8 = undefined;
                    @memcpy(data[0..20], &token_id.bytes);
                    @memcpy(data[20..40], &from.bytes);
                    @memcpy(data[40..60], &to.bytes);
                    const amount_bytes = amount.toBytes();
                    @memcpy(data[60..92], &amount_bytes);

                    const result = hedera.htsCall(.TRANSFER, data[0..92]);
                    const success = if (result.isSuccess()) U256.one() else U256.zero();
                    try self.stack.push(success);
                } else {
                    return error.InvalidOpcode; // Hedera not available
                }
            },

            .HTS_MINT => {
                if (self.hedera_syscalls) |hedera| {
                    try self.gas.charge(HederaGas.htsGasCost(.MINT));

                    // Stack: token_id, amount
                    const token_id_u256 = try self.stack.pop();
                    const amount = try self.stack.pop();

                    const token_id = u256ToAddress(token_id_u256);

                    var data: [64]u8 = undefined;
                    @memcpy(data[0..20], &token_id.bytes);
                    const amount_bytes = amount.toBytes();
                    @memcpy(data[20..52], &amount_bytes);

                    const result = hedera.htsCall(.MINT, data[0..52]);
                    const success = if (result.isSuccess()) U256.one() else U256.zero();
                    try self.stack.push(success);
                } else {
                    return error.InvalidOpcode;
                }
            },

            .HTS_BURN => {
                if (self.hedera_syscalls) |hedera| {
                    try self.gas.charge(HederaGas.htsGasCost(.BURN));

                    // Stack: token_id, amount
                    const token_id_u256 = try self.stack.pop();
                    const amount = try self.stack.pop();

                    const token_id = u256ToAddress(token_id_u256);

                    var data: [64]u8 = undefined;
                    @memcpy(data[0..20], &token_id.bytes);
                    const amount_bytes = amount.toBytes();
                    @memcpy(data[20..52], &amount_bytes);

                    const result = hedera.htsCall(.BURN, data[0..52]);
                    const success = if (result.isSuccess()) U256.one() else U256.zero();
                    try self.stack.push(success);
                } else {
                    return error.InvalidOpcode;
                }
            },

            .HTS_ASSOCIATE => {
                if (self.hedera_syscalls) |hedera| {
                    try self.gas.charge(HederaGas.htsGasCost(.ASSOCIATE));

                    // Stack: account, token_id
                    const account_u256 = try self.stack.pop();
                    const token_id_u256 = try self.stack.pop();

                    var data: [64]u8 = undefined;
                    const account = u256ToAddress(account_u256);
                    const token_id = u256ToAddress(token_id_u256);
                    @memcpy(data[0..20], &account.bytes);
                    @memcpy(data[20..40], &token_id.bytes);

                    const result = hedera.htsCall(.ASSOCIATE, data[0..40]);
                    const success = if (result.isSuccess()) U256.one() else U256.zero();
                    try self.stack.push(success);
                } else {
                    return error.InvalidOpcode;
                }
            },

            .HTS_CREATE => {
                if (self.hedera_syscalls) |hedera| {
                    try self.gas.charge(HederaGas.htsGasCost(.CREATE_TOKEN));

                    // Simplified - just return success for now
                    const result = hedera.htsCall(.CREATE_TOKEN, &[_]u8{});

                    switch (result) {
                        .address => |addr| try self.stack.push(addressToU256(addr)),
                        else => try self.stack.push(U256.zero()),
                    }
                } else {
                    return error.InvalidOpcode;
                }
            },

            // === Hedera Consensus Service (HCS) ===
            .HCS_SUBMIT => {
                if (self.hedera_syscalls) |hedera| {
                    // Stack: topic_id, offset, length (message in memory)
                    const topic_id_u256 = try self.stack.pop();
                    const offset = try self.stack.pop();
                    const length = try self.stack.pop();

                    const offset_usize = offset.toUsize();
                    const length_usize = length.toUsize();

                    const message = try self.memory.slice(offset_usize, length_usize);

                    try self.gas.charge(HederaGas.hcsGasCost(.SUBMIT_MESSAGE, message.len));

                    const topic_id = u256ToAddress(topic_id_u256);

                    // Encode: topic_id + message
                    var data = std.ArrayListUnmanaged(u8){};
                    defer data.deinit(self.allocator);
                    try data.appendSlice(self.allocator, &topic_id.bytes);
                    try data.appendSlice(self.allocator, message);

                    const result = hedera.hcsCall(.SUBMIT_MESSAGE, data.items);
                    const success = if (result.isSuccess()) U256.one() else U256.zero();
                    try self.stack.push(success);
                } else {
                    return error.InvalidOpcode;
                }
            },

            .HCS_CREATE_TOPIC => {
                if (self.hedera_syscalls) |hedera| {
                    try self.gas.charge(HederaGas.hcsGasCost(.CREATE_TOPIC, 0));

                    const result = hedera.hcsCall(.CREATE_TOPIC, &[_]u8{});

                    switch (result) {
                        .address => |addr| try self.stack.push(addressToU256(addr)),
                        else => try self.stack.push(U256.zero()),
                    }
                } else {
                    return error.InvalidOpcode;
                }
            },

            else => {
                std.debug.print("Unimplemented opcode: {any}\n", .{op});
                return error.InvalidOpcode;
            },
        }
    }

    fn addressToU256(addr: Address) U256 {
        var bytes: [32]u8 = [_]u8{0} ** 32;
        @memcpy(bytes[12..32], &addr.bytes);
        return U256.fromBytes(bytes);
    }

    fn u256ToAddress(value: U256) Address {
        const bytes = value.toBytes();
        var addr_bytes: [20]u8 = undefined;
        @memcpy(&addr_bytes, bytes[12..32]);
        return Address{ .bytes = addr_bytes };
    }
};

// Tests
test "VM basic execution" {
    const journaled = @import("../state/journaled.zig");
    const transient = @import("../state/transient.zig");

    // PUSH1 42, PUSH1 8, ADD, HALT
    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
        @intFromEnum(Opcode.PUSH1), 8,
        @intFromEnum(Opcode.ADD),
        @intFromEnum(Opcode.HALT),
    };

    var state = journaled.JournaledState.init(std.testing.allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(std.testing.allocator);
    defer tstorage.deinit();

    var vm = VM.init(std.testing.allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm.deinit();

    vm.loadBytecode(&bytecode);
    const result = try vm.execute();

    try std.testing.expect(result.gas_used > 0);
    try std.testing.expectEqual(@as(u64, 50), (try vm.stack.peek(0)).toU64());
}

test "VM out of gas" {
    const journaled = @import("../state/journaled.zig");
    const transient = @import("../state/transient.zig");

    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
    };

    var state = journaled.JournaledState.init(std.testing.allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(std.testing.allocator);
    defer tstorage.deinit();

    var vm = VM.init(std.testing.allocator, 1, state.asStorage(), tstorage.asTransientStorage(), null); // Only 1 gas
    defer vm.deinit();

    vm.loadBytecode(&bytecode);
    try std.testing.expectError(error.OutOfGas, vm.execute());
}

test "VM memory operations" {
    const journaled = @import("../state/journaled.zig");
    const transient = @import("../state/transient.zig");

    // PUSH1 42, PUSH1 0, MSTORE, PUSH1 0, MLOAD, HALT
    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.MSTORE),
        @intFromEnum(Opcode.PUSH1), 0,
        @intFromEnum(Opcode.MLOAD),
        @intFromEnum(Opcode.HALT),
    };

    var state = journaled.JournaledState.init(std.testing.allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(std.testing.allocator);
    defer tstorage.deinit();

    var vm = VM.init(std.testing.allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm.deinit();

    vm.loadBytecode(&bytecode);
    _ = try vm.execute();

    try std.testing.expectEqual(@as(u64, 42), (try vm.stack.peek(0)).toU64());
}

test "VM storage operations" {
    const journaled = @import("../state/journaled.zig");
    const transient = @import("../state/transient.zig");

    // PUSH1 42, PUSH1 1, SSTORE, PUSH1 1, SLOAD, HALT
    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,  // value
        @intFromEnum(Opcode.PUSH1), 1,   // key
        @intFromEnum(Opcode.SSTORE),     // store
        @intFromEnum(Opcode.PUSH1), 1,   // key
        @intFromEnum(Opcode.SLOAD),      // load
        @intFromEnum(Opcode.HALT),
    };

    var state = journaled.JournaledState.init(std.testing.allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(std.testing.allocator);
    defer tstorage.deinit();

    var vm = VM.init(std.testing.allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm.deinit();

    vm.loadBytecode(&bytecode);
    _ = try vm.execute();

    try std.testing.expectEqual(@as(u64, 42), (try vm.stack.peek(0)).toU64());
}

test "VM transient storage operations" {
    const journaled = @import("../state/journaled.zig");
    const transient = @import("../state/transient.zig");

    // PUSH1 99, PUSH1 5, TSTORE, PUSH1 5, TLOAD, HALT
    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 99,  // value
        @intFromEnum(Opcode.PUSH1), 5,   // key
        @intFromEnum(Opcode.TSTORE),     // transient store
        @intFromEnum(Opcode.PUSH1), 5,   // key
        @intFromEnum(Opcode.TLOAD),      // transient load
        @intFromEnum(Opcode.HALT),
    };

    var state = journaled.JournaledState.init(std.testing.allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(std.testing.allocator);
    defer tstorage.deinit();

    var vm = VM.init(std.testing.allocator, 100000, state.asStorage(), tstorage.asTransientStorage(), null);
    defer vm.deinit();

    vm.loadBytecode(&bytecode);
    _ = try vm.execute();

    try std.testing.expectEqual(@as(u64, 99), (try vm.stack.peek(0)).toU64());
}
