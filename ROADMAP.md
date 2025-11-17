# ZVM Rebuild Roadmap
## The Zig Virtual Machine - Multi-Chain Smart Contract Execution Engine

**Vision:** A minimal, high-performance VM built in pure Zig that executes KALIX contracts natively while supporting Hedera, EVM, and Soroban bytecode.

**Philosophy:**
- Zero dependencies for core interpreter
- Modular architecture (REVM-inspired)
- Deterministic execution
- Multi-chain from day one
- KALIX-native compilation target

---

## Phase 0: Foundation & Architecture (Week 1-2)

### Goals
Establish clean project structure, define bytecode format, and core types.

### Deliverables

#### Project Structure
```
zvm/
├── src/
│   ├── primitives/          # Core types (Address, Hash, U256)
│   ├── bytecode/            # Opcode definitions, format spec
│   ├── interpreter/         # Execution engine
│   ├── gas/                 # Gas metering
│   ├── state/               # Storage interfaces
│   ├── chains/              # Multi-chain support
│   │   ├── hedera.zig      # Hedera syscalls
│   │   ├── evm.zig         # EVM compatibility
│   │   └── soroban.zig     # Soroban/WASM bridge
│   ├── runtime/             # Runtime entry point
│   └── root.zig            # Public API
├── tests/                   # Test suite
├── examples/                # Example contracts
├── docs/                    # Documentation
│   ├── bytecode-spec.md    # ZVM bytecode specification
│   ├── opcodes.md          # Opcode reference
│   └── integration.md      # Integration guide
├── build.zig
└── build.zig.zon           # Zero dependencies
```

#### Core Types (src/primitives/)
```zig
// types.zig - Pure Zig, no dependencies
pub const Address = [20]u8;
pub const Hash = [32]u8;
pub const U256 = struct {
    // Comptime-optimized 256-bit integer
    high: u128,
    low: u128,

    pub fn add(a: U256, b: U256) U256 { /* ... */ }
    pub fn mul(a: U256, b: U256) U256 { /* ... */ }
    // Full arithmetic suite
};

pub const Bytes = struct {
    data: []const u8,
    // Dynamic byte arrays
};
```

#### Bytecode Format (src/bytecode/)
```zig
// format.zig - ZVM bytecode container
pub const BytecodeContainer = struct {
    version: u8,                    // ZVM version
    target: Target,                 // Native, EVM, WASM
    code: []const u8,               // Opcode stream
    constants: []const Constant,    // Constant pool
    metadata: Metadata,             // ABI, source map

    pub const Target = enum {
        zvm_native,    // KALIX-compiled
        evm_compat,    // Translated EVM
        wasm_bridge,   // Soroban WASM
    };
};

// opcode.zig - Opcode definitions
pub const Opcode = enum(u8) {
    // === Stack Operations (0x00-0x1F) ===
    HALT = 0x00,
    NOP = 0x01,
    POP = 0x02,
    PUSH1 = 0x03,
    PUSH2 = 0x04,
    PUSH4 = 0x05,
    PUSH8 = 0x06,
    PUSH32 = 0x07,
    DUP1 = 0x08,
    DUP2 = 0x09,
    SWAP1 = 0x0A,
    SWAP2 = 0x0B,

    // === Arithmetic (0x20-0x3F) ===
    ADD = 0x20,
    SUB = 0x21,
    MUL = 0x22,
    DIV = 0x23,
    MOD = 0x24,
    ADDMOD = 0x25,
    MULMOD = 0x26,
    EXP = 0x27,

    // === Comparison & Bitwise (0x40-0x5F) ===
    LT = 0x40,
    GT = 0x41,
    EQ = 0x42,
    ISZERO = 0x43,
    AND = 0x44,
    OR = 0x45,
    XOR = 0x46,
    NOT = 0x47,
    SHL = 0x48,
    SHR = 0x49,

    // === Memory (0x60-0x7F) ===
    MLOAD = 0x60,
    MSTORE = 0x61,
    MSTORE8 = 0x62,
    MSIZE = 0x63,

    // === Storage (0x80-0x9F) ===
    SLOAD = 0x80,
    SSTORE = 0x81,
    TLOAD = 0x82,  // Transient storage
    TSTORE = 0x83,

    // === Control Flow (0xA0-0xBF) ===
    JUMP = 0xA0,
    JUMPI = 0xA1,
    PC = 0xA2,
    JUMPDEST = 0xA3,
    CALL = 0xA4,
    RETURN = 0xA5,
    REVERT = 0xA6,

    // === Context (0xC0-0xDF) ===
    ADDRESS = 0xC0,
    CALLER = 0xC1,
    CALLVALUE = 0xC2,
    CALLDATALOAD = 0xC3,
    CALLDATASIZE = 0xC4,
    CALLDATACOPY = 0xC5,
    CODESIZE = 0xC6,
    CODECOPY = 0xC7,
    GASPRICE = 0xC8,
    RETURNDATASIZE = 0xC9,
    RETURNDATACOPY = 0xCA,

    // === Hedera-Specific Syscalls (0xE0-0xEF) ===
    HTS_TRANSFER = 0xE0,      // HTS token transfer
    HTS_MINT = 0xE1,          // Mint tokens
    HTS_BURN = 0xE2,          // Burn tokens
    HTS_ASSOCIATE = 0xE3,     // Associate token
    HTS_DISSOCIATE = 0xE4,    // Dissociate token
    HCS_SUBMIT = 0xE5,        // Submit message to topic
    HCS_CREATE_TOPIC = 0xE6,  // Create new topic
    HEDERA_ACCOUNT_ID = 0xE7, // Get Hedera account ID
    HEDERA_TIMESTAMP = 0xE8,  // Get consensus timestamp

    // === Post-Quantum Crypto (0xF0-0xF7) ===
    PQ_VERIFY_DILITHIUM = 0xF0,
    PQ_VERIFY_FALCON = 0xF1,
    PQ_VERIFY_SPHINCS = 0xF2,
    PQ_KEYGEN = 0xF3,

    // === Logging (0xF8-0xFF) ===
    LOG0 = 0xF8,
    LOG1 = 0xF9,
    LOG2 = 0xFA,
    LOG3 = 0xFB,
    LOG4 = 0xFC,

    pub fn gas_cost(self: Opcode) u64 {
        return switch (self) {
            .ADD, .SUB, .NOT, .LT, .GT, .EQ, .ISZERO => 3,
            .MUL, .DIV, .MOD => 5,
            .EXP => 10,
            .SLOAD => 100,
            .SSTORE => 20000,
            .CALL => 100,
            .HTS_TRANSFER => 50,
            .PQ_VERIFY_DILITHIUM => 1000,
            else => 1,
        };
    }
};
```

#### Documentation
- [ ] `docs/bytecode-spec.md` - ZVM bytecode format specification
- [ ] `docs/opcodes.md` - Complete opcode reference with gas costs
- [ ] `docs/architecture.md` - System architecture overview
- [ ] `docs/kalix-integration.md` - KALIX compiler integration guide

### Exit Criteria
- [x] Analysis complete (ZVM_REBUILD_ANALYSIS.md)
- [ ] Project structure created
- [ ] Bytecode format documented
- [ ] Core types implemented (primitives/)
- [ ] Opcode definitions complete with gas costs
- [ ] Documentation written

---

## Phase 1: Core Interpreter (Week 3-4)

### Goals
Build minimal working interpreter that can execute ZVM bytecode.

### Deliverables

#### Stack Machine (src/interpreter/stack.zig)
```zig
pub const Stack = struct {
    items: [1024]U256,  // Fixed size, EVM-compatible
    len: usize,

    pub fn init() Stack {
        return .{ .items = undefined, .len = 0 };
    }

    pub fn push(self: *Stack, value: U256) !void {
        if (self.len >= 1024) return error.StackOverflow;
        self.items[self.len] = value;
        self.len += 1;
    }

    pub fn pop(self: *Stack) !U256 {
        if (self.len == 0) return error.StackUnderflow;
        self.len -= 1;
        return self.items[self.len];
    }

    pub fn peek(self: *Stack, depth: usize) !U256 {
        if (depth >= self.len) return error.StackUnderflow;
        return self.items[self.len - 1 - depth];
    }

    pub fn swap(self: *Stack, depth: usize) !void {
        if (depth >= self.len) return error.StackUnderflow;
        const top = self.items[self.len - 1];
        const target = self.items[self.len - 1 - depth];
        self.items[self.len - 1] = target;
        self.items[self.len - 1 - depth] = top;
    }
};
```

#### Memory (src/interpreter/memory.zig)
```zig
pub const Memory = struct {
    data: std.ArrayList(u8),

    pub fn init(allocator: Allocator) Memory {
        return .{ .data = std.ArrayList(u8).init(allocator) };
    }

    pub fn load(self: *Memory, offset: usize) !U256 {
        try self.expand(offset + 32);
        // Load 32 bytes starting at offset
        var result: U256 = undefined;
        @memcpy(result.bytes(), self.data.items[offset..offset+32]);
        return result;
    }

    pub fn store(self: *Memory, offset: usize, value: U256) !void {
        try self.expand(offset + 32);
        @memcpy(self.data.items[offset..offset+32], value.bytes());
    }

    fn expand(self: *Memory, size: usize) !void {
        if (size > self.data.items.len) {
            // Quadratic memory expansion cost
            const words = (size + 31) / 32;
            const gas_cost = 3 * words + (words * words) / 512;
            _ = gas_cost; // Caller tracks gas

            try self.data.resize(size);
        }
    }
};
```

#### Gas Metering (src/gas/meter.zig)
```zig
pub const Gas = struct {
    limit: u64,
    used: u64,

    pub fn init(limit: u64) Gas {
        return .{ .limit = limit, .used = 0 };
    }

    pub fn charge(self: *Gas, amount: u64) !void {
        const new_used = self.used + amount;
        if (new_used > self.limit) return error.OutOfGas;
        self.used = new_used;
    }

    pub fn remaining(self: Gas) u64 {
        return self.limit - self.used;
    }
};
```

#### Main Interpreter (src/interpreter/vm.zig)
```zig
pub const VM = struct {
    stack: Stack,
    memory: Memory,
    storage: Storage,  // Interface, not implementation
    pc: usize,
    gas: Gas,
    bytecode: []const u8,
    calldata: []const u8,
    returndata: []const u8,
    context: ExecutionContext,

    pub const ExecutionContext = struct {
        caller: Address,
        address: Address,
        value: U256,
        gas_price: u64,
    };

    pub fn init(allocator: Allocator, storage: Storage) VM {
        return .{
            .stack = Stack.init(),
            .memory = Memory.init(allocator),
            .storage = storage,
            .pc = 0,
            .gas = Gas.init(0),
            .bytecode = &.{},
            .calldata = &.{},
            .returndata = &.{},
            .context = undefined,
        };
    }

    pub fn execute(self: *VM) !ExecutionResult {
        while (self.pc < self.bytecode.len) {
            const op = @as(Opcode, @enumFromInt(self.bytecode[self.pc]));

            // Charge gas
            try self.gas.charge(op.gas_cost());

            // Execute
            try self.executeOpcode(op);

            // Advance PC (unless opcode changed it)
            if (op != .JUMP and op != .JUMPI) {
                self.pc += 1;
            }
        }

        return .{
            .success = true,
            .gas_used = self.gas.used,
            .output = self.returndata,
        };
    }

    fn executeOpcode(self: *VM, op: Opcode) !void {
        switch (op) {
            .HALT => return,

            // Stack operations
            .POP => _ = try self.stack.pop(),
            .PUSH1 => {
                self.pc += 1;
                const val = self.bytecode[self.pc];
                try self.stack.push(U256.fromU64(val));
            },
            .DUP1 => {
                const val = try self.stack.peek(0);
                try self.stack.push(val);
            },
            .SWAP1 => try self.stack.swap(1),

            // Arithmetic
            .ADD => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a.add(b));
            },
            .MUL => {
                const a = try self.stack.pop();
                const b = try self.stack.pop();
                try self.stack.push(a.mul(b));
            },

            // Storage
            .SLOAD => {
                const key = try self.stack.pop();
                const value = self.storage.load(key);
                try self.stack.push(value);
            },
            .SSTORE => {
                const key = try self.stack.pop();
                const value = try self.stack.pop();
                self.storage.store(key, value);
            },

            // Memory
            .MLOAD => {
                const offset = try self.stack.pop();
                const value = try self.memory.load(offset.toUsize());
                try self.stack.push(value);
            },
            .MSTORE => {
                const offset = try self.stack.pop();
                const value = try self.stack.pop();
                try self.memory.store(offset.toUsize(), value);
            },

            // Control flow
            .JUMP => {
                const dest = try self.stack.pop();
                self.pc = dest.toUsize();
            },
            .JUMPI => {
                const dest = try self.stack.pop();
                const condition = try self.stack.pop();
                if (!condition.isZero()) {
                    self.pc = dest.toUsize();
                }
            },

            // Context
            .CALLER => try self.stack.push(U256.fromAddress(self.context.caller)),
            .ADDRESS => try self.stack.push(U256.fromAddress(self.context.address)),
            .CALLVALUE => try self.stack.push(self.context.value),

            else => return error.UnimplementedOpcode,
        }
    }
};

pub const ExecutionResult = struct {
    success: bool,
    gas_used: u64,
    output: []const u8,
};
```

### Testing
```zig
// tests/interpreter_test.zig
test "basic arithmetic" {
    // PUSH1 42, PUSH1 8, ADD, HALT
    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
        @intFromEnum(Opcode.PUSH1), 8,
        @intFromEnum(Opcode.ADD),
        @intFromEnum(Opcode.HALT),
    };

    var vm = VM.init(testing.allocator, MockStorage{});
    vm.load_bytecode(&bytecode, 100000);

    const result = try vm.execute();
    try testing.expect(result.success);
    try testing.expectEqual(@as(u64, 50), vm.stack.peek(0).toU64());
}

test "out of gas" {
    const bytecode = [_]u8{ @intFromEnum(Opcode.PUSH1), 1 };
    var vm = VM.init(testing.allocator, MockStorage{});
    vm.load_bytecode(&bytecode, 1); // Only 1 gas

    try testing.expectError(error.OutOfGas, vm.execute());
}
```

### Exit Criteria
- [ ] Stack implementation complete with all operations
- [ ] Memory with quadratic expansion
- [ ] Gas metering functional
- [ ] Core opcodes implemented (stack, arithmetic, memory, storage)
- [ ] Control flow (JUMP, JUMPI) working
- [ ] Test suite passing (>90% coverage)
- [ ] Can execute simple bytecode programs

---

## Phase 2: Storage & State (Week 5)

### Goals
Implement state management with clean interfaces for external storage backends.

### Deliverables

#### Storage Interface (src/state/storage.zig)
```zig
pub const Storage = struct {
    vtable: *const VTable,
    ptr: *anyopaque,

    pub const VTable = struct {
        load: *const fn(*anyopaque, key: U256) U256,
        store: *const fn(*anyopaque, key: U256, value: U256) void,
        commit: *const fn(*anyopaque) void,
        rollback: *const fn(*anyopaque) void,
    };

    pub fn load(self: Storage, key: U256) U256 {
        return self.vtable.load(self.ptr, key);
    }

    pub fn store(self: Storage, key: U256, value: U256) void {
        self.vtable.store(self.ptr, key, value);
    }

    pub fn commit(self: Storage) void {
        self.vtable.commit(self.ptr);
    }

    pub fn rollback(self: Storage) void {
        self.vtable.rollback(self.ptr);
    }
};
```

#### Journaled State (src/state/journaled.zig)
```zig
pub const JournaledState = struct {
    state: std.AutoHashMap(U256, U256),
    journal: std.ArrayList(std.ArrayList(JournalEntry)),

    const JournalEntry = union(enum) {
        storage_set: struct { key: U256, old: U256, new: U256 },
        storage_delete: struct { key: U256, old: U256 },
    };

    pub fn checkpoint(self: *JournaledState) !void {
        try self.journal.append(std.ArrayList(JournalEntry).init(self.allocator));
    }

    pub fn commit(self: *JournaledState) void {
        _ = self.journal.pop();
    }

    pub fn rollback(self: *JournaledState) void {
        const entries = self.journal.pop();
        for (entries.items) |entry| {
            switch (entry) {
                .storage_set => |s| {
                    self.state.put(s.key, s.old) catch unreachable;
                },
                .storage_delete => |s| {
                    _ = self.state.remove(s.key);
                },
            }
        }
    }

    pub fn asStorage(self: *JournaledState) Storage {
        return .{
            .vtable = &VTable{
                .load = load,
                .store = store,
                .commit = commit,
                .rollback = rollback,
            },
            .ptr = self,
        };
    }

    fn load(ptr: *anyopaque, key: U256) U256 {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        return self.state.get(key) orelse U256.zero();
    }

    fn store(ptr: *anyopaque, key: U256, value: U256) void {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        const old = self.state.get(key) orelse U256.zero();

        self.state.put(key, value) catch unreachable;

        const current_journal = &self.journal.items[self.journal.items.len - 1];
        current_journal.append(.{ .storage_set = .{ .key = key, .old = old, .new = value }}) catch unreachable;
    }
};
```

### Exit Criteria
- [ ] Storage interface defined
- [ ] Journaled state implementation with checkpoint/rollback
- [ ] Test implementations (in-memory, mock)
- [ ] State transitions tested
- [ ] Revert functionality working

---

## Phase 3: Hedera Integration (Week 6-7)

### Goals
Implement Hedera-specific syscalls and ZELIX integration.

### Deliverables

#### Hedera Syscalls (src/chains/hedera.zig)
```zig
pub const HederaSyscalls = struct {
    zelix_client: *zelix.Client,  // ZELIX handles network calls

    pub fn hts_transfer(
        self: *HederaSyscalls,
        token_id: TokenId,
        from: Address,
        to: Address,
        amount: u64
    ) !void {
        // Emit syscall event for Hedera consensus node
        // ZELIX will construct actual HTS transfer transaction
        const syscall = HederaSyscallEvent{
            .kind = .hts_transfer,
            .data = .{
                .token_id = token_id,
                .from = from,
                .to = to,
                .amount = amount,
            },
        };

        try self.emit_syscall(syscall);
    }

    pub fn hcs_submit_message(
        self: *HederaSyscalls,
        topic_id: TopicId,
        message: []const u8
    ) !void {
        const syscall = HederaSyscallEvent{
            .kind = .hcs_submit,
            .data = .{
                .topic_id = topic_id,
                .message = message,
            },
        };

        try self.emit_syscall(syscall);
    }

    fn emit_syscall(self: *HederaSyscalls, event: HederaSyscallEvent) !void {
        // ZVM doesn't execute syscalls directly
        // It emits events that ZELIX translates to Hedera transactions
        try self.syscall_log.append(event);
    }
};
```

#### ZELIX Bridge (src/chains/zelix_bridge.zig)
```zig
pub const ZelixBridge = struct {
    client: *zelix.Client,
    vm: *VM,

    pub fn deploy_contract(
        self: *ZelixBridge,
        bytecode: []const u8,
        constructor_params: []const u8
    ) !zelix.ContractId {
        // 1. ZVM validates bytecode
        try self.vm.validate_bytecode(bytecode);

        // 2. ZELIX submits to Hedera
        const contract_create = zelix.ContractCreateTransaction{
            .bytecode = bytecode,
            .gas = 1_000_000,
            .constructor_parameters = constructor_params,
        };

        const receipt = try contract_create.execute(self.client);
        return receipt.contract_id.?;
    }

    pub fn call_contract(
        self: *ZelixBridge,
        contract_id: zelix.ContractId,
        function: []const u8,
        params: []const u8
    ) ![]const u8 {
        // 1. Execute locally in ZVM for read-only calls
        if (is_view_function(function)) {
            return try self.vm.execute_view(contract_id, function, params);
        }

        // 2. Submit transaction via ZELIX for state-changing calls
        const contract_call = zelix.ContractCallTransaction{
            .contract_id = contract_id,
            .gas = 500_000,
            .function = function,
            .parameters = params,
        };

        const receipt = try contract_call.execute(self.client);
        return receipt.output;
    }
};
```

### Integration with KALIX

```zig
// KALIX compiler output target
pub const KalixCompiler = struct {
    pub fn compile(source: []const u8) ![]const u8 {
        // 1. KALIX frontend: parse → AST → semantic analysis
        const ast = try kalix.parse(source);
        try kalix.check_semantics(ast);

        // 2. Lower to ZVM IR
        const ir = try kalix.lower_to_ir(ast);

        // 3. Emit ZVM bytecode
        const bytecode = try kalix.emit_zvm_bytecode(ir);

        return bytecode;
    }
};

// Example KALIX contract
const kalix_source =
    \\contract Token {
    \\    pub state balances: Map<Address, u64>;
    \\    pub state total_supply: u64;
    \\
    \\    pub fn transfer(to: Address, amount: u64) -> Result<()> {
    \\        let sender = msg.sender();
    \\        let sender_balance = balances.get(sender)?;
    \\        if sender_balance < amount { return Err("Insufficient balance"); }
    \\
    \\        balances.set(sender, sender_balance - amount);
    \\        balances.set(to, balances.get(to)? + amount);
    \\
    \\        emit Transfer { from: sender, to, amount };
    \\        Ok(())
    \\    }
    \\}
;

// Compiles to ZVM bytecode:
// 1. Load sender from context (CALLER)
// 2. Load balance from storage (SLOAD)
// 3. Compare with amount (LT)
// 4. Conditional revert (JUMPI)
// 5. Update balances (SSTORE x2)
// 6. Emit event (LOG2)
```

### Exit Criteria
- [ ] Hedera syscall interface defined
- [ ] HTS operations (transfer, mint, burn, associate)
- [ ] HCS operations (submit message, create topic)
- [ ] ZELIX bridge for deployment and calls
- [ ] KALIX compilation target working
- [ ] End-to-end test: KALIX → ZVM → Hedera testnet

---

## Phase 4: EVM Compatibility (Week 8-9)

### Goals
Full EVM bytecode support via translation layer.

### Deliverables

#### EVM Translator (src/chains/evm.zig)
```zig
pub const EvmCompat = struct {
    pub fn translate(evm_bytecode: []const u8) ![]const u8 {
        var zvm_bytecode = std.ArrayList(u8).init(allocator);

        var i: usize = 0;
        while (i < evm_bytecode.len) {
            const evm_op = evm_bytecode[i];

            // Most EVM opcodes map directly to ZVM
            switch (evm_op) {
                0x01 => try zvm_bytecode.append(@intFromEnum(Opcode.ADD)),
                0x02 => try zvm_bytecode.append(@intFromEnum(Opcode.MUL)),
                0x60 => { // PUSH1
                    try zvm_bytecode.append(@intFromEnum(Opcode.PUSH1));
                    i += 1;
                    try zvm_bytecode.append(evm_bytecode[i]);
                },
                // ... all EVM opcodes

                // Precompiles get special handling
                0xf1 => { // CALL to precompile addresses
                    try handle_precompile_call(&zvm_bytecode);
                },

                else => return error.UnsupportedEvmOpcode,
            }

            i += 1;
        }

        return zvm_bytecode.toOwnedSlice();
    }

    fn handle_precompile_call(out: *std.ArrayList(u8)) !void {
        // EVM precompiles (ecrecover, sha256, etc.) → ZVM opcodes
        // Address 0x01 (ecrecover) → PQ_VERIFY_ECDSA
        // Address 0x02 (sha256) → HASH_SHA256
    }
};
```

#### EVM Precompiles
```zig
pub const EvmPrecompiles = struct {
    pub fn ecrecover(hash: [32]u8, v: u8, r: U256, s: U256) !Address {
        // ECDSA signature recovery
        // Uses std.crypto or zcrypto if available
    }

    pub fn sha256(data: []const u8) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(data);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    pub fn ripemd160(data: []const u8) [20]u8 {
        // RIPEMD-160 hash
    }

    pub fn identity(data: []const u8) []const u8 {
        return data;
    }

    pub fn modexp(base: U256, exp: U256, mod: U256) U256 {
        // Modular exponentiation
    }

    pub fn bn256_add(x1: U256, y1: U256, x2: U256, y2: U256) struct { U256, U256 } {
        // BN256 elliptic curve addition
    }

    pub fn bn256_mul(x: U256, y: U256, scalar: U256) struct { U256, U256 } {
        // BN256 scalar multiplication
    }

    pub fn bn256_pairing(points: []const U256) bool {
        // BN256 pairing check (for ZK proofs)
    }

    pub fn blake2f(rounds: u32, h: [8]u64, m: [16]u64, t: [2]u64, f: bool) [8]u64 {
        // Blake2 compression function
    }
};
```

### Testing
```zig
test "EVM bytecode translation" {
    // Solidity: return 42 + 8;
    const solidity_bytecode = [_]u8{
        0x60, 0x2a, // PUSH1 42
        0x60, 0x08, // PUSH1 8
        0x01,       // ADD
        0xf3,       // RETURN
    };

    const zvm_bytecode = try EvmCompat.translate(&solidity_bytecode);

    var vm = VM.init(testing.allocator, MockStorage{});
    vm.load_bytecode(zvm_bytecode, 100000);
    const result = try vm.execute();

    try testing.expectEqual(@as(u64, 50), vm.stack.peek(0).toU64());
}
```

### Exit Criteria
- [ ] All EVM opcodes mapped to ZVM
- [ ] EVM precompiles implemented
- [ ] Ethereum test suite compatibility (state tests)
- [ ] Can execute Solidity contracts
- [ ] Gas costs match EVM semantics

---

## Phase 5: Soroban/WASM Bridge (Week 10-11)

### Goals
Execute Soroban-style WASM contracts with host functions.

### Deliverables

#### WASM Runtime (src/chains/soroban.zig)
```zig
pub const SorobanBridge = struct {
    wasm_runtime: WasmRuntime,  // Could use std.wasm or minimal runtime
    host_functions: HostFunctions,

    pub fn execute_wasm(
        self: *SorobanBridge,
        wasm_bytecode: []const u8,
        function_name: []const u8,
        args: []const Val
    ) ![]const Val {
        // 1. Validate WASM module
        try self.wasm_runtime.validate(wasm_bytecode);

        // 2. Instantiate with host functions
        const instance = try self.wasm_runtime.instantiate(
            wasm_bytecode,
            self.host_functions
        );

        // 3. Call exported function
        return try instance.call(function_name, args);
    }
};

pub const HostFunctions = struct {
    vm: *VM,  // ZVM context

    // Storage operations
    pub fn storage_get(env: *Env, key: Val) Val {
        const key_u256 = val_to_u256(key);
        const value = env.vm.storage.load(key_u256);
        return u256_to_val(value);
    }

    pub fn storage_set(env: *Env, key: Val, value: Val) void {
        const key_u256 = val_to_u256(key);
        const value_u256 = val_to_u256(value);
        env.vm.storage.store(key_u256, value_u256);
    }

    // Crypto operations
    pub fn verify_ed25519(env: *Env, msg: Val, sig: Val, pubkey: Val) Val {
        // Signature verification
        _ = env;
        _ = msg;
        _ = sig;
        _ = pubkey;
        return val_true();
    }

    // Logging
    pub fn log(env: *Env, message: Val) void {
        _ = env;
        _ = message;
        // Emit log event
    }
};

pub const Val = u64;  // Soroban uses 64-bit tagged values
```

### Exit Criteria
- [ ] WASM module validation
- [ ] Host function interface
- [ ] Basic Soroban contracts working
- [ ] Storage operations functional
- [ ] Crypto host functions implemented

---

## Phase 6: Optimization & Testing (Week 12-13)

### Goals
Performance optimization and comprehensive testing.

### Deliverables

#### Performance Optimizations
- [ ] Computed goto dispatch (if needed for performance)
- [ ] JIT compilation for hot paths
- [ ] Memory pooling for allocations
- [ ] Bytecode caching

#### Testing Infrastructure
```zig
// Ethereum test suite integration
test "ethereum state tests" {
    const test_dir = "tests/ethereum/";
    var dir = try std.fs.cwd().openIterableDir(test_dir, .{});
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".json")) continue;

        const test_json = try std.fs.cwd().readFileAlloc(
            testing.allocator,
            entry.name,
            1024 * 1024
        );
        defer testing.allocator.free(test_json);

        const test_case = try std.json.parseFromSlice(
            EthereumTest,
            testing.allocator,
            test_json,
            .{}
        );
        defer test_case.deinit();

        // Run test
        try run_ethereum_test(test_case.value);
    }
}

// Fuzzing
test "fuzz bytecode execution" {
    const seed = std.crypto.random.int(u64);
    var prng = std.rand.DefaultPrng.init(seed);

    for (0..10000) |_| {
        const bytecode = generate_random_bytecode(&prng);
        var vm = VM.init(testing.allocator, MockStorage{});
        vm.load_bytecode(bytecode, 1_000_000);

        // Should never panic, only return errors
        _ = vm.execute() catch |err| {
            switch (err) {
                error.OutOfGas,
                error.StackOverflow,
                error.StackUnderflow,
                error.InvalidJumpDest,
                => {}, // Expected errors
                else => return err, // Unexpected error
            }
        };
    }
}

// Property-based testing
test "property: stack operations preserve count" {
    // DUP followed by POP should be a no-op
    const bytecode = [_]u8{
        @intFromEnum(Opcode.PUSH1), 42,
        @intFromEnum(Opcode.DUP1),
        @intFromEnum(Opcode.POP),
        @intFromEnum(Opcode.HALT),
    };

    var vm = VM.init(testing.allocator, MockStorage{});
    vm.load_bytecode(&bytecode, 100000);
    _ = try vm.execute();

    try testing.expectEqual(@as(usize, 1), vm.stack.len);
    try testing.expectEqual(@as(u64, 42), vm.stack.peek(0).toU64());
}
```

### Benchmarking
```zig
// Benchmark suite
pub fn benchmark_opcodes() !void {
    const iterations = 1_000_000;

    // Arithmetic
    const add_time = try benchmark_opcode(.ADD, iterations);
    const mul_time = try benchmark_opcode(.MUL, iterations);

    // Memory
    const mload_time = try benchmark_opcode(.MLOAD, iterations);
    const mstore_time = try benchmark_opcode(.MSTORE, iterations);

    // Storage
    const sload_time = try benchmark_opcode(.SLOAD, iterations);
    const sstore_time = try benchmark_opcode(.SSTORE, iterations);

    std.debug.print("Opcode benchmarks ({} iterations):\n", .{iterations});
    std.debug.print("  ADD:    {} ns/op\n", .{add_time});
    std.debug.print("  MUL:    {} ns/op\n", .{mul_time});
    std.debug.print("  MLOAD:  {} ns/op\n", .{mload_time});
    std.debug.print("  MSTORE: {} ns/op\n", .{mstore_time});
    std.debug.print("  SLOAD:  {} ns/op\n", .{sload_time});
    std.debug.print("  SSTORE: {} ns/op\n", .{sstore_time});
}
```

### Exit Criteria
- [ ] >90% test coverage
- [ ] Ethereum state test compliance
- [ ] Fuzzing with no crashes (10k+ iterations)
- [ ] Property tests passing
- [ ] Benchmarks documented
- [ ] Performance comparable to evmone baseline

---

## Phase 7: Documentation & Examples (Week 14)

### Goals
Complete documentation and example contracts.

### Deliverables

#### Documentation
- [ ] Complete API reference
- [ ] Bytecode specification
- [ ] KALIX integration guide
- [ ] ZELIX integration guide
- [ ] Security best practices
- [ ] Gas optimization guide

#### Examples
```zig
// examples/token_kalix.kalix - KALIX ERC20 token
contract Token {
    pub state balances: Map<Address, u64>;
    pub state allowances: Map<Address, Map<Address, u64>>;
    pub state total_supply: u64;

    pub fn transfer(to: Address, amount: u64) -> Result<()> {
        let sender = msg.sender();
        let balance = balances.get(sender)?;
        if balance < amount { return Err("Insufficient balance"); }

        balances.set(sender, balance - amount);
        balances.set(to, balances.get(to)? + amount);

        emit Transfer { from: sender, to, amount };
        Ok(())
    }

    pub fn approve(spender: Address, amount: u64) -> Result<()> {
        allowances.get_mut(msg.sender())?.set(spender, amount);
        emit Approval { owner: msg.sender(), spender, amount };
        Ok(())
    }

    pub view fn balance_of(account: Address) -> u64 {
        balances.get(account).unwrap_or(0)
    }
}

// examples/deploy_token.zig - Deploy via ZELIX
pub fn main() !void {
    var client = try zelix.Client.init(allocator, .testnet);
    defer client.deinit();

    // Compile KALIX to ZVM bytecode
    const kalix_source = @embedFile("token_kalix.kalix");
    const bytecode = try kalix.compile(kalix_source);

    // Deploy via ZELIX
    var bridge = ZelixBridge{ .client = &client, .vm = &vm };
    const contract_id = try bridge.deploy_contract(bytecode, &.{});

    std.debug.print("Token deployed: {}\n", .{contract_id});
}

// examples/hedera_hts.zig - Hedera Token Service integration
pub fn main() !void {
    // KALIX contract calling HTS
    const kalix_hts_contract =
        \\contract HTSWrapper {
        \\    pub fn mint_tokens(token_id: TokenId, amount: u64) -> Result<()> {
        \\        hts.mint(token_id, msg.sender(), amount)?;
        \\        Ok(())
        \\    }
        \\}
    ;

    const bytecode = try kalix.compile(kalix_hts_contract);

    var client = try zelix.Client.init(allocator, .testnet);
    var bridge = ZelixBridge{ .client = &client, .vm = &vm };

    const contract_id = try bridge.deploy_contract(bytecode, &.{});

    // Call contract, which calls HTS
    const result = try bridge.call_contract(
        contract_id,
        "mint_tokens",
        encode_params(.{ token_id, 1000 })
    );
}

// examples/evm_compat.zig - Run Solidity contracts
pub fn main() !void {
    // Solidity ERC20 bytecode
    const solidity_bytecode = @embedFile("Token.bin");

    // Translate to ZVM
    const zvm_bytecode = try EvmCompat.translate(solidity_bytecode);

    // Execute
    var vm = VM.init(allocator, JournaledState.init(allocator).asStorage());
    vm.load_bytecode(zvm_bytecode, 10_000_000);

    const result = try vm.execute();
    std.debug.print("Contract deployed, gas used: {}\n", .{result.gas_used});
}
```

### Exit Criteria
- [ ] All documentation complete
- [ ] 10+ example contracts
- [ ] Tutorial series written
- [ ] API reference generated
- [ ] Architecture diagrams created

---

## Phase 8: Launch & Integration (Week 15-16)

### Goals
Final integration, release preparation, and ecosystem integration.

### Deliverables

#### KALIX Integration
- [ ] KALIX Phase 2 complete (ZVM backend)
- [ ] KALIX → ZVM compilation tested end-to-end
- [ ] Standard library for KALIX contracts

#### ZELIX Integration
- [ ] ZVM deployment via ZELIX working
- [ ] Contract calls functional
- [ ] Event parsing integrated
- [ ] Documentation for ZELIX + ZVM usage

#### Release Preparation
- [ ] Version 1.0.0 tagged
- [ ] Release notes written
- [ ] Migration guide from v0.2.2
- [ ] Performance benchmarks published
- [ ] Security audit (if applicable)

#### Community
- [ ] GitHub repository public
- [ ] Documentation website live
- [ ] Example contracts published
- [ ] Developer onboarding guide
- [ ] Integration with Hedera developer portal

### Exit Criteria
- [ ] v1.0.0 released
- [ ] KALIX can compile to ZVM
- [ ] ZELIX can deploy ZVM contracts
- [ ] End-to-end tested on Hedera testnet
- [ ] Documentation complete
- [ ] Example dApps running

---

## Success Metrics

### Technical
- **Performance:** Within 2x of evmone baseline
- **Correctness:** 100% Ethereum state test compliance
- **Coverage:** >90% test coverage
- **Reliability:** Zero segfaults in fuzzing
- **Dependencies:** Zero for core interpreter

### Ecosystem
- **KALIX Integration:** Phase 2 complete, compiles to ZVM
- **ZELIX Integration:** Contract deployment working
- **Multi-chain:** Hedera, EVM, and Soroban contracts executable
- **Developer Experience:** Complete docs, examples, tooling

### Adoption
- **Internal:** KALIX uses ZVM as primary backend
- **External:** 5+ external developers using ZVM
- **Production:** 3+ contracts deployed on Hedera mainnet
- **Community:** 50+ GitHub stars, 10+ contributors

---

## Maintenance & Future Work

### Post-1.0 Roadmap
- **Phase 9:** Advanced optimizations (JIT, AOT compilation)
- **Phase 10:** Formal verification tools
- **Phase 11:** Debugger and profiler
- **Phase 12:** Multi-VM orchestration (cross-chain calls)

### Long-term Vision
- **ZVM as standard:** Become the reference VM for Hedera ecosystem
- **Language support:** Support for multiple smart contract languages beyond KALIX
- **Cross-chain:** Execute contracts across Hedera, Ethereum, Stellar
- **Research:** Explore ZK-VM integration (Cairo-style provable execution)

---

## Timeline Summary

| Phase | Duration | Key Deliverable |
|-------|----------|----------------|
| **0: Foundation** | Week 1-2 | Project structure, bytecode spec, core types |
| **1: Core Interpreter** | Week 3-4 | Working VM with stack/memory/gas |
| **2: Storage & State** | Week 5 | Journaled state, storage interfaces |
| **3: Hedera Integration** | Week 6-7 | HTS/HCS syscalls, ZELIX bridge, KALIX target |
| **4: EVM Compatibility** | Week 8-9 | EVM translation, precompiles, Solidity support |
| **5: Soroban/WASM** | Week 10-11 | WASM runtime, host functions |
| **6: Optimization** | Week 12-13 | Performance tuning, comprehensive testing |
| **7: Documentation** | Week 14 | Docs, examples, tutorials |
| **8: Launch** | Week 15-16 | v1.0 release, integrations, community |

**Total: ~4 months to v1.0**

---

## Decision Points

### Architecture Decisions
- ✅ Fresh start (not incremental)
- ✅ Zero dependencies for core
- ✅ Modular design (REVM-inspired)
- ✅ KALIX-first, multi-chain capable
- ✅ ZELIX handles networking/storage

### What We're Building
- ✅ Pure Zig VM core
- ✅ KALIX native compilation target
- ✅ Hedera-specific syscalls (HTS, HCS)
- ✅ EVM compatibility layer
- ✅ Soroban/WASM bridge
- ✅ Deterministic execution
- ✅ Gas metering

### What We're NOT Building (Out of Scope)
- ❌ Networking layer (ZELIX handles this)
- ❌ Consensus protocol
- ❌ Storage backend (interface only)
- ❌ Wallet functionality (ZELIX handles this)
- ❌ Transaction building (ZELIX handles this)
- ❌ Mirror node queries (ZELIX handles this)

---

## Next Immediate Actions

1. **Archive current ZVM:**
   ```bash
   mv /data/projects/zvm /data/projects/archive/zvm-v0.2.2
   mkdir /data/projects/zvm
   ```

2. **Initialize new project:**
   ```bash
   cd /data/projects/zvm
   zig init
   # Update build.zig.zon to remove all dependencies
   ```

3. **Create structure:**
   ```bash
   mkdir -p src/{primitives,bytecode,interpreter,gas,state,chains,runtime}
   mkdir -p tests examples docs
   ```

4. **Start Phase 0:**
   - Implement `src/primitives/types.zig`
   - Define `src/bytecode/opcode.zig`
   - Write `docs/bytecode-spec.md`

---

**Ready to build the best Zig Virtual Machine for the next generation of smart contracts!**
