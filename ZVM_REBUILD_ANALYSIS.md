# ZVM Rebuild Analysis & Decision

## Executive Summary

**RECOMMENDATION: Fresh start with minimal dependencies**

After comprehensive analysis of:
- Archive reference implementations (REVM, evmone, Move VM, Soroban, Cairo)
- Current ZVM implementation
- KALIX smart contract language requirements (Phase 2 needs ZVM backend)
- ZELIX Hedera SDK integration points
- Current dependency footprint

**The optimal path is a clean rebuild focused on:**
1. Pure Zig implementation (no heavy dependencies)
2. Multi-chain bytecode support (Hedera, EVM, Soroban)
3. KALIX-native compilation target
4. Modular architecture inspired by REVM

---

## Current State Analysis

### Existing ZVM (v0.2.2)

**What exists:**
- Basic VM with EVM-compatible opcodes
- WASM runtime support
- Placeholder crypto hooks
- Runtime with event logging
- Storage abstraction layer
- Networking via zquic/zsync
- Database via zqlite

**Dependencies (9 total):**
1. **zcrypto** - Post-quantum crypto (ML-DSA, Ed25519, secp256k1)
2. **zsig** - Multi-signature verification
3. **zquic** - QUIC/HTTP3 networking
4. **zsync** - Async runtime
5. **zwallet** - HD wallet integration
6. **zns** - Name Service (DID, .ghost domains)
7. **shroud** - Enterprise identity & ZKP
8. **zqlite** - Persistent storage
9. **zledger** - Ledger operations

**Actual usage in current code:**
- `zquic`: Used in networking.zig (2 imports)
- `zsync`: Used in networking.zig (1 import)
- `zqlite`: Commented out in database.zig (mock implementation used)
- `zcrypto`: Only TODO comments, not actively used
- Others: **Not imported anywhere in source code**

**Verdict: 6 of 9 dependencies are completely unused**

---

## Ecosystem Context

### KALIX (Smart Contract Language)

**Status:** Phase 1 (Language Foundations) in progress
- Zig-based compiler: Lexer ✅ Parser ✅ AST ✅
- Surface syntax defined: contracts, state, functions, qualifiers
- **Phase 2 requires:** ZVM bytecode backend

**What KALIX needs from ZVM:**
```zig
// KALIX compiler output
contract Token {
    pub state balances: Map<Address, u64>;

    pub fn transfer(to: Address, amount: u64) -> Result<()> {
        // Compiles to ZVM bytecode
    }
}
```

**Requirements:**
1. Well-defined bytecode format (KALIX IR → ZVM opcodes)
2. Hedera syscalls (HTS, HCS, accounts, ledger)
3. Deterministic execution
4. Gas metering
5. Storage primitives (maps, arrays)
6. Event emission
7. Cross-contract calls

### ZELIX (Hedera SDK)

**Status:** v0.2.0 - Transaction submission complete
- REST/gRPC/Block Streams for queries
- Transaction signing and submission
- Smart contract deployment (EVM + Native Hedera)
- Protobuf parsing for Hedera types

**Integration points with ZVM:**
1. **Contract deployment:** ZELIX submits bytecode → Hedera → ZVM executes
2. **Contract calls:** ZELIX encodes params → Hedera → ZVM runs
3. **Event parsing:** ZVM emits events → Hedera receipts → ZELIX parses
4. **Account management:** ZELIX handles keys/signing for ZVM transactions

**What ZELIX provides to ZVM:**
- Network communication (no need for zquic/zsync in VM core)
- Transaction building and signing
- Hedera-specific protobuf encoding
- Mirror node queries for state verification

---

## Reference VM Analysis (from archive/)

### Key Lessons

**1. REVM (Rust) - Best modular design:**
```
revm/
├── primitives/     # Core types only
├── interpreter/    # Opcode execution (no I/O)
├── state/          # State management
├── database/       # Storage trait (no impl)
├── precompile/     # Precompiled contracts
└── handler/        # Execution flow
```
**Dependencies:** Minimal core (alloy-primitives), optional crypto

**2. evmone (C++) - Maximum performance:**
- Only 3 dependencies (intx, evmc, ethash)
- Two-tier interpreter (baseline + optimized)
- Computed goto dispatch for speed

**3. Move VM - Type safety:**
- Typed bytecode with resource safety
- Explicit module system
- Verification before execution
- Linear types prevent asset duplication

**4. Soroban - Language flexibility:**
- WASM for any language → bytecode
- Host functions for complex operations
- Clear guest/native separation

### Recommended Pattern for ZVM

**Inspired by REVM modularity + Zig's compile-time power:**

```
zvm/
├── primitives/      # Types, addresses, hashes (pure Zig std)
├── bytecode/        # Opcode definitions, format spec
├── interpreter/     # Core execution engine (zero dependencies)
├── state/           # State management (trait-like interfaces)
├── gas/             # Gas metering (deterministic)
├── hedera/          # Hedera-specific syscalls
├── evm-compat/      # EVM translation layer
├── soroban-compat/  # Soroban/WASM bridge
└── runtime/         # Main entry point
```

---

## Dependency Decision Matrix

| Dependency | Current Use | ZVM Core Needs | Recommendation |
|------------|-------------|----------------|----------------|
| **zcrypto** | TODO comments only | ✅ Signature verification | **KEEP** (minimal subset) |
| **zsig** | Unused | ❌ Not needed | **REMOVE** |
| **zquic** | networking.zig | ❌ ZELIX handles this | **REMOVE** |
| **zsync** | networking.zig | ❌ Not VM concern | **REMOVE** |
| **zwallet** | Unused | ❌ ZELIX handles this | **REMOVE** |
| **zns** | Unused | ❌ Application layer | **REMOVE** |
| **shroud** | Unused | ❌ Enterprise addon | **REMOVE** |
| **zqlite** | Mock only | ❌ State backend, not VM | **REMOVE** |
| **zledger** | Unused | ❌ ZELIX handles this | **REMOVE** |

### Recommended Dependencies for ZVM Core

**ZERO external dependencies for core interpreter**

**Optional (compile-time flags):**
- **zcrypto subset**: Only if native crypto verification needed
  - Most crypto should be Hedera precompiles (handled by network)
  - KALIX contracts use Hedera's crypto services
  - Only need verification in VM for ZK proofs

**Everything else provided by:**
- Pure Zig std library (hash, crypto, allocators)
- ZELIX for network I/O
- Hedera consensus nodes for state persistence

---

## Why Fresh Start vs. Incremental

### Arguments for Fresh Start

1. **Clean architecture**
   - Current code mixes concerns (VM + networking + storage)
   - Fresh start = clean separation

2. **No legacy baggage**
   - Remove 6 unused dependencies immediately
   - Start with minimal footprint

3. **KALIX alignment**
   - Design ZVM bytecode format alongside KALIX compiler
   - Co-evolve the IR and execution engine

4. **Reference implementations studied**
   - We now have clear patterns from REVM, evmone, Move
   - Can implement best practices from day 1

5. **Zig best practices**
   - Leverage Zig 0.15+ features
   - Comptime-first design
   - No hidden control flow

### What to salvage from current ZVM

**Copy/reference these files:**
- `src/zvm.zig` - Opcode definitions (good foundation)
- `src/runtime.zig` - Event logging pattern
- `src/contract.zig` - Address and storage types
- `examples/*` - Test cases to validate new implementation

**Don't carry forward:**
- `src/networking.zig` - ZELIX handles this
- `src/database.zig` - Storage backend is separate concern
- `src/rpc*.zig` - Network layer, not VM core
- Build system with 9 dependencies

---

## Recommended Architecture

### ZVM Core (Zero Dependencies)

```zig
// zvm/src/primitives/types.zig
pub const Address = [20]u8;
pub const Hash = [32]u8;
pub const U256 = struct { /* comptime int operations */ };

// zvm/src/bytecode/opcode.zig
pub const Opcode = enum(u8) {
    // Stack operations
    PUSH1 = 0x60,
    POP = 0x50,
    DUP1 = 0x80,
    SWAP1 = 0x90,

    // Arithmetic
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,

    // Hedera-specific (custom range)
    HTS_TRANSFER = 0xE0,
    HTS_MINT = 0xE1,
    HCS_SUBMIT = 0xE2,

    // Post-quantum crypto
    PQ_VERIFY = 0xF0,

    // EVM compatibility
    CALL = 0xF1,
    DELEGATECALL = 0xF4,

    // Control flow
    JUMP = 0x56,
    JUMPI = 0x57,
    HALT = 0x00,
};

// zvm/src/interpreter/vm.zig
pub const VM = struct {
    stack: Stack,
    memory: Memory,
    pc: usize,
    gas: Gas,
    bytecode: []const u8,

    pub fn init(allocator: Allocator) VM {
        return .{
            .stack = Stack.init(allocator),
            .memory = Memory.init(allocator),
            .pc = 0,
            .gas = Gas.init(0),
            .bytecode = &.{},
        };
    }

    pub fn execute(self: *VM) !ExecutionResult {
        while (self.pc < self.bytecode.len) {
            const op = @as(Opcode, @enumFromInt(self.bytecode[self.pc]));
            try self.gas.charge(op.gas_cost());
            try self.executeOpcode(op);
        }
        return .{ .gas_used = self.gas.used, .output = self.returndata };
    }
};
```

### Modular Interfaces

```zig
// zvm/src/state/storage.zig
pub const Storage = struct {
    vtable: *const VTable,
    ptr: *anyopaque,

    pub const VTable = struct {
        load: *const fn(*anyopaque, key: U256) U256,
        store: *const fn(*anyopaque, key: U256, value: U256) void,
    };

    pub fn load(self: Storage, key: U256) U256 {
        return self.vtable.load(self.ptr, key);
    }

    pub fn store(self: Storage, key: U256, value: U256) void {
        self.vtable.store(self.ptr, key, value);
    }
};

// Implementations provided by consumer (ZELIX, test harness, etc.)
```

### Multi-Chain Support

```zig
// zvm/src/chains/hedera.zig
pub const HederaSyscalls = struct {
    pub fn hts_transfer(token_id: TokenId, from: Address, to: Address, amount: u64) !void {
        // Maps to Hedera HTS precompile
        // Actual execution happens on consensus nodes
        // ZVM just validates and emits syscall event
    }

    pub fn hcs_submit_message(topic_id: TopicId, message: []const u8) !void {
        // Maps to Hedera HCS
    }
};

// zvm/src/chains/evm.zig
pub const EvmCompat = struct {
    pub fn translateBytecode(evm_bytecode: []const u8) ![]const u8 {
        // EVM opcodes → ZVM opcodes
        // Most opcodes map 1:1, some need translation
    }
};

// zvm/src/chains/soroban.zig
pub const SorobanBridge = struct {
    pub fn executeWasm(wasm_bytecode: []const u8, host_fns: HostFunctions) ![]const u8 {
        // WASM execution with Soroban host functions
    }
};
```

---

## Decision: Fresh Start

**Rationale:**

1. Current codebase has 67% unused dependencies
2. Architecture doesn't separate VM core from I/O
3. KALIX needs a clean compilation target (Phase 2)
4. We have studied 5 reference implementations
5. ZELIX already handles networking/storage concerns
6. Zig 0.16+ enables better patterns than v0.2.2 used

**Migration path:**
- Archive current zvm/ to archive/zvm-v0.2.2/
- Start fresh with lessons learned
- Reference old code for opcode definitions
- Reuse test cases as validation

---

## Next Steps

See `ZVM_ROADMAP.md` for phased implementation plan.
