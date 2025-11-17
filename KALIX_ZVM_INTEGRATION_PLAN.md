# KALIX ↔ ZVM Integration Plan
**Critical Path to Production-Ready Smart Contract Compilation**

---

## 📊 Current State Analysis

### KALIX Status (Dec 2025)
✅ **Phase 1 Complete**: Full language foundations
- Lexer, Parser, AST, Semantic Analyzer
- Type system with ownership rules
- Documentation and 14 tests

✅ **Phase 2 In Progress**: Backend implementation at ~80%
- ✅ IR (Intermediate Representation) defined
- ✅ Lowering pass (AST → IR) complete
- ✅ CodeGen framework complete
- ✅ Gas analyzer integrated
- ✅ Integration tests for comparisons (!=, <=, >=)
- ⚠️ **BLOCKER**: Using temporary `table_hash_opcode = 0xD2` (needs finalized ZVM opcode)
- ⚠️ **BLOCKER**: Gas costs using placeholder values (need real ZVM opcode costs)

**Current KALIX ZVM Opcode Usage**:
```zig
// codegen.zig maps to zvm_constants.zig
HALT = 0x00          ✅ Matches ZVM
PUSH1-32 = 0x11-16   ✅ Matches ZVM
ADD = 0x30           ✅ Matches ZVM
SUB = 0x31           ✅ Matches ZVM
MUL = 0x32           ✅ Matches ZVM
DIV = 0x33           ✅ Matches ZVM
MOD = 0x35           ✅ Matches ZVM
LT = 0x50            ✅ Matches ZVM
GT = 0x51            ✅ Matches ZVM
EQ = 0x54            ✅ Matches ZVM
XOR = 0x58           ✅ Matches ZVM (for boolean inversion)
SLOAD = 0x90         ✅ Matches ZVM
SSTORE = 0x91        ✅ Matches ZVM
TLOAD = 0x92         ✅ Matches ZVM
TSTORE = 0x93        ✅ Matches ZVM
JUMP = 0xA0          ✅ Matches ZVM
JUMPI = 0xA1         ✅ Matches ZVM
```

**KALIX is READY except for 2 blockers!**

---

### ZVM Status (Phase 6 Complete)
✅ **Phases 0-6 Complete**: Production-ready VM
- ✅ Full EVM-compatible opcode set (50+ opcodes)
- ✅ Account state management
- ✅ CREATE/CREATE2/CALL/DELEGATECALL/STATICCALL
- ✅ Bytecode container format (ZVMC)
- ✅ Storage (SLOAD/SSTORE, TLOAD/TSTORE)
- ✅ Hedera syscalls (HTS, HCS)
- ✅ Gas metering
- ✅ 19 comprehensive tests, all passing

**Missing for KALIX**:
1. ❌ **Table hashing opcode** (KALIX needs this!)
2. ❌ **Formalized gas cost table** (currently hardcoded in opcode.zig)
3. ❌ **KALIX bytecode loader** (to execute KALIX-compiled contracts)

---

## 🎯 Critical Next Steps for ZVM

### Priority 1: Table Hashing Opcode (BLOCKER for KALIX)

**Problem**: KALIX uses temporary opcode `0xD2` for table hashing
```zig
// kalix/src/backend/codegen.zig:34
pub const table_hash_opcode: u8 = 0xD2;  // TEMPORARY!

// Used in:
fn emitTableHashSequence(self: *CodeGen, slot: u64) !void {
    try self.appendRawOpcode(table_hash_opcode);  // Needs real ZVM opcode
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, slot, .little);
    try self.bytecode.appendSlice(self.allocator, &buf);
}
```

**What KALIX Needs**:
- Opcode to hash table keys for storage mapping
- Input: table slot (u64) + key values (on stack)
- Output: hashed storage key (U256) for SLOAD/SSTORE

**Proposed ZVM Opcode**:
```zig
// Add to src/bytecode/opcode.zig
TABLEHASH = 0xD2,  // Table key hashing for structured storage

// Stack effect:
// Before: key_n, key_(n-1), ..., key_1, table_slot
// After: hashed_storage_key (U256)

// Implementation:
// storage_key = keccak256(table_slot || key_1 || ... || key_n)
```

**Implementation Location**: `src/interpreter/vm.zig`
```zig
.TABLEHASH => {
    // Pop table slot (stored as U256 on stack for uniformity)
    const table_slot = try self.stack.pop();

    // Pop all keys (number determined by table schema - simplified: pop until marker)
    // For MVP: assume single key on stack
    const key = try self.stack.pop();

    // Hash: keccak256(table_slot || key)
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    const slot_bytes = table_slot.toBytes();
    const key_bytes = key.toBytes();
    hasher.update(&slot_bytes);
    hasher.update(&key_bytes);

    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    try self.stack.push(U256.fromBytes(hash));
},
```

**Gas Cost**: 30 gas (same as KECCAK256)

---

### Priority 2: Formalized Gas Cost Export

**Problem**: KALIX gas analyzer needs accurate opcode costs
```zig
// kalix/src/backend/gas.zig needs this data
// Currently using hardcoded estimates
```

**Solution**: Create ZVM gas cost export module

**File**: `src/gas/costs.zig`
```zig
//! ZVM Gas Cost Catalog
//! Exported for KALIX compiler integration

const opcode = @import("../bytecode/opcode.zig");

pub const GasCosts = struct {
    // Direct opcode cost lookup
    pub fn getOpcodeCost(op: opcode.Opcode) u64 {
        return op.gasCost();
    }

    // Memory expansion costs
    pub fn memoryExpansion(current_size: usize, new_size: usize) u64 {
        // Formula: 3 * words + (words^2 / 512)
        // Implementation from Memory.expansionCost
    }

    // Storage costs (warm vs cold)
    pub const storage_warm = 100;
    pub const storage_cold = 2100;
    pub const storage_set = 20000;
    pub const storage_clear_refund = 4800;

    // Call costs
    pub const call_base = 100;
    pub const call_value_transfer = 9000;
    pub const call_new_account = 25000;

    // Create costs
    pub const create_base = 32000;
    pub const create_code_deposit = 200; // per byte

    // Catalog as constant array for static export
    pub const OPCODE_COSTS = blk: {
        var costs: [256]u64 = undefined;
        inline for (0..256) |i| {
            costs[i] = if (@enumFromInt(opcode.Opcode, i)) |op|
                op.gasCost()
            else
                0;
        }
        break :blk costs;
    };
};
```

**Integration with KALIX**:
```zig
// kalix can import this directly or codegen a lookup table
const zvm_gas = @import("zvm").gas.costs;

pub const GasAnalyzer = struct {
    pub fn analyze(instructions: []const ir.IR) GasAnalysis {
        var total: u64 = 0;
        for (instructions) |instr| {
            total += switch (instr) {
                .add => zvm_gas.GasCosts.getOpcodeCost(.ADD),
                .sload => zvm_gas.GasCosts.storage_warm,
                // etc.
            };
        }
        return .{ .total = total };
    }
};
```

---

### Priority 3: KALIX Bytecode Loader/Executor

**Purpose**: Load KALIX-compiled bytecode into ZVM

**File**: `src/runtime/kalix_loader.zig`
```zig
//! KALIX Bytecode Loader
//! Loads and validates KALIX-compiled contracts

const std = @import("std");
const VM = @import("../interpreter/vm.zig").VM;
const BytecodeContainer = @import("../bytecode/container.zig").BytecodeContainer;
const AccountState = @import("../state/accounts.zig").AccountState;

pub const KalixLoader = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) KalixLoader {
        return .{ .allocator = allocator };
    }

    /// Load KALIX bytecode container and prepare for execution
    pub fn loadContract(
        self: *KalixLoader,
        bytecode: []const u8,
    ) !BytecodeContainer {
        // Deserialize ZVMC container
        var container = try BytecodeContainer.deserialize(bytecode, self.allocator);

        // Validate it's KALIX-compiled (check target)
        if (container.target != .zvm_native) {
            return error.InvalidTarget;
        }

        return container;
    }

    /// Execute KALIX contract function
    pub fn executeFunction(
        self: *KalixLoader,
        container: *const BytecodeContainer,
        function_selector: [4]u8,
        calldata: []const u8,
        gas_limit: u64,
        accounts: *AccountState,
    ) !ExecutionResult {
        // Create VM instance
        var vm = VM.init(
            self.allocator,
            gas_limit,
            // ... storage, transient, hedera syscalls
        );
        vm.account_state = accounts;
        defer vm.deinit();

        // Load contract bytecode
        vm.loadBytecode(container.code);

        // Set up context (function selector in calldata)
        vm.context.calldata = calldata;

        // Execute
        return try vm.execute();
    }
};
```

---

## 🚀 Implementation Timeline

### Week 1: Table Hashing Opcode
- [ ] Add TABLEHASH opcode (0xD2) to `opcode.zig`
- [ ] Implement in `vm.zig` executeOpcode
- [ ] Add gas cost (30 gas)
- [ ] Write 5+ tests for table hashing
- [ ] Update KALIX to use finalized opcode

**Deliverable**: KALIX can remove temporary table_hash_opcode

### Week 2: Gas Cost Formalization
- [ ] Create `src/gas/costs.zig` export module
- [ ] Document all opcode gas costs
- [ ] Add memory expansion formula
- [ ] Create constant lookup table
- [ ] Integrate with KALIX gas analyzer

**Deliverable**: KALIX has accurate gas estimates

### Week 3: KALIX Loader
- [ ] Create `src/runtime/kalix_loader.zig`
- [ ] Implement contract loading
- [ ] Add function selector routing
- [ ] Write integration tests (KALIX contract → ZVM execution)
- [ ] Document KALIX → ZVM integration flow

**Deliverable**: End-to-end KALIX compilation and execution

---

## 📋 Additional Integration Needs

### 1. ABI Format Alignment
**Current**: KALIX uses JSON ABI in BytecodeContainer
**Needed**: Define KALIX ABI schema in `docs/kalix_abi.md`

Example:
```json
{
  "contract": "TokenVault",
  "functions": [
    {
      "name": "deposit",
      "selector": "0xb6b55f25",
      "inputs": [{"name": "amount", "type": "u64"}],
      "outputs": [],
      "mutability": "mutable"
    }
  ],
  "tables": [
    {
      "name": "balances",
      "slot": 0,
      "key_type": "Address",
      "value_type": "u64"
    }
  ]
}
```

### 2. Precompiled Contracts (Future Phase)
KALIX mentioned in Phase 6 requirements:
- ecrecover (signature verification)
- sha256 (hashing)
- ripemd160 (legacy hashing)

**Status in ZVM**: Not yet implemented (Phase 7 candidate)

### 3. Multi-Contract Deployment
KALIX will compile contracts that deploy other contracts.
**ZVM Status**: ✅ CREATE/CREATE2 opcodes implemented in Phase 6!

---

## ✅ Success Criteria

KALIX → ZVM integration is **PRODUCTION READY** when:

1. ✅ KALIX compiles without temporary opcodes
2. ✅ Gas estimates match actual ZVM execution costs (±5%)
3. ✅ KALIX-compiled contracts execute on ZVM with correct results
4. ✅ Integration test suite covers:
   - [ ] Arithmetic operations
   - [ ] State persistence (SLOAD/SSTORE)
   - [ ] Table operations with hashing
   - [ ] Control flow (if/else, loops)
   - [ ] Multi-contract calls
5. ✅ Performance: <10ms compilation, <1ms execution for simple contracts
6. ✅ Documentation complete for KALIX developers

---

## 🎯 Immediate Action Items (This Week)

**For ZVM**:
1. **Add TABLEHASH opcode** (0xD2)
   - File: `src/bytecode/opcode.zig`
   - File: `src/interpreter/vm.zig`
   - Tests: `src/interpreter/vm_tablehash_test.zig`

2. **Create gas cost export**
   - File: `src/gas/costs.zig`
   - Export constant array for KALIX

3. **Update PHASE_6_COMPLETE.md**
   - Mark KALIX integration blockers resolved
   - Add "Ready for KALIX Phase 2 completion"

**For KALIX** (once ZVM updated):
1. Replace `table_hash_opcode = 0xD2` with ZVM import
2. Update gas analyzer to use ZVM cost catalog
3. Run full integration test suite
4. Mark Phase 2 as COMPLETE ✅

---

## 📞 Next Steps Summary

**KALIX says**: "Need finalized ZVM table hash instruction and gas costs"

**ZVM needs to deliver**:
1. **TABLEHASH opcode (0xD2)** - 1 day
2. **Gas cost export module** - 1 day
3. **KALIX loader (optional but nice)** - 2 days

**Total time to unblock KALIX**: 2-4 days

Then KALIX Phase 2 is **COMPLETE** and we move to Phase 3 (Hedera Integration)! 🚀

---

**Status**: ZVM is 95% ready for KALIX. Just need these 3 final pieces!
