# KALIX → ZVM Integration Guide

## Overview

KALIX is a smart contract language that compiles to ZVM bytecode. This guide shows how to integrate the KALIX compiler with ZVM.

## ZVM as a Compilation Target

### Bytecode Format

KALIX compiles to ZVMC (ZVM Container) format:

```zig
const BytecodeContainer = @import("zvm").BytecodeContainer;

// Create ZVMC container
var container = try BytecodeContainer.create(
    allocator,
    bytecode,        // ZVM opcodes
    abi_metadata,    // JSON ABI
    .zvm_native,     // Target type
);

// Serialize for storage/transmission
const serialized = try container.serialize(allocator);
```

### Gas Cost Import

KALIX can import ZVM gas costs for accurate gas estimation during compilation:

```zig
// In KALIX compiler
const zvm_gas = @import("zvm").gas_costs;

// Get opcode costs
const add_cost = zvm_gas.OPCODE_COSTS[@intFromEnum(Opcode.ADD)]; // 3
const sload_cost = zvm_gas.OPCODE_COSTS[@intFromEnum(Opcode.SLOAD)]; // 100

// Calculate dynamic costs
const keccak_cost = zvm_gas.keccak256Cost(data_size);
const memory_cost = zvm_gas.memoryExpansion(current_size, new_size);
const log_cost = zvm_gas.logCost(num_topics, data_size);
```

## TABLEHASH Opcode for Structured Storage

ZVM provides the `TABLEHASH` opcode (0xD2) for efficient key-value storage in KALIX contracts.

### Usage

```kalix
// KALIX contract with table storage
contract Token {
    pub state balances: Table<Address, u64>;  // Maps Address → Balance

    pub fn transfer(to: Address, amount: u64) -> Result<()> {
        let sender = msg.sender();

        // Compiler generates TABLEHASH for table access:
        // PUSH key (sender address)
        // PUSH slot (balances slot)
        // TABLEHASH -> storage_key
        // SLOAD

        let balance = balances.get(sender)?;
        // ... rest of logic
    }
}
```

### Bytecode Generation

```zig
// KALIX compiler generates:
// For `balances.get(key)`:
PUSH32 <key>           // Push the key
PUSH32 <table_slot>    // Push the table's storage slot
TABLEHASH              // Hash them together -> storage_key
SLOAD                  // Load value from storage

// For `balances.set(key, value)`:
PUSH32 <value>         // Push value to store
PUSH32 <key>           // Push the key
PUSH32 <table_slot>    // Push the table's storage slot
TABLEHASH              // Hash them together -> storage_key
SSTORE                 // Store value
```

### TABLEHASH Semantics

```
Input Stack:  [key: U256] [table_slot: U256]
Output Stack: [storage_key: U256]

storage_key = keccak256(table_slot || key)
```

**Gas Cost:** 30 gas (same as KECCAK256)

## Function Selector Routing

ZVM loader uses 4-byte function selectors (Ethereum-style):

```zig
// KALIX compiler generates function selector
const selector = keccak256("transfer(address,uint64)")[0..4];

// ZVM loader routes calls based on selector
const KalixLoader = @import("zvm").KalixLoader;
var loader = KalixLoader.init(allocator);

const result = try loader.executeFunction(
    &container,
    selector,           // [4]u8 function selector
    calldata,           // ABI-encoded parameters
    gas_limit,
    storage,
    transient_storage,
    accounts,
);
```

## Complete Integration Example

### 1. KALIX Contract

```kalix
contract SimpleStorage {
    pub state value: u64;
    pub state owner: Address;

    pub fn constructor(initial_value: u64) {
        self.owner = msg.sender();
        self.value = initial_value;
    }

    pub fn set(new_value: u64) -> Result<()> {
        if msg.sender() != self.owner {
            return Err("Not owner");
        }
        self.value = new_value;
        emit ValueChanged { old: self.value, new: new_value };
        Ok(())
    }

    pub view fn get() -> u64 {
        return self.value;
    }
}
```

### 2. KALIX Compiler Output

```zig
// Generated ZVM bytecode structure:

// Constructor (called once at deployment):
// 1. Load initial_value from calldata
// 2. Store msg.sender() to owner slot
// 3. Store initial_value to value slot
// 4. RETURN

// Function dispatch table:
// selector_map = {
//     0xAABBCCDD: set_function,    // set(uint64)
//     0x6D4CE63C: get_function,    // get()
// }

// set() function bytecode:
// 1. Check msg.sender() == owner (REVERT if not)
// 2. Load new_value from calldata
// 3. SSTORE to value slot
// 4. LOG1 (emit event)
// 5. RETURN success

// get() function bytecode:
// 1. SLOAD value slot
// 2. PUSH to stack
// 3. MSTORE (prepare return data)
// 4. RETURN
```

### 3. ZVM Deployment

```zig
const zvm = @import("zvm");
const std = @import("std");

pub fn deployKalixContract(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    constructor_params: []const u8,
) !zvm.Address {
    // 1. Load bytecode container
    var loader = zvm.KalixLoader.init(allocator);
    var container = try loader.loadContract(bytecode);
    defer container.deinit(allocator);

    // 2. Setup state
    var state = zvm.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = zvm.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();
    var accounts = zvm.AccountState.init(allocator);
    defer accounts.deinit();

    // 3. Generate contract address
    const deployer = zvm.Address.zero(); // In production, use actual deployer
    const contract_address = try generateContractAddress(deployer, 1);

    // 4. Execute constructor
    const result = try loader.executeDirect(
        &container,
        constructor_params,
        1_000_000, // Gas limit
        state.asStorage(),
        tstorage.asTransientStorage(),
        &accounts,
    );

    if (!result.success) {
        return error.ConstructorFailed;
    }

    // 5. Deploy bytecode to account
    try accounts.deployContract(contract_address, container.code);

    return contract_address;
}
```

### 4. ZVM Execution

```zig
pub fn callKalixContract(
    allocator: std.mem.Allocator,
    contract_address: zvm.Address,
    function_name: []const u8,
    params: []const u8,
    accounts: *zvm.AccountState,
    storage: zvm.Storage,
) ![]const u8 {
    var loader = zvm.KalixLoader.init(allocator);

    // 1. Compute function selector
    const selector = zvm.KalixLoader.computeSelector(function_name);

    // 2. Get contract code
    const code = accounts.getCode(contract_address);
    var container = try loader.loadContract(code);
    defer container.deinit(allocator);

    // 3. Execute function
    var tstorage = zvm.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    const result = try loader.executeFunction(
        &container,
        selector,
        params,
        500_000, // Gas limit
        storage,
        tstorage.asTransientStorage(),
        accounts,
    );

    if (!result.success) {
        return error.ExecutionFailed;
    }

    return result.return_data;
}
```

## ABI Metadata

KALIX should generate ABI metadata in the ZVMC container:

```json
{
  "contract": "SimpleStorage",
  "functions": [
    {
      "name": "set",
      "selector": "0xAABBCCDD",
      "inputs": [
        { "name": "new_value", "type": "u64" }
      ],
      "outputs": [],
      "mutability": "nonpayable"
    },
    {
      "name": "get",
      "selector": "0x6D4CE63C",
      "inputs": [],
      "outputs": [
        { "name": "value", "type": "u64" }
      ],
      "mutability": "view"
    }
  ],
  "events": [
    {
      "name": "ValueChanged",
      "fields": [
        { "name": "old", "type": "u64", "indexed": false },
        { "name": "new", "type": "u64", "indexed": false }
      ]
    }
  ],
  "state_variables": [
    { "name": "value", "type": "u64", "slot": 0 },
    { "name": "owner", "type": "Address", "slot": 1 }
  ]
}
```

## Optimization Tips

### 1. Use TABLEHASH for Maps

```kalix
// GOOD: Uses efficient TABLEHASH
pub state balances: Table<Address, u64>;

// BAD: Would require multiple storage slots
pub state balance_array: [100]u64;
```

### 2. Pack State Variables

```kalix
// GOOD: Packs into single U256
pub state {
    count: u64,      // Slot 0, offset 0
    active: bool,    // Slot 0, offset 8
    owner: Address,  // Slot 0, offset 9
}

// BAD: Each uses full slot
pub state count: u256;
pub state active: u256;
pub state owner: u256;
```

### 3. Use View Functions

```kalix
// View functions don't modify state (STATICCALL)
pub view fn getBalance(account: Address) -> u64 {
    return balances.get(account);  // No SSTORE, cheaper gas
}
```

## Gas Estimation

KALIX compiler should provide gas estimates:

```zig
// Estimate gas for function call
pub fn estimateGas(
    function_name: []const u8,
    params: []const u8,
) !u64 {
    // 1. Parse function bytecode
    // 2. Simulate execution
    // 3. Track gas used
    // 4. Add safety margin (10-20%)

    return estimated_gas * 1.1; // 10% buffer
}
```

## Testing

```zig
test "KALIX contract deployment and call" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Deploy contract
    const contract_addr = try deployKalixContract(
        allocator,
        kalix_bytecode,
        constructor_params,
    );

    // Call set(42)
    const set_params = encodeU64(42);
    _ = try callKalixContract(
        allocator,
        contract_addr,
        "set(u64)",
        &set_params,
        &accounts,
        storage,
    );

    // Call get()
    const result = try callKalixContract(
        allocator,
        contract_addr,
        "get()",
        &[_]u8{},
        &accounts,
        storage,
    );

    const value = decodeU64(result);
    try testing.expectEqual(@as(u64, 42), value);
}
```

## Next Steps

1. **Implement KALIX Compiler Backend**
   - Parse KALIX AST
   - Generate ZVM opcodes
   - Emit ZVMC containers

2. **Gas Optimization**
   - Dead code elimination
   - Constant folding
   - Inline small functions

3. **Debugging Support**
   - Source maps
   - Breakpoint support
   - Stack traces

## Resources

- [ZVM Opcode Reference](./OPCODES.md)
- [ZVM Architecture](./ARCHITECTURE.md)
- [Gas Costs Reference](./GAS_COSTS.md)
- [ZVMC Container Specification](./BYTECODE_SPEC.md)
