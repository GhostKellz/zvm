# ZVM Architecture

## Overview

ZVM (Zig Virtual Machine) is a high-performance, multi-chain smart contract execution engine built in pure Zig with zero external dependencies.

## Design Principles

1. **Zero Dependencies**: Core interpreter has no external dependencies
2. **Multi-Chain**: Native support for Hedera, EVM, and Soroban contracts
3. **Deterministic**: Reproducible execution across all platforms
4. **KALIX-First**: Optimized as the primary target for KALIX compiler
5. **Modular**: Clean separation of concerns (REVM-inspired)

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Language Layer                             │
│  KALIX │ Solidity │ Soroban                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │   Compilation       │
          │   & Translation     │
          └──────────┬──────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│                  Bytecode Layer                               │
│  ZVMC (ZVM Native) │ EVM Compat │ WASM Bridge               │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│                   ZVM Core Engine                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │  Stack   │  │  Memory  │  │ Storage  │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │   Gas    │  │ Opcodes  │  │ Context  │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│              Chain-Specific Syscalls                          │
│  Hedera (HTS/HCS) │ EVM Precompiles │ Soroban Host Funcs   │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│                Network Integration                            │
│              ZELIX (Hedera Bridge)                           │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Interpreter (`src/interpreter/`)

The execution engine that runs ZVM bytecode.

**Components:**
- **VM**: Main interpreter with execution loop
- **Stack**: 1024-slot U256 stack (EVM-compatible)
- **Memory**: Dynamic memory with quadratic expansion costs
- **Execution Context**: Caller, value, calldata, block info

**Execution Flow:**
```zig
1. Load bytecode
2. Initialize context (caller, gas, storage)
3. Execute loop:
   a. Fetch opcode
   b. Charge gas
   c. Execute opcode
   d. Advance PC (unless jump)
4. Return result (success, gas_used, return_data, logs)
```

### 2. State Management (`src/state/`)

**Storage Interface:**
- Clean abstraction over external storage
- Supports any backend (in-memory, database, network)
- Journaled state for transaction rollback
- Transient storage (EIP-1153)

**Account State:**
- Balance tracking
- Nonce management
- Contract code storage
- CREATE/CREATE2 address generation

### 3. Gas Metering (`src/gas/`)

**Components:**
- **Gas Meter**: Tracks gas consumption
- **Gas Costs**: Opcode cost lookup table (exported for compilers)
- **Dynamic Costs**: Memory expansion, KECCAK256, LOG, COPY operations

**Gas Cost Formula Examples:**
- Memory expansion: `3 * words + (words^2 / 512)`
- KECCAK256: `30 + 6 * words`
- LOG: `base + 375 * topics + 8 * size`

### 4. Bytecode Container (`src/bytecode/`)

**ZVMC Format:**
```
Magic: "ZVMC" (4 bytes)
Version: 1 (1 byte)
Target: zvm_native | evm_compat | wasm_bridge (1 byte)
Code Length: u32 (4 bytes)
Code: [bytecode]
ABI Length: u32 (4 bytes)
ABI: [metadata]
```

**Opcodes:**
- 0x00-0x1F: Stack operations
- 0x20-0x3F: Arithmetic
- 0x40-0x5F: Comparison & Bitwise
- 0x60-0x7F: Memory
- 0x80-0x9F: Storage
- 0xA0-0xBF: Control flow
- 0xC0-0xDF: Context
- 0xE0-0xEF: Hedera syscalls
- 0xF0-0xFF: System operations

### 5. Multi-Chain Support

#### Hedera (`src/chains/hedera/`)
- **HTS Operations**: token transfer, mint, burn, associate
- **HCS Operations**: submit message, create topic
- **Mock**: Testing without network access

#### EVM (`src/chains/evm/`)
- **Bytecode Translation**: EVM → ZVM opcode mapping
- **Precompiles**: ecrecover, sha256, ripemd160, modexp, bn256, blake2f
- **Gas Compatibility**: EVM-equivalent gas costs

#### Soroban (`src/chains/soroban/`)
- **WASM Bridge**: Stellar smart contract execution
- **Host Functions**: Storage, crypto, context operations
- **Val Type**: 64-bit tagged values (Soroban format)

### 6. Runtime Integration (`src/runtime/`)

#### KALIX Loader
- Load KALIX-compiled contracts (ZVMC format)
- Function selector routing (4-byte keccak256)
- Direct execution and deployment
- ABI metadata extraction

#### ZELIX Bridge
- Deploy contracts to Hedera via ZELIX
- Execute contract calls
- Query contract state (read-only)
- Gas estimation

## Execution Model

### Contract Deployment (CREATE/CREATE2)

```
1. Load constructor bytecode
2. Execute constructor with init params
3. Store deployed bytecode in account
4. Return contract address
```

### Contract Call (CALL/DELEGATECALL/STATICCALL)

```
1. Load contract bytecode from account
2. Create new execution context
3. Execute with calldata
4. Return result to caller
5. Commit/revert state changes
```

### Gas Handling

```
1. Charge gas before each operation
2. Track gas used
3. If gas limit exceeded → OutOfGas error
4. Return remaining gas to caller
5. Refunds for storage clearing
```

## State Transitions

### Journaled State (Checkpoints)

```zig
Transaction Start:
  checkpoint()         // Create savepoint

Execution:
  SSTORE → journal entry
  CALL → nested checkpoint

Transaction End:
  Success → commit()   // Discard journal
  Failure → rollback() // Restore from journal
```

### Transient Storage (EIP-1153)

- Lifetime: Single transaction
- Cleared after execution
- No gas refunds
- Use case: Reentrancy locks, temporary state

## Security Features

1. **Stack Overflow Protection**: 1024-slot limit
2. **Memory Expansion Costs**: Quadratic growth prevents DoS
3. **Gas Metering**: Prevents infinite loops
4. **Static Call Mode**: Prevents state modification
5. **Revert on Error**: Clean rollback on failure

## Performance Optimizations

1. **Computed Gas Costs**: Constant-time lookup table
2. **Stack-Based**: Minimal memory allocations
3. **Journaled State**: Efficient checkpoint/rollback
4. **Deterministic**: No non-deterministic operations

## Integration Points

### For Compilers (KALIX)

```zig
// Import gas costs for accurate estimation
const zvm_gas = @import("zvm").gas_costs;

const add_gas = zvm_gas.OPCODE_COSTS[@intFromEnum(Opcode.ADD)]; // 3
const sstore_gas = zvm_gas.OPCODE_COSTS[@intFromEnum(Opcode.SSTORE)]; // 100
```

### For Runtimes (ZELIX)

```zig
// Deploy contract to Hedera
var bridge = ZelixBridge.init(allocator, .{ .network = .testnet });
const result = try bridge.deployContract(bytecode, constructor_params, gas_limit);

// Call contract function
const call_result = try bridge.callContract(
    contract_address,
    function_selector,
    params,
    gas_limit,
    storage,
    transient_storage,
    accounts,
);
```

## Testing Strategy

1. **Unit Tests**: Each component tested in isolation
2. **Integration Tests**: Full execution scenarios
3. **Compliance Tests**: Ethereum state test compatibility
4. **Fuzzing**: Random bytecode execution (no panics)
5. **Property Tests**: Invariant checking

## Future Enhancements

1. **JIT Compilation**: Hot path optimization
2. **AOT Compilation**: Ahead-of-time bytecode compilation
3. **Formal Verification**: Mathematical correctness proofs
4. **ZK-VM Integration**: Provable execution (Cairo-style)

## References

- [REVM Architecture](https://github.com/bluealloy/revm)
- [EVM Opcodes](https://www.evm.codes/)
- [Hedera Smart Contract Service](https://docs.hedera.com/hedera/smart-contracts)
- [Soroban Documentation](https://soroban.stellar.org/docs)
