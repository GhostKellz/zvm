# ZVM - The Zig Virtual Machine

**A zero-dependency, multi-chain smart contract execution engine built in pure Zig.**

## Features

✨ **Zero External Dependencies** - Pure Zig implementation
🔗 **Multi-Chain Support** - Hedera, EVM, and Soroban compatibility
🚀 **KALIX-Native** - Primary compilation target for KALIX smart contracts
⚡ **High Performance** - Efficient stack-based execution
🔒 **Deterministic** - Predictable gas metering and execution
🛡️ **Post-Quantum Ready** - Built-in PQ crypto opcodes

## Quick Start

```bash
# Build and run demo
zig build run

# Run tests
zig build test
```

## Example Usage

```zig
const zvm = @import("zvm");

// Create VM instance
var vm = zvm.VM.init(allocator, 1_000_000); // 1M gas limit
defer vm.deinit();

// Simple bytecode: PUSH1 42, PUSH1 8, ADD, HALT
const bytecode = [_]u8{
    @intFromEnum(zvm.Opcode.PUSH1), 42,
    @intFromEnum(zvm.Opcode.PUSH1), 8,
    @intFromEnum(zvm.Opcode.ADD),
    @intFromEnum(zvm.Opcode.HALT),
};

// Execute
vm.loadBytecode(&bytecode);
const result = try vm.execute();

// Result: 50 (42 + 8)
const top = try vm.stack.peek(0);
std.debug.print("Result: {d}\n", .{top.toU64()}); // 50
std.debug.print("Gas used: {d}\n", .{result.gas_used}); // 9
```

## Architecture

```
zvm/
├── src/
│   ├── primitives/      # Core types (U256, Address, Hash)
│   ├── bytecode/        # Opcode definitions
│   ├── interpreter/     # VM execution engine
│   │   ├── vm.zig      # Main interpreter
│   │   ├── stack.zig   # Stack machine
│   │   └── memory.zig  # Memory management
│   ├── gas/             # Gas metering
│   ├── state/           # Storage layer
│   │   ├── storage.zig  # Storage trait interface
│   │   ├── journaled.zig # Persistent storage with checkpoints
│   │   └── transient.zig # Transient storage (EIP-1153)
│   ├── chains/          # Multi-chain support (coming soon)
│   └── root.zig         # Public API
├── examples/
│   └── storage_counter.zig # Storage demo contract
└── build.zig.zon        # ZERO dependencies!
```

## Opcodes

### Current Implementation

- **Stack Operations**: PUSH1-32, POP, DUP1-4, SWAP1-4
- **Arithmetic**: ADD, SUB, MUL, DIV, MOD
- **Comparison**: LT, GT, EQ, ISZERO
- **Bitwise**: AND, OR, XOR, NOT, SHL, SHR
- **Memory**: MLOAD, MSTORE, MSTORE8, MSIZE
- **Storage**: SLOAD, SSTORE (persistent), TLOAD, TSTORE (transient EIP-1153)
- **Control Flow**: JUMP, JUMPI, HALT, RETURN, REVERT
- **Context**: ADDRESS, CALLER, CALLVALUE, CALLDATALOAD
- **Crypto**: KECCAK256

### Coming Soon

- **Hedera Syscalls**: HTS_TRANSFER, HCS_SUBMIT, etc.
- **Post-Quantum Crypto**: PQ_VERIFY_DILITHIUM, PQ_VERIFY_FALCON
- **EVM Compatibility**: Full opcode set, precompiles

## Gas Costs

ZVM uses EVM-compatible gas costs:

| Operation | Gas | Notes |
|-----------|-----|-------|
| ADD, SUB | 3 | Basic arithmetic |
| MUL, DIV | 5 | Multiplication/division |
| KECCAK256 | 30 | Base cost + 6 per word |
| SLOAD (cold) | 2100 | First access (EIP-2929) |
| SLOAD (warm) | 100 | Subsequent access |
| SSTORE (create) | 20000 | Zero → non-zero |
| SSTORE (modify) | 100-2200 | Warm/cold modification |
| TLOAD | 100 | Transient storage read |
| TSTORE | 100 | Transient storage write |
| JUMP | 8 | Unconditional jump |
| JUMPI | 10 | Conditional jump |

## Integration with KALIX

ZVM is the primary execution target for [KALIX](../kalix), a modern smart contract language:

```kalix
contract Token {
    pub state balances: Map<Address, u64>;

    pub fn transfer(to: Address, amount: u64) -> Result<()> {
        // Compiles to ZVM bytecode
        let sender = msg.sender();
        balances.set(sender, balances.get(sender)? - amount);
        balances.set(to, balances.get(to)? + amount);
        Ok(())
    }
}
```

The KALIX compiler (Phase 2) will emit ZVM bytecode that can be executed natively.

## Integration with ZELIX

[ZELIX](../zelix) is the Hedera SDK that handles:
- Transaction building and signing
- Network communication
- Contract deployment via ZVM bytecode
- Receipt parsing and event extraction

```zig
// Deploy ZVM contract via ZELIX
const zelix_client = try zelix.Client.init(allocator, .testnet);
const contract_id = try zelix_client.deployContract(zvm_bytecode);

// Execute contract call
const result = try zelix_client.callContract(contract_id, "transfer", params);
```

## Roadmap

See [ZVM_ROADMAP.md](ZVM_ROADMAP.md) for the full 16-week implementation plan.

### Phase 0-1: Foundation ✅ (Complete!)
- Core types (Address, Hash, U256)
- Opcode definitions
- Stack machine
- Memory management
- Gas metering
- Core interpreter

### Phase 2: Storage & State ✅ (Complete!)
- Journaled state with checkpoint/rollback for atomic execution
- Persistent storage (SLOAD/SSTORE) with cold/warm gas accounting
- Transient storage (TLOAD/TSTORE) implementing EIP-1153
- Storage trait interface for backend flexibility
- Nested call simulation with full rollback support

### Phase 3: Hedera Integration (Week 6-7)
- HTS syscalls (token operations)
- HCS syscalls (consensus service)
- ZELIX bridge
- KALIX compilation target

### Phase 4: EVM Compatibility (Week 8-9)
- EVM bytecode translation
- Precompiled contracts
- Full opcode coverage

### Phase 5: Soroban/WASM Bridge (Week 10-11)
- WASM runtime
- Host functions
- Soroban compatibility

## Testing

```bash
# Run all tests
zig build test

# Run specific test
zig test src/primitives/types.zig

# Run with coverage
zig build test --summary all

# Run storage example
zig build example-storage
```

Current test coverage (39 tests passing):
- ✅ Primitive types (U256, Address, Hash)
- ✅ Stack operations
- ✅ Memory operations
- ✅ Gas metering
- ✅ VM execution
- ✅ Opcode gas costs
- ✅ Storage operations (SLOAD/SSTORE/TLOAD/TSTORE)
- ✅ Journaled state with checkpoint/rollback
- ✅ Transient storage (EIP-1153)
- ✅ Cold/warm gas accounting (EIP-2929)

## Performance

Initial benchmarks (will improve with optimization):

| Operation | Time | Gas |
|-----------|------|-----|
| ADD | ~3ns | 3 |
| MUL | ~5ns | 5 |
| KECCAK256 (32 bytes) | ~100ns | 30 |
| Memory load | ~8ns | 3 |
| Full execution (simple) | ~100ns | 9 |

## License

MIT License - See LICENSE file

## Contributing

Contributions welcome! Areas of focus:
1. Storage layer implementation
2. Hedera syscall integration
3. EVM compatibility testing
4. Performance optimization
5. Documentation improvements

## References

- **KALIX**: Smart contract language → [/data/projects/kalix](../kalix)
- **ZELIX**: Hedera SDK → [/data/projects/zelix](../zelix)
- **Analysis**: [ZVM_REBUILD_ANALYSIS.md](ZVM_REBUILD_ANALYSIS.md)
- **Roadmap**: [ZVM_ROADMAP.md](ZVM_ROADMAP.md)
- **EVM Spec**: [ethereum.org/en/developers/docs/evm](https://ethereum.org/en/developers/docs/evm/)
- **Hedera**: [hedera.com](https://hedera.com)

---

**Built with ❤️ in pure Zig. Zero dependencies. Maximum performance.**
