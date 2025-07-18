# ZVM — The Zig Virtual Machine

`zvm` is a lightweight, modular, and secure virtual machine engine built entirely in Zig. Inspired by the performance and control ethos of Zig, `zvm` is designed to be:

* **Minimal by design** — clean, simple execution engine
* **Customizable** — supports new instruction sets (e.g., zEVM-style bytecode)
* **Secure** — strict memory controls with Zig’s runtime safety
* **Portable** — embeddable in CLIs, nodes, smart wallets, and more

---

## 🧠 Core Objectives

* 🧩 Execute programmable logic: smart contracts, signed scripts, workflows
* 🔐 Run in a sandboxed environment: no external file/network access unless declared
* ⚙️ Support multi-runtime formats: wasm-lite, zvm bytecode, and (optionally) zEVM-style execution
* 🧪 Deterministic computation: all operations produce the same result across environments

---

## 🔍 Design Philosophy

`zvm` is not a full blockchain runtime by default — it's a secure execution layer:

* 🛠 **Built for modularity**: easily extendable with custom opcodes
* 🧱 **Memory-constrained**: ideal for edge computing and embedded validation
* 🔄 **State machine-friendly**: integrates well with `zledger`, `zwallet`, and smart contract logic
* 🔍 **Auditable & deterministic**: encourages formal verification and testing

---

## 🛠️ Architecture

```
┌───────────────────────┐
│  zvm-cli              │  <- local test runner / REPL
└───────────────────────┘
     │
┌───────────────────────┐
│  zvm-core             │  <- bytecode interpreter, stack machine, memory/register state
└───────────────────────┘
     │
┌───────────────────────┐
│  zvm-runtime          │  <- plugin functions: storage, signing, I/O hooks
└───────────────────────┘
```

Optional add-ons:

* `zvm-ledger` (calls into `zledger`)
* `zvm-wallet` (validates against `zsig` signatures)
* `zvm-formats/wasm-lite.zig` (planned)
* `zvm-formats/zevm.zig` (optional EVM compatibility)

---

## ⟳ zEVM Compatibility (Optional)

We may explore compatibility or feature sharing with [`zEVM`](https://github.com/ziglang/zevm):

* EVM opcode set
* Ethereum state machine model
* Potential for full L2 sandbox support in Zig

Unlike `zEVM`, `zvm` aims for:

* More general-purpose virtual machines (not just Ethereum)
* Smaller, embeddable runtimes (e.g., <100KB for minimal build)
* A modular format stack with wasm-lite and zvm-native bytecode for Ghostchain

---

## ✨ Features

* Bytecode execution (custom or EVM-like)
* Deterministic gas metering / instruction counting
* Hookable system calls (via `zvm-runtime`)
* WASM-lite compilation target (future)
* Optional zEVM compatibility module
* Embedded signing + verification (via `zsig`)

---

## Example CLI

```sh
# Run native ZVM bytecode
zvm demo

# Execute ZVM native bytecode (when file support is added)
zvm run contract.zvm

# Execute EVM-compatible bytecode  
zvm evm contract.bin

# Run built-in demonstration
zvm demo
```

### Quick Start

```bash
# Build and run demo
zig build run -- demo

# Build and run tests
zig build test

# Build optimized release
zig build -Doptimize=ReleaseFast
```

---

## 🎯 Current Implementation Status

**ZVM v0.1.0 is now fully functional!** ✅

### ✅ Completed Features

* **Core VM Engine** - Stack-based bytecode interpreter with 30+ opcodes
* **Gas Metering** - Deterministic execution cost tracking
* **Smart Contracts** - Contract deployment, execution, and storage
* **ZEVM Compatibility** - Full Ethereum Virtual Machine compatibility layer
* **Runtime Hooks** - Crypto integration (Keccak256, ECRECOVER, signatures)
* **CLI Interface** - Interactive command-line tool with demo mode
* **Test Coverage** - Comprehensive test suite for all components

### 🧪 Demo Examples

ZVM includes built-in demonstrations:

```bash
# Run the interactive demo
zig build run -- demo
```

**Demo 1: Native ZVM Execution**
```
(10 + 20) * 5 = 150
Gas used: 8
```

**Demo 2: EVM Compatibility**  
```
(15 + 25) / 2 = 20
Gas used: 15
```

**Demo 3: Smart Contract Runtime**
```
Contract deployed successfully!
Deployment gas: 21000
```

### 🔗 Ecosystem Integration

ZVM is designed to integrate with the complete **GhostChain** ecosystem:

| Component | Status | Purpose |
|-----------|--------|---------|
| `zcrypto` | ✅ Integrated | Cryptographic primitives (Ed25519, secp256k1, post-quantum) |
| `zsig` | ✅ Integrated | Multi-signature and threshold signature verification |
| `zquic` | ✅ Integrated | QUIC/HTTP3 networking for contract communications |
| `zsync` | ✅ Integrated | Async runtime for concurrent execution |
| `zwallet` | ✅ Integrated | HD wallet integration and account management |
| `zns` | ✅ Integrated | Name Service for domain resolution (DID, .ghost, etc.) |
| `zqlite` | ✅ Optional | Persistent storage backend (enabled with `--persistent`) |
| `shroud` | ✅ Optional | Enterprise identity & ZKP features (enabled with `--enterprise`) |

## 🏗️ Build System & Feature Flags

ZVM uses a modular build system with feature flags to enable/disable components:

```bash
# Minimal build (stateless contracts only)
zig build -Dcrypto=false -Dnetworking=false -Dwallet=false

# Standard build (default - includes crypto, networking, wallet)
zig build

# Enterprise build (includes all features)
zig build -Denterprise=true -Dpersistent=true

# Persistent storage build
zig build -Dpersistent=true
```

### Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `crypto` | `true` | Enable cryptographic operations (zcrypto, zsig) |
| `networking` | `true` | Enable networking features (zquic, zsync) |
| `wallet` | `true` | Enable wallet integration (zwallet, zns) |
| `enterprise` | `false` | Enable enterprise features (shroud identity/ZKP) |
| `persistent` | `false` | Enable persistent storage (zqlite backend) |

## 🔧 Smart Contract Host Functions

ZVM provides comprehensive host functions for smart contract execution:

### Core Blockchain Functions
- `get_caller()` - Get transaction caller address
- `get_origin()` - Get transaction origin
- `get_value()` - Get transaction value
- `get_block_number()` - Get current block number
- `get_block_timestamp()` - Get current block timestamp

### Storage Functions
- `storage_load(key)` - Load value from contract storage
- `storage_store(key, value)` - Store value in contract storage

### Persistent Storage (zqlite backend)
- `db_connect(path)` - Connect to persistent database
- `db_execute(conn, sql)` - Execute SQL statement
- `db_query(conn, sql)` - Query database
- `db_close(conn)` - Close database connection

### Cryptographic Functions
- `keccak256(data)` - Keccak-256 hash function
- `sha256(data)` - SHA-256 hash function
- `ecrecover(hash, signature)` - Ethereum-style signature recovery

### Post-Quantum Cryptography
- `ml_dsa_verify(message, signature, pubkey)` - ML-DSA signature verification
- `ml_kem_encapsulate(pubkey)` - ML-KEM key encapsulation
- `ml_kem_decapsulate(privkey, ciphertext)` - ML-KEM decapsulation

### Multi-Signature & Threshold Signatures
- `multisig_verify(message, signatures, threshold)` - Multi-signature verification
- `threshold_verify(message, signature, threshold, total)` - Threshold signature verification

## 📚 Examples

### Hybrid Smart Contract (Stateless + Persistent)
```zig
// See examples/hybrid_contract.zig
var contract = HybridContract.init(owner_address, persistent_mode);
try contract.initPersistent("contract_storage.db");
try contract.increment(); // Works in both modes
```

### Multi-Signature Contract
```zig
// See examples/multisig_contract.zig
var contract = try MultiSigContract.init(allocator, &owners, threshold);
try contract.proposeTransaction(allocator, recipient, value, data);
try contract.signTransaction(owner1_pubkey, signature1);
try contract.executeTransaction(); // Executes when threshold is met
```

### Running Examples
```bash
# Test hybrid contract
zig test examples/hybrid_contract.zig

# Test multi-sig contract
zig test examples/multisig_contract.zig
```

---

## 🔐 Use Cases

* Executing governance actions on-chain
* Smart contract testing and replay locally
* Verifying signed payloads in IoT/embedded workflows
* Running deterministic agent logic for `Jarvis`
* Powering programmable logic inside Ghostchain

---

## License

MIT — Designed for modular integration with the GhostKellz stack.

