# ✅ TODO.md – GhostChain ZQUIC, ZCRYPTO & Ghost-WASM Integration Roadmap

*Version: 2025.07 (ZCrypto v0.5.0, ZQUIC v0.3.0, Ghost-WASM Spec Init)*  
*Maintainer: GhostKellz*

---

## 🧠 GOAL

Implement full QUIC + Crypto + WASM-lite stack using:
- 🔐 `zcrypto v0.5.0` — post-quantum safe + FFI-stable crypto
- 🌐 `zquic v0.3.0` — QUIC transport layer with stream control
- 🔥 Ghost-WASM — lightweight, gas-metered WASM engine purpose-built for smart contracts, identity-aware, and QUIC-native

REPO: 
https://github.com/ghostkellz/zcrypto 

https://github.com/ghostkellz/zquic 
---

## 📦 PHASE 1: ZCrypto v0.5.0 Integration

**Targets**: `walletd`, `ghostd`, `zvm`, `zevm`

- [ ] Update all `Cargo.toml` or `build.zig` to use `zcrypto = "0.5.0"`
- [ ] Replace all internal SHA2, HMAC, BLAKE3 calls with `zcrypto` equivalents
- [ ] Add support for:
  - [ ] `ed25519`, `secp256k1` (sign/verify)
  - [ ] Blake3 hashing
  - [ ] Base58 + base64 + hex encoding/decoding
  - [ ] Curve25519 + AES-GCM for QUIC stream crypto

- [ ] Export Zig crypto types over FFI
- [ ] Fallback to `gcrypt` if `zcrypto` not present (via `#[cfg(feature = "fallback")]`)

---

## 🌐 PHASE 2: ZQUIC v0.3.0 Integration

**Targets**: `ghostd`, `walletd`, `zvm`, `ghostbridge`

- [ ] Replace `gquic` usage with `zquic`
- [ ] Replace gRPC/WebSocket with QUIC stream messages:
  - [ ] `TransactionSubmit`
  - [ ] `BalanceStream`
  - [ ] `SmartContractInvoke`
  - [ ] `BlockBroadcast`
  - [ ] `ConsensusSync`

- [ ] API-level modules:
  - [ ] `mod transactions.rs`
  - [ ] `mod consensus.rs`
  - [ ] `mod state.rs`
  - [ ] `mod balance.rs`
  - [ ] `mod session.rs`

- [ ] Load peer metadata (QID) from `realid`
- [ ] Add support for QUIC stream priority + backpressure

---

## 🧬 PHASE 3: Ghost-WASM Runtime Spec

**Target**: `zvm`, `zevm`, `ghostd`, `ghostvm` (CLI)

> Define and implement a lightweight, deterministic, gas-accounted smart contract runtime

- [ ] Write initial spec: `docs/GHOSTWASM.md`
- [ ] Define opcode set (subset of WASM + custom extensions)
- [ ] Add memory sandboxing (via Zig allocator)
- [ ] Define gas model per opcode:
  - [ ] load/store
  - [ ] arithmetic
  - [ ] crypto ops (base cost)
  - [ ] QUIC stream reads/writes

- [ ] Define `.ghostwasm` binary format (header + payload)
  - [ ] Magic: `0xDEADBEEF`
  - [ ] Version: `1`
  - [ ] Flags: `QUIC/ID-required`
  - [ ] Signature: `realid-signed`

- [ ] Streaming contract execution over ZQUIC
- [ ] Add QUIC-based contract logging and tracing

---

## 🧪 PHASE 4: Testing & Fuzzing

- [ ] Write contract test suite (`tests/contracts/`)
- [ ] Fuzz smart contract gas behavior
- [ ] Simulate network QUIC stress
- [ ] Benchmark `zcrypto` vs `dalek` (sig verify/tx sign)
- [ ] Latency test: `ghostd <-> walletd` QUIC relay via `ghostbridge`

---

## 🧩 PHASE 5: Developer Tooling

**Target**: `ghostvm`, `ghostctl`, `ghostbridge`

- [ ] Add Ghost-WASM compiler CLI: `ghostvm compile contract.zig`
- [ ] Add deploy tooling via `ghostctl deploy contract.ghostwasm`
- [ ] Add WASM debugger: `ghostvm debug ./contracts/foo.ghostwasm`
- [ ] Add `ghostctl` QUIC trace tool
- [ ] Real-time QUIC stream inspector: `ghostbridge --watch`

---

## 🔐 Final Checklist for v1 Milestone

- [ ] 🔐 ZCrypto 0.5.0 stable in all services
- [ ] 🌐 ZQUIC 0.3.0 used as primary transport in all daemons
- [ ] 🔥 Ghost-WASM engine functional + streamable over QUIC
- [ ] 📦 CLI tooling (`ghostctl`, `ghostvm`) tested and documented
- [ ] ✅ Contracts can be signed, deployed, streamed, executed over QUIC

---

## 📜 References

- [`zcrypto` Docs](https://github.com/ghostkellz/zcrypto)
- [`zquic` Docs](https://github.com/ghostkellz/zquic)
- [`JUN-29.md`](./docs/JUN-29.md)
- [`GHOSTWASM.md`](./docs/GHOSTWASM.md)

---

MIT © 2025 GhostKellz — “Let the dead code walk.”

