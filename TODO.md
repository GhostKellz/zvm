1. Direct Dependencies & Zig Package Integration

Integrate zcrypto main branch for all cryptographic ops (remove all wrappers)

Integrate zsig for contract signature verification, multi-sig, batch, threshold signatures

Integrate zquic for all transport/networking, streaming, and future QUIC/HTTP3 contract calls

    Integrate zsync for async runtime, IO, concurrency, contract streaming

2. Core Ecosystem Integration

Integrate zwallet for on-chain account signing and programmable contract wallets

Integrate zns/cns for contract name/domain resolution (DID, .ghost, etc.)

    (Optional/Recommended) Integrate zqlite for pluggable persistent contract storage:

        Modularize state: stateless (in-mem) or zqlite (persistent DB)

        Test contract state survival and migration

3. Identity & Enterprise Integration

Integrate shroud (QID/DID, SSO, ZKP, Sigil identity) with optional build flag

Use Sigil (from shroud) for advanced credential validation and device binding

    Add Guardian (from shroud) for enterprise-grade multi-sig/auth enforcement (optional)

4. Modular Build & Feature Flags

Modularize all external/enterprise features (shroud, zqlite, ghostbridge) via feature flags/build.zig.zon

    Document minimal vs. enterprise build profiles (README & docs)

5. Smart Contract Runtime Upgrades

Direct crypto via zcrypto/zsig—remove shroud GhostCipher legacy

Add post-quantum signatures and KEM (ML-KEM, ML-DSA) for contracts

Add contract host functions for signature verification, identity, ZKP (only if shroud present)

Add contract state host functions for persistent storage (via zqlite backend)

    Add multi-chain bridge contracts via ghostbridge (optional for validators/bridges)

6. Example & Test Coverage

Example: hybrid smart contract (stateless + zqlite persistent state)

Example: contract with DID/identity validation (shroud present)

Example: multi-sig contract with threshold signature verification

    Example: contract event streaming with zquic/zsync

7. Developer Experience

Document all major dependencies and feature flags in README

Provide minimal/advanced usage guides and CLI instructions

Add integration test coverage for all major features

    Provide zig fetch URLs for all packages in READ_FIRST.md

Priorities

    Step 1: Get all core dependencies (zcrypto, zsig, zquic, zsync) cleanly integrated and modularized

    Step 2: Add shroud/identity/enterprise features as optional

    Step 3: Modularize storage (zqlite backend) for persistent contracts

    Step 4: Update CLI/demo/test suite for new capabilities

Result:
ZVM will become the default programmable logic layer for GhostChain, supporting both “lean” stateless contract execution and “enterprise” persistent, identity-enforced, and cross-chain logic—without hard dependencies except for the core Zig libraries.
