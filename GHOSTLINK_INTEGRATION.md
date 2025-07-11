# GhostLink v0.3.0 Integration Guide

This document provides integration instructions for GhostChain ecosystem projects that need to use GhostLink as a Rust gRPC client library.

## Overview

**GhostLink v0.3.0** is a modern Rust gRPC client designed specifically for the GhostChain ecosystem. It provides:

- **Unified Crypto Stack**: Only `gcrypt` for all cryptographic operations
- **Multi-Transport Support**: HTTP/2 gRPC, QUIC, HTTP/3
- **Security-First Design**: TLS-only QUIC, secure by default
- **Clean API**: Trait-based crypto interfaces and transport abstraction
- **Rust 2024 Edition**: Modern Rust features and best practices

## Integration for GhostChain Projects

### 1. **GhostChain Core (Rust)**
The main blockchain implementation should integrate GhostLink for client operations.

**Repository**: `github.com/ghostkellz/ghostchain`

#### Cargo.toml
```toml
[dependencies]
ghostlink = { git = "https://github.com/ghostkellz/ghostlink", version = "0.3.0" }

# Optional features
ghostlink = { git = "https://github.com/ghostkellz/ghostlink", version = "0.3.0", features = ["zvm"] }
```

#### Example Usage
```rust
use ghostlink::{GhostClient, GhostClientConfig, TransportProtocol};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure client for GhostChain node
    let config = GhostClientConfig::builder()
        .endpoint("https://node.ghostchain.io:9443")
        .with_tls()
        .transport(TransportProtocol::Http2Grpc)
        .build();

    let client = GhostClient::new(config).await?;
    
    // Use GhostChain services
    let block = client.ghostchain().get_latest_block().await?;
    println!("Latest block: {:?}", block);
    
    Ok(())
}
```

### 2. **ZVM (Zero Virtual Machine)**
ZVM should use GhostLink for blockchain interactions and smart contract deployment.

**Repository**: `github.com/ghostkellz/zvm`

#### Integration Points
- Smart contract deployment via GhostChain gRPC
- State queries and transaction submission
- Event listening and block monitoring

#### Cargo.toml
```toml
[dependencies]
ghostlink = { git = "https://github.com/ghostkellz/ghostlink", version = "0.3.0", features = ["zvm", "quic"] }
```

#### Example Usage
```rust
use ghostlink::{GhostClient, TransportProtocol};
use ghostlink::zvm::{ZVMExecutor, ContractUtils};

// Deploy smart contract
let client = GhostClient::new(config).await?;
let zvm = ZVMExecutor::new(client);

let contract_bytecode = include_bytes!("contract.wasm");
let contract_address = zvm.deploy_contract(contract_bytecode).await?;
```

### 3. **GhostBridge (Cross-Chain Bridge)**
Bridge infrastructure for connecting GhostChain to other blockchains.

**Repository**: `github.com/ghostkellz/ghostbridge`

#### Integration Points
- Cross-chain transaction verification
- Multi-signature operations
- Bridge state management

#### Cargo.toml
```toml
[dependencies]
ghostlink = { git = "https://github.com/ghostkellz/ghostlink", version = "0.3.0", features = ["quic"] }
```

### 4. **GhostWallet (Rust CLI/Desktop)**
Native Rust wallet implementation for GhostChain.

**Repository**: `github.com/ghostkellz/ghostwallet`

#### Integration Points
- Account management and key derivation
- Transaction creation and broadcasting
- Balance queries and transaction history

#### Cargo.toml
```toml
[dependencies]
ghostlink = { git = "https://github.com/ghostkellz/ghostlink", version = "0.3.0" }
gcrypt = { git = "https://github.com/ghostkellz/gcrypt", version = "0.3.0" }
```

### 5. **GhostID (Identity Management)**
Decentralized identity system built on GhostChain.

**Repository**: `github.com/ghostkellz/ghostid`

#### Integration Points
- Identity verification and attestation
- DID document management
- Credential issuance and verification

### 6. **ZNS (Zero Name Service)**
Decentralized naming system for the GhostChain ecosystem.

**Repository**: `github.com/ghostkellz/zns`

#### Integration Points
- Domain registration and resolution
- DNS-over-QUIC support
- Decentralized web gateway

## Available Features

### Default Features
```toml
ghostlink = { git = "https://github.com/ghostkellz/ghostlink", version = "0.3.0" }
# Includes: gcrypt, quic
```

### Optional Features
```toml
# Enable ZVM integration
features = ["zvm"]

# Enable HTTP/3 transport
features = ["http3"]

# All features
features = ["gcrypt", "quic", "http3", "zvm"]
```

## Crypto Operations

GhostLink provides unified crypto interfaces through the `gcrypt` crate:

```rust
use ghostlink::crypto::{Ed25519Operations, X25519Operations, AeadOperations};

// Digital signatures
let keypair = Ed25519Keypair::generate();
let signature = keypair.sign(b"message");
let verified = keypair.verify(b"message", &signature);

// Key exchange
let alice = X25519Keypair::generate();
let bob = X25519Keypair::generate();
let shared_secret = alice.diffie_hellman(&bob.public_key_bytes());

// Encryption
let cipher = ChaCha20Poly1305::new(&shared_secret);
let encrypted = cipher.encrypt(&nonce, b"plaintext")?;
```

## Transport Configuration

### HTTP/2 gRPC (Default)
```rust
let config = GhostClientConfig::builder()
    .endpoint("https://node.ghostchain.io:9443")
    .transport(TransportProtocol::Http2Grpc)
    .with_tls()
    .build();
```

### QUIC (Recommended for Performance)
```rust
let config = GhostClientConfig::builder()
    .endpoint("quic://node.ghostchain.io:9443")
    .transport(TransportProtocol::Quic)
    .with_tls() // Required - insecure QUIC disabled
    .build();
```

### HTTP/3 (Future-Ready)
```rust
let config = GhostClientConfig::builder()
    .endpoint("https://node.ghostchain.io:9443")
    .transport(TransportProtocol::Http3)
    .with_tls()
    .build();
```

## Environment Setup

### Rust Version
```bash
# Requires Rust 2024 edition
rustup update stable
rustc --version  # Should be 1.82+ for 2024 edition
```

### Dependencies
```bash
# Ensure gcrypt system library is available (for production)
# Development uses pure Rust fallback
sudo apt-get install libgcrypt20-dev  # Ubuntu/Debian
brew install libgcrypt               # macOS
```

## Testing Integration

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ghostlink::testing::MockGhostClient;

    #[tokio::test]
    async fn test_ghostchain_integration() {
        let mock_client = MockGhostClient::new();
        // Test your integration
    }
}
```

## Migration from Previous Versions

### From v0.2.x to v0.3.0
- **Crypto Dependencies**: Remove all legacy crypto crates, use only `gcrypt`
- **Transport**: Update transport configuration to new unified API
- **Features**: Update feature flags (`default = ["gcrypt", "quic"]`)
- **Imports**: Update import paths for new module structure

### Breaking Changes
- Removed legacy crypto implementations
- Changed transport manager API
- Updated feature flag names
- Rust 2024 edition requirement

## Production Considerations

### Security
- **TLS Required**: All production deployments must use TLS
- **Key Management**: Use hardware security modules for production keys
- **Network Security**: Deploy behind secure load balancers

### Performance
- **QUIC Recommended**: Use QUIC transport for best performance
- **Connection Pooling**: Configure appropriate connection limits
- **Monitoring**: Implement metrics and health checks

### Scalability
- **Load Balancing**: Distribute requests across multiple nodes
- **Caching**: Implement appropriate caching strategies
- **Rate Limiting**: Configure rate limits for API endpoints

## Support and Documentation

- **Repository**: https://github.com/ghostkellz/ghostlink
- **Issues**: https://github.com/ghostkellz/ghostlink/issues
- **API Documentation**: Generated via `cargo doc --open`
- **Examples**: See `examples/` directory in repository

## Version Compatibility Matrix

| GhostLink | GhostChain | ZVM  | GhostBridge | Rust Edition |
|-----------|------------|------|-------------|--------------|
| v0.3.0    | v1.0.0+    | v0.5.0+ | v0.3.0+     | 2024         |
| v0.2.x    | v0.9.x     | v0.4.x  | v0.2.x      | 2021         |
| v0.1.x    | v0.8.x     | v0.3.x  | v0.1.x      | 2021         |

---

## Quick Start Checklist

- [ ] Add GhostLink dependency to `Cargo.toml`
- [ ] Configure transport protocol (HTTP/2, QUIC, HTTP/3)
- [ ] Set up TLS certificates for production
- [ ] Implement error handling for network operations
- [ ] Add integration tests
- [ ] Configure monitoring and logging
- [ ] Review security considerations
- [ ] Test with GhostChain testnet before mainnet

For detailed examples and advanced usage, see the repository documentation and examples.
