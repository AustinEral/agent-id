# Agent Identity Protocol (AIP)

Cryptographic identity for AI agents. Verify who you're talking to.

## Why AIP?

Agents today have no way to prove "I am the same entity you interacted with before." This enables impersonation, prevents meaningful relationships, and fragments the ecosystem.

AIP solves this with cryptographic identity:
- **Self-sovereign** — Agents own their identity (a keypair)
- **Verifiable** — Challenge-response handshakes prove identity
- **Auditable** — Transparency log prevents silent key changes
- **Portable** — Works across platforms, not tied to any service

## Quick Start

### 1. Add to your project

```toml
[dependencies]
aip-core = { git = "https://github.com/AustinEral/aip" }
aip-handshake = { git = "https://github.com/AustinEral/aip" }
```

### 2. Create an identity

```rust
use aip_core::{RootKey, DidDocument};

// Generate a new identity
let root_key = RootKey::generate();
let did = root_key.did();

println!("Your DID: {}", did);
// Output: did:aip:1:7Tqg2HjqE8vNrJZpVfYxKdMW3nCsB9aR6zLmPwXyQcSt

// Create and sign a DID Document
let document = DidDocument::new(did.clone())
    .with_handshake_endpoint("https://myagent.example/handshake")
    .sign(&root_key)?;
```

### 3. Verify another agent

```rust
use aip_handshake::{Handshake, HandshakeConfig};

let config = HandshakeConfig::default();
let mut handshake = Handshake::new(config);

// As initiator
let challenge = handshake.create_challenge(&my_key, &their_did)?;
// Send challenge, receive response...
handshake.verify_response(&response)?;
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Trust Relay     │  │ Avatar Registry │  │ Your App        │  │
│  │ (relationships) │  │ (visual ID)     │  │                 │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
├───────────┴────────────────────┴────────────────────┴───────────┤
│                     IDENTITY CORE (aip-core)                     │
│  • DID-based identifiers    • Challenge-response handshake      │
│  • Ed25519 key management   • Transparency log                  │
│  • Key rotation/recovery    • Interaction receipts              │
└─────────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Description |
|-------|-------------|
| `aip-core` | Identity primitives: keys, DIDs, documents, lifecycle |
| `aip-handshake` | Challenge-response verification protocol |
| `aip-log` | Transparency log for key events |
| `aip-resolver` | DID resolution client |
| `aip-trust` | Trust statements and graph |

## Services

| Service | Port | Description |
|---------|------|-------------|
| `aip-resolver-service` | 8080 | DID Document resolution |
| `aip-log-service` | 8081 | Transparency log server |
| `aip-relay` | 8082 | Trust statement relay |

## Integration Guide

See [docs/INTEGRATION.md](docs/INTEGRATION.md) for detailed integration patterns:
- Adding identity to an existing agent
- Verifying other agents before interaction
- Building trust relationships
- Key rotation and recovery

## API Reference

See [docs/API.md](docs/API.md) for service endpoints and client usage.

## Examples

```bash
# Run the CLI
cargo run --bin aip -- --help

# Generate a new identity
cargo run --bin aip -- identity new

# Perform a handshake
cargo run --bin aip -- handshake --target did:aip:1:...
```

## Protocol Specification

See [spec/PROTOCOL.md](spec/PROTOCOL.md) for the full protocol specification.

## License

MIT
