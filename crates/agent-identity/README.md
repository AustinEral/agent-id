# agent-identity

Agent Identity Protocol - cryptographic identity and authentication for AI agents.

## Installation

```bash
cargo add agent-identity
```

## Usage

```rust
use agent_identity::{RootKey, Did};

// Generate an identity
let key = RootKey::generate();
println!("DID: {}", key.did());
// did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y

// Perform a handshake
use agent_identity::handshake::protocol::Verifier;
let verifier = Verifier::new(key.did());
```

## Crates

This is an umbrella crate that re-exports:

- [aip-core](https://crates.io/crates/aip-core) - Identity primitives
- [aip-handshake](https://crates.io/crates/aip-handshake) - Authentication protocol

## License

Apache-2.0
