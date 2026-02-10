# agent-id

Agent Identity Protocol - cryptographic identity and authentication for AI agents.

## Installation

```bash
cargo add agent-id
```

## Usage

```rust
use agent_id::{RootKey, Did};

// Generate an identity
let key = RootKey::generate();
println!("DID: {}", key.did());
// did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y

// Perform a handshake
use agent_id::handshake::protocol::Verifier;
let verifier = Verifier::new(key.did());
```

## Crates

This is an umbrella crate that re-exports:

- [agent-id-core](https://crates.io/crates/agent-id-core) - Identity primitives
- [agent-id-handshake](https://crates.io/crates/agent-id-handshake) - Authentication protocol

## License

Apache-2.0
