# aip

Agent Identity Protocol - cryptographic identity and authentication for AI agents.

## Installation

```bash
cargo add aip
```

## Usage

```rust
use aip::{RootKey, Did};

// Generate an identity
let key = RootKey::generate();
println!("DID: {}", key.did());
// did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y

// Perform a handshake
use aip::handshake::protocol::Verifier;
let verifier = Verifier::new(key.did());
```

## Crates

This is an umbrella crate that re-exports:

- [aip-core](https://crates.io/crates/aip-core) - Identity primitives
- [aip-handshake](https://crates.io/crates/aip-handshake) - Authentication protocol

## License

Apache-2.0
