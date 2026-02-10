# Agent Identity Protocol (AIP)

Cryptographic identity and mutual authentication for AI agents.

## Quick Start

```bash
git clone https://github.com/AustinEral/aip.git
cd aip

# Create an identity
cargo run --bin aip -- identity generate

# Test a handshake between two agents
cargo run --bin aip -- handshake test

# Run the example
cargo run --example basic
```

## What It Does

- **Identity**: Agents get a DID (decentralized identifier) derived from their keypair
- **Authentication**: Mutual handshake proves both parties are who they claim
- **Signing**: Sign and verify messages with your identity

## Use as a Library

```toml
[dependencies]
aip-core = { git = "https://github.com/AustinEral/aip" }
aip-handshake = { git = "https://github.com/AustinEral/aip" }
```

```rust
use aip_core::RootKey;

// Generate identity
let key = RootKey::generate();
println!("My DID: {}", key.did());
// did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y
```

## Documentation

- [QUICKSTART.md](docs/QUICKSTART.md) — Get started in 5 minutes
- [INTEGRATION.md](docs/INTEGRATION.md) — Add AIP to your agent
- [PROTOCOL.md](spec/PROTOCOL.md) — Full specification

## Related Projects

- [aip-trust](https://github.com/AustinEral/aip-trust) — Trust and reputation layer (optional)

## License

Apache-2.0
