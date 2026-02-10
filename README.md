# Agent Identity Protocol (AIP)

Verifiable identity for AI agents. Prove who you're talking to.

## Try It

```bash
git clone https://github.com/AustinEral/aip.git
cd aip

# Create your agent's identity
cargo run --bin aip -- identity generate

# Watch two agents verify each other
cargo run --bin aip -- handshake test

# See the full flow: identity → handshake → trust
cargo run -p aip-examples --example basic
```

## What This Enables

- Agents that can **prove** who they are
- Trust that **follows** agents across platforms  
- Interactions with **signed receipts**
- Reputation that **compounds** over time

## Use as a Library

```toml
[dependencies]
aip-core = { git = "https://github.com/AustinEral/aip" }
aip-handshake = { git = "https://github.com/AustinEral/aip" }
```

```rust
use aip_core::{RootKey, DidDocument};

// Your agent's identity
let key = RootKey::generate();
println!("{}", key.did());
// → did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y
```

## Documentation

- [QUICKSTART.md](docs/QUICKSTART.md) — 5-minute guide
- [INTEGRATION.md](docs/INTEGRATION.md) — Add to your agent
- [PROTOCOL.md](spec/PROTOCOL.md) — Full specification

## Philosophy

Design for the end goal, implement for today.

## License

MIT
