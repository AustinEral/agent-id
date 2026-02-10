# AIP Quickstart

Get started with the Agent Identity Protocol in 5 minutes.

## Try the CLI

```bash
git clone https://github.com/AustinEral/agent-id.git
cd agent-id

# Generate an identity
cargo run --bin agent-id -- identity generate
# → did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y

# Show your identity
cargo run --bin agent-id -- identity show

# Test a handshake
cargo run --bin agent-id -- handshake test

# Run the example
cargo run --example basic
```

## Use as a Library

### Add Dependencies

```toml
[dependencies]
agent-id-core = { git = "https://github.com/AustinEral/agent-id" }
agent-id-handshake = { git = "https://github.com/AustinEral/agent-id" }
```

### Create an Identity

```rust
use agent_id_core::RootKey;

fn main() {
    let key = RootKey::generate();
    println!("DID: {}", key.did());
}
```

### Perform a Handshake

```rust
use agent_id_core::RootKey;
use agent_id_handshake::messages::Hello;
use agent_id_handshake::protocol::{sign_proof, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Two agents
    let alice = RootKey::generate();
    let bob = RootKey::generate();

    // Bob sends Hello
    let hello = Hello::new(bob.did().to_string());

    // Alice creates challenge
    let verifier = Verifier::new(alice.did());
    let challenge = verifier.handle_hello(&hello)?;

    // Bob proves identity
    let proof = sign_proof(&challenge, &bob.did(), &bob, None)?;

    // Alice verifies
    verifier.verify_proof(&proof, &challenge)?;

    println!("Bob verified: {}", bob.did());
    Ok(())
}
```

## Concepts

| Concept | Description |
|---------|-------------|
| **DID** | `did:key:z6Mk...` — Self-certifying identifier from public key |
| **RootKey** | Your agent's identity keypair (Ed25519) |
| **Handshake** | Challenge-response to prove identity |

## Next Steps

- [INTEGRATION.md](INTEGRATION.md) — Full integration guide
- [PROTOCOL.md](../spec/PROTOCOL.md) — Protocol specification
- [aip-trust](https://github.com/AustinEral/agent-id-trust) — Optional trust layer
