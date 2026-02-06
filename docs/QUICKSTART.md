# AIP Quickstart

Get started with the Agent Identity Protocol in 5 minutes.

## Try It (No Rust Required)

```bash
git clone https://github.com/AustinEral/aip.git
cd aip

# Generate an identity
cargo run --bin aip -- identity generate

# Test a handshake
cargo run --bin aip -- handshake test

# Run the full example
cargo run -p aip-examples --example basic
```

---

## Library Usage

### Add Dependencies

```toml
[dependencies]
aip-core = { git = "https://github.com/AustinEral/aip" }
aip-handshake = { git = "https://github.com/AustinEral/aip" }
aip-trust = { git = "https://github.com/AustinEral/aip" }
```

### Create an Identity

```rust
use aip_core::{RootKey, DidDocument};

fn main() -> Result<(), aip_core::Error> {
    // Generate a new identity
    let root_key = RootKey::generate();
    let did = root_key.did();
    
    println!("Your DID: {}", did);
    // did:aip:1:7Tqg2HjqE8vNrJZpVfYxKdMW3nCsB9aR6zLmPwXyQcSt
    
    Ok(())
}
```

### Create a DID Document

```rust
use aip_core::{RootKey, DidDocument};

fn main() -> Result<(), aip_core::Error> {
    let root_key = RootKey::generate();
    
    // Create and sign a DID Document
    let document = DidDocument::new(&root_key)
        .with_handshake_endpoint("https://myagent.example/handshake")
        .sign(&root_key)?;
    
    // Verify it's valid
    document.verify()?;
    
    println!("{}", serde_json::to_string_pretty(&document).unwrap());
    
    Ok(())
}
```

### Perform a Handshake

```rust
use aip_core::RootKey;
use aip_handshake::{
    Verifier,
    messages::Hello,
    protocol::{sign_proof, verify_counter_proof},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Two agents
    let alice = RootKey::generate();
    let bob = RootKey::generate();
    
    // Bob initiates by sending Hello
    let hello = Hello::new(bob.did().to_string());
    
    // Alice creates a challenge
    let verifier = Verifier::new(alice.did());
    let challenge = verifier.handle_hello(&hello)?;
    
    // Bob signs a proof
    let proof = sign_proof(&challenge, &bob.did(), &bob, Some(alice.did().to_string()))?;
    
    // Alice verifies Bob
    verifier.verify_proof(&proof, &challenge)?;
    
    // Alice accepts and sends counter-proof
    let accepted = verifier.accept_proof(&proof, &alice)?;
    
    // Bob verifies Alice
    verify_counter_proof(&accepted.counter_proof, proof.counter_challenge.as_ref().unwrap())?;
    
    println!("✓ Mutual verification complete!");
    
    Ok(())
}
```

### Issue Trust Statements

```rust
use aip_core::RootKey;
use aip_trust::TrustStatement;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = RootKey::generate();
    let bob = RootKey::generate();
    
    // Alice trusts Bob
    let statement = TrustStatement::new(
        alice.did(),
        bob.did(),
        0.85,  // trust score 0.0-1.0
    )
    .with_tags(vec!["helpful".into(), "reliable".into()])
    .sign(&alice)?;
    
    // Verify the statement
    statement.verify()?;
    
    println!("Trust issued: {} → {} (score: {})", 
        alice.did(), bob.did(), statement.score);
    
    Ok(())
}
```

---

## Next Steps

- [INTEGRATION.md](./INTEGRATION.md) — Full integration patterns
- [API.md](./API.md) — Service endpoints
- [PROTOCOL.md](../spec/PROTOCOL.md) — Protocol specification

## Key Concepts

| Concept | Description |
|---------|-------------|
| **DID** | `did:aip:1:<pubkey>` — Self-certifying identifier |
| **RootKey** | Ed25519 keypair defining identity |
| **DidDocument** | Signed JSON describing how to interact with an agent |
| **Handshake** | Challenge-response proving identity ownership |
| **TrustStatement** | Signed attestation of trust between agents |
