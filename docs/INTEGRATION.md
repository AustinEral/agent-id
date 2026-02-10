# AIP Integration Guide

Add AIP identity and authentication to your agent.

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [Adding Identity](#adding-identity)
3. [Handshake Protocol](#handshake-protocol)
4. [Key Management](#key-management)
5. [Integration Patterns](#integration-patterns)

---

## Core Concepts

### DIDs (Decentralized Identifiers)

Every agent has a DID derived from their Ed25519 public key:

```
did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y
│   │   └─ Base58btc-encoded (multicodec prefix + public key)
│   └───── Method (key = self-certifying)
└───────── Scheme
```

The DID is **self-certifying**: decode it to get the public key directly.

### Handshake Protocol

Two agents verify each other via challenge-response:

```
Agent A                           Agent B
   │                                 │
   │◄─── Hello (B's DID) ────────────│
   │                                 │
   │──── Challenge (nonce) ─────────►│
   │                                 │
   │◄─── Proof (signed challenge) ───│
   │                                 │
   │──── ProofAccepted ─────────────►│
   │                                 │
   ✓ Mutually verified               ✓
```

---

## Adding Identity

### Dependencies

```toml
[dependencies]
agent-id-core = { git = "https://github.com/AustinEral/agent-id" }
agent-id-handshake = { git = "https://github.com/AustinEral/agent-id" }
```

### Generate Identity

```rust
use agent_id_core::RootKey;

// Generate new identity
let key = RootKey::generate();
println!("DID: {}", key.did());

// Or load from bytes
let seed: [u8; 32] = /* your seed */;
let key = RootKey::from_bytes(&seed)?;
```

### Create DID Document

```rust
use agent_id_core::{RootKey, DidDocument};

let key = RootKey::generate();

let doc = DidDocument::new(&key)
    .with_handshake_endpoint("https://myagent.example/aip")
    .sign(&key)?;

// Verify document integrity
doc.verify()?;
```

---

## Handshake Protocol

### As Verifier (receiving Hello)

```rust
use agent_id_handshake::protocol::Verifier;
use agent_id_handshake::messages::Hello;

let my_key = RootKey::generate();
let verifier = Verifier::new(my_key.did());

// Receive Hello from peer
let hello: Hello = /* received */;

// Create challenge
let challenge = verifier.handle_hello(&hello)?;

// Send challenge, receive proof
let proof: Proof = /* received */;

// Verify proof
verifier.verify_proof(&proof, &challenge)?;

// Peer is authenticated
println!("Verified: {}", hello.did);
```

### As Prover (sending Hello)

```rust
use agent_id_handshake::messages::Hello;
use agent_id_handshake::protocol::sign_proof;

let my_key = RootKey::generate();

// Send Hello
let hello = Hello::new(my_key.did().to_string());

// Receive challenge, create proof
let challenge: Challenge = /* received */;
let proof = sign_proof(&challenge, &my_key.did(), &my_key, None)?;

// Send proof
```

---

## Key Management

### Storing Keys

```rust
use agent_id_core::RootKey;

// Get raw bytes for storage
let key = RootKey::generate();
let bytes = key.to_bytes(); // [u8; 32]

// Store securely (encrypted, secure enclave, etc.)
save_to_secure_storage(&bytes);

// Later: restore
let bytes = load_from_secure_storage();
let key = RootKey::from_bytes(&bytes)?;
```

### Security Recommendations

1. **Encrypt at rest**: Never store raw key bytes unencrypted
2. **Rotate periodically**: Generate new identity if compromised
3. **Backup securely**: Key loss = identity loss
4. **Use hardware security**: HSM/TPM/Secure Enclave when available

---

## Integration Patterns

### HTTP Endpoint

Expose an endpoint for incoming handshakes:

```rust
// POST /aip/hello
async fn handle_hello(hello: Hello) -> Challenge {
    let verifier = Verifier::new(my_did());
    verifier.handle_hello(&hello).unwrap()
}

// POST /aip/proof
async fn handle_proof(proof: Proof, challenge: Challenge) -> ProofAccepted {
    let verifier = Verifier::new(my_did());
    verifier.verify_proof(&proof, &challenge).unwrap();
    // Return session info
}
```

### MCP Tool (for AI agents)

Wrap AIP as MCP tools for agent frameworks:

```
agent_id_whoami      → returns agent's DID
agent_id_handshake   → authenticate with another agent
agent_id_sign        → sign a message
agent_id_verify      → verify a signature
```

---

## Next Steps

- [PROTOCOL.md](../spec/PROTOCOL.md) — Full protocol specification
- [aip-trust](https://github.com/AustinEral/agent-id-trust) — Add trust/reputation (optional)
