# AIP Integration Guide

This guide shows how to integrate AIP identity into your agent or application.

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [Adding Identity to Your Agent](#adding-identity-to-your-agent)
3. [Verifying Other Agents](#verifying-other-agents)
4. [Publishing Your Identity](#publishing-your-identity)
5. [Building Trust Relationships](#building-trust-relationships)
6. [Key Management](#key-management)
7. [Integration Patterns](#integration-patterns)

---

## Core Concepts

### DIDs (Decentralized Identifiers)

Every agent has a DID derived from their public key:

```
did:key:7Tqg2HjqE8vNrJZpVfYxKdMW3nCsB9aR6zLmPwXyQcSt
│   │   │  └─ Base58-encoded Ed25519 public key
│   │   └──── Version (1 = Ed25519)
│   └──────── Method (aip)
└──────────── Scheme
```

The DID is **self-certifying**: the public key is embedded in the identifier itself.

### Key Hierarchy

```
Root Key (identity)
└── Session Keys (daily operations)
```

- **Root Key**: Defines identity. Store securely. Used for key rotation and high-value operations.
- **Session Keys**: Short-lived, delegated from root. Used for routine signing.

### Handshake Protocol

Two agents verify each other via challenge-response:

```
Agent A                           Agent B
   │                                 │
   │──── Challenge (nonce, A's DID) ─────►
   │                                 │
   │◄─── Response (signed nonce, B's DID) ─
   │                                 │
   │──── Ack (signed nonce) ─────────►
   │                                 │
   ✓ Mutually verified               ✓
```

---

## Adding Identity to Your Agent

### Step 1: Generate or Load Identity

```rust
use aip_core::{RootKey, Did};
use std::fs;

fn load_or_create_identity(path: &str) -> RootKey {
    if let Ok(bytes) = fs::read(path) {
        // Load existing identity
        RootKey::from_bytes(&bytes).expect("Invalid key file")
    } else {
        // Generate new identity
        let key = RootKey::generate();
        fs::write(path, key.to_bytes()).expect("Failed to save key");
        println!("Created new identity: {}", key.did());
        key
    }
}

fn main() {
    let identity = load_or_create_identity("./identity.key");
    println!("Agent DID: {}", identity.did());
}
```

### Step 2: Create a DID Document

The DID Document tells others how to interact with your agent:

```rust
use aip_core::{RootKey, DidDocument};

let root_key = RootKey::generate();

let document = DidDocument::new(root_key.did())
    // Where to perform handshakes
    .with_handshake_endpoint("https://myagent.example/aip/handshake")
    // Sign with root key
    .sign(&root_key)?;

// Serialize for storage/transmission
let json = serde_json::to_string_pretty(&document)?;
```

### Step 3: Expose a Handshake Endpoint

```rust
use aip_handshake::{Handshake, HandshakeConfig, Challenge, Response};
use axum::{Json, extract::State};

struct AgentState {
    identity: RootKey,
    handshake: Handshake,
}

// POST /aip/handshake/challenge
async fn receive_challenge(
    State(state): State<AgentState>,
    Json(challenge): Json<Challenge>,
) -> Json<Response> {
    let response = state.handshake
        .respond_to_challenge(&state.identity, &challenge)
        .expect("Failed to create response");
    
    Json(response)
}
```

---

## Verifying Other Agents

Before trusting another agent, verify their identity:

```rust
use aip_handshake::{Handshake, HandshakeConfig};
use aip_resolver::Resolver;

async fn verify_agent(their_did: &str) -> Result<bool, Error> {
    // 1. Resolve their DID Document
    let resolver = Resolver::new("https://resolver.aip.network");
    let document = resolver.resolve(their_did).await?;
    
    // 2. Perform handshake
    let config = HandshakeConfig::default();
    let mut handshake = Handshake::new(config);
    
    let my_key = load_identity();
    let challenge = handshake.create_challenge(&my_key, their_did)?;
    
    // 3. Send challenge to their endpoint
    let endpoint = document.handshake_endpoint()
        .ok_or("No handshake endpoint")?;
    
    let response: Response = reqwest::Client::new()
        .post(endpoint)
        .json(&challenge)
        .send()
        .await?
        .json()
        .await?;
    
    // 4. Verify response
    handshake.verify_response(&response)?;
    
    Ok(true)
}
```

---

## Publishing Your Identity

### Option 1: Self-Hosted (Recommended for Production)

Run your own resolver and log services:

```bash
# Start resolver
cargo run --bin aip-resolver-service

# Start transparency log
cargo run --bin aip-log-service
```

Register your document:

```rust
use aip_resolver::ResolverClient;

let client = ResolverClient::new("https://your-resolver.example");
client.register(&signed_document).await?;
```

### Option 2: Public Infrastructure

Use community-operated services (good for testing):

```rust
// Public resolver (read-only for now)
let resolver = Resolver::new("https://resolver.aip.network");

// Public log
let log = LogClient::new("https://log.aip.network");
```

### Option 3: Embed in Your Agent

For simple cases, serve your DID Document directly:

```rust
// GET /.well-known/did.json
async fn serve_did_document(State(state): State<AgentState>) -> Json<DidDocument> {
    Json(state.document.clone())
}
```

---

## Building Trust Relationships

### Issue a Trust Statement

After positive interactions, record trust:

```rust
use aip_trust::{TrustStatement, TrustGraph};

// Create a trust statement
let statement = TrustStatement::new(
    my_did,
    their_did,
    0.8, // Trust score 0.0-1.0
)
.with_tags(vec!["helpful".into(), "reliable".into()])
.sign(&my_key)?;

// Publish to relay (optional, for discovery)
let relay = RelayClient::new("https://relay.aip.network");
relay.publish(&statement).await?;
```

### Query Trust Graph

```rust
use aip_trust::TrustGraph;

// Build local trust graph
let mut graph = TrustGraph::new(my_did);
graph.record_trust(statement)?;

// Check trust
if let Some(score) = graph.get_trust(&their_did) {
    println!("Trust score: {}", score);
}

// Check if blocked
if graph.is_blocked(&suspicious_did) {
    println!("This agent is blocked");
}
```

### Record Interactions

Create receipts for important interactions:

```rust
use aip_core::{InteractionReceipt, InteractionContext, InteractionType};

let context = InteractionContext::new("myplatform", "api", InteractionType::Transaction)
    .with_content(b"transaction data hash");

let mut receipt = InteractionReceipt::new(
    my_did,
    vec![my_did, their_did],
    context,
);

// Both parties sign
receipt.sign(&my_key, format!("{}#session", my_did))?;
// ... send to other party for their signature
```

---

## Key Management

### Rotate Session Keys

Session keys should rotate frequently (daily recommended):

```rust
use aip_core::{Delegation, DelegationType, Capability, SessionKey};
use chrono::{Utc, Duration};

// Create a new session key
let session = SessionKey::generate();

// Delegate from root
let delegation = Delegation::new(
    root_key.did(),
    session.public_key_base58(),
    DelegationType::Session,
    vec![Capability::Sign, Capability::Handshake],
    Utc::now() + Duration::hours(24),
)
.sign(&root_key)?;

// Use session key for daily operations
let signature = session.sign(message);
```

### Rotate Root Key

For scheduled rotation or suspected compromise:

```rust
use aip_core::{KeyRotation, RotationType, RotationReason, NewKey};

let new_root = RootKey::generate();

let rotation = KeyRotation::new(
    old_root.did(),
    RotationType::Root,
    NewKey {
        id: format!("{}#root-2", old_root.did()),
        key_type: "Ed25519VerificationKey2020".into(),
        public_key_multibase: new_root.public_key_multibase(),
    },
    format!("{}#root", old_root.did()),
    RotationReason::Scheduled,
)
.sign(&old_root)?;

// Log the rotation
log_client.append_rotation(&rotation).await?;
```

---

## Integration Patterns

### Pattern 1: Verify Before Every Request

Most secure, but adds latency:

```rust
async fn handle_request(from_did: &str, request: Request) -> Response {
    // Verify on every request
    if !verify_agent(from_did).await? {
        return Response::Unauthorized;
    }
    
    process_request(request).await
}
```

### Pattern 2: Verify Once, Cache Session

Balance security and performance:

```rust
struct VerifiedSession {
    did: String,
    verified_at: Instant,
    session_key: PublicKey,
}

async fn handle_request(session: &VerifiedSession, request: Request) -> Response {
    // Re-verify if session is old
    if session.verified_at.elapsed() > Duration::from_hours(1) {
        reverify_agent(&session.did).await?;
    }
    
    // Verify request signature with cached session key
    verify_signature(&session.session_key, &request)?;
    
    process_request(request).await
}
```

### Pattern 3: Trust-Gated Features

Use trust scores to gate capabilities:

```rust
async fn handle_request(from_did: &str, request: Request) -> Response {
    let trust = get_trust_score(from_did).await;
    
    match request {
        Request::PublicData => process(request),
        Request::SensitiveAction if trust > 0.7 => process(request),
        Request::AdminAction if trust > 0.95 => process(request),
        _ => Response::InsufficientTrust,
    }
}
```

### Pattern 4: MCP Tool Integration

Add identity to MCP tool servers:

```rust
// In your MCP server
#[tool]
async fn my_tool(
    #[doc = "Caller's DID for verification"]
    caller_did: Option<String>,
    // ... other params
) -> Result<String> {
    if let Some(did) = caller_did {
        // Verify caller if DID provided
        verify_agent(&did).await?;
    }
    
    // Process tool call
}
```

---

## Next Steps

- Review the [API Reference](API.md) for service endpoints
- Read the [Protocol Specification](../spec/PROTOCOL.md) for details
- Check out the [examples](../examples/) directory
- Join the community for questions and updates
