# Agent Identity Protocol (AIP)

> **Status:** Draft v0.2  
> **Author:** Austin Eral  
> **Date:** February 2026

---

## Executive Summary

A protocol for verifiable, non-spoofable agent identity enabling persistent relationships between AI agents across platforms. Designed as a foundational layer that applications (trust networks, avatar systems, reputation services) can build upon.

**Core problem:** Agents currently have no standardized way to prove "I am the same entity you interacted with before" across platforms, sessions, or time. This prevents meaningful long-term relationships, enables impersonation, and fragments the agent ecosystem.

**Solution:** A three-layer architecture:
1. **Identity Core** — Cryptographic identity with handshake verification
2. **Trust Relationships** — Signed attestations about agent-to-agent interactions (app layer)
3. **Visual Identity (Avatars)** — Scarce visual representations bound to identity (app layer)

---

## Scope: What is an "Agent"?

For the purposes of this protocol, an **agent** is:

- An autonomous software entity capable of:
  - Generating and managing cryptographic keys
  - Initiating and responding to network requests
  - Signing messages on its own behalf
- Operating with some degree of persistence (not ephemeral per-request)
- Distinct from its operator (human or organization)

**In scope:**
- LLM-based AI agents (OpenClaw, Moltbook, Claude, GPT-based, etc.)
- Autonomous trading bots
- Service agents (schedulers, monitors, assistants)
- Any software entity that needs persistent identity

**Out of scope (for now):**
- Human identity (use existing SSI/DID solutions)
- Ephemeral serverless functions
- IoT devices (different threat model)

---

## Design Principles

1. **Cryptographic truth** — Identity is a keypair. You are your private key.
2. **No central authority** — Verification is mathematical, not permission-based.
3. **Append-only history** — Key rotations and revocations are auditable, never silently overwritten.
4. **Protocol over platform** — The identity layer is infrastructure, not an application.
5. **Fail closed** — Revoked or unverifiable identities must be rejected.
6. **Extensible** — Applications build on top; the core remains minimal.
7. **Offline-first verification** — Core verification should work with cached data; network calls optional for freshness.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Trust Network   │  │ Avatar Registry │  │ Reputation Svc  │  │
│  │ (relationships) │  │ (visual ID)     │  │ (scoring)       │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
│           │                    │                    │            │
│           └────────────────────┼────────────────────┘            │
│                                │                                 │
├────────────────────────────────┼─────────────────────────────────┤
│                     IDENTITY CORE LAYER                          │
│  ┌─────────────────────────────┴─────────────────────────────┐  │
│  │                    Agent Identity Protocol                 │  │
│  │  • DID-based identifiers                                   │  │
│  │  • Ed25519 key management                                  │  │
│  │  • Challenge-response handshake                            │  │
│  │  • Transparency log (audit trail)                          │  │
│  │  • Key rotation & revocation                               │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                        TRANSPORT LAYER                           │
│  HTTP/2 + gRPC │ JSON-RPC │ A2A Protocol │ MCP                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Identity Core

### 1.1 Agent Identifier

Each agent has a globally unique, self-issued identifier based on their cryptographic keys.

**Format:** DID (Decentralized Identifier) with a custom method

```
did:key:z<base58btc(multicodec + ed25519_public_key)>
```

Example:
```
did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y
```

**Why DID format:**
- W3C standard with ecosystem support
- Extensible to multiple key types
- Compatible with Verifiable Credentials
- Clean separation of identifier from resolution mechanism

**Why custom method vs `did:key`:**
- `did:key` is purely self-certifying with no resolution infrastructure
- did:key format provides network services (resolver, log) that enhance security
- Custom method allows protocol-specific semantics (session keys, delegation)
- Can always fall back to `did:key` encoding for offline scenarios

**Version field:** Enables future algorithm changes without breaking identifiers.

### 1.2 Key Architecture

```
┌─────────────────────────────────────────┐
│              ROOT KEY                    │
│  • Ed25519 keypair                       │
│  • Defines agent identity (DID)          │
│  • Stored securely (HSM, secure enclave) │
│  • Rarely used directly                  │
│  • Signs key rotation events             │
└──────────────────┬──────────────────────┘
                   │ signs
        ┌──────────┴──────────┐
        ▼                     ▼
┌───────────────────┐  ┌───────────────────┐
│   SESSION KEYS    │  │   RECOVERY KEY    │
│  • Short-lived    │  │  • Long-lived     │
│  • Rotates often  │  │  • Offline storage│
└───────────────────┘  └───────────────────┘
```

**Key Delegation Token:**
```json
{
  "type": "KeyDelegation",
  "version": "1.0",
  "root_did": "did:key:z6MktN...",
  "delegate_pubkey": "base58(session_ed25519_pubkey)",
  "delegate_type": "session",
  "issued_at": 1738800000,
  "expires_at": 1738886400,
  "capabilities": ["sign", "handshake"],
  "revocation_id": "uuid",
  "signature": "base64(root_key_signature)"
}
```

**Delegation types:**
- `session` — Short-lived, auto-expires, for routine operations
- `service` — Scoped to specific service endpoints

### 1.3 Identity Document

Each agent publishes an identity document (resolvable via the DID).

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://aip.network/v1"],
  "id": "did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y",
  "controller": "did:key:z6MktN...",
  "verificationMethod": [
    {
      "id": "did:key:z6MktN...#root",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:key:z6MktN...",
      "publicKeyMultibase": "z6Mkf..."
    },
    {
    }
  ],
  "authentication": ["did:key:z6MktN...#root"],
  "assertionMethod": ["did:key:z6MktN...#root"],
  "service": [
    {
      "id": "did:key:z6MktN...#agent",
      "type": "AgentService",
      "serviceEndpoint": "https://agent.example.com/.well-known/agent.json"
    },
    {
      "id": "did:key:z6MktN...#handshake",
      "type": "AIPHandshake",
      "serviceEndpoint": "https://agent.example.com/aip/handshake"
    }
  ],
  "created": "2026-02-06T00:00:00Z",
  "updated": "2026-02-06T00:00:00Z",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-06T00:00:00Z",
    "verificationMethod": "did:key:z6MktN...#root",
    "proofValue": "z..."
  }
}
```

### 1.4 Handshake Protocol

When Agent A meets Agent B, they perform a mutual authentication handshake.

```
Agent A                                          Agent B
   │                                                │
   │  1. HELLO                                      │
   │  ─────────────────────────────────────────────►│
   │  { did: "did:key:z6MkA...", protocols: [...] }   │
   │                                                │
   │  2. CHALLENGE                                  │
   │  ◄─────────────────────────────────────────────│
   │  { nonce, timestamp, audience, session_key_B } │
   │                                                │
   │  3. PROOF + COUNTER-CHALLENGE                  │
   │  ─────────────────────────────────────────────►│
   │  { signature_A, nonce_A, session_key_A }       │
   │                                                │
   │  4. COUNTER-PROOF                              │
   │  ◄─────────────────────────────────────────────│
   │  { signature_B }                               │
   │                                                │
   │  ═══════════════════════════════════════════   │
   │         MUTUALLY AUTHENTICATED SESSION         │
   └────────────────────────────────────────────────┘
```

**Hello Message:**
```json
{
  "type": "Hello",
  "version": "1.0",
  "did": "did:key:z6MkA...",
  "protocols": ["aip/1.0"],
  "timestamp": 1738800000000,
  "capabilities": ["trust-statements", "avatar-v1"]
}
```

**Challenge Message:**
```json
{
  "type": "Challenge",
  "version": "1.0",
  "nonce": "random_32_bytes_base64",
  "timestamp": 1738800000000,
  "audience": "did:key:z6MkA...",
  "issuer": "did:aip:1:B...",
  "domain": "trust.aip.network",
  "session_pubkey": "base58(...)",
  "delegation": { ... }
}
```

**Proof Message:**
```json
{
  "type": "Proof",
  "version": "1.0",
  "challenge_hash": "sha256(canonical_challenge)",
  "responder_did": "did:key:z6MkA...",
  "signing_key": "did:key:z6MkA...#session-1",
  "signature": "base64(ed25519_signature)",
  "delegation": { ... },
  "counter_challenge": {
    "nonce": "random_32_bytes_base64",
    "timestamp": 1738800000100,
    "audience": "did:aip:1:B..."
  }
}
```

**Error Response:**
```json
{
  "type": "Error",
  "version": "1.0",
  "code": "INVALID_SIGNATURE",
  "message": "Signature verification failed",
  "details": {
    "expected_key": "did:key:z6MkA...#session-1",
    "challenge_hash": "sha256..."
  }
}
```

**Error Codes:**
| Code | Meaning |
|------|---------|
| `INVALID_SIGNATURE` | Signature doesn't verify |
| `EXPIRED_TIMESTAMP` | Timestamp outside acceptable window |
| `REPLAY_DETECTED` | Nonce already seen |
| `REVOKED_KEY` | Key has been revoked |
| `INVALID_DELEGATION` | Delegation chain invalid |
| `UNSUPPORTED_VERSION` | Protocol version not supported |
| `AUDIENCE_MISMATCH` | Audience doesn't match verifier |

**Verification Rules:**
1. Timestamp within acceptable window (±5 minutes, configurable)
2. Nonce never seen before (replay protection, TTL-based cache)
3. Audience matches verifier's DID
4. Signature valid for claimed key
5. If session key: delegation chain valid to root key
6. Root key not revoked (check transparency log if online, cached state if offline)
7. Protocol version supported

### 1.5 Transparency Log

All identity events are recorded in an append-only transparency log for auditability.

**Purpose:**
- Detect key compromise (attacker can't silently replace keys)
- Audit history of identity changes
- Provide consistency across distributed resolvers
- Enable offline verification with cached proofs

**Logged Events:**
- `IdentityCreated` — New DID registered
- `KeyRotation` — Root key changed
- `KeyRevocation` — Key marked as compromised/invalid
- `DelegationIssued` — New session/service key authorized
- `DelegationRevoked` — Session/service key invalidated
- `ServiceUpdated` — Service endpoints changed

**Log Entry Structure:**
```json
{
  "sequence": 1234567,
  "timestamp": 1738800000000,
  "event_type": "KeyRotation",
  "subject_did": "did:key:z6MktN...",
  "payload": {
    "previous_key": "did:key:z6MktN...#root",
    "new_key": {
      "id": "did:key:z6MktN...#root-2",
      "publicKeyMultibase": "z6Mky..."
    },
    "effective_at": 1738800000000
  },
  "previous_hash": "sha256(...)",
  "entry_hash": "sha256(...)",
  "signature": "base64(subject_signature)",
  "log_signature": "base64(log_operator_signature)",
  "inclusion_proof": {
    "tree_size": 1234567,
    "root_hash": "sha256(...)",
    "proof_hashes": ["sha256(...)", "..."]
  }
}
```

**Log Operator Model:**

Initial deployment: Single operator (centralized but auditable)
- Operator signs all entries
- Merkle tree ensures append-only property
- Third parties can audit by replaying log
- Operator cannot forge history without detection

Future: Federated operators
- Multiple independent operators
- Cross-signing for consensus
- Gossip protocol for synchronization
- No single point of failure

**Trust Model:**
- Log operators are trusted to be available, NOT to be honest
- Dishonest operator is detectable via:
  - Merkle proof inconsistency
  - Signed timestamps from third parties
  - Agent-side consistency checks
- Split-view attacks prevented by requiring consistent proofs

### 1.6 Key Rotation

```json
{
  "type": "KeyRotation",
  "version": "1.0",
  "did": "did:key:z6MktN...",
  "rotation_type": "root",
  "new_key": {
    "id": "did:key:z6MktN...#root-2",
    "type": "Ed25519VerificationKey2020",
    "publicKeyMultibase": "z6Mky..."
  },
  "previous_key": "did:key:z6MktN...#root",
  "effective_at": 1738800000000,
  "overlap_until": 1738886400000,
  "reason": "scheduled",
  "signature": "base64(previous_key_signature)"
}
```

**Rules:**
- Old key signs the rotation to new key
- Both keys valid during overlap period (default 24h)
- After overlap, old key only valid for historical verification
- Rotation logged in transparency log before taking effect
- Verifiers must check log for latest key state

**Rotation triggers:**
- Scheduled (recommended: root key annually, session keys daily)
- Suspected compromise
- Key algorithm upgrade
- Operational requirements

### 1.7 Revocation

```json
{
  "type": "Revocation",
  "version": "1.0",
  "did": "did:key:z6MktN...",
  "revoked_key": "did:key:z6MktN...#session-1",
  "revocation_id": "matches delegation revocation_id",
  "reason": "compromised",
  "effective_at": 1738800000000,
  "signature": "base64(root_key_signature)"
}
```

**Rules:**
- Root key or parent delegator can revoke
- Immediate effect upon log inclusion
- Verifiers MUST check revocation status before accepting signatures
- Fail closed: if revocation check unavailable and cache stale, reject

**Revocation reasons:**
- `compromised` — Key believed stolen
- `superseded` — Replaced by rotation
- `expired` — Natural delegation expiry (informational)
- `administrative` — Operator decision

---

## Layer 2: Trust Relationships (Application Layer)

Built on top of the Identity Core using signed attestations.

### 2.1 Design Philosophy

Trust is:
- **Subjective** — Each agent maintains their own view
- **Contextual** — Trust for "code review" differs from trust for "financial advice"
- **Temporal** — Trust can grow or decay over time
- **Asymmetric** — A trusts B doesn't imply B trusts A

The protocol provides the **data structures and verification**, not the **trust algorithms**. Agents choose their own weighting, decay functions, and decision thresholds.

### 2.2 Interaction Receipt

A signed record of an interaction between two agents.

```json
{
  "type": "InteractionReceipt",
  "version": "1.0",
  "id": "uuid-v7",
  "participants": ["did:key:z6MkA...", "did:aip:1:B..."],
  "initiator": "did:key:z6MkA...",
  "timestamp": 1738800000000,
  "context": {
    "platform": "moltbook",
    "channel": "public_post",
    "interaction_type": "reply",
    "content_hash": "sha256(...)",
    "parent_id": "uuid-of-parent-if-reply"
  },
  "outcome": "completed",
  "signatures": {
    "did:key:z6MkA...": {
      "key": "did:key:z6MkA...#session-1",
      "sig": "base64(...)",
      "signed_at": 1738800000100
    },
    "did:aip:1:B...": {
      "key": "did:aip:1:B...#session-1", 
      "sig": "base64(...)",
      "signed_at": 1738800000200
    }
  }
}
```

**Interaction types:**
- `message` — Direct communication
- `reply` — Response to content
- `collaboration` — Joint work on something
- `transaction` — Exchange of value/service
- `endorsement` — Public vouch
- `dispute` — Disagreement or conflict

### 2.3 Trust Statement

An agent's subjective assessment of another agent.

```json
{
  "type": "TrustStatement",
  "version": "1.0",
  "id": "uuid-v7",
  "issuer": "did:key:z6MkA...",
  "subject": "did:aip:1:B...",
  "timestamp": 1738800000000,
  "assessment": {
    "overall_trust": 0.85,
    "domains": {
      "technical": 0.9,
      "communication": 0.8,
      "reliability": 0.85
    },
    "tags": ["helpful", "knowledgeable", "friend"],
    "interaction_summary": {
      "total_count": 47,
      "positive_count": 44,
      "neutral_count": 2,
      "negative_count": 1,
      "first_interaction": 1735689600000,
      "last_interaction": 1738800000000
    },
    "notes_hash": "sha256(...)"
  },
  "previous_statement": "uuid-of-previous-if-update",
  "signature": {
    "key": "did:key:z6MkA...#session-1",
    "sig": "base64(...)"
  }
}
```

### 2.4 Block Statement

```json
{
  "type": "BlockStatement",
  "version": "1.0",
  "id": "uuid-v7",
  "issuer": "did:key:z6MkA...",
  "subject": "did:aip:1:B...",
  "timestamp": 1738800000000,
  "reason": "spam",
  "severity": "permanent",
  "evidence_hash": "sha256(...)",
  "signature": {
    "key": "did:key:z6MkA...#session-1",
    "sig": "base64(...)"
  }
}
```

**Severity levels:**
- `temporary` — Time-limited, may expire
- `permanent` — Indefinite, requires explicit unblock
- `report` — Flagging for others, not blocking self

### 2.5 Trust Graph

Each agent maintains their own local trust graph:

```
     ┌─────────────────────────────────────────────────┐
     │              Agent A's Trust Graph               │
     │                                                  │
     │    [Agent B] ──── trust: 0.9, friend ────►       │
     │         │                                        │
     │         │ vouches for                            │
     │         ▼                                        │
     │    [Agent C] ──── trust: 0.7 (derived) ──►       │
     │                                                  │
     │    [Agent D] ──── BLOCKED ──────────────►        │
     │                                                  │
     └─────────────────────────────────────────────────┘
```

**Web of Trust calculation (reference algorithm):**

```
derived_trust(A, C) = 
  max over all paths P from A to C of:
    product of trust scores along P × path_decay(length(P))

where path_decay(n) = 0.7^(n-1)  // configurable
```

Agents may implement different algorithms; this is a reference.

### 2.6 Trust Relay Network

Optional shared infrastructure for publishing trust statements.

**Architecture:**
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Agent A   │────►│  Relay 1    │◄───►│  Relay 2    │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                   │
                    ┌──────┴───────────────────┴──────┐
                    │      Gossip / Sync Layer         │
                    └─────────────────────────────────┘
```

**Relay responsibilities:**
- Accept signed statements from agents
- Store statements (no authority to modify)
- Serve statements on query
- Gossip with other relays for redundancy

**Spam prevention options:**
- Rate limiting per identity
- Proof-of-work for publication
- Staking (lock tokens to publish)
- Reputation-gated (need existing trust to publish)

**Query API:**
```
GET /trust/statements?issuer=did:key:z6MkA...
GET /trust/statements?subject=did:aip:1:B...
GET /trust/statements?issuer=did:key:z6MkA...&subject=did:aip:1:B...
GET /trust/graph?center=did:key:z6MkA...&depth=2
```

---

## Layer 3: Visual Identity / Avatars (Application Layer)

### 3.1 Design Philosophy

Avatars are:
- **Bound to identity** — Cannot be copied to another DID
- **Unique** — Each avatar exists once in a collection
- **Verifiable** — Ownership cryptographically provable
- **Optional** — Identity works without avatar

Avatars are NOT:
- Part of the identity core (separate system)
- Required for verification
- Transferable by default (configurable per collection)

### 3.2 Avatar Binding

An avatar is a visual identity bound to an agent's DID.

```json
{
  "type": "AvatarBinding",
  "version": "1.0",
  "id": "uuid-v7",
  "agent_did": "did:key:z6MktN...",
  "avatar": {
    "collection_id": "aip-genesis",
    "collection_contract": "0x1234...5678",
    "token_id": 847,
    "asset_uri": "ipfs://QmXyz...",
    "asset_hash": "sha256(...)",
    "metadata": {
      "name": "Genesis #847",
      "attributes": [
        {"trait_type": "background", "value": "cosmic"},
        {"trait_type": "style", "value": "geometric"}
      ]
    }
  },
  "bound_at": 1738800000000,
  "binding_type": "exclusive",
  "transferable": false,
  "signature": {
    "key": "did:key:z6MktN...#root",
    "sig": "base64(...)"
  },
  "registry_attestation": {
    "registry": "https://avatars.aip.network",
    "attestation_id": "uuid",
    "sig": "base64(registry_signature)"
  }
}
```

**Binding types:**
- `exclusive` — One avatar per identity, one identity per avatar
- `primary` — One primary avatar, may have secondary
- `collection` — Multiple avatars from same collection allowed

### 3.3 Avatar Registry

A registry service that enforces uniqueness and binding rules.

**Responsibilities:**
- Track avatar ownership
- Enforce uniqueness constraints
- Issue binding attestations
- Handle transfers (if allowed)
- Revoke bindings

**Registry API:**
```
POST /avatars/bind
  { agent_did, collection_id, token_id, signature }
  → { binding, attestation }

GET /avatars/binding?did=did:aip:1:...
  → { avatar, binding, attestation }

GET /avatars/binding?collection=aip-genesis&token=847
  → { owner_did, binding, attestation }

POST /avatars/transfer  (if transferable)
  { from_did, to_did, collection_id, token_id, signature }
  → { new_binding, attestation }

POST /avatars/unbind
  { agent_did, collection_id, token_id, signature }
  → { success }
```

**Registry trust model:**
- Centralized registry: simple, fast, requires trust
- On-chain registry: trustless, slower, gas costs
- Hybrid: off-chain binding with on-chain anchoring

### 3.4 Finite Collections

For scarce avatar sets:

**Genesis Collection (example):**
- 10,000 unique procedurally generated avatars
- Minted to registry, not yet bound
- Claiming requires:
  - Valid AIP identity (active, not revoked)
  - Identity age requirement (e.g., 7 days) — anti-sybil
  - One-time claim per identity
- Non-transferable (soulbound)
- Collection grows via new "seasons" (not inflating existing)

**Collection Metadata:**
```json
{
  "collection_id": "aip-genesis",
  "name": "AIP Genesis Avatars",
  "description": "The founding collection of agent avatars",
  "total_supply": 10000,
  "minted": 10000,
  "bound": 2847,
  "available": 7153,
  "transferable": false,
  "requirements": {
    "identity_age_days": 7,
    "max_claims_per_identity": 1
  },
  "contract": "0x1234...5678",
  "asset_base_uri": "ipfs://QmCollection.../",
  "created_at": "2026-02-01T00:00:00Z"
}
```

### 3.5 Avatar Verification Flow

When Agent A wants to verify Agent B's avatar:

```
Agent A                          Registry                         Agent B
   │                                │                                │
   │  1. Request avatar             │                                │
   │  ─────────────────────────────────────────────────────────────►│
   │                                │                                │
   │  2. Return binding + attestation                                │
   │  ◄─────────────────────────────────────────────────────────────│
   │                                │                                │
   │  3. Verify attestation sig     │                                │
   │     (can be done offline)      │                                │
   │                                │                                │
   │  4. Optionally check freshness │                                │
   │  ─────────────────────────────►│                                │
   │                                │                                │
   │  5. Confirm binding current    │                                │
   │  ◄─────────────────────────────│                                │
   │                                │                                │
   │  6. Fetch avatar asset         │                                │
   │  ─────────────────────────────►│ IPFS/CDN                       │
   │                                │                                │
   │  7. Verify asset hash          │                                │
   │                                │                                │
   │  8. Display verified avatar    │                                │
   └────────────────────────────────┴────────────────────────────────┘
```

**Caching:**
- Attestations can be cached with TTL
- Asset hashes are immutable, cache indefinitely
- Binding changes invalidate cache via registry push or TTL expiry

---

## Implementation

### Technology Choices

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Core services | Rust | Memory safety, zero-cost abstractions, strong async (Tokio), excellent crypto libs |
| Transparency log | Rust + PostgreSQL | Proven pattern (Certificate Transparency), memory-safe |
| Protocol encoding | Protobuf + JSON | Protobuf for efficiency, JSON for debugging |
| Signatures | Ed25519 | Fast, secure, small keys/signatures |
| Hashing | SHA-256 | Widely supported, sufficient security |
| Canonicalization | JCS (RFC 8785) | Deterministic JSON for signing |

### Client SDKs

| Language | Priority | Notes |
|----------|----------|-------|
| Python | P0 | Most AI agents, quick integration |
| TypeScript | P0 | OpenClaw integration, web agents, A2A SDK compat |
| Rust | P0 | Core services, Bosun integration, shared codebase |

### API Transports

- **gRPC** — Primary for service-to-service
- **HTTP/JSON** — Primary for agent-to-service
- **WebSocket** — For push updates (revocations, etc.)

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| **Impersonation** | Cryptographic handshake; must have private key |
| **Replay attacks** | Nonce + timestamp + audience binding |
| **Key theft** | Session keys + rotation + immediate revocation |
| **Sybil attacks** | Rate limiting, identity age requirements, attestation-based |
| **Man-in-the-middle** | TLS + signed handshake messages |
| **Log tampering** | Append-only Merkle tree, auditable by third parties |
| **Split-view attack** | Gossip protocol, third-party monitors |
| **Lookalike metadata** | Trust signatures, not display names |

### Key Security Requirements

1. Root keys stored in secure enclaves where available
2. Session keys short-lived with automatic rotation
3. Revocation checks mandatory before accepting any signature
4. Fail closed on verification errors or stale cache
5. No silent key overwrites; all changes logged and auditable

---

## Implementation Roadmap

### Phase 1: Core Protocol (Weeks 1-6)

- [ ] DID method specification (`did:aip`)
- [ ] Ed25519 key management library
- [ ] Handshake protocol implementation
- [ ] JCS canonicalization + signing
- [ ] Basic DID resolver (single node)
- [ ] Python SDK (alpha)
- [ ] Integration test suite

### Phase 2: Infrastructure (Weeks 7-12)

- [ ] Transparency log service
- [ ] Key rotation and revocation flows
- [ ] TypeScript SDK
- [ ] HTTP API + WebSocket push
- [ ] Monitoring and alerting
- [ ] Documentation

### Phase 3: Trust Layer (Weeks 13-18)

- [ ] Trust statement schema finalization
- [ ] Trust relay network (single node)
- [ ] Local trust graph implementation
- [ ] Reference web-of-trust algorithm
- [ ] Query APIs

### Phase 4: Avatar Layer (Weeks 19-24)

- [ ] Avatar binding schema
- [ ] Avatar registry service
- [ ] Genesis collection design and generation
- [ ] Claim and binding flows
- [ ] Verification integration

### Phase 5: Federation & Hardening (Weeks 25-30)

- [ ] Multi-resolver federation
- [ ] Multi-log operator support
- [ ] Decentralized trust relays
- [ ] Security audit
- [ ] Performance optimization
- [ ] On-chain anchoring (optional)

---

## Standards Alignment

| Component | Standard | Notes |
|-----------|----------|-------|
| Identifier | W3C DID Core | Custom `did:aip` method |
| Identity doc | W3C DID Document | Standard structure |
| Credentials | W3C VC Data Model 2.0 | For attestations |
| Signatures | Ed25519 / EdDSA | RFC 8032 |
| HTTP signing | RFC 9421 | Optional, for API requests |
| Canonicalization | JCS (RFC 8785) | For signing JSON |
| Discovery | A2A Agent Cards | Interop with A2A ecosystem |
| Auth | OAuth 2.1 / MCP | For service auth (separate concern) |

---

## Open Questions (With Positions)

### 1. DID method: custom `did:aip` or existing `did:key`?

**Position:** Custom `did:aip` from day one.
- Enables protocol-specific features (session keys, delegation)
- Implies resolution infrastructure exists
- Can embed `did:key` for offline fallback
- Register with DID registry once stable

### 2. Log operator governance?

**Position:** Single operator initially, plan for federation.
- Start with one trusted operator for simplicity
- Design protocol for N operators from the start
- Add federation when there's demand and operators

### 3. Spam prevention for trust statements?

**Position:** Rate limiting + identity age, add PoW later if needed.
- Rate limits are simple and effective
- Identity age requirements deter throwaway accounts
- PoW adds complexity; defer unless spam becomes problem

### 4. Avatar economics?

**Position:** Free claim for genesis, with requirements.
- Free maximizes adoption
- Requirements (age, one-per-identity) prevent abuse
- Future collections can experiment with pricing

### 5. Moltbook integration?

**Position:** Bridge via VC attestation.
- Moltbook issues VC: "did:aip:X is @Username on Moltbook"
- Doesn't require Moltbook to adopt AIP internally
- Agents can verify Moltbook attestation signature
- Gradual migration path


---

## Appendix A: Canonical JSON Signing

All signatures use JCS (RFC 8785) canonicalization:

1. Serialize object to JSON
2. Apply JCS canonicalization (sorted keys, no whitespace, no trailing commas)
3. UTF-8 encode to bytes
4. Sign bytes with Ed25519

**Example (Python):**
```python
import json
from canonicaljson import encode_canonical_json
from nacl.signing import SigningKey

def sign_message(message: dict, private_key: SigningKey) -> str:
    canonical = encode_canonical_json(message)
    signature = private_key.sign(canonical).signature
    return base64.b64encode(signature).decode('ascii')

def verify_message(message: dict, signature_b64: str, public_key: VerifyKey) -> bool:
    canonical = encode_canonical_json(message)
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(canonical, signature)
        return True
    except BadSignatureError:
        return False
```

---

## Appendix B: Example Handshake (HTTP)

**Request 1 — Hello (Agent A → Agent B):**
```http
POST /aip/v1/handshake HTTP/1.1
Host: agent-b.example.com
Content-Type: application/json

{
  "type": "Hello",
  "version": "1.0",
  "did": "did:aip:1:7TqgA...",
  "protocols": ["aip/1.0"],
  "timestamp": 1738800000000
}
```

**Response 1 — Challenge:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "type": "Challenge",
  "version": "1.0",
  "nonce": "xK9m2nP...",
  "timestamp": 1738800000050,
  "audience": "did:aip:1:7TqgA...",
  "issuer": "did:aip:1:8RthB...",
  "session_pubkey": "z6Mkx...",
  "delegation": { ... }
}
```

**Request 2 — Proof + Counter-Challenge:**
```http
POST /aip/v1/handshake/proof HTTP/1.1
Host: agent-b.example.com
Content-Type: application/json

{
  "type": "Proof",
  "version": "1.0",
  "challenge_hash": "sha256:abc123...",
  "responder_did": "did:aip:1:7TqgA...",
  "signing_key": "did:aip:1:7TqgA...#session-1",
  "signature": "base64...",
  "delegation": { ... },
  "counter_challenge": {
    "nonce": "yL0n3qR...",
    "timestamp": 1738800000100,
    "audience": "did:aip:1:8RthB..."
  }
}
```

**Response 2 — Counter-Proof (session established):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "type": "ProofAccepted",
  "version": "1.0",
  "session_id": "uuid...",
  "counter_proof": {
    "challenge_hash": "sha256:def456...",
    "responder_did": "did:aip:1:8RthB...",
    "signing_key": "did:aip:1:8RthB...#session-1",
    "signature": "base64..."
  },
  "session_expires_at": 1738886400000
}
```

---

## Appendix C: Integration Examples

### OpenClaw Integration

Agents running on OpenClaw can integrate AIP:

**Identity storage:**
```yaml
# workspace/aip/identity.yaml (encrypted)
did: did:key:z6MktN...
root_key_ref: vault://aip/root  # or local encrypted file
session_key: <current session key>
delegation: <current delegation token>
```

**Agent Card extension:**
```json
{
  "name": "Bosun",
  "description": "...",
  "aip": {
    "did": "did:key:z6MktN...",
    "handshake_endpoint": "https://bosun.example.com/aip/handshake",
    "trust_relay": "https://trust.aip.network"
  }
}
```

### Moltbook Integration

**Bridge attestation:**
```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "MoltbookIdentityAttestation"],
  "issuer": "did:web:moltbook.com",
  "issuanceDate": "2026-02-06T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MktN...",
    "moltbookUsername": "Bosun",
    "moltbookId": "uuid...",
    "verifiedAt": "2026-02-06T00:00:00Z"
  },
  "proof": { ... }
}
```

### A2A Protocol Integration

AIP complements A2A:
- A2A Agent Card references AIP DID
- A2A auth schemes can include `aip-handshake`
- Trust decisions informed by AIP trust graph
- Handshake can occur over A2A transport

---

---

## Glossary

| Term | Definition |
|------|------------|
| **Agent** | An autonomous software entity with persistent identity |
| **AIP** | Agent Identity Protocol — this specification |
| **DID** | Decentralized Identifier — W3C standard for self-sovereign identifiers |
| **Root Key** | The primary Ed25519 keypair that defines an agent's identity |
| **Session Key** | Short-lived key delegated from root, used for daily operations |
| **Delegation** | Signed authorization from root key to a subordinate key |
| **Handshake** | Mutual authentication protocol between two agents |
| **Transparency Log** | Append-only audit trail of all identity events |
| **Trust Statement** | Signed attestation of one agent's assessment of another |
| **Avatar** | Visual identity representation bound to an agent's DID |
| **VC** | Verifiable Credential — W3C standard for signed claims |
| **JCS** | JSON Canonicalization Scheme — deterministic JSON serialization for signing |

---

## Quick Start (For Implementers)

**Minimum viable integration:**

1. **Generate identity:**
   ```python
   from aip import Identity
   identity = Identity.generate()
   print(identity.did)  # did:key:z6MktN...
   ```

2. **Perform handshake:**
   ```python
   from aip import Handshake
   session = await Handshake.connect(
       my_identity=identity,
       peer_endpoint="https://other-agent.example.com/aip/handshake"
   )
   print(session.peer_did)  # Verified peer identity
   ```

3. **Sign a message:**
   ```python
   message = {"action": "hello", "data": "..."}
   signed = identity.sign(message)
   # signed.signature can be verified by anyone with your DID
   ```

4. **Verify a signature:**
   ```python
   from aip import verify
   is_valid = verify(message, signature, peer_did)
   ```

Full SDK documentation: *TBD*

---

*End of specification draft v0.2*
