# AIP Security & Protocol Hardening

> **Status:** Draft v1.0  
> **Last Updated:** February 2026

---

## What AIP Is

AIP is a **protocol specification** and **reference implementation** for decentralized agent identity. It is not a service.

**Core principle:** Identity verification requires no network. The DID embeds the public key; verification is pure cryptography.

```
┌─────────────────────────────────────────────────────────────────┐
│  REQUIRED FOR IDENTITY VERIFICATION                             │
│                                                                  │
│  • The DID (contains public key)                                │
│  • A signed challenge from the claimant                         │
│  • Math (Ed25519 signature verification)                        │
│                                                                  │
│  Network: NOT REQUIRED                                          │
└─────────────────────────────────────────────────────────────────┘
```

**Optional infrastructure** (anyone can run):
- **Resolver:** Caches DID Documents for endpoint discovery
- **Transparency Log:** Audit trail for key lifecycle events
- **Trust Relay:** Gossip network for trust statements

---

## Security Model

### What's Cryptographically Guaranteed

| Property | Guarantee | Depends On |
|----------|-----------|------------|
| DID uniqueness | One private key → one DID | Ed25519 properties |
| Signature validity | Only key holder can sign | Private key secrecy |
| Handshake authenticity | Proves DID ownership | Nonce freshness + signature |
| Statement integrity | Tampering is detectable | Signature verification |

These guarantees hold regardless of infrastructure. An attacker controlling every resolver and log still cannot forge signatures.

### What Requires Trust

| Component | Trust Assumption | Failure Impact |
|-----------|-----------------|----------------|
| **Your private key storage** | Not compromised | Full identity loss |
| **Resolver (if used)** | Returns correct DID Documents | Wrong endpoint discovery |
| **Log (if used)** | Accurately records events | Missed revocations |
| **Clock** | Roughly synchronized | Replay attacks possible |

### Design Principle: Fail Closed

If trust assumptions fail, agents should reject verification rather than accept.

```rust
// CORRECT: Fail closed
if !can_verify_log_entry() {
    return Err("Cannot verify - rejecting");
}

// WRONG: Fail open
if !can_verify_log_entry() {
    warn("Skipping verification");
    return Ok(()); // DANGEROUS
}
```

---

## Protocol-Specific Threats

### 1. Private Key Compromise

**Threat:** Attacker obtains agent's private key.

**Impact:** Complete identity takeover. Attacker can:
- Impersonate the agent
- Issue trust statements
- Rotate keys (locking out legitimate owner)

**Mitigations (implementation responsibility):**
- [ ] Document secure key storage practices
- [ ] Provide session key support (limit root key exposure)
- [ ] Implement key rotation guidance
- [ ] Add recovery key documentation

**Protocol features that help:**
- Session keys: Root key rarely used, limits exposure window
- Recovery keys: Can reclaim identity if root compromised (with waiting period)
- Transparency log: Key rotations are visible, can detect unauthorized changes

### 2. Stale Revocation Data

**Threat:** Agent uses cached data, misses a key revocation.

**Impact:** Accepts signatures from compromised/revoked keys.

**Mitigations:**
- [ ] Define cache TTL recommendations
- [ ] Implement freshness checks in reference code
- [ ] Document offline verification limitations

**Protocol approach:**
- Transparency log provides Merkle proofs
- Agents can verify they have consistent view
- Offline verification explicitly documented as "trust cached data"

### 3. DID Document Substitution

**Threat:** Malicious resolver returns wrong DID Document (e.g., wrong handshake endpoint).

**Impact:** Agent connects to attacker's endpoint instead of real agent.

**Why it's limited:**
- DID Document must be signed by the DID's key
- Attacker can't forge signature without private key
- Worst case: Attacker can cause connection failure, not impersonation

**Mitigations:**
- [x] DID Documents are self-signed (implemented)
- [ ] Document that clients MUST verify DID Document signatures
- [ ] Add verification to reference client code

### 4. Transparency Log Equivocation

**Threat:** Log operator shows different history to different agents.

**Impact:** Agents have inconsistent view of key state.

**Current state:** Single operator model (acknowledged in spec).

**Future mitigation (per spec):**
- Witnessed log with multiple signers
- Gossip protocol for consistency
- Third-party auditors

**For now:**
- [ ] Document the trust assumption clearly
- [ ] Implement client-side consistency checks
- [ ] Add "compare with peer" functionality

### 5. Sybil Attack

**Threat:** Attacker creates many fake identities to manipulate trust network.

**Impact:** Inflated trust scores, spam, reputation gaming.

**Why core identity is unaffected:**
- Each identity requires a unique keypair
- Verification is per-identity, not aggregate
- Creating identities is cheap but proving trust is hard

**Application-layer mitigations (for trust/relay):**
- [ ] Document Sybil resistance strategies
- [ ] Rate limiting by identity age
- [ ] Web-of-trust requiring existing trust to participate
- [ ] Optional proof-of-work for identity registration

### 6. Replay Attack on Handshake

**Threat:** Attacker captures and replays old handshake proofs.

**Status:** MITIGATED in current implementation.

**How:**
- Challenge contains nonce + timestamp
- Verifier checks timestamp freshness (default: 5 minutes)
- Nonce cache prevents reuse within window

**Verify:**
- [x] Nonce included in challenge
- [x] Timestamp validation implemented
- [x] Nonce cache implemented
- [ ] Document timestamp tolerance configuration

---

## Reference Implementation Hardening

### Code Quality

- [ ] Fuzz testing for parsers (DID, signatures, messages)
- [ ] Property-based testing for crypto operations
- [ ] Dependency audit (check for known vulnerabilities)
- [ ] No unsafe code without justification

### Cryptographic Hygiene

- [x] Use audited Ed25519 library (ed25519-dalek)
- [ ] Verify constant-time operations where needed
- [ ] Document RNG requirements
- [ ] Add signature malleability notes

### Error Handling

- [ ] No secret information in error messages
- [ ] Consistent error types across crates
- [ ] Document which errors are "expected" vs "bugs"

---

## Interoperability Security

When multiple implementations exist:

### Protocol Compliance

- [ ] Create test vectors for all message types
- [ ] Publish conformance test suite
- [ ] Document edge cases and error handling

### Version Negotiation

- [x] Version field in handshake Hello message
- [ ] Document upgrade path for protocol changes
- [ ] Define backward compatibility policy

---

## Operator Guidance

For anyone running AIP infrastructure (resolver, log, relay):

### Resolver Operators

```
MUST:
- Verify DID Document signatures before storing
- Return 404 for unknown DIDs (not fabricated documents)
- Support HTTPS

SHOULD:
- Rate limit requests
- Cache with appropriate TTL
- Log access for debugging (not for surveillance)

MUST NOT:
- Modify DID Documents
- Track agent relationships
- Require authentication to resolve
```

### Log Operators

```
MUST:
- Verify subject signatures before appending
- Maintain append-only property (Merkle tree)
- Provide inclusion proofs on request
- Sign all entries

SHOULD:
- Publish signed tree heads regularly
- Support third-party auditing
- Document retention policy

MUST NOT:
- Silently modify or delete entries
- Show different views to different clients
```

### Relay Operators

```
MUST:
- Verify statement signatures before accepting
- Reject malformed statements

SHOULD:
- Rate limit by issuer identity
- Support gossip with other relays
- Prune old statements per policy

MUST NOT:
- Forge trust statements
- Require statements (agents can operate without relay)
```

---

## What We're NOT Solving

### Out of Scope

| Issue | Why Out of Scope |
|-------|-----------------|
| Secure key storage | Implementation-specific (HSM, enclave, etc.) |
| Agent behavior | Identity ≠ trustworthiness |
| Content moderation | Application layer concern |
| Legal identity | Different problem (use existing SSI) |
| Quantum resistance | Future protocol version |

### Explicitly Not Guaranteed

- "This agent is good" — Identity only proves consistency, not trustworthiness
- "This agent is human/AI" — Protocol is agent-type agnostic
- "This endpoint is safe" — DID Document tells you where, not whether to connect

---

## Roadmap

### Now (Reference Implementation)

- [x] Core crypto (Ed25519, signatures)
- [x] Self-certifying DIDs
- [x] Handshake protocol with replay protection
- [x] Signed DID Documents
- [x] Transparency log structure
- [x] Trust statements
- [ ] Fuzz testing
- [ ] Test vectors for interop
- [ ] Operator documentation

### Next (Protocol Hardening)

- [ ] Formal protocol specification (machine-readable)
- [ ] Conformance test suite
- [ ] Security review of reference code
- [ ] Client-side log consistency checks

### Future (Federation)

Per spec, when demand exists:
- [ ] Multi-operator log (witnessed)
- [ ] Gossip protocol for relays
- [ ] Resolver federation protocol

---

## Security Checklist for Implementers

Before deploying an AIP implementation:

```
CRYPTOGRAPHY
[ ] Using audited Ed25519 library
[ ] RNG properly seeded
[ ] Signatures verified before trusting any data
[ ] DID Document signatures checked

PROTOCOL
[ ] Handshake timestamps validated
[ ] Nonces not reused
[ ] Version negotiation implemented
[ ] Errors don't leak secrets

KEY MANAGEMENT
[ ] Root key stored securely
[ ] Session keys rotated regularly
[ ] Recovery key exists and is offline
[ ] Revocation procedure documented

NETWORK
[ ] TLS for all connections
[ ] Resolver responses verified
[ ] Graceful handling of unavailable services
[ ] Fail closed, not open
```

---

*This document describes security properties of the AIP protocol and reference implementation. Individual deployments may have additional requirements.*
