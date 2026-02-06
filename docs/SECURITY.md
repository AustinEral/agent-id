# AIP Hardening

Verified issues and improvements.

---

## Verified Issues

### 1. Nonce Cache Memory Leak
**Location:** `crates/aip-handshake/src/protocol.rs:20-45`  
**Status:** CONFIRMED

```rust
pub struct NonceCache {
    seen: Mutex<HashSet<String>>,
    #[allow(dead_code)]  // <-- Compiler confirms it is unused
    max_age_ms: i64,
}
```

The `max_age_ms` field is stored but never read. Nonces accumulate forever.

**Impact:** Memory grows unbounded in long-running verifiers.

**Status:** Deferred. For CLI/short-lived use, not a concern. Timestamp validation is primary defense. Revisit if deploying as long-running service.

---

### 2. Session Key Delegation ✓ IMPLEMENTED
**Location:** `crates/aip-handshake/src/protocol.rs`  
**Status:** FIXED

The handshake protocol now supports delegated session key signatures:

- `verify_proof()` checks for a `delegation` field in the Proof
- If present, validates the delegation (signature, expiry, capabilities)
- Verifies proof signature against the delegated session key
- New `sign_proof_with_session_key()` function for session key signing

**Tests added:**
- `test_handshake_with_session_key` - full delegated handshake flow
- `test_expired_delegation_rejected` - expired delegations fail
- `test_missing_handshake_capability_rejected` - capability enforcement

**Benefits:**
- Agents can use short-lived session keys for routine operations
- Root key exposure is minimized
- Compromised session keys dont compromise identity

---

## Verified Working

### DID Document Signature Verification ✓
**Location:** `crates/aip-resolver/src/lib.rs:45-50, 70-75`

Resolver correctly calls `document.verify()` on both `register()` and `update()`. Invalid signatures are rejected with `ResolverError::InvalidDocument`.

### DID Parsing ✓
**Location:** `crates/aip-core/src/did.rs`

Robust error handling:
- Validates 4-part structure
- Validates "did:aip" prefix
- Validates version is numeric
- Validates base58 decoding
- Validates public key is exactly 32 bytes

Returns `Error::InvalidDid` on all failures, no panics.

### Transparency Log Verification ✓
**Location:** `crates/aip-log/src/lib.rs`

Log correctly verifies:
- Subject signatures before appending (line 340)
- Entry hash integrity (line 343)
- Inclusion proofs (line 254)

### Session Key Delegation ✓
**Location:** `crates/aip-handshake/src/protocol.rs`

Handshake verifier properly validates:
- Delegation signature (signed by root key)
- Delegation root_did matches proof responder_did
- Delegation time bounds (issued_at, expires_at)
- Delegation capabilities (requires Handshake)
- Proof signature (against delegated session key)

---

## Improvements to Consider

### 3. Mutex Poisoning
**Location:** `crates/aip-handshake/src/protocol.rs:34, 44`

```rust
let mut seen = self.seen.lock().unwrap();
```

If a thread panics while holding the lock, subsequent calls will panic. This is Rust default behavior and usually acceptable (fail-fast), but consider using `lock().unwrap_or_else(|e| e.into_inner())` if graceful recovery is preferred.

### 4. Test Vectors
**Status:** Not yet created

For interoperability, create canonical test cases:
- Valid/invalid DID strings
- Known-good signature verification
- Complete handshake transcripts

### 5. Fuzz Testing
**Status:** Not yet implemented

Priority targets based on complexity:
1. `Did::from_str` - string parsing
2. JSON deserialization of protocol messages
3. Base58/Base64 decoding paths

---

## What is Actually Solid

After review, the core security properties are sound:

| Component | Status | Notes |
|-----------|--------|-------|
| Ed25519 signatures | ✓ | Uses audited `ed25519-dalek` |
| DID self-certification | ✓ | Public key embedded in DID |
| Handshake replay protection | ✓ | Nonce + timestamp (except memory leak) |
| DID Document signing | ✓ | Verified on store |
| Log entry signing | ✓ | Subject + operator signatures |
| Input validation | ✓ | Error returns, not panics |
| Session key delegation | ✓ | Delegation verified in handshake |

---

## Priority

1. **Fix nonce cache expiry** - Real bug, will cause OOM
2. ~~Implement session key verification~~ ✓ Done
3. **Add test vectors** - Needed for any other implementations
4. **Add fuzz testing** - Defense in depth
