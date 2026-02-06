# AIP Hardening TODO

Concrete issues to fix, prioritized.

---

## P0: Must Fix (Security Vulnerabilities)

### 1. Nonce Cache Memory Leak
**File:** `crates/aip-handshake/src/protocol.rs`

**Issue:** `NonceCache` stores nonces forever. The `max_age_ms` field exists but is never used.

**Impact:** Memory grows unbounded. Long-running verifiers will OOM.

**Fix:**
```rust
// Current: nonces never expire
pub fn check_and_insert(&self, nonce: &str) -> bool {
    // just inserts, never cleans up
}

// Needed: expire old nonces
pub fn check_and_insert(&self, nonce: &str, timestamp: i64) -> bool {
    self.cleanup_expired();
    // then check and insert
}
```

**Test:** Run verifier for extended period, monitor memory.

---

### 2. Session Key Verification Not Implemented
**File:** `crates/aip-handshake/src/protocol.rs:119`

**Issue:** Comment says `TODO: Support delegated session keys`. Currently only root key signatures accepted.

**Impact:** Agents must use root key for every handshake, increasing exposure risk.

**Fix:**
- Accept proof signed by session key
- Verify delegation chain back to root
- Check delegation not expired/revoked

---

### 3. DID Document Signature Verification in Resolver
**File:** `crates/aip-resolver/src/lib.rs`

**Issue:** Need to verify resolver actually checks DID Document signatures on registration and retrieval.

**Check:**
```bash
grep -n "verify" crates/aip-resolver/src/lib.rs
```

**Must ensure:**
- Documents verified before storing
- Invalid signatures rejected
- Clients reminded to verify on retrieval

---

## P1: Should Fix (Robustness)

### 4. Input Validation Audit

**Check all parse/deserialize points:**
- DID parsing (`Did::from_str`)
- Signature parsing
- JSON message parsing
- Base58/Base64 decoding

**For each, verify:**
- Malformed input returns error (not panic)
- No buffer overflows
- Reasonable size limits

---

### 5. Error Message Information Leaks

**Audit all error types:**
```bash
grep -rn "Error" crates/*/src/error.rs
```

**Ensure:**
- No private keys in errors
- No internal paths exposed
- Timing-safe comparisons where needed

---

### 6. Timestamp Tolerance Configuration

**File:** `crates/aip-handshake/src/protocol.rs`

**Current:** `DEFAULT_TIMESTAMP_TOLERANCE_MS = 300_000` (5 minutes)

**Issue:** Hardcoded, not configurable per deployment.

**Fix:** Allow operators to configure based on their clock sync guarantees.

---

## P2: Should Add (Completeness)

### 7. Test Vectors

**Need:** Canonical test cases for interoperability.

```
tests/vectors/
├── did_parsing.json       # Valid and invalid DIDs
├── signature_verify.json  # Known-good signatures
├── handshake_flow.json    # Complete handshake transcripts
└── delegation_chain.json  # Valid delegation examples
```

---

### 8. Fuzz Testing

**Targets:**
- `Did::from_str` 
- `serde_json::from_str` for all message types
- Signature verification
- Base58/Base64 decoding

**Tool:** `cargo-fuzz`

---

### 9. Revocation Checking

**Current:** Revocation types exist but no verification flow.

**Needed:**
- Client checks log for revocations before accepting
- Caching strategy for offline operation
- Clear documentation of freshness guarantees

---

## P3: Consider (Future)

### 10. Constant-Time Comparisons

**Where:** Signature verification, nonce comparison

**Why:** Prevent timing side-channels

**Check:** Verify `ed25519-dalek` uses constant-time internally

---

### 11. Rate Limiting Guidance

**Not our code, but document:**
- Recommended limits for resolver operators
- Handshake rate limiting
- Trust statement submission limits

---

## Verification Checklist

After fixes, verify:

```
[ ] Nonce cache has bounded memory (run 24h test)
[ ] Session key handshakes work
[ ] Invalid DID Documents rejected by resolver
[ ] Fuzz tests pass (1M iterations minimum)
[ ] All error messages reviewed
[ ] Test vectors pass against implementation
```

---

## Files to Audit

Priority order:

1. `crates/aip-handshake/src/protocol.rs` - Core verification
2. `crates/aip-core/src/keys.rs` - Key operations
3. `crates/aip-core/src/delegation.rs` - Delegation verification
4. `crates/aip-resolver/src/lib.rs` - Document handling
5. `crates/aip-core/src/lifecycle.rs` - Rotation/revocation
