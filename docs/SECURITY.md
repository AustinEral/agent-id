# AIP Security

Security considerations and known issues.

---

## Security Properties

| Property | Status | Implementation |
|----------|--------|----------------|
| Ed25519 signatures | ✅ | Audited `ed25519-dalek` crate |
| DID self-certification | ✅ | Public key embedded in DID |
| Replay protection | ✅ | Nonce + timestamp validation |
| Input validation | ✅ | Error returns, no panics |

---

## Known Issues

### 1. Nonce Cache Memory Growth

**Location:** `crates/agent-id-handshake/src/protocol.rs`

The nonce cache doesn't expire old entries. In long-running verifiers, memory will grow unbounded.

**Impact:** Memory growth over time. Not a concern for CLI/short-lived use.

**Mitigation:** Timestamp validation is the primary replay defense. The nonce cache is secondary.

**Status:** Documented. Will fix if deploying as long-running service.

### 2. Session Keys Not Yet Implemented

Handshake only accepts root key signatures. Session key delegation exists in `agent-id-core` but isn't used in verification yet.

**Impact:** Root key must be used for every handshake instead of short-lived session keys.

**Status:** Future enhancement.

---

## Cryptographic Details

### Algorithms

- **Signing**: Ed25519 (RFC 8032)
- **Key encoding**: Base58btc with multicodec prefix
- **Canonicalization**: RFC 8785 (JCS)

### DID Format

```
did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y
        └─ z = base58btc
           6Mk = Ed25519 multicodec (0xed01)
           ... = 32-byte public key
```

To verify a DID:
1. Strip `did:key:` prefix
2. Decode base58btc (strip `z` prefix)
3. Verify multicodec prefix is `0xed01`
4. Extract 32-byte Ed25519 public key

---

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately.

**Do not open public GitHub issues for security vulnerabilities.**

Contact the maintainers directly or use GitHub's private vulnerability reporting.

---

## Dependencies

Security-critical dependencies:

| Crate | Purpose | Notes |
|-------|---------|-------|
| `ed25519-dalek` | Signatures | Audited, widely used |
| `rand` | Key generation | Uses OS entropy |
| `sha2` | Hashing | Pure Rust, audited |
| `bs58` | Base58 encoding | Standard Bitcoin alphabet |
