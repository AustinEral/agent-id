# AIP Test Vectors

Test vectors for interoperability testing of AIP implementations.

## Purpose

These vectors provide known-good inputs and outputs that any AIP implementation
can use to verify correctness. They are essential for:

1. Verifying new implementations
2. Regression testing
3. Cross-platform compatibility

## Test Keys

The test vectors use well-known seeds (NOT secret - public test data):

| Agent | Seed (hex) |
|-------|------------|
| A | `0100000000000000000000000000000000000000000000000000000000000000` |
| B | `0200000000000000000000000000000000000000000000000000000000000000` |

These produce deterministic Ed25519 keypairs via `ed25519-dalek::SigningKey::from_bytes()`.

## Files

- `dids.json` - DID parsing test cases (valid and invalid)
- `signatures.json` - Known-good signature verification
- `handshake.json` - Complete handshake transcript

## Usage

```rust
// Load vectors
let vectors: SignatureVectors = serde_json::from_str(include_str!("vectors/signatures.json"))?;

// Verify against your implementation
for case in vectors.valid {
    let signature = your_sign(&case.message, &case.seed);
    assert_eq!(signature, case.expected_signature);
}
```

## Generating

Run `cargo run --example gen_vectors -p agent-id-examples` to regenerate values.
