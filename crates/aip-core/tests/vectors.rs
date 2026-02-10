//! Test vector validation for AIP interoperability.

#![allow(dead_code)]

use aip_core::{Did, RootKey};
use serde::Deserialize;
use std::str::FromStr;

// ============================================================================
// DID Vector Tests
// ============================================================================

#[derive(Deserialize)]
struct DidVectors {
    valid: Vec<ValidDidCase>,
    invalid: Vec<InvalidDidCase>,
}

#[derive(Deserialize)]
struct ValidDidCase {
    description: String,
    input: String,
    expected: ExpectedDid,
}

#[derive(Deserialize)]
struct ExpectedDid {
    key_id_prefix: String,
}

#[derive(Deserialize)]
struct InvalidDidCase {
    description: String,
    input: String,
    error_contains: String,
}

#[test]
fn test_valid_dids() {
    let vectors: DidVectors =
        serde_json::from_str(include_str!("vectors/dids.json")).expect("Failed to parse vectors");

    for case in vectors.valid {
        let did = Did::from_str(&case.input)
            .unwrap_or_else(|e| panic!("{}: failed to parse: {}", case.description, e));

        assert!(
            did.key_id().starts_with(&case.expected.key_id_prefix),
            "{}: key_id should start with {}",
            case.description,
            case.expected.key_id_prefix
        );
    }
}

#[test]
fn test_invalid_dids() {
    let vectors: DidVectors =
        serde_json::from_str(include_str!("vectors/dids.json")).expect("Failed to parse vectors");

    for case in vectors.invalid {
        let result = Did::from_str(&case.input);
        assert!(result.is_err(), "{}: should have failed", case.description);
    }
}

// ============================================================================
// Signature Vector Tests
// ============================================================================

#[derive(Deserialize)]
struct SignatureVectors {
    test_keys: TestKeys,
}

#[derive(Deserialize)]
struct TestKeys {
    agent_a: TestKey,
    agent_b: TestKey,
}

#[derive(Deserialize)]
struct TestKey {
    seed_hex: String,
}

fn load_test_key(seed_hex: &str) -> RootKey {
    let seed_bytes = hex::decode(seed_hex).expect("Invalid hex seed");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    RootKey::from_bytes(&seed).expect("Invalid seed")
}

#[test]
fn test_key_derivation() {
    let vectors: SignatureVectors = serde_json::from_str(include_str!("vectors/signatures.json"))
        .expect("Failed to parse vectors");

    let key_a = load_test_key(&vectors.test_keys.agent_a.seed_hex);
    let key_b = load_test_key(&vectors.test_keys.agent_b.seed_hex);

    // Verify keys produce valid did:key format DIDs
    assert!(key_a.did().to_string().starts_with("did:key:z6Mk"));
    assert!(key_b.did().to_string().starts_with("did:key:z6Mk"));
}

#[test]
fn test_signature_roundtrip() {
    let vectors: SignatureVectors = serde_json::from_str(include_str!("vectors/signatures.json"))
        .expect("Failed to parse vectors");

    let key_a = load_test_key(&vectors.test_keys.agent_a.seed_hex);
    let message = b"test message";
    let signature = key_a.sign(message);

    aip_core::keys::verify(&key_a.verifying_key(), message, &signature)
        .expect("Should verify own signature");
}

// ============================================================================
// Handshake Vector Tests
// ============================================================================

#[derive(Deserialize)]
struct HandshakeVectors {
    message_flow: Vec<HandshakeMessage>,
    error_cases: Vec<HandshakeError>,
}

#[derive(Deserialize)]
struct HandshakeMessage {
    step: u32,
    message_type: String,
}

#[derive(Deserialize)]
struct HandshakeError {
    name: String,
}

#[test]
fn test_handshake_vectors_parse() {
    let vectors: HandshakeVectors = serde_json::from_str(include_str!("vectors/handshake.json"))
        .expect("Failed to parse handshake vectors");

    assert_eq!(vectors.message_flow.len(), 4, "Expected 4 handshake steps");
    assert!(!vectors.error_cases.is_empty(), "Should have error cases");
}
