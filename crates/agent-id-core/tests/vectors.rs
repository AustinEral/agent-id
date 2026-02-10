//! Test vector validation for AIP interoperability.
//!
//! These tests verify that the implementation matches the canonical test vectors.
//! Other implementations can use the same vectors to verify compatibility.

#![allow(dead_code)] // JSON fields intentionally unused in some cases

use agent_id_core::{Did, RootKey};
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
    key_id: String,
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

        assert_eq!(
            did.key_id(),
            case.expected.key_id,
            "{}: key_id mismatch",
            case.description
        );
    }
}

#[test]
fn test_invalid_dids() {
    let vectors: DidVectors =
        serde_json::from_str(include_str!("vectors/dids.json")).expect("Failed to parse vectors");

    for case in vectors.invalid {
        let result = Did::from_str(&case.input);
        assert!(
            result.is_err(),
            "{}: should have failed but parsed successfully",
            case.description
        );

        let err = result.unwrap_err().to_string().to_lowercase();
        let expected = case.error_contains.to_lowercase();
        assert!(
            err.contains(&expected),
            "{}: error '{}' should contain '{}'",
            case.description,
            err,
            expected
        );
    }
}

// ============================================================================
// Signature Vector Tests
// ============================================================================

#[derive(Deserialize)]
struct SignatureVectors {
    test_keys: TestKeys,
    valid_signatures: Vec<ValidSignatureCase>,
    invalid_signatures: Vec<InvalidSignatureCase>,
}

#[derive(Deserialize)]
struct TestKeys {
    agent_a: TestKey,
    agent_b: TestKey,
}

#[derive(Deserialize)]
struct TestKey {
    seed_hex: String,
    did: String,
    public_key_hex: String,
}

#[derive(Deserialize)]
struct ValidSignatureCase {
    description: String,
    signer: String,
    message: String,
    signature_hex: String,
    signature_base64: String,
}

#[derive(Deserialize)]
struct InvalidSignatureCase {
    description: String,
    message: String,
    claimed_signer_did: String,
    signature_hex: String,
    should_fail: bool,
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

    // Verify Agent A
    let key_a = load_test_key(&vectors.test_keys.agent_a.seed_hex);
    assert_eq!(
        key_a.did().to_string(),
        vectors.test_keys.agent_a.did,
        "Agent A DID mismatch"
    );

    // Verify Agent B
    let key_b = load_test_key(&vectors.test_keys.agent_b.seed_hex);
    assert_eq!(
        key_b.did().to_string(),
        vectors.test_keys.agent_b.did,
        "Agent B DID mismatch"
    );
}

#[test]
fn test_valid_signatures() {
    let vectors: SignatureVectors = serde_json::from_str(include_str!("vectors/signatures.json"))
        .expect("Failed to parse vectors");

    let key_a = load_test_key(&vectors.test_keys.agent_a.seed_hex);

    for case in vectors.valid_signatures {
        assert_eq!(case.signer, "agent_a", "Only agent_a vectors supported");

        // Sign the message
        let signature = key_a.sign(case.message.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        assert_eq!(
            sig_hex, case.signature_hex,
            "{}: signature mismatch",
            case.description
        );

        // Also verify the signature
        let public_key = key_a.verifying_key();
        agent_id_core::keys::verify(&public_key, case.message.as_bytes(), &signature)
            .unwrap_or_else(|e| panic!("{}: verification failed: {}", case.description, e));
    }
}

#[test]
fn test_invalid_signatures() {
    let vectors: SignatureVectors = serde_json::from_str(include_str!("vectors/signatures.json"))
        .expect("Failed to parse vectors");

    for case in vectors.invalid_signatures {
        assert!(case.should_fail, "Test case must be expected to fail");

        let did: Did = case
            .claimed_signer_did
            .parse()
            .expect("Invalid DID in test case");
        let public_key = did.public_key().expect("Invalid public key");

        let sig_bytes = hex::decode(&case.signature_hex).unwrap_or_default();

        // Handle truncated signatures
        if sig_bytes.len() != 64 {
            // This is expected to fail - signature wrong length
            continue;
        }

        let signature = ed25519_dalek::Signature::from_bytes(
            &sig_bytes.try_into().expect("Wrong signature length"),
        );

        let result = agent_id_core::keys::verify(&public_key, case.message.as_bytes(), &signature);
        assert!(
            result.is_err(),
            "{}: should have failed verification",
            case.description
        );
    }
}

// ============================================================================
// Handshake Vector Tests (structural validation only)
// ============================================================================

#[derive(Deserialize)]
struct HandshakeVectors {
    test_keys: HandshakeTestKeys,
    message_flow: Vec<MessageStep>,
    error_cases: Vec<ErrorCase>,
}

#[derive(Deserialize)]
struct HandshakeTestKeys {
    initiator: SimpleTestKey,
    responder: SimpleTestKey,
}

#[derive(Deserialize)]
struct SimpleTestKey {
    seed_hex: String,
    did: String,
}

#[derive(Deserialize)]
struct MessageStep {
    step: u32,
    message_type: String,
    description: String,
}

#[derive(Deserialize)]
struct ErrorCase {
    name: String,
    description: String,
    expected_error: String,
}

#[test]
fn test_handshake_vectors_parse() {
    let vectors: HandshakeVectors = serde_json::from_str(include_str!("vectors/handshake.json"))
        .expect("Failed to parse handshake vectors");

    // Verify we have the expected message flow
    assert_eq!(vectors.message_flow.len(), 4, "Expected 4 handshake steps");
    assert_eq!(vectors.message_flow[0].message_type, "Hello");
    assert_eq!(vectors.message_flow[1].message_type, "Challenge");
    assert_eq!(vectors.message_flow[2].message_type, "Proof");
    assert_eq!(vectors.message_flow[3].message_type, "ProofAccepted");

    // Verify test keys match
    let initiator = load_test_key(&vectors.test_keys.initiator.seed_hex);
    assert_eq!(initiator.did().to_string(), vectors.test_keys.initiator.did);

    let responder = load_test_key(&vectors.test_keys.responder.seed_hex);
    assert_eq!(responder.did().to_string(), vectors.test_keys.responder.did);

    // Verify error cases are documented
    assert!(!vectors.error_cases.is_empty(), "Should have error cases");
    let error_names: Vec<_> = vectors
        .error_cases
        .iter()
        .map(|e| e.name.as_str())
        .collect();
    assert!(error_names.contains(&"replay_attack"));
    assert!(error_names.contains(&"timestamp_too_old"));
    assert!(error_names.contains(&"wrong_signature"));
}
