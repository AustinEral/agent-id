//! Integration tests for the Agent Identity Protocol.

use aip_core::{Did, RootKey, SessionKey};

#[test]
fn test_full_identity_creation() {
    // Generate a root identity
    let root = RootKey::generate();
    let did = root.did();
    
    // DID should be valid format
    let did_str = did.to_string();
    assert!(did_str.starts_with("did:aip:1:"));
    
    // Should be parseable
    let parsed: Did = did_str.parse().unwrap();
    assert_eq!(did, parsed);
    
    // Create a session key
    let session = SessionKey::generate(did.clone());
    assert_eq!(session.root_did(), &did);
}

#[test]
fn test_sign_and_verify_flow() {
    let root = RootKey::generate();
    
    // Sign a message
    let message = b"test message for signing";
    let signature = root.sign(message);
    
    // Verify with the public key from DID
    let did = root.did();
    let pubkey = did.public_key().unwrap();
    
    aip_core::keys::verify(&pubkey, message, &signature).unwrap();
}

#[test]
fn test_did_roundtrip_multiple() {
    // Generate several identities and ensure uniqueness
    let ids: Vec<_> = (0..10).map(|_| RootKey::generate().did()).collect();
    
    // All should be unique
    for (i, id1) in ids.iter().enumerate() {
        for (j, id2) in ids.iter().enumerate() {
            if i != j {
                assert_ne!(id1, id2, "DIDs should be unique");
            }
        }
    }
    
    // All should roundtrip
    for id in &ids {
        let parsed: Did = id.to_string().parse().unwrap();
        assert_eq!(id, &parsed);
    }
}
