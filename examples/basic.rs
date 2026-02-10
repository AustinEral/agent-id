//! Basic AIP Example
//!
//! Demonstrates core AIP functionality:
//! - Creating an identity  
//! - Creating a DID Document
//! - Performing a handshake between two agents
//!
//! Run with: cargo run --example basic

use aip_core::{DidDocument, RootKey};
use aip_handshake::messages::Hello;
use aip_handshake::protocol::{sign_proof, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== AIP Basic Example ===\n");

    println!("1. Creating identities...");
    let alice_key = RootKey::generate();
    let bob_key = RootKey::generate();
    println!("   Alice: {}", alice_key.did());
    println!("   Bob:   {}", bob_key.did());
    println!();

    println!("2. Creating DID Documents...");
    let alice_doc = DidDocument::new(&alice_key)
        .with_handshake_endpoint("https://alice.example/aip")
        .sign(&alice_key)?;
    let bob_doc = DidDocument::new(&bob_key)
        .with_handshake_endpoint("https://bob.example/aip")
        .sign(&bob_key)?;
    alice_doc.verify()?;
    bob_doc.verify()?;
    println!("   Documents created and verified ✓");
    println!();

    println!("3. Performing handshake...");
    let hello = Hello::new(bob_key.did().to_string());
    let verifier = Verifier::new(alice_key.did());
    let challenge = verifier.handle_hello(&hello)?;
    let proof = sign_proof(&challenge, &bob_key.did(), &bob_key, None)?;
    verifier.verify_proof(&proof, &challenge)?;
    println!("   Handshake complete ✓");
    println!();

    println!("=== Done ===");
    println!("Alice and Bob have verified identities!");
    println!();
    println!("For trust features: https://github.com/AustinEral/aip-trust");

    Ok(())
}
