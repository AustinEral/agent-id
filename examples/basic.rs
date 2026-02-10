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

    // =========================================
    // Step 1: Create identities for two agents
    // =========================================
    println!("1. Creating identities...");

    let alice_key = RootKey::generate();
    let bob_key = RootKey::generate();

    println!("   Alice DID: {}", alice_key.did());
    println!("   Bob DID:   {}", bob_key.did());
    println!();

    // =========================================
    // Step 2: Create DID Documents
    // =========================================
    println!("2. Creating DID Documents...");

    let alice_doc = DidDocument::new(&alice_key)
        .with_handshake_endpoint("https://alice.example/aip/handshake")
        .sign(&alice_key)?;

    let bob_doc = DidDocument::new(&bob_key)
        .with_handshake_endpoint("https://bob.example/aip/handshake")
        .sign(&bob_key)?;

    println!("   Alice document signed: ✓");
    println!("   Bob document signed:   ✓");

    // Verify documents
    alice_doc.verify()?;
    bob_doc.verify()?;
    println!("   Documents verified:    ✓");
    println!();

    // =========================================
    // Step 3: Perform a handshake
    // =========================================
    println!("3. Performing handshake (Alice verifies Bob)...");

    // Bob sends Hello to Alice
    let bob_hello = Hello::new(bob_key.did().to_string());
    println!("   Bob sends Hello:         ✓");

    // Alice creates a challenge for Bob
    let alice_verifier = Verifier::new(alice_key.did());
    let challenge = alice_verifier.handle_hello(&bob_hello)?;
    println!("   Alice creates Challenge: ✓");

    // Bob signs the challenge (proving he owns the DID)
    let proof = sign_proof(&challenge, &bob_key.did(), &bob_key, None)?;
    println!("   Bob signs Proof:         ✓");

    // Alice verifies Bob proof
    alice_verifier.verify_proof(&proof, &challenge)?;
    println!("   Alice verifies Bob:      ✓");
    println!();

    // =========================================
    // Summary
    // =========================================
    println!("=== Summary ===");
    println!("✓ Created 2 agent identities");
    println!("✓ Created and signed DID Documents");
    println!("✓ Performed handshake verification");
    println!();
    println!("Alice and Bob can now communicate with verified identities!");
    println!();
    println!("For trust/reputation features, see: https://github.com/AustinEral/aip-trust");

    Ok(())
}
