//! Handshake protocol for mutual agent authentication.
//!
//! This crate implements the challenge-response handshake defined in the AIP spec.
//!
//! # Example
//!
//! ```no_run
//! use agent_id_core::RootKey;
//! use agent_id_handshake::{messages::Hello, protocol::{Verifier, sign_proof}};
//!
//! // Agent A initiates
//! let key_a = RootKey::generate();
//! let hello = Hello::new(key_a.did().to_string());
//!
//! // Agent B responds with challenge
//! let key_b = RootKey::generate();
//! let verifier = Verifier::new(key_b.did());
//! let challenge = verifier.handle_hello(&hello).unwrap();
//!
//! // Agent A signs proof
//! let proof = sign_proof(&challenge, &key_a.did(), &key_a, Some(key_b.did().to_string())).unwrap();
//!
//! // Agent B verifies and accepts
//! verifier.verify_proof(&proof, &challenge).unwrap();
//! ```

pub mod error;
pub mod messages;
pub mod protocol;

pub use error::{HandshakeError, Result};
pub use messages::{Challenge, Hello, Proof, ProofAccepted};
pub use protocol::{sign_proof, verify_counter_proof, Verifier};
