//! # Agent Identity Protocol (AIP)
//!
//! Cryptographic identity and mutual authentication for AI agents.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use agent_id::{RootKey, Did};
//!
//! // Generate an identity
//! let key = RootKey::generate();
//! println!("DID: {}", key.did());
//! ```
//!
//! ## Modules
//!
//! - [`core`] - Identity primitives (keys, DIDs, documents)
//! - [`handshake`] - Mutual authentication protocol
//!
//! ## Re-exports
//!
//! Common types are re-exported at the crate root for convenience.

pub use agent_id_core as core;
pub use agent_id_handshake as handshake;

// Re-export common types at root
pub use agent_id_core::{Did, DidDocument, Error, Result, RootKey};
