//! # Agent Identity Protocol (AIP)
//!
//! Cryptographic identity and mutual authentication for AI agents.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use aip::{RootKey, Did};
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

pub use aip_core as core;
pub use aip_handshake as handshake;

// Re-export common types at root
pub use aip_core::{Did, DidDocument, Error, Result, RootKey};
