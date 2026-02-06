//! # aip-core
//!
//! Core identity primitives for the Agent Identity Protocol.
//!
//! This crate provides:
//! - Ed25519 key generation and management
//! - DID creation and parsing
//! - DID Document structure and signing
//! - JCS canonicalization and signing
//! - Delegation tokens
//! - Key lifecycle management (rotation, revocation, recovery)
//! - Interaction receipts

pub mod delegation;
pub mod did;
pub mod document;
pub mod error;
pub mod keys;
pub mod lifecycle;
pub mod receipt;
pub mod signing;

pub use did::Did;
pub use document::DidDocument;
pub use error::Error;
pub use keys::{RootKey, SessionKey};
pub use lifecycle::{KeyRotation, Revocation, RootRecovery, RecoveryCancellation};
pub use receipt::{InteractionReceipt, InteractionContext, InteractionType, InteractionOutcome};

/// Result type for aip-core operations.
pub type Result<T> = std::result::Result<T, Error>;
