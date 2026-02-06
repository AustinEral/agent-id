//! # aip-core
//!
//! Core identity primitives for the Agent Identity Protocol.
//!
//! This crate provides:
//! - Ed25519 key generation and management
//! - DID creation and parsing
//! - JCS canonicalization and signing
//! - Delegation tokens

pub mod delegation;
pub mod did;
pub mod error;
pub mod keys;
pub mod signing;

pub use did::Did;
pub use error::Error;
pub use keys::{RootKey, SessionKey};

/// Result type for aip-core operations.
pub type Result<T> = std::result::Result<T, Error>;
