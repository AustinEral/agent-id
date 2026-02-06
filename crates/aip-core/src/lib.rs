//! # aip-core
//!
//! Core identity primitives for the Agent Identity Protocol.
//!
//! This crate provides:
//! - Ed25519 key generation and management
//! - DID creation and parsing
//! - JCS canonicalization and signing
//! - Delegation tokens

pub mod did;
pub mod keys;
pub mod signing;
pub mod delegation;
pub mod error;

pub use did::Did;
pub use keys::{RootKey, SessionKey};
pub use error::Error;

/// Result type for aip-core operations.
pub type Result<T> = std::result::Result<T, Error>;
