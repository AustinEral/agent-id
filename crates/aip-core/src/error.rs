//! Error types for aip-core.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid base58 encoding: {0}")]
    Base58(String),

    #[error("Delegation expired")]
    DelegationExpired,

    #[error("Delegation not yet valid")]
    DelegationNotYetValid,

    #[error("Invalid delegation chain")]
    InvalidDelegationChain,
}
