//! Error types for handshake protocol.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Invalid message type: expected {expected}, got {got}")]
    InvalidMessageType { expected: String, got: String },

    #[error("Timestamp out of acceptable range")]
    TimestampOutOfRange,

    #[error("Nonce already seen (replay attack)")]
    NonceReplay,

    #[error("Audience mismatch: expected {expected}, got {got}")]
    AudienceMismatch { expected: String, got: String },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid delegation")]
    InvalidDelegation,

    #[error("Core error: {0}")]
    Core(#[from] agent_id_core::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Protocol version not supported: {0}")]
    UnsupportedVersion(String),

    #[error("Missing required field: {0}")]
    MissingField(String),
}

pub type Result<T> = std::result::Result<T, HandshakeError>;
