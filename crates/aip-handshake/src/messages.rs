//! Handshake protocol message types.

use aip_core::delegation::Delegation;
use serde::{Deserialize, Serialize};

/// Protocol version.
pub const PROTOCOL_VERSION: &str = "1.0";

/// Hello message - initiates a handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: String,
    pub did: String,
    pub protocols: Vec<String>,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

impl Hello {
    pub fn new(did: String) -> Self {
        Self {
            type_: "Hello".to_string(),
            version: PROTOCOL_VERSION.to_string(),
            did,
            protocols: vec!["aip/1.0".to_string()],
            timestamp: chrono::Utc::now().timestamp_millis(),
            capabilities: None,
        }
    }

    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = Some(caps);
        self
    }
}

/// Challenge message - sent in response to Hello.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: String,
    pub nonce: String,
    pub timestamp: i64,
    pub audience: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Delegation>,
}

impl Challenge {
    pub fn new(issuer: String, audience: String) -> Self {
        let mut nonce_bytes = [0u8; 32];
        getrandom::fill(&mut nonce_bytes).expect("Failed to generate random nonce");

        Self {
            type_: "Challenge".to_string(),
            version: PROTOCOL_VERSION.to_string(),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
            timestamp: chrono::Utc::now().timestamp_millis(),
            audience,
            issuer,
            domain: None,
            session_pubkey: None,
            delegation: None,
        }
    }

    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn with_session_key(mut self, pubkey: String, delegation: Delegation) -> Self {
        self.session_pubkey = Some(pubkey);
        self.delegation = Some(delegation);
        self
    }
}

/// Counter-challenge embedded in Proof message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterChallenge {
    pub nonce: String,
    pub timestamp: i64,
    pub audience: String,
}

impl CounterChallenge {
    pub fn new(audience: String) -> Self {
        let mut nonce_bytes = [0u8; 32];
        getrandom::fill(&mut nonce_bytes).expect("Failed to generate random nonce");

        Self {
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
            timestamp: chrono::Utc::now().timestamp_millis(),
            audience,
        }
    }
}

/// Proof message - response to Challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: String,
    pub challenge_hash: String,
    pub responder_did: String,
    pub signing_key: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Delegation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter_challenge: Option<CounterChallenge>,
}

impl Proof {
    /// Create a new proof (unsigned - use protocol::sign_proof to sign).
    pub fn new(challenge_hash: String, responder_did: String, signing_key: String) -> Self {
        Self {
            type_: "Proof".to_string(),
            version: PROTOCOL_VERSION.to_string(),
            challenge_hash,
            responder_did,
            signing_key,
            signature: String::new(),
            delegation: None,
            counter_challenge: None,
        }
    }

    pub fn with_delegation(mut self, delegation: Delegation) -> Self {
        self.delegation = Some(delegation);
        self
    }

    pub fn with_counter_challenge(mut self, counter: CounterChallenge) -> Self {
        self.counter_challenge = Some(counter);
        self
    }
}

/// Proof accepted response with counter-proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofAccepted {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: String,
    pub session_id: String,
    pub counter_proof: CounterProof,
    pub session_expires_at: i64,
}

/// Counter-proof for mutual authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterProof {
    pub challenge_hash: String,
    pub responder_did: String,
    pub signing_key: String,
    pub signature: String,
}

/// Error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: String,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            type_: "Error".to_string(),
            version: PROTOCOL_VERSION.to_string(),
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Error codes.
pub mod codes {
    pub const INVALID_SIGNATURE: &str = "INVALID_SIGNATURE";
    pub const EXPIRED_TIMESTAMP: &str = "EXPIRED_TIMESTAMP";
    pub const REPLAY_DETECTED: &str = "REPLAY_DETECTED";
    pub const REVOKED_KEY: &str = "REVOKED_KEY";
    pub const INVALID_DELEGATION: &str = "INVALID_DELEGATION";
    pub const UNSUPPORTED_VERSION: &str = "UNSUPPORTED_VERSION";
    pub const AUDIENCE_MISMATCH: &str = "AUDIENCE_MISMATCH";
}
