//! Delegation tokens for session and service keys.

use crate::{signing, Did, Error, Result, RootKey};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationType {
    /// Short-lived key for routine operations.
    Session,
    /// Long-lived key for root recovery.
    Recovery,
    /// Key scoped to specific services.
    Service,
}

/// Capabilities granted by a delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Can sign messages.
    Sign,
    /// Can perform handshakes.
    Handshake,
    /// Can issue sub-delegations.
    Delegate,
    /// Can rotate the root key (recovery only).
    RotateRoot,
}

/// A delegation token authorizing a key to act on behalf of an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Token type identifier.
    #[serde(rename = "type")]
    pub type_: String,
    
    /// Protocol version.
    pub version: String,
    
    /// The root DID this delegation is for.
    pub root_did: String,
    
    /// Public key being delegated to (base58).
    pub delegate_pubkey: String,
    
    /// Type of delegation.
    pub delegate_type: DelegationType,
    
    /// When this delegation was issued (unix ms).
    pub issued_at: i64,
    
    /// When this delegation expires (unix ms).
    pub expires_at: i64,
    
    /// Capabilities granted.
    pub capabilities: Vec<Capability>,
    
    /// Unique ID for revocation.
    pub revocation_id: String,
    
    /// Signature from the root key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Delegation {
    /// Create a new unsigned delegation.
    pub fn new(
        root_did: Did,
        delegate_pubkey: String,
        delegate_type: DelegationType,
        capabilities: Vec<Capability>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            type_: "KeyDelegation".to_string(),
            version: "1.0".to_string(),
            root_did: root_did.to_string(),
            delegate_pubkey,
            delegate_type,
            issued_at: Utc::now().timestamp_millis(),
            expires_at: expires_at.timestamp_millis(),
            capabilities,
            revocation_id: Uuid::now_v7().to_string(),
            signature: None,
        }
    }

    /// Sign this delegation with a root key.
    pub fn sign(mut self, root_key: &RootKey) -> Result<Self> {
        // Clear signature before hashing
        self.signature = None;
        
        let canonical = signing::canonicalize(&self)?;
        let sig = root_key.sign(&canonical);
        self.signature = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig.to_bytes(),
        ));
        
        Ok(self)
    }

    /// Verify this delegation's signature.
    pub fn verify(&self) -> Result<()> {
        let sig_b64 = self.signature.as_ref().ok_or(Error::InvalidSignature)?;
        let sig_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            sig_b64,
        )
        .map_err(|_| Error::InvalidSignature)?;
        
        let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?);
        
        // Parse the root DID to get the public key
        let root_did: Did = self.root_did.parse()?;
        let public_key = root_did.public_key()?;
        
        // Canonicalize without signature
        let mut unsigned = self.clone();
        unsigned.signature = None;
        let canonical = signing::canonicalize(&unsigned)?;
        
        public_key
            .verify(&canonical, &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Check if this delegation is currently valid (not expired, not before issued).
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> Result<()> {
        let now_ms = now.timestamp_millis();
        
        if now_ms < self.issued_at {
            return Err(Error::DelegationNotYetValid);
        }
        
        if now_ms > self.expires_at {
            return Err(Error::DelegationExpired);
        }
        
        Ok(())
    }

    /// Check if this delegation has a specific capability.
    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_delegation_roundtrip() {
        let root = RootKey::generate();
        let session_pubkey = "test_session_key_base58".to_string();
        
        let delegation = Delegation::new(
            root.did(),
            session_pubkey,
            DelegationType::Session,
            vec![Capability::Sign, Capability::Handshake],
            Utc::now() + Duration::hours(24),
        );

        let signed = delegation.sign(&root).unwrap();
        assert!(signed.signature.is_some());
        
        signed.verify().unwrap();
    }

    #[test]
    fn test_delegation_expiry() {
        let root = RootKey::generate();
        
        let delegation = Delegation::new(
            root.did(),
            "test".to_string(),
            DelegationType::Session,
            vec![Capability::Sign],
            Utc::now() - Duration::hours(1), // Already expired
        );

        let result = delegation.is_valid_at(Utc::now());
        assert!(matches!(result, Err(Error::DelegationExpired)));
    }
}
