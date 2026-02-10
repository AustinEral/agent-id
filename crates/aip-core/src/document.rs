//! DID Document structure and signing.
//!
//! A DID Document contains the public keys and service endpoints for an agent.
//! Documents are self-signed to prevent tampering.

use crate::{signing, Did, Error, Result, RootKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A verification method (public key) in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Full ID of this key (e.g., "did:key:z6Mk...#root")
    pub id: String,
    /// Key type
    #[serde(rename = "type")]
    pub type_: String,
    /// Controller DID
    pub controller: String,
    /// Public key in multibase format
    pub public_key_multibase: String,
}

/// A service endpoint in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Service ID (e.g., "did:key:z6Mk...#handshake")
    pub id: String,
    /// Service type
    #[serde(rename = "type")]
    pub type_: String,
    /// Service endpoint URL
    pub service_endpoint: String,
}

/// Proof attached to a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentProof {
    /// Proof type
    #[serde(rename = "type")]
    pub type_: String,
    /// When the proof was created
    pub created: DateTime<Utc>,
    /// Which key was used to sign
    pub verification_method: String,
    /// The signature value (base64)
    pub proof_value: String,
}

/// A DID Document describing an agent's keys and services.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID this document describes
    pub id: String,
    /// Controller of this DID (usually self)
    pub controller: String,
    /// Verification methods (public keys)
    pub verification_method: Vec<VerificationMethod>,
    /// Keys that can authenticate as this DID
    pub authentication: Vec<String>,
    /// Keys that can make assertions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<String>>,
    /// Service endpoints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
    /// When this document was created
    pub created: DateTime<Utc>,
    /// When this document was last updated
    pub updated: DateTime<Utc>,
    /// Proof of authenticity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<DocumentProof>,
}

impl DidDocument {
    /// Create a new unsigned DID Document for a root key.
    pub fn new(root_key: &RootKey) -> Self {
        let did = root_key.did();
        let did_str = did.to_string();
        let now = Utc::now();

        // Encode public key as multibase (z = base58btc)
        let pubkey_multibase = format!("z{}", did.key_id());

        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: did_str.clone(),
            controller: did_str.clone(),
            verification_method: vec![VerificationMethod {
                id: format!("{}#root", did_str),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did_str.clone(),
                public_key_multibase: pubkey_multibase,
            }],
            authentication: vec![format!("{}#root", did_str)],
            assertion_method: Some(vec![format!("{}#root", did_str)]),
            service: None,
            created: now,
            updated: now,
            proof: None,
        }
    }

    /// Add a service endpoint.
    pub fn add_service(mut self, id: &str, type_: &str, endpoint: &str) -> Self {
        let service = Service {
            id: format!("{}#{}", self.id, id),
            type_: type_.to_string(),
            service_endpoint: endpoint.to_string(),
        };

        match &mut self.service {
            Some(services) => services.push(service),
            None => self.service = Some(vec![service]),
        }

        self.updated = Utc::now();
        self
    }

    /// Add the handshake service endpoint.
    pub fn with_handshake_endpoint(self, endpoint: &str) -> Self {
        self.add_service("handshake", "AIPHandshake", endpoint)
    }

    /// Sign this document with the root key.
    pub fn sign(mut self, root_key: &RootKey) -> Result<Self> {
        // Clear any existing proof before signing
        self.proof = None;
        self.updated = Utc::now();

        // Canonicalize and sign
        let canonical = signing::canonicalize(&self)?;
        let signature = root_key.sign(&canonical);
        let sig_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.to_bytes(),
        );

        self.proof = Some(DocumentProof {
            type_: "Ed25519Signature2020".to_string(),
            created: Utc::now(),
            verification_method: format!("{}#root", self.id),
            proof_value: sig_b64,
        });

        Ok(self)
    }

    /// Verify this document's signature.
    pub fn verify(&self) -> Result<()> {
        let proof = self.proof.as_ref().ok_or(Error::InvalidSignature)?;

        // Parse the DID to get the expected public key
        let did: Did = self.id.parse()?;
        let public_key = did.public_key()?;

        // Create unsigned version for verification
        let mut unsigned = self.clone();
        unsigned.proof = None;

        let canonical = signing::canonicalize(&unsigned)?;

        // Decode and verify signature
        let sig_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &proof.proof_value,
        )
        .map_err(|_| Error::InvalidSignature)?;

        let signature = ed25519_dalek::Signature::from_bytes(
            &sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?,
        );

        crate::keys::verify(&public_key, &canonical, &signature)?;

        Ok(())
    }

    /// Get the handshake endpoint if present.
    pub fn handshake_endpoint(&self) -> Option<&str> {
        self.service.as_ref()?.iter().find_map(|s| {
            if s.type_ == "AIPHandshake" {
                Some(s.service_endpoint.as_str())
            } else {
                None
            }
        })
    }

    /// Get the DID this document describes.
    pub fn did(&self) -> Result<Did> {
        self.id.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_document_creation() {
        let key = RootKey::generate();
        let doc = DidDocument::new(&key);

        assert!(doc.id.starts_with("did:key:z6Mk"));
        assert_eq!(doc.verification_method.len(), 1);
        assert!(doc.proof.is_none());
    }

    #[test]
    fn test_document_signing() {
        let key = RootKey::generate();
        let doc = DidDocument::new(&key)
            .with_handshake_endpoint("https://example.com/handshake")
            .sign(&key)
            .unwrap();

        assert!(doc.proof.is_some());
        doc.verify().unwrap();
    }

    #[test]
    fn test_document_tamper_detection() {
        let key = RootKey::generate();
        let mut doc = DidDocument::new(&key).sign(&key).unwrap();

        // Tamper with the document
        doc.controller = "did:key:z6MkATTACKER".to_string();

        // Verification should fail
        assert!(doc.verify().is_err());
    }

    #[test]
    fn test_handshake_endpoint() {
        let key = RootKey::generate();
        let doc = DidDocument::new(&key).with_handshake_endpoint("https://example.com/hs");

        assert_eq!(doc.handshake_endpoint(), Some("https://example.com/hs"));
    }
}
