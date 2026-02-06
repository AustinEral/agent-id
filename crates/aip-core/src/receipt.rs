//! Interaction receipts for recording agent-to-agent interactions.

use crate::{signing, Did, Error, Result, RootKey};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Type of interaction between agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionType {
    /// Direct communication.
    Message,
    /// Response to content.
    Reply,
    /// Joint work on something.
    Collaboration,
    /// Exchange of value/service.
    Transaction,
    /// Public vouch.
    Endorsement,
    /// Disagreement or conflict.
    Dispute,
}

/// Outcome of an interaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionOutcome {
    /// Interaction completed successfully.
    Completed,
    /// Interaction is still in progress.
    InProgress,
    /// Interaction was cancelled.
    Cancelled,
    /// Interaction failed.
    Failed,
}

/// Context about where/how the interaction occurred.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InteractionContext {
    /// Platform where interaction occurred (e.g., "moltbook", "discord").
    pub platform: String,

    /// Channel within platform (e.g., "public_post", "dm").
    pub channel: String,

    /// Type of interaction.
    pub interaction_type: InteractionType,

    /// Hash of content (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,

    /// Parent interaction ID (for replies).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// Additional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl InteractionContext {
    /// Create a new interaction context.
    pub fn new(
        platform: impl Into<String>,
        channel: impl Into<String>,
        interaction_type: InteractionType,
    ) -> Self {
        Self {
            platform: platform.into(),
            channel: channel.into(),
            interaction_type,
            content_hash: None,
            parent_id: None,
            metadata: None,
        }
    }

    /// Add content hash.
    pub fn with_content(mut self, content: &[u8]) -> Self {
        let hash = Sha256::digest(content);
        self.content_hash = Some(format!("sha256:{}", hex::encode(hash)));
        self
    }

    /// Add parent ID (for replies).
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// A signature on the receipt from a participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParticipantSignature {
    /// Key used to sign (e.g., "did:aip:1:...#session-1").
    pub key: String,

    /// Base64-encoded signature.
    pub sig: String,

    /// When the signature was made (unix ms).
    pub signed_at: i64,
}

/// A signed record of an interaction between two or more agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InteractionReceipt {
    /// Type identifier.
    #[serde(rename = "type")]
    pub type_: String,

    /// Protocol version.
    pub version: String,

    /// Unique receipt ID.
    pub id: String,

    /// DIDs of all participants.
    pub participants: Vec<String>,

    /// DID of the initiator.
    pub initiator: String,

    /// When the interaction occurred (unix ms).
    pub timestamp: i64,

    /// Context about the interaction.
    pub context: InteractionContext,

    /// Outcome of the interaction.
    pub outcome: InteractionOutcome,

    /// Signatures from participants (DID -> signature).
    #[serde(default)]
    pub signatures: HashMap<String, ParticipantSignature>,
}

impl InteractionReceipt {
    /// Create a new unsigned interaction receipt.
    pub fn new(initiator: Did, participants: Vec<Did>, context: InteractionContext) -> Self {
        Self {
            type_: "InteractionReceipt".to_string(),
            version: "1.0".to_string(),
            id: Uuid::now_v7().to_string(),
            participants: participants.iter().map(|d| d.to_string()).collect(),
            initiator: initiator.to_string(),
            timestamp: Utc::now().timestamp_millis(),
            context,
            outcome: InteractionOutcome::InProgress,
            signatures: HashMap::new(),
        }
    }

    /// Set the outcome.
    pub fn with_outcome(mut self, outcome: InteractionOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Set custom timestamp.
    pub fn at(mut self, time: DateTime<Utc>) -> Self {
        self.timestamp = time.timestamp_millis();
        self
    }

    /// Get the data to be signed (excludes signatures).
    fn signing_data(&self) -> Result<Vec<u8>> {
        let data = serde_json::json!({
            "type": self.type_,
            "version": self.version,
            "id": self.id,
            "participants": self.participants,
            "initiator": self.initiator,
            "timestamp": self.timestamp,
            "context": self.context,
            "outcome": self.outcome,
        });
        signing::canonicalize(&data)
    }

    /// Add a signature from a participant.
    pub fn sign(&mut self, signer: &RootKey, key_id: impl Into<String>) -> Result<()> {
        let did = signer.did().to_string();

        // Verify signer is a participant
        if !self.participants.contains(&did) {
            return Err(Error::Validation("Signer is not a participant".into()));
        }

        let canonical = self.signing_data()?;
        let sig = signer.sign(&canonical);

        self.signatures.insert(
            did,
            ParticipantSignature {
                key: key_id.into(),
                sig: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    sig.to_bytes(),
                ),
                signed_at: Utc::now().timestamp_millis(),
            },
        );

        Ok(())
    }

    /// Verify a specific participant's signature.
    pub fn verify_participant(&self, participant_did: &str) -> Result<()> {
        let sig_data = self
            .signatures
            .get(participant_did)
            .ok_or_else(|| Error::Validation("No signature from participant".into()))?;

        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sig_data.sig)
                .map_err(|_| Error::InvalidSignature)?;

        let signature =
            Signature::from_bytes(&sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?);

        let did: Did = participant_did.parse()?;
        let public_key = did.public_key()?;

        let canonical = self.signing_data()?;

        public_key
            .verify(&canonical, &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Verify all signatures.
    pub fn verify_all(&self) -> Result<()> {
        for did in self.signatures.keys() {
            self.verify_participant(did)?;
        }
        Ok(())
    }

    /// Check if all participants have signed.
    pub fn is_fully_signed(&self) -> bool {
        self.participants
            .iter()
            .all(|p| self.signatures.contains_key(p))
    }

    /// Get list of participants who haven't signed yet.
    pub fn pending_signatures(&self) -> Vec<&str> {
        self.participants
            .iter()
            .filter(|p| !self.signatures.contains_key(*p))
            .map(|s| s.as_str())
            .collect()
    }

    /// Get the number of signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_receipt() {
        let agent_a = RootKey::generate();
        let agent_b = RootKey::generate();

        let context = InteractionContext::new("moltbook", "public_post", InteractionType::Reply)
            .with_content(b"Hello, world!");

        let receipt =
            InteractionReceipt::new(agent_a.did(), vec![agent_a.did(), agent_b.did()], context);

        assert_eq!(receipt.participants.len(), 2);
        assert_eq!(receipt.initiator, agent_a.did().to_string());
        assert!(receipt.context.content_hash.is_some());
    }

    #[test]
    fn test_sign_receipt() {
        let agent_a = RootKey::generate();
        let agent_b = RootKey::generate();

        let context = InteractionContext::new("discord", "dm", InteractionType::Message);

        let mut receipt =
            InteractionReceipt::new(agent_a.did(), vec![agent_a.did(), agent_b.did()], context)
                .with_outcome(InteractionOutcome::Completed);

        // Sign from both parties
        receipt
            .sign(&agent_a, format!("{}#session-1", agent_a.did()))
            .unwrap();
        receipt
            .sign(&agent_b, format!("{}#session-1", agent_b.did()))
            .unwrap();

        assert!(receipt.is_fully_signed());
        receipt.verify_all().unwrap();
    }

    #[test]
    fn test_partial_signatures() {
        let agent_a = RootKey::generate();
        let agent_b = RootKey::generate();

        let context = InteractionContext::new("moltbook", "post", InteractionType::Endorsement);

        let mut receipt =
            InteractionReceipt::new(agent_a.did(), vec![agent_a.did(), agent_b.did()], context);

        receipt
            .sign(&agent_a, format!("{}#root", agent_a.did()))
            .unwrap();

        assert!(!receipt.is_fully_signed());
        assert_eq!(receipt.pending_signatures().len(), 1);
        assert_eq!(receipt.signature_count(), 1);
    }

    #[test]
    fn test_non_participant_cannot_sign() {
        let agent_a = RootKey::generate();
        let agent_b = RootKey::generate();
        let outsider = RootKey::generate();

        let context = InteractionContext::new("platform", "channel", InteractionType::Message);

        let mut receipt =
            InteractionReceipt::new(agent_a.did(), vec![agent_a.did(), agent_b.did()], context);

        let result = receipt.sign(&outsider, format!("{}#root", outsider.did()));
        assert!(result.is_err());
    }

    #[test]
    fn test_reply_context() {
        let _agent = RootKey::generate();

        let context = InteractionContext::new("twitter", "reply", InteractionType::Reply)
            .with_parent("parent-tweet-id-123")
            .with_content(b"Great point!")
            .with_metadata(serde_json::json!({"likes": 42}));

        assert_eq!(context.parent_id, Some("parent-tweet-id-123".to_string()));
        assert!(context.content_hash.is_some());
        assert!(context.metadata.is_some());
    }
}
