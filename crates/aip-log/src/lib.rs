//! Transparency Log for the Agent Identity Protocol.
//!
//! Provides an append-only log of identity events with Merkle tree verification.
//! This enables detection of key compromise and prevents silent key rotation.

use aip_core::{Did, DidDocument, Error as CoreError, RootKey, signing, KeyRotation, Revocation, RootRecovery, RecoveryCancellation};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("Entry not found: {0}")]
    NotFound(u64),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Sequence mismatch: expected {expected}, got {got}")]
    SequenceMismatch { expected: u64, got: u64 },

    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, LogError>;

/// Types of events that can be logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// New identity created
    IdentityCreated,
    /// DID Document registered or updated
    DocumentUpdated,
    /// Key rotation
    KeyRotation,
    /// Key revocation
    KeyRevocation,
    /// Root recovery initiated
    RootRecovery,
    /// Recovery cancelled
    RecoveryCancelled,
}

/// A log entry representing an identity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// Sequence number (0-indexed)
    pub sequence: u64,
    /// When this entry was created
    pub timestamp: DateTime<Utc>,
    /// Type of event
    pub event_type: EventType,
    /// DID this event relates to
    pub subject_did: String,
    /// Event payload (JSON)
    pub payload: serde_json::Value,
    /// Hash of previous entry (empty for first entry)
    pub previous_hash: String,
    /// Hash of this entry (computed over all fields except this one)
    pub entry_hash: String,
    /// Signature from the subject's key
    pub subject_signature: String,
    /// Signature from the log operator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_signature: Option<String>,
}

/// Data to be signed for an entry (excludes signatures and entry_hash).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntrySigningData {
    sequence: u64,
    timestamp: DateTime<Utc>,
    event_type: EventType,
    subject_did: String,
    payload: serde_json::Value,
    previous_hash: String,
}

impl LogEntry {
    /// Create a new log entry (unsigned).
    pub fn new(
        sequence: u64,
        event_type: EventType,
        subject_did: String,
        payload: serde_json::Value,
        previous_hash: String,
    ) -> Self {
        Self {
            sequence,
            timestamp: Utc::now(),
            event_type,
            subject_did,
            payload,
            previous_hash,
            entry_hash: String::new(),
            subject_signature: String::new(),
            operator_signature: None,
        }
    }

    /// Sign this entry with the subject's key and compute the hash.
    pub fn sign(mut self, subject_key: &RootKey) -> Result<Self> {
        let signing_data = EntrySigningData {
            sequence: self.sequence,
            timestamp: self.timestamp,
            event_type: self.event_type.clone(),
            subject_did: self.subject_did.clone(),
            payload: self.payload.clone(),
            previous_hash: self.previous_hash.clone(),
        };

        // Sign the entry
        let canonical = signing::canonicalize(&signing_data)?;
        let signature = subject_key.sign(&canonical);
        self.subject_signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.to_bytes(),
        );

        // Compute entry hash
        self.entry_hash = self.compute_hash()?;

        Ok(self)
    }

    /// Add operator signature.
    pub fn with_operator_signature(mut self, operator_key: &RootKey) -> Result<Self> {
        let canonical = signing::canonicalize(&self.entry_hash)?;
        let signature = operator_key.sign(&canonical);
        self.operator_signature = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.to_bytes(),
        ));
        Ok(self)
    }

    /// Verify the subject's signature.
    pub fn verify_subject_signature(&self) -> Result<()> {
        let signing_data = EntrySigningData {
            sequence: self.sequence,
            timestamp: self.timestamp,
            event_type: self.event_type.clone(),
            subject_did: self.subject_did.clone(),
            payload: self.payload.clone(),
            previous_hash: self.previous_hash.clone(),
        };

        let canonical = signing::canonicalize(&signing_data)?;

        let sig_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.subject_signature,
        )
        .map_err(|_| LogError::InvalidSignature)?;

        let signature = ed25519_dalek::Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| LogError::InvalidSignature)?,
        );

        let did: Did = self.subject_did.parse()?;
        let public_key = did.public_key()?;

        aip_core::keys::verify(&public_key, &canonical, &signature)
            .map_err(|_| LogError::InvalidSignature)?;

        Ok(())
    }

    /// Compute the hash of this entry.
    fn compute_hash(&self) -> Result<String> {
        let hash_data = serde_json::json!({
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "eventType": self.event_type,
            "subjectDid": self.subject_did,
            "payload": self.payload,
            "previousHash": self.previous_hash,
            "subjectSignature": self.subject_signature,
        });

        let canonical = signing::canonicalize(&hash_data)?;
        let hash = Sha256::digest(&canonical);
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    /// Verify the entry hash is correct.
    pub fn verify_hash(&self) -> Result<()> {
        let computed = self.compute_hash()?;
        if computed != self.entry_hash {
            return Err(LogError::InvalidProof);
        }
        Ok(())
    }
}

/// Merkle tree node for inclusion proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: String,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

/// An inclusion proof for a log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// The entry's sequence number
    pub sequence: u64,
    /// Hash of the entry
    pub entry_hash: String,
    /// Tree size at time of proof
    pub tree_size: u64,
    /// Root hash of the Merkle tree
    pub root_hash: String,
    /// Proof path (hashes needed to reconstruct root)
    pub proof_path: Vec<ProofNode>,
}

/// A node in the proof path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    /// The hash at this node
    pub hash: String,
    /// Whether this is a left or right sibling
    pub position: ProofPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProofPosition {
    Left,
    Right,
}

impl InclusionProof {
    /// Verify this proof against the entry hash.
    pub fn verify(&self, entry_hash: &str) -> Result<()> {
        if self.entry_hash != entry_hash {
            return Err(LogError::InvalidProof);
        }

        // Reconstruct root hash from proof path
        let mut current_hash = entry_hash.to_string();

        for node in &self.proof_path {
            let combined = match node.position {
                ProofPosition::Left => format!("{}{}", node.hash, current_hash),
                ProofPosition::Right => format!("{}{}", current_hash, node.hash),
            };

            let hash = Sha256::digest(combined.as_bytes());
            current_hash = format!("sha256:{}", hex::encode(hash));
        }

        if current_hash != self.root_hash {
            return Err(LogError::InvalidProof);
        }

        Ok(())
    }
}

/// In-memory transparency log.
pub struct TransparencyLog {
    entries: std::sync::RwLock<Vec<LogEntry>>,
    operator_key: Option<RootKey>,
}

impl TransparencyLog {
    /// Create a new empty log.
    pub fn new() -> Self {
        Self {
            entries: std::sync::RwLock::new(Vec::new()),
            operator_key: None,
        }
    }

    /// Create a log with an operator key for signing entries.
    pub fn with_operator(operator_key: RootKey) -> Self {
        Self {
            entries: std::sync::RwLock::new(Vec::new()),
            operator_key: Some(operator_key),
        }
    }

    /// Get the current size of the log.
    pub fn size(&self) -> u64 {
        self.entries.read().unwrap().len() as u64
    }

    /// Get the hash of the last entry (or empty string if log is empty).
    pub fn last_hash(&self) -> String {
        let entries = self.entries.read().unwrap();
        entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_default()
    }

    /// Append a signed entry to the log.
    pub fn append(&self, mut entry: LogEntry) -> Result<LogEntry> {
        let mut entries = self.entries.write().unwrap();

        // Verify sequence
        let expected_seq = entries.len() as u64;
        if entry.sequence != expected_seq {
            return Err(LogError::SequenceMismatch {
                expected: expected_seq,
                got: entry.sequence,
            });
        }

        // Verify previous hash
        let expected_prev = entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_default();
        if entry.previous_hash != expected_prev {
            return Err(LogError::InvalidProof);
        }

        // Verify subject signature
        entry.verify_subject_signature()?;

        // Verify entry hash
        entry.verify_hash()?;

        // Add operator signature if we have an operator key
        if let Some(ref op_key) = self.operator_key {
            entry = entry.with_operator_signature(op_key)?;
        }

        entries.push(entry.clone());
        Ok(entry)
    }

    /// Get an entry by sequence number.
    pub fn get(&self, sequence: u64) -> Result<LogEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .get(sequence as usize)
            .cloned()
            .ok_or(LogError::NotFound(sequence))
    }

    /// Get all entries for a DID.
    pub fn get_by_did(&self, did: &str) -> Vec<LogEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| e.subject_did == did)
            .cloned()
            .collect()
    }

    /// Get the latest entry for a DID.
    pub fn get_latest_for_did(&self, did: &str) -> Option<LogEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter().rfind(|e| e.subject_did == did).cloned()
    }

    /// Compute the Merkle root hash.
    pub fn root_hash(&self) -> String {
        let entries = self.entries.read().unwrap();
        if entries.is_empty() {
            return String::new();
        }

        let hashes: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();
        Self::compute_merkle_root(&hashes)
    }

    /// Compute Merkle root from a list of hashes.
    fn compute_merkle_root(hashes: &[String]) -> String {
        if hashes.is_empty() {
            return String::new();
        }
        if hashes.len() == 1 {
            return hashes[0].clone();
        }

        let mut level: Vec<String> = hashes.to_vec();

        while level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    format!("{}{}", chunk[0], chunk[0]) // duplicate odd node
                };

                let hash = Sha256::digest(combined.as_bytes());
                next_level.push(format!("sha256:{}", hex::encode(hash)));
            }

            level = next_level;
        }

        level[0].clone()
    }

    /// Generate an inclusion proof for an entry.
    pub fn prove(&self, sequence: u64) -> Result<InclusionProof> {
        let entries = self.entries.read().unwrap();

        if sequence >= entries.len() as u64 {
            return Err(LogError::NotFound(sequence));
        }

        let entry = &entries[sequence as usize];
        let hashes: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();

        let proof_path = Self::compute_proof_path(&hashes, sequence as usize);

        Ok(InclusionProof {
            sequence,
            entry_hash: entry.entry_hash.clone(),
            tree_size: entries.len() as u64,
            root_hash: Self::compute_merkle_root(&hashes),
            proof_path,
        })
    }

    /// Compute the proof path for an entry.
    fn compute_proof_path(hashes: &[String], index: usize) -> Vec<ProofNode> {
        if hashes.len() <= 1 {
            return Vec::new();
        }

        let mut path = Vec::new();
        let mut level: Vec<String> = hashes.to_vec();
        let mut idx = index;

        while level.len() > 1 {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };

            if sibling_idx < level.len() {
                path.push(ProofNode {
                    hash: level[sibling_idx].clone(),
                    position: if idx.is_multiple_of(2) {
                        ProofPosition::Right
                    } else {
                        ProofPosition::Left
                    },
                });
            } else {
                // Odd node, duplicate
                path.push(ProofNode {
                    hash: level[idx].clone(),
                    position: ProofPosition::Right,
                });
            }

            // Move to next level
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    format!("{}{}", chunk[0], chunk[0])
                };
                let hash = Sha256::digest(combined.as_bytes());
                next_level.push(format!("sha256:{}", hex::encode(hash)));
            }

            level = next_level;
            idx /= 2;
        }

        path
    }
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create a document registration entry.
pub fn create_document_entry(
    document: &DidDocument,
    subject_key: &RootKey,
    previous_hash: String,
    sequence: u64,
) -> Result<LogEntry> {
    let entry = LogEntry::new(
        sequence,
        EventType::DocumentUpdated,
        document.id.clone(),
        serde_json::to_value(document)?,
        previous_hash,
    );

    entry.sign(subject_key)
}


/// Helper to create a key rotation log entry.
pub fn create_rotation_entry(
    rotation: &KeyRotation,
    subject_key: &RootKey,
    previous_hash: String,
    sequence: u64,
) -> Result<LogEntry> {
    let entry = LogEntry::new(
        sequence,
        EventType::KeyRotation,
        rotation.did.clone(),
        serde_json::to_value(rotation)?,
        previous_hash,
    );
    entry.sign(subject_key)
}

/// Helper to create a key revocation log entry.
pub fn create_revocation_entry(
    revocation: &Revocation,
    subject_key: &RootKey,
    previous_hash: String,
    sequence: u64,
) -> Result<LogEntry> {
    let entry = LogEntry::new(
        sequence,
        EventType::KeyRevocation,
        revocation.did.clone(),
        serde_json::to_value(revocation)?,
        previous_hash,
    );
    entry.sign(subject_key)
}

/// Helper to create a root recovery log entry.
pub fn create_recovery_entry(
    recovery: &RootRecovery,
    recovery_key: &RootKey,
    previous_hash: String,
    sequence: u64,
) -> Result<LogEntry> {
    let entry = LogEntry::new(
        sequence,
        EventType::RootRecovery,
        recovery.did.clone(),
        serde_json::to_value(recovery)?,
        previous_hash,
    );
    entry.sign(recovery_key)
}

/// Helper to create a recovery cancellation log entry.
pub fn create_cancellation_entry(
    cancellation: &RecoveryCancellation,
    root_key: &RootKey,
    previous_hash: String,
    sequence: u64,
) -> Result<LogEntry> {
    let entry = LogEntry::new(
        sequence,
        EventType::RecoveryCancelled,
        cancellation.did.clone(),
        serde_json::to_value(cancellation)?,
        previous_hash,
    );
    entry.sign(root_key)
}

/// Helper to create an identity creation log entry.
pub fn create_identity_entry(
    did: &Did,
    subject_key: &RootKey,
    previous_hash: String,
    sequence: u64,
) -> Result<LogEntry> {
    let entry = LogEntry::new(
        sequence,
        EventType::IdentityCreated,
        did.to_string(),
        serde_json::json!({"created": true}),
        previous_hash,
    );
    entry.sign(subject_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_append() {
        let log = TransparencyLog::new();
        let key = RootKey::generate();
        let did = key.did();

        let entry = LogEntry::new(
            0,
            EventType::IdentityCreated,
            did.to_string(),
            serde_json::json!({"created": true}),
            String::new(),
        )
        .sign(&key)
        .unwrap();

        let appended = log.append(entry).unwrap();
        assert_eq!(appended.sequence, 0);
        assert!(!appended.entry_hash.is_empty());

        assert_eq!(log.size(), 1);
    }

    #[test]
    fn test_log_chain() {
        let log = TransparencyLog::new();
        let key = RootKey::generate();
        let did = key.did();

        // First entry
        let entry1 = LogEntry::new(
            0,
            EventType::IdentityCreated,
            did.to_string(),
            serde_json::json!({"event": 1}),
            String::new(),
        )
        .sign(&key)
        .unwrap();

        log.append(entry1).unwrap();

        // Second entry (must reference first)
        let prev_hash = log.last_hash();
        let entry2 = LogEntry::new(
            1,
            EventType::DocumentUpdated,
            did.to_string(),
            serde_json::json!({"event": 2}),
            prev_hash,
        )
        .sign(&key)
        .unwrap();

        log.append(entry2).unwrap();

        assert_eq!(log.size(), 2);
    }

    #[test]
    fn test_inclusion_proof() {
        let log = TransparencyLog::new();
        let key = RootKey::generate();
        let did = key.did();

        // Add some entries
        for i in 0..4 {
            let entry = LogEntry::new(
                i,
                EventType::DocumentUpdated,
                did.to_string(),
                serde_json::json!({"event": i}),
                log.last_hash(),
            )
            .sign(&key)
            .unwrap();

            log.append(entry).unwrap();
        }

        // Generate and verify proof for entry 2
        let proof = log.prove(2).unwrap();
        let entry = log.get(2).unwrap();

        proof.verify(&entry.entry_hash).unwrap();
    }

    #[test]
    fn test_reject_tampered_entry() {
        let log = TransparencyLog::new();
        let key = RootKey::generate();
        let did = key.did();

        let mut entry = LogEntry::new(
            0,
            EventType::IdentityCreated,
            did.to_string(),
            serde_json::json!({"good": true}),
            String::new(),
        )
        .sign(&key)
        .unwrap();

        // Tamper with payload
        entry.payload = serde_json::json!({"evil": true});

        // Should reject
        assert!(log.append(entry).is_err());
    }

    #[test]
    fn test_get_by_did() {
        let log = TransparencyLog::new();
        let key1 = RootKey::generate();
        let key2 = RootKey::generate();
        let did1 = key1.did();
        let did2 = key2.did();

        // Add entries for did1
        let entry1 = LogEntry::new(
            0,
            EventType::IdentityCreated,
            did1.to_string(),
            serde_json::json!({}),
            String::new(),
        )
        .sign(&key1)
        .unwrap();
        log.append(entry1).unwrap();

        // Add entry for did2
        let entry2 = LogEntry::new(
            1,
            EventType::IdentityCreated,
            did2.to_string(),
            serde_json::json!({}),
            log.last_hash(),
        )
        .sign(&key2)
        .unwrap();
        log.append(entry2).unwrap();

        // Add another for did1
        let entry3 = LogEntry::new(
            2,
            EventType::DocumentUpdated,
            did1.to_string(),
            serde_json::json!({}),
            log.last_hash(),
        )
        .sign(&key1)
        .unwrap();
        log.append(entry3).unwrap();

        let did1_entries = log.get_by_did(&did1.to_string());
        assert_eq!(did1_entries.len(), 2);

        let did2_entries = log.get_by_did(&did2.to_string());
        assert_eq!(did2_entries.len(), 1);
    }
}
