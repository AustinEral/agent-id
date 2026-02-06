//! Trust Layer for the Agent Identity Protocol.
//!
//! Enables agents to build and maintain trust relationships with each other.
//!
//! This layer provides:
//! - Trust statements (subjective assessments)
//! - Interaction receipts (signed records)
//! - Block statements
//! - Local trust graph

use aip_core::{Did, Error as CoreError, RootKey, signing};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Statement not found")]
    NotFound,

    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, TrustError>;

// ============================================================================
// Trust Statement
// ============================================================================

/// Domain-specific trust scores.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DomainTrust {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub communication: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reliability: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honesty: Option<f64>,
}

/// Summary of interactions between two agents.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct InteractionSummary {
    pub total_count: u32,
    pub positive_count: u32,
    pub neutral_count: u32,
    pub negative_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_interaction: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_interaction: Option<DateTime<Utc>>,
}

/// Assessment data in a trust statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustAssessment {
    /// Overall trust score (0.0 to 1.0)
    pub overall_trust: f64,
    /// Domain-specific scores
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<DomainTrust>,
    /// Descriptive tags
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Interaction summary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_summary: Option<InteractionSummary>,
    /// Hash of private notes (not shared)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes_hash: Option<String>,
}

/// Signature on a statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementSignature {
    pub key: String,
    pub sig: String,
}

/// A trust statement - one agent's assessment of another.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustStatement {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: String,
    pub id: String,
    /// DID of the agent making the statement
    pub issuer: String,
    /// DID of the agent being assessed
    pub subject: String,
    pub timestamp: DateTime<Utc>,
    pub assessment: TrustAssessment,
    /// ID of previous statement if this is an update
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<StatementSignature>,
}

impl TrustStatement {
    /// Create a new trust statement.
    pub fn new(issuer: Did, subject: Did, trust_score: f64) -> Self {
        Self {
            type_: "TrustStatement".to_string(),
            version: "1.0".to_string(),
            id: Uuid::now_v7().to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            timestamp: Utc::now(),
            assessment: TrustAssessment {
                overall_trust: trust_score.clamp(0.0, 1.0),
                domains: None,
                tags: Vec::new(),
                interaction_summary: None,
                notes_hash: None,
            },
            previous_statement: None,
            signature: None,
        }
    }

    /// Add tags to the assessment.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.assessment.tags = tags;
        self
    }

    /// Add domain-specific trust scores.
    pub fn with_domains(mut self, domains: DomainTrust) -> Self {
        self.assessment.domains = Some(domains);
        self
    }

    /// Sign this statement.
    pub fn sign(mut self, key: &RootKey) -> Result<Self> {
        self.signature = None; // Clear before signing

        let canonical = signing::canonicalize(&self)?;
        let sig = key.sign(&canonical);
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes());

        self.signature = Some(StatementSignature {
            key: format!("{}#root", self.issuer),
            sig: sig_b64,
        });

        Ok(self)
    }

    /// Verify this statement's signature.
    pub fn verify(&self) -> Result<()> {
        let sig_data = self
            .signature
            .as_ref()
            .ok_or(TrustError::InvalidSignature)?;

        let mut unsigned = self.clone();
        unsigned.signature = None;

        let canonical = signing::canonicalize(&unsigned)?;

        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sig_data.sig)
                .map_err(|_| TrustError::InvalidSignature)?;

        let signature = ed25519_dalek::Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| TrustError::InvalidSignature)?,
        );

        let issuer_did: Did = self.issuer.parse()?;
        let public_key = issuer_did.public_key()?;

        aip_core::keys::verify(&public_key, &canonical, &signature)
            .map_err(|_| TrustError::InvalidSignature)?;

        Ok(())
    }
}

// ============================================================================
// Block Statement
// ============================================================================

/// Severity of a block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlockSeverity {
    Temporary,
    Permanent,
    Report,
}

/// A block statement - agent refuses to interact with another.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockStatement {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: String,
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub timestamp: DateTime<Utc>,
    pub reason: String,
    pub severity: BlockSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<StatementSignature>,
}

impl BlockStatement {
    /// Create a new block statement.
    pub fn new(issuer: Did, subject: Did, reason: &str, severity: BlockSeverity) -> Self {
        Self {
            type_: "BlockStatement".to_string(),
            version: "1.0".to_string(),
            id: Uuid::now_v7().to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            timestamp: Utc::now(),
            reason: reason.to_string(),
            severity,
            evidence_hash: None,
            signature: None,
        }
    }

    /// Sign this statement.
    pub fn sign(mut self, key: &RootKey) -> Result<Self> {
        self.signature = None;

        let canonical = signing::canonicalize(&self)?;
        let sig = key.sign(&canonical);
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes());

        self.signature = Some(StatementSignature {
            key: format!("{}#root", self.issuer),
            sig: sig_b64,
        });

        Ok(self)
    }

    /// Verify this statement's signature.
    pub fn verify(&self) -> Result<()> {
        let sig_data = self
            .signature
            .as_ref()
            .ok_or(TrustError::InvalidSignature)?;

        let mut unsigned = self.clone();
        unsigned.signature = None;

        let canonical = signing::canonicalize(&unsigned)?;

        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sig_data.sig)
                .map_err(|_| TrustError::InvalidSignature)?;

        let signature = ed25519_dalek::Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| TrustError::InvalidSignature)?,
        );

        let issuer_did: Did = self.issuer.parse()?;
        let public_key = issuer_did.public_key()?;

        aip_core::keys::verify(&public_key, &canonical, &signature)
            .map_err(|_| TrustError::InvalidSignature)?;

        Ok(())
    }
}

// ============================================================================
// Trust Graph
// ============================================================================

/// Edge in the trust graph.
#[derive(Debug, Clone)]
pub struct TrustEdge {
    pub target: String,
    pub trust_score: f64,
    pub tags: Vec<String>,
    pub last_updated: DateTime<Utc>,
    pub blocked: bool,
}

/// Local trust graph maintained by an agent.
pub struct TrustGraph {
    /// Our DID
    owner: String,
    /// Direct trust relationships (DID -> edge)
    edges: HashMap<String, TrustEdge>,
    /// Trust statements we've issued
    statements: Vec<TrustStatement>,
    /// Block statements we've issued
    blocks: Vec<BlockStatement>,
}

impl TrustGraph {
    /// Create a new trust graph for an agent.
    pub fn new(owner: Did) -> Self {
        Self {
            owner: owner.to_string(),
            edges: HashMap::new(),
            statements: Vec::new(),
            blocks: Vec::new(),
        }
    }

    /// Get direct trust score for a DID (None if no relationship).
    pub fn get_trust(&self, did: &str) -> Option<f64> {
        self.edges.get(did).map(|e| e.trust_score)
    }

    /// Check if a DID is blocked.
    pub fn is_blocked(&self, did: &str) -> bool {
        self.edges.get(did).map(|e| e.blocked).unwrap_or(false)
    }

    /// Record a trust statement and update the graph.
    pub fn record_trust(&mut self, statement: TrustStatement) -> Result<()> {
        statement.verify()?;

        // Ensure we're the issuer
        if statement.issuer != self.owner {
            return Err(TrustError::InvalidSignature);
        }

        let edge = TrustEdge {
            target: statement.subject.clone(),
            trust_score: statement.assessment.overall_trust,
            tags: statement.assessment.tags.clone(),
            last_updated: statement.timestamp,
            blocked: false,
        };

        self.edges.insert(statement.subject.clone(), edge);
        self.statements.push(statement);

        Ok(())
    }

    /// Record a block and update the graph.
    pub fn record_block(&mut self, block: BlockStatement) -> Result<()> {
        block.verify()?;

        if block.issuer != self.owner {
            return Err(TrustError::InvalidSignature);
        }

        // Mark as blocked in graph
        if let Some(edge) = self.edges.get_mut(&block.subject) {
            edge.blocked = true;
            edge.trust_score = 0.0;
        } else {
            self.edges.insert(
                block.subject.clone(),
                TrustEdge {
                    target: block.subject.clone(),
                    trust_score: 0.0,
                    tags: vec!["blocked".to_string()],
                    last_updated: block.timestamp,
                    blocked: true,
                },
            );
        }

        self.blocks.push(block);

        Ok(())
    }

    /// Get all DIDs we have a relationship with.
    pub fn known_dids(&self) -> Vec<&str> {
        self.edges.keys().map(|s| s.as_str()).collect()
    }

    /// Get all trust statements.
    pub fn statements(&self) -> &[TrustStatement] {
        &self.statements
    }

    /// Get all block statements.
    pub fn blocks(&self) -> &[BlockStatement] {
        &self.blocks
    }

    /// Calculate derived trust (through trusted intermediaries).
    /// Simple algorithm: trust(A,C) = max over B of (trust(A,B) * trust(B,C) * decay)
    pub fn derived_trust(&self, did: &str, intermediaries: &HashMap<String, f64>) -> f64 {
        const DECAY: f64 = 0.7;

        let mut max_trust = 0.0;

        for (intermediate_did, intermediate_trust_in_target) in intermediaries {
            if let Some(our_trust_in_intermediate) = self.get_trust(intermediate_did) {
                let derived = our_trust_in_intermediate * intermediate_trust_in_target * DECAY;
                if derived > max_trust {
                    max_trust = derived;
                }
            }
        }

        max_trust
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_statement() {
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        let statement = TrustStatement::new(did_a.clone(), did_b.clone(), 0.85)
            .with_tags(vec!["helpful".to_string(), "reliable".to_string()])
            .sign(&key_a)
            .unwrap();

        assert!(statement.signature.is_some());
        statement.verify().unwrap();
    }

    #[test]
    fn test_trust_statement_tamper_detection() {
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        let mut statement = TrustStatement::new(did_a, did_b, 0.85)
            .sign(&key_a)
            .unwrap();

        // Tamper with the trust score
        statement.assessment.overall_trust = 0.1;

        assert!(statement.verify().is_err());
    }

    #[test]
    fn test_block_statement() {
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        let block = BlockStatement::new(did_a, did_b, "spam", BlockSeverity::Permanent)
            .sign(&key_a)
            .unwrap();

        block.verify().unwrap();
    }

    #[test]
    fn test_trust_graph() {
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let key_c = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();
        let did_c = key_c.did();

        let mut graph = TrustGraph::new(did_a.clone());

        // Trust B
        let trust_b = TrustStatement::new(did_a.clone(), did_b.clone(), 0.9)
            .sign(&key_a)
            .unwrap();
        graph.record_trust(trust_b).unwrap();

        assert_eq!(graph.get_trust(&did_b.to_string()), Some(0.9));
        assert!(!graph.is_blocked(&did_b.to_string()));

        // Block C
        let block_c = BlockStatement::new(
            did_a.clone(),
            did_c.clone(),
            "malicious",
            BlockSeverity::Permanent,
        )
        .sign(&key_a)
        .unwrap();
        graph.record_block(block_c).unwrap();

        assert!(graph.is_blocked(&did_c.to_string()));
        assert_eq!(graph.get_trust(&did_c.to_string()), Some(0.0));
    }

    #[test]
    fn test_derived_trust() {
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        let mut graph = TrustGraph::new(did_a.clone());

        // A trusts B with 0.8
        let trust_b = TrustStatement::new(did_a.clone(), did_b.clone(), 0.8)
            .sign(&key_a)
            .unwrap();
        graph.record_trust(trust_b).unwrap();

        // B trusts C with 0.9 (we receive this externally)
        let mut intermediaries = HashMap::new();
        intermediaries.insert(did_b.to_string(), 0.9);

        // Derived trust in C = 0.8 * 0.9 * 0.7 = 0.504
        let derived = graph.derived_trust("did:aip:1:C", &intermediaries);
        assert!((derived - 0.504).abs() < 0.001);
    }
}
