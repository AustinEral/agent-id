//! Key lifecycle management: rotation and revocation.

use crate::{signing, Did, Error, Result, RootKey};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};

/// Type of key being rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationType {
    /// Root key rotation.
    Root,
    /// Session key rotation.
    Session,
}

/// Reason for key rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    /// Scheduled rotation.
    Scheduled,
    /// Suspected compromise.
    Compromise,
    /// Algorithm upgrade.
    AlgorithmUpgrade,
    /// Operational requirements.
    Operational,
}

/// A new key being rotated to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewKey {
    /// Key identifier (e.g., "did:key:...#root-2").
    pub id: String,
    /// Key type.
    #[serde(rename = "type")]
    pub key_type: String,
    /// Public key in multibase format.
    pub public_key_multibase: String,
}

/// A key rotation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRotation {
    /// Type identifier.
    #[serde(rename = "type")]
    pub type_: String,

    /// Protocol version.
    pub version: String,

    /// The DID this rotation is for.
    pub did: String,

    /// Type of rotation.
    pub rotation_type: RotationType,

    /// The new key.
    pub new_key: NewKey,

    /// Reference to the previous key.
    pub previous_key: String,

    /// When this rotation takes effect (unix ms).
    pub effective_at: i64,

    /// When the overlap period ends (unix ms).
    pub overlap_until: i64,

    /// Reason for rotation.
    pub reason: RotationReason,

    /// Signature from the previous key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl KeyRotation {
    /// Default overlap period (24 hours).
    pub const DEFAULT_OVERLAP: Duration = Duration::hours(24);

    /// Create a new unsigned key rotation.
    pub fn new(
        did: Did,
        rotation_type: RotationType,
        new_key: NewKey,
        previous_key: String,
        reason: RotationReason,
    ) -> Self {
        let now = Utc::now();
        Self {
            type_: "KeyRotation".to_string(),
            version: "1.0".to_string(),
            did: did.to_string(),
            rotation_type,
            new_key,
            previous_key,
            effective_at: now.timestamp_millis(),
            overlap_until: (now + Self::DEFAULT_OVERLAP).timestamp_millis(),
            reason,
            signature: None,
        }
    }

    /// Set custom effective time.
    pub fn effective_at(mut self, time: DateTime<Utc>) -> Self {
        self.effective_at = time.timestamp_millis();
        self
    }

    /// Set custom overlap period.
    pub fn overlap_duration(mut self, duration: Duration) -> Self {
        let effective = DateTime::from_timestamp_millis(self.effective_at).unwrap_or_else(Utc::now);
        self.overlap_until = (effective + duration).timestamp_millis();
        self
    }

    /// Sign this rotation with the previous (old) key.
    pub fn sign(mut self, old_key: &RootKey) -> Result<Self> {
        self.signature = None;
        let canonical = signing::canonicalize(&self)?;
        let sig = old_key.sign(&canonical);
        self.signature = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig.to_bytes(),
        ));
        Ok(self)
    }

    /// Verify this rotation's signature against the DID's public key.
    pub fn verify(&self) -> Result<()> {
        let sig_b64 = self.signature.as_ref().ok_or(Error::InvalidSignature)?;
        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .map_err(|_| Error::InvalidSignature)?;

        let signature =
            Signature::from_bytes(&sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?);

        let did: Did = self.did.parse()?;
        let public_key = did.public_key()?;

        let mut unsigned = self.clone();
        unsigned.signature = None;
        let canonical = signing::canonicalize(&unsigned)?;

        public_key
            .verify(&canonical, &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Check if a key is valid at a given time (considering overlap).
    pub fn is_old_key_valid_at(&self, time: DateTime<Utc>) -> bool {
        time.timestamp_millis() <= self.overlap_until
    }

    /// Check if the new key is active at a given time.
    pub fn is_new_key_active_at(&self, time: DateTime<Utc>) -> bool {
        time.timestamp_millis() >= self.effective_at
    }
}

/// Reason for key revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Key believed stolen.
    Compromised,
    /// Replaced by rotation.
    Superseded,
    /// Natural delegation expiry.
    Expired,
    /// Operator decision.
    Administrative,
}

/// A key revocation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Revocation {
    /// Type identifier.
    #[serde(rename = "type")]
    pub type_: String,

    /// Protocol version.
    pub version: String,

    /// The DID this revocation is for.
    pub did: String,

    /// Key being revoked (key ID).
    pub revoked_key: String,

    /// Revocation ID (matches delegation revocation_id if revoking a delegation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_id: Option<String>,

    /// Reason for revocation.
    pub reason: RevocationReason,

    /// When this revocation takes effect (unix ms).
    pub effective_at: i64,

    /// Signature from root key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Revocation {
    /// Create a new unsigned revocation.
    pub fn new(did: Did, revoked_key: String, reason: RevocationReason) -> Self {
        Self {
            type_: "Revocation".to_string(),
            version: "1.0".to_string(),
            did: did.to_string(),
            revoked_key,
            revocation_id: None,
            reason,
            effective_at: Utc::now().timestamp_millis(),
            signature: None,
        }
    }

    /// Set revocation ID (for revoking delegations).
    pub fn with_revocation_id(mut self, id: String) -> Self {
        self.revocation_id = Some(id);
        self
    }

    /// Sign this revocation with a root key.
    pub fn sign(mut self, signing_key: &RootKey) -> Result<Self> {
        self.signature = None;
        let canonical = signing::canonicalize(&self)?;
        let sig = signing_key.sign(&canonical);
        self.signature = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig.to_bytes(),
        ));
        Ok(self)
    }

    /// Verify this revocation's signature.
    pub fn verify(&self, verifying_did: &Did) -> Result<()> {
        let sig_b64 = self.signature.as_ref().ok_or(Error::InvalidSignature)?;
        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .map_err(|_| Error::InvalidSignature)?;

        let signature =
            Signature::from_bytes(&sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?);

        let public_key = verifying_did.public_key()?;

        let mut unsigned = self.clone();
        unsigned.signature = None;
        let canonical = signing::canonicalize(&unsigned)?;

        public_key
            .verify(&canonical, &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Check if this revocation is effective at a given time.
    pub fn is_effective_at(&self, time: DateTime<Utc>) -> bool {
        time.timestamp_millis() >= self.effective_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_new_key(root: &RootKey, suffix: &str) -> NewKey {
        NewKey {
            id: format!("{}#{}", root.did(), suffix),
            key_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: format!(
                "z{}",
                root.did().to_string().split(':').next_back().unwrap()
            ),
        }
    }

    #[test]
    fn test_key_rotation() {
        let old_key = RootKey::generate();
        let new_key = RootKey::generate();

        let rotation = KeyRotation::new(
            old_key.did(),
            RotationType::Root,
            make_new_key(&new_key, "root-2"),
            format!("{}#root", old_key.did()),
            RotationReason::Scheduled,
        );

        let signed = rotation.sign(&old_key).unwrap();
        assert!(signed.signature.is_some());
        signed.verify().unwrap();
    }

    #[test]
    fn test_key_rotation_overlap() {
        let key = RootKey::generate();
        let new_key = RootKey::generate();

        let rotation = KeyRotation::new(
            key.did(),
            RotationType::Root,
            make_new_key(&new_key, "root-2"),
            format!("{}#root", key.did()),
            RotationReason::Scheduled,
        );

        // Old key should be valid during overlap
        assert!(rotation.is_old_key_valid_at(Utc::now()));
        assert!(rotation.is_new_key_active_at(Utc::now()));

        // Old key should be invalid after overlap
        let after_overlap = Utc::now() + Duration::hours(25);
        assert!(!rotation.is_old_key_valid_at(after_overlap));
    }

    #[test]
    fn test_revocation() {
        let root = RootKey::generate();

        let revocation = Revocation::new(
            root.did(),
            format!("{}#session-1", root.did()),
            RevocationReason::Compromised,
        );

        let signed = revocation.sign(&root).unwrap();
        assert!(signed.signature.is_some());
        signed.verify(&root.did()).unwrap();
    }

    #[test]
    fn test_revocation_with_id() {
        let root = RootKey::generate();

        let revocation = Revocation::new(
            root.did(),
            format!("{}#session-1", root.did()),
            RevocationReason::Administrative,
        )
        .with_revocation_id("delegation-uuid-123".to_string());

        assert_eq!(
            revocation.revocation_id,
            Some("delegation-uuid-123".to_string())
        );
    }
}
