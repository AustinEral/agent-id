//! Key lifecycle management: rotation, revocation, and recovery.

use crate::{Did, Error, Result, RootKey, signing};
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
    /// Recovery key rotation.
    Recovery,
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
    /// Key identifier (e.g., "did:aip:1:...#root-2").
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
        let effective = DateTime::from_timestamp_millis(self.effective_at)
            .unwrap_or_else(Utc::now);
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

        let signature = Signature::from_bytes(
            &sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?
        );

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

    /// Signature from root or recovery key.
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

    /// Sign this revocation with a root or recovery key.
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

        let signature = Signature::from_bytes(
            &sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?
        );

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

/// Reason for root recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReason {
    /// Root key was lost.
    RootKeyLost,
    /// Root key was compromised.
    RootKeyCompromised,
    /// Preventive rotation via recovery.
    Preventive,
}

/// A root recovery event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootRecovery {
    /// Type identifier.
    #[serde(rename = "type")]
    pub type_: String,

    /// Protocol version.
    pub version: String,

    /// The DID being recovered.
    pub did: String,

    /// Reference to the old root key.
    pub old_root: String,

    /// The new root key.
    pub new_root: NewKey,

    /// Reference to the recovery key used.
    pub recovery_key_used: String,

    /// Reason for recovery.
    pub reason: RecoveryReason,

    /// When this recovery takes effect (unix ms).
    pub effective_at: i64,

    /// Waiting period before recovery completes (ms).
    /// Original root can cancel during this window.
    pub waiting_period: i64,

    /// Signature from the recovery key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl RootRecovery {
    /// Default waiting period (7 days).
    pub const DEFAULT_WAITING_PERIOD: Duration = Duration::days(7);

    /// Create a new unsigned root recovery.
    pub fn new(
        did: Did,
        old_root: String,
        new_root: NewKey,
        recovery_key_used: String,
        reason: RecoveryReason,
    ) -> Self {
        Self {
            type_: "RootRecovery".to_string(),
            version: "1.0".to_string(),
            did: did.to_string(),
            old_root,
            new_root,
            recovery_key_used,
            reason,
            effective_at: Utc::now().timestamp_millis(),
            waiting_period: Self::DEFAULT_WAITING_PERIOD.num_milliseconds(),
            signature: None,
        }
    }

    /// Set custom waiting period.
    pub fn waiting_period(mut self, duration: Duration) -> Self {
        self.waiting_period = duration.num_milliseconds();
        self
    }

    /// Sign this recovery with the recovery key.
    pub fn sign(mut self, recovery_key: &RootKey) -> Result<Self> {
        self.signature = None;
        let canonical = signing::canonicalize(&self)?;
        let sig = recovery_key.sign(&canonical);
        self.signature = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig.to_bytes(),
        ));
        Ok(self)
    }

    /// Verify this recovery's signature against the recovery key DID.
    pub fn verify(&self, recovery_did: &Did) -> Result<()> {
        let sig_b64 = self.signature.as_ref().ok_or(Error::InvalidSignature)?;
        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .map_err(|_| Error::InvalidSignature)?;

        let signature = Signature::from_bytes(
            &sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?
        );

        let public_key = recovery_did.public_key()?;

        let mut unsigned = self.clone();
        unsigned.signature = None;
        let canonical = signing::canonicalize(&unsigned)?;

        public_key
            .verify(&canonical, &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Calculate when the recovery completes.
    pub fn completes_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.effective_at + self.waiting_period)
            .unwrap_or_else(Utc::now)
    }

    /// Check if the waiting period has passed.
    pub fn is_complete(&self) -> bool {
        Utc::now() >= self.completes_at()
    }

    /// Check if the recovery can still be cancelled.
    pub fn is_cancellable(&self) -> bool {
        !self.is_complete()
    }
}

/// A cancellation of a pending recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCancellation {
    /// Type identifier.
    #[serde(rename = "type")]
    pub type_: String,

    /// Protocol version.
    pub version: String,

    /// The DID this cancellation is for.
    pub did: String,

    /// Reference to the recovery being cancelled.
    pub recovery_id: String,

    /// When this cancellation was issued (unix ms).
    pub cancelled_at: i64,

    /// Signature from the original root key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl RecoveryCancellation {
    /// Create a new unsigned cancellation.
    pub fn new(did: Did, recovery_id: String) -> Self {
        Self {
            type_: "RecoveryCancellation".to_string(),
            version: "1.0".to_string(),
            did: did.to_string(),
            recovery_id,
            cancelled_at: Utc::now().timestamp_millis(),
            signature: None,
        }
    }

    /// Sign this cancellation with the original root key.
    pub fn sign(mut self, root_key: &RootKey) -> Result<Self> {
        self.signature = None;
        let canonical = signing::canonicalize(&self)?;
        let sig = root_key.sign(&canonical);
        self.signature = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig.to_bytes(),
        ));
        Ok(self)
    }

    /// Verify this cancellation's signature.
    pub fn verify(&self) -> Result<()> {
        let sig_b64 = self.signature.as_ref().ok_or(Error::InvalidSignature)?;
        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .map_err(|_| Error::InvalidSignature)?;

        let signature = Signature::from_bytes(
            &sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?
        );

        let did: Did = self.did.parse()?;
        let public_key = did.public_key()?;

        let mut unsigned = self.clone();
        unsigned.signature = None;
        let canonical = signing::canonicalize(&unsigned)?;

        public_key
            .verify(&canonical, &signature)
            .map_err(|_| Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_new_key(root: &RootKey, suffix: &str) -> NewKey {
        NewKey {
            id: format!("{}#{}", root.did(), suffix),
            key_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: format!("z{}", root.did().to_string().split(':').last().unwrap()),
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

        assert_eq!(revocation.revocation_id, Some("delegation-uuid-123".to_string()));
    }

    #[test]
    fn test_root_recovery() {
        let old_root = RootKey::generate();
        let new_root = RootKey::generate();
        let recovery_key = RootKey::generate();

        let recovery = RootRecovery::new(
            old_root.did(),
            format!("{}#root", old_root.did()),
            make_new_key(&new_root, "root-recovered"),
            format!("{}#recovery", recovery_key.did()),
            RecoveryReason::RootKeyLost,
        );

        let signed = recovery.sign(&recovery_key).unwrap();
        assert!(signed.signature.is_some());
        signed.verify(&recovery_key.did()).unwrap();
    }

    #[test]
    fn test_recovery_waiting_period() {
        let old_root = RootKey::generate();
        let new_root = RootKey::generate();
        let recovery_key = RootKey::generate();

        let recovery = RootRecovery::new(
            old_root.did(),
            format!("{}#root", old_root.did()),
            make_new_key(&new_root, "root-recovered"),
            format!("{}#recovery", recovery_key.did()),
            RecoveryReason::RootKeyLost,
        );

        // Should not be complete immediately
        assert!(!recovery.is_complete());
        assert!(recovery.is_cancellable());

        // Completion time should be 7 days from now
        let expected = Utc::now() + Duration::days(7);
        let actual = recovery.completes_at();
        assert!((expected - actual).num_seconds().abs() < 2);
    }

    #[test]
    fn test_recovery_cancellation() {
        let root = RootKey::generate();

        let cancellation = RecoveryCancellation::new(
            root.did(),
            "recovery-uuid-123".to_string(),
        );

        let signed = cancellation.sign(&root).unwrap();
        assert!(signed.signature.is_some());
        signed.verify().unwrap();
    }
}
