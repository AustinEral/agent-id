//! Handshake protocol implementation.

use crate::error::{HandshakeError, Result};
use crate::messages::{Challenge, CounterChallenge, CounterProof, Hello, Proof, ProofAccepted};
use aip_core::delegation::Capability;
use aip_core::{signing, Did, RootKey, SessionKey};
use chrono::Utc;
use std::collections::HashSet;
use std::sync::Mutex;

/// Default timestamp tolerance (±5 minutes).
pub const DEFAULT_TIMESTAMP_TOLERANCE_MS: i64 = 5 * 60 * 1000;

/// Default session duration (24 hours).
pub const DEFAULT_SESSION_DURATION_MS: i64 = 24 * 60 * 60 * 1000;

/// Nonce cache for replay protection.
pub struct NonceCache {
    seen: Mutex<HashSet<String>>,
    #[allow(dead_code)]
    max_age_ms: i64,
}

impl NonceCache {
    pub fn new(max_age_ms: i64) -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            max_age_ms,
        }
    }

    /// Check if nonce is fresh (not seen before).
    /// Returns true if fresh, false if replay.
    pub fn check_and_insert(&self, nonce: &str) -> bool {
        let mut seen = self.seen.lock().unwrap();
        if seen.contains(nonce) {
            return false;
        }
        seen.insert(nonce.to_string());
        true
    }

    /// Clear old nonces (call periodically).
    pub fn clear(&self) {
        let mut seen = self.seen.lock().unwrap();
        seen.clear();
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new(DEFAULT_TIMESTAMP_TOLERANCE_MS * 2)
    }
}

/// Handshake verifier configuration.
pub struct Verifier {
    pub my_did: Did,
    pub timestamp_tolerance_ms: i64,
    pub nonce_cache: NonceCache,
}

impl Verifier {
    pub fn new(my_did: Did) -> Self {
        Self {
            my_did,
            timestamp_tolerance_ms: DEFAULT_TIMESTAMP_TOLERANCE_MS,
            nonce_cache: NonceCache::default(),
        }
    }

    /// Verify a Hello message and create a Challenge.
    pub fn handle_hello(&self, hello: &Hello) -> Result<Challenge> {
        // Verify timestamp is recent
        self.verify_timestamp(hello.timestamp)?;

        // Verify protocol version
        if hello.version != "1.0" {
            return Err(HandshakeError::UnsupportedVersion(hello.version.clone()));
        }

        // Create challenge
        Ok(Challenge::new(self.my_did.to_string(), hello.did.clone()))
    }

    /// Verify a Proof message.
    ///
    /// Supports both root key signatures and delegated session key signatures.
    /// If a delegation is provided, it is validated before accepting the signature.
    pub fn verify_proof(&self, proof: &Proof, original_challenge: &Challenge) -> Result<()> {
        // Verify this proof is for our challenge
        let expected_hash = hash_challenge(original_challenge)?;
        if proof.challenge_hash != expected_hash {
            return Err(HandshakeError::InvalidSignature);
        }

        // Verify timestamp of any counter-challenge
        if let Some(ref counter) = proof.counter_challenge {
            self.verify_timestamp(counter.timestamp)?;

            // Verify counter-challenge audience is us
            if counter.audience != self.my_did.to_string() {
                return Err(HandshakeError::AudienceMismatch {
                    expected: self.my_did.to_string(),
                    got: counter.audience.clone(),
                });
            }

            // Check nonce freshness
            if !self.nonce_cache.check_and_insert(&counter.nonce) {
                return Err(HandshakeError::NonceReplay);
            }
        }

        // Parse responder DID
        let responder_did: Did = proof.responder_did.parse()?;

        // Determine which public key to verify against
        let public_key = if let Some(ref delegation) = proof.delegation {
            // Validate the delegation
            self.verify_delegation(delegation, &responder_did)?;

            // Use the delegated session key
            let delegate_bytes = bs58::decode(&delegation.delegate_pubkey)
                .into_vec()
                .map_err(|_| HandshakeError::InvalidDelegation)?;

            let delegate_bytes: [u8; 32] = delegate_bytes
                .try_into()
                .map_err(|_| HandshakeError::InvalidDelegation)?;

            ed25519_dalek::VerifyingKey::from_bytes(&delegate_bytes)
                .map_err(|_| HandshakeError::InvalidDelegation)?
        } else {
            // No delegation - use the root key from the DID
            responder_did.public_key()?
        };

        // Verify signature over the challenge hash
        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &proof.signature)
                .map_err(|_| HandshakeError::InvalidSignature)?;

        let signature = ed25519_dalek::Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| HandshakeError::InvalidSignature)?,
        );

        aip_core::keys::verify(&public_key, proof.challenge_hash.as_bytes(), &signature)?;

        Ok(())
    }

    /// Verify a delegation is valid for handshake operations.
    fn verify_delegation(
        &self,
        delegation: &aip_core::delegation::Delegation,
        expected_root: &Did,
    ) -> Result<()> {
        // Verify the delegation signature (signed by root key)
        delegation
            .verify()
            .map_err(|_| HandshakeError::InvalidDelegation)?;

        // Verify the delegation is for the claimed root DID
        if delegation.root_did != expected_root.to_string() {
            return Err(HandshakeError::InvalidDelegation);
        }

        // Verify the delegation is currently valid (not expired, not before issued)
        delegation
            .is_valid_at(Utc::now())
            .map_err(|_| HandshakeError::InvalidDelegation)?;

        // Verify the delegation grants handshake capability
        if !delegation.has_capability(&Capability::Handshake) {
            return Err(HandshakeError::InvalidDelegation);
        }

        Ok(())
    }

    /// Create a ProofAccepted response with counter-proof.
    pub fn accept_proof(&self, proof: &Proof, my_key: &RootKey) -> Result<ProofAccepted> {
        let counter_challenge = proof
            .counter_challenge
            .as_ref()
            .ok_or_else(|| HandshakeError::MissingField("counter_challenge".to_string()))?;

        let counter_proof = sign_counter_proof(counter_challenge, my_key)?;

        Ok(ProofAccepted {
            type_: "ProofAccepted".to_string(),
            version: "1.0".to_string(),
            session_id: uuid::Uuid::now_v7().to_string(),
            counter_proof,
            session_expires_at: Utc::now().timestamp_millis() + DEFAULT_SESSION_DURATION_MS,
        })
    }

    fn verify_timestamp(&self, timestamp: i64) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let diff = (now - timestamp).abs();

        if diff > self.timestamp_tolerance_ms {
            return Err(HandshakeError::TimestampOutOfRange);
        }

        Ok(())
    }
}

/// Hash a challenge for signing.
pub fn hash_challenge(challenge: &Challenge) -> Result<String> {
    let hash = signing::hash(challenge)?;
    Ok(format!("sha256:{}", hex::encode(hash)))
}

/// Hash a counter-challenge for signing.
pub fn hash_counter_challenge(counter: &CounterChallenge) -> Result<String> {
    let hash = signing::hash(counter)?;
    Ok(format!("sha256:{}", hex::encode(hash)))
}

/// Sign a challenge to create a Proof using the root key.
pub fn sign_proof(
    challenge: &Challenge,
    my_did: &Did,
    my_key: &RootKey,
    counter_audience: Option<String>,
) -> Result<Proof> {
    sign_proof_internal(
        challenge,
        my_did,
        |msg| my_key.sign(msg),
        format!("{}#root", my_did),
        None,
        counter_audience,
    )
}

/// Sign a challenge using a delegated session key.
pub fn sign_proof_with_session_key(
    challenge: &Challenge,
    root_did: &Did,
    session_key: &SessionKey,
    delegation: aip_core::delegation::Delegation,
    counter_audience: Option<String>,
) -> Result<Proof> {
    sign_proof_internal(
        challenge,
        root_did,
        |msg| session_key.sign(msg),
        format!("{}#session", root_did),
        Some(delegation),
        counter_audience,
    )
}

fn sign_proof_internal<F>(
    challenge: &Challenge,
    my_did: &Did,
    sign_fn: F,
    signing_key: String,
    delegation: Option<aip_core::delegation::Delegation>,
    counter_audience: Option<String>,
) -> Result<Proof>
where
    F: FnOnce(&[u8]) -> ed25519_dalek::Signature,
{
    let challenge_hash = hash_challenge(challenge)?;

    // Sign the challenge hash
    let signature = sign_fn(challenge_hash.as_bytes());
    let sig_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    );

    let mut proof = Proof::new(challenge_hash, my_did.to_string(), signing_key);
    proof.signature = sig_b64;

    // Attach delegation if using session key
    if let Some(del) = delegation {
        proof = proof.with_delegation(del);
    }

    // Add counter-challenge if this is mutual auth
    if let Some(audience) = counter_audience {
        proof = proof.with_counter_challenge(CounterChallenge::new(audience));
    }

    Ok(proof)
}

/// Sign a counter-challenge to complete mutual authentication.
pub fn sign_counter_proof(counter: &CounterChallenge, my_key: &RootKey) -> Result<CounterProof> {
    let challenge_hash = hash_counter_challenge(counter)?;

    let signature = my_key.sign(challenge_hash.as_bytes());
    let sig_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    );

    let my_did = my_key.did();

    Ok(CounterProof {
        challenge_hash,
        responder_did: my_did.to_string(),
        signing_key: format!("{}#root", my_did),
        signature: sig_b64,
    })
}

/// Verify a counter-proof to complete mutual authentication.
pub fn verify_counter_proof(
    counter_proof: &CounterProof,
    original_counter_challenge: &CounterChallenge,
) -> Result<()> {
    // Verify hash matches
    let expected_hash = hash_counter_challenge(original_counter_challenge)?;
    if counter_proof.challenge_hash != expected_hash {
        return Err(HandshakeError::InvalidSignature);
    }

    // Parse responder DID and verify signature
    let responder_did: Did = counter_proof.responder_did.parse()?;
    let public_key = responder_did.public_key()?;

    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &counter_proof.signature,
    )
    .map_err(|_| HandshakeError::InvalidSignature)?;

    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| HandshakeError::InvalidSignature)?,
    );

    aip_core::keys::verify(
        &public_key,
        counter_proof.challenge_hash.as_bytes(),
        &signature,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_core::delegation::{Delegation, DelegationType};
    use chrono::Duration;

    #[test]
    fn test_full_handshake() {
        // Agent A and Agent B
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        // A sends Hello to B
        let hello = Hello::new(did_a.to_string());

        // B receives Hello, sends Challenge
        let verifier_b = Verifier::new(did_b.clone());
        let challenge = verifier_b.handle_hello(&hello).unwrap();

        assert_eq!(challenge.issuer, did_b.to_string());
        assert_eq!(challenge.audience, did_a.to_string());

        // A receives Challenge, sends Proof with counter-challenge
        let proof = sign_proof(&challenge, &did_a, &key_a, Some(did_b.to_string())).unwrap();

        assert!(!proof.signature.is_empty());
        assert!(proof.counter_challenge.is_some());

        // B receives Proof, verifies it
        verifier_b.verify_proof(&proof, &challenge).unwrap();

        // B sends ProofAccepted with counter-proof
        let accepted = verifier_b.accept_proof(&proof, &key_b).unwrap();

        assert!(!accepted.session_id.is_empty());
        assert!(!accepted.counter_proof.signature.is_empty());

        // A verifies counter-proof
        verify_counter_proof(
            &accepted.counter_proof,
            proof.counter_challenge.as_ref().unwrap(),
        )
        .unwrap();

        // Handshake complete!
    }

    #[test]
    fn test_handshake_with_session_key() {
        // Agent A uses a session key, Agent B uses root key
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        // A creates a session key and delegation
        let session_a = SessionKey::generate(did_a.clone());
        let delegation = Delegation::new(
            did_a.clone(),
            session_a.public_key_base58(),
            DelegationType::Session,
            vec![Capability::Sign, Capability::Handshake],
            Utc::now() + Duration::hours(24),
        )
        .sign(&key_a)
        .unwrap();

        // A sends Hello to B
        let hello = Hello::new(did_a.to_string());

        // B receives Hello, sends Challenge
        let verifier_b = Verifier::new(did_b.clone());
        let challenge = verifier_b.handle_hello(&hello).unwrap();

        // A signs proof with session key + delegation
        let proof = sign_proof_with_session_key(
            &challenge,
            &did_a,
            &session_a,
            delegation,
            Some(did_b.to_string()),
        )
        .unwrap();

        assert!(proof.delegation.is_some());
        assert!(!proof.signature.is_empty());

        // B verifies proof (should accept delegated session key)
        verifier_b.verify_proof(&proof, &challenge).unwrap();

        // B sends ProofAccepted
        let accepted = verifier_b.accept_proof(&proof, &key_b).unwrap();

        // A verifies counter-proof
        verify_counter_proof(
            &accepted.counter_proof,
            proof.counter_challenge.as_ref().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn test_expired_delegation_rejected() {
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        // Create an already-expired delegation
        let session_a = SessionKey::generate(did_a.clone());
        let delegation = Delegation::new(
            did_a.clone(),
            session_a.public_key_base58(),
            DelegationType::Session,
            vec![Capability::Sign, Capability::Handshake],
            Utc::now() - Duration::hours(1), // Already expired
        )
        .sign(&key_a)
        .unwrap();

        let hello = Hello::new(did_a.to_string());
        let verifier_b = Verifier::new(did_b.clone());
        let challenge = verifier_b.handle_hello(&hello).unwrap();

        let proof = sign_proof_with_session_key(
            &challenge,
            &did_a,
            &session_a,
            delegation,
            Some(did_b.to_string()),
        )
        .unwrap();

        // Verification should fail due to expired delegation
        let result = verifier_b.verify_proof(&proof, &challenge);
        assert!(matches!(result, Err(HandshakeError::InvalidDelegation)));
    }

    #[test]
    fn test_missing_handshake_capability_rejected() {
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        // Create delegation WITHOUT Handshake capability
        let session_a = SessionKey::generate(did_a.clone());
        let delegation = Delegation::new(
            did_a.clone(),
            session_a.public_key_base58(),
            DelegationType::Session,
            vec![Capability::Sign], // No Handshake!
            Utc::now() + Duration::hours(24),
        )
        .sign(&key_a)
        .unwrap();

        let hello = Hello::new(did_a.to_string());
        let verifier_b = Verifier::new(did_b.clone());
        let challenge = verifier_b.handle_hello(&hello).unwrap();

        let proof = sign_proof_with_session_key(
            &challenge,
            &did_a,
            &session_a,
            delegation,
            Some(did_b.to_string()),
        )
        .unwrap();

        // Verification should fail due to missing capability
        let result = verifier_b.verify_proof(&proof, &challenge);
        assert!(matches!(result, Err(HandshakeError::InvalidDelegation)));
    }

    #[test]
    fn test_replay_protection() {
        let key_a = RootKey::generate();
        let key_b = RootKey::generate();
        let did_a = key_a.did();
        let did_b = key_b.did();

        let verifier_b = Verifier::new(did_b.clone());

        // First handshake
        let hello = Hello::new(did_a.to_string());
        let challenge = verifier_b.handle_hello(&hello).unwrap();
        let proof = sign_proof(&challenge, &did_a, &key_a, Some(did_b.to_string())).unwrap();

        verifier_b.verify_proof(&proof, &challenge).unwrap();

        // Try to replay the same proof - should fail due to nonce
        let result = verifier_b.verify_proof(&proof, &challenge);
        assert!(matches!(result, Err(HandshakeError::NonceReplay)));
    }

    #[test]
    fn test_nonce_cache() {
        let cache = NonceCache::default();

        assert!(cache.check_and_insert("nonce1"));
        assert!(cache.check_and_insert("nonce2"));

        // Replay should fail
        assert!(!cache.check_and_insert("nonce1"));
        assert!(!cache.check_and_insert("nonce2"));

        // New nonce should work
        assert!(cache.check_and_insert("nonce3"));
    }
}
