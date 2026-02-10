//! Key management for AIP identities.
//!
//! # Security
//!
//! This module handles secret key material. Key security properties:
//!
//! - **Zeroization on drop**: Secret key bytes are automatically zeroed when
//!   dropped. This is handled by `ed25519-dalek`'s `SigningKey` via its
//!   `zeroize` feature, preventing leakage via memory dumps, swap files,
//!   or cold boot attacks.
//!
//! - **No Debug leakage**: Keys implement Debug safely, showing only the
//!   DID (public info), not secret material.

use crate::{Did, Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fmt;

/// A root identity key.
///
/// This is the primary key that defines an agent's identity.
/// It should be stored securely and used sparingly.
///
/// # Security
///
/// - The inner `SigningKey` automatically zeroizes secret key bytes on drop
///   (via ed25519-dalek's `zeroize` feature).
/// - The `Debug` implementation only shows the DID (public info) to prevent
///   accidental exposure of key material in logs.
pub struct RootKey {
    signing_key: SigningKey,
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootKey")
            .field("did", &self.did().to_string())
            .finish_non_exhaustive()
    }
}

impl RootKey {
    /// Generate a new random root key.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Create from existing bytes.
    ///
    /// # Security
    ///
    /// The caller should zeroize the source bytes after this call
    /// if they are no longer needed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            signing_key: SigningKey::from_bytes(bytes),
        })
    }

    /// Get the DID for this root key.
    pub fn did(&self) -> Did {
        Did::new(self.signing_key.verifying_key())
    }

    /// Get the public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Get the secret key bytes.
    ///
    /// # Security Warning
    ///
    /// This returns raw secret key material. The caller is responsible for:
    /// - Storing the bytes securely
    /// - Zeroizing the bytes when no longer needed
    /// - Not logging or printing these bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// A session key delegated from a root key.
///
/// Used for day-to-day operations without exposing the root key.
///
/// # Security
///
/// - The inner `SigningKey` automatically zeroizes secret key bytes on drop.
/// - Session keys should be short-lived and rotated frequently.
/// - The `Debug` implementation only shows public info (root DID and pubkey
///   fingerprint).
pub struct SessionKey {
    signing_key: SigningKey,
    root_did: Did,
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show a short fingerprint of the public key (first 8 chars of base58)
        let pubkey_fingerprint = {
            let full = self.public_key_base58();
            if full.len() > 8 {
                format!("{}...", &full[..8])
            } else {
                full
            }
        };

        f.debug_struct("SessionKey")
            .field("root_did", &self.root_did.to_string())
            .field("pubkey", &pubkey_fingerprint)
            .finish_non_exhaustive()
    }
}

impl SessionKey {
    /// Generate a new session key for a root identity.
    pub fn generate(root_did: Did) -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            root_did,
        }
    }

    /// Get the root DID this session key belongs to.
    pub fn root_did(&self) -> &Did {
        &self.root_did
    }

    /// Get the public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Get the public key as base58.
    pub fn public_key_base58(&self) -> String {
        bs58::encode(self.signing_key.verifying_key().as_bytes()).into_string()
    }
}

/// Verify a signature against a public key.
pub fn verify(public_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
    public_key
        .verify(message, signature)
        .map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_key_generation() {
        let root = RootKey::generate();
        let did = root.did();
        assert!(did.to_string().starts_with("did:key:"));
    }

    #[test]
    fn test_sign_verify() {
        let root = RootKey::generate();
        let message = b"hello world";
        let signature = root.sign(message);

        verify(&root.verifying_key(), message, &signature).unwrap();
    }

    #[test]
    fn test_session_key() {
        let root = RootKey::generate();
        let session = SessionKey::generate(root.did());

        assert_eq!(session.root_did(), &root.did());

        let message = b"session message";
        let sig = session.sign(message);
        verify(&session.verifying_key(), message, &sig).unwrap();
    }

    #[test]
    fn test_root_key_roundtrip() {
        let root = RootKey::generate();
        let bytes = root.to_bytes();
        let restored = RootKey::from_bytes(&bytes).unwrap();

        assert_eq!(root.did(), restored.did());
    }

    #[test]
    fn test_root_key_debug_does_not_leak_secrets() {
        let root = RootKey::generate();
        let debug_output = format!("{:?}", root);

        // Should contain the DID (public info)
        assert!(debug_output.contains("did:key:"));

        // Should NOT contain any of these patterns that would indicate leaked key material
        assert!(
            !debug_output.contains("FieldElement"),
            "Debug output should not contain internal crypto field elements"
        );
        assert!(
            !debug_output.contains("EdwardsPoint"),
            "Debug output should not contain internal crypto types"
        );
        assert!(
            !debug_output.to_lowercase().contains("secret"),
            "Debug output should not reference 'secret'"
        );

        // Should use finish_non_exhaustive (indicated by "..")
        assert!(
            debug_output.contains(".."),
            "Debug should indicate hidden fields with .."
        );
    }

    #[test]
    fn test_session_key_debug_does_not_leak_secrets() {
        let root = RootKey::generate();
        let session = SessionKey::generate(root.did());
        let debug_output = format!("{:?}", session);

        // Should contain root_did and truncated pubkey
        assert!(debug_output.contains("root_did"));
        assert!(debug_output.contains("pubkey"));

        // Pubkey should be truncated (ends with ...)
        assert!(
            debug_output.contains("...\""),
            "Public key should be truncated in debug output"
        );

        // Should NOT contain leaked key material
        assert!(
            !debug_output.contains("FieldElement"),
            "Debug output should not contain internal crypto field elements"
        );
        assert!(
            !debug_output.contains("EdwardsPoint"),
            "Debug output should not contain internal crypto types"
        );
        assert!(
            !debug_output.to_lowercase().contains("secret"),
            "Debug output should not reference 'secret'"
        );
    }
}
