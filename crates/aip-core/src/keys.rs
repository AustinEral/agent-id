//! Key management for AIP identities.

use crate::{Did, Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// A root identity key.
///
/// This is the primary key that defines an agent's identity.
/// It should be stored securely and used sparingly.
#[derive(Debug)]
pub struct RootKey {
    signing_key: SigningKey,
}

impl RootKey {
    /// Generate a new random root key.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Create from existing bytes.
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

    /// Get the secret key bytes (be careful with this!).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// A session key delegated from a root key.
///
/// Used for day-to-day operations without exposing the root key.
#[derive(Debug)]
pub struct SessionKey {
    signing_key: SigningKey,
    root_did: Did,
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
        assert!(did.to_string().starts_with("did:aip:1:"));
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
}
