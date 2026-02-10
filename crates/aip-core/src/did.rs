//! Decentralized Identifier (DID) handling.
//!
//! Uses the did:key method (W3C CCG specification) for self-certifying
//! identifiers derived from Ed25519 public keys.
//!
//! Format: `did:key:z6Mk...` where the suffix is a multibase-encoded
//! (base58btc) multicodec-prefixed public key.
//!
//! See: https://w3c-ccg.github.io/did-method-key/

use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;
use multibase::Base;
use std::fmt;
use std::str::FromStr;

/// Multicodec prefix for Ed25519 public keys (0xed01)
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// A parsed did:key DID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    public_key: [u8; 32],
}

impl Did {
    /// Create a new DID from a public key.
    pub fn new(public_key: VerifyingKey) -> Self {
        Self {
            public_key: public_key.to_bytes(),
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Get the public key.
    pub fn public_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.public_key).map_err(|e| Error::InvalidDid(e.to_string()))
    }

    /// Get the multibase-encoded key identifier (the part after "did:key:").
    pub fn key_id(&self) -> String {
        let mut bytes = Vec::with_capacity(2 + 32);
        bytes.extend_from_slice(&ED25519_MULTICODEC);
        bytes.extend_from_slice(&self.public_key);
        multibase::encode(Base::Base58Btc, &bytes)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did:key:{}", self.key_id())
    }
}

impl FromStr for Did {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        // Parse "did:key:z..." format
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidDid("expected did:key:<multibase>".into()));
        }
        if parts[0] != "did" {
            return Err(Error::InvalidDid("must start with 'did'".into()));
        }
        if parts[1] != "key" {
            return Err(Error::InvalidDid("method must be 'key'".into()));
        }

        // Decode multibase
        let (base, bytes) = multibase::decode(parts[2])
            .map_err(|e| Error::InvalidDid(format!("invalid multibase: {}", e)))?;

        if base != Base::Base58Btc {
            return Err(Error::InvalidDid("expected base58btc encoding".into()));
        }

        // Check multicodec prefix
        if bytes.len() < 2 {
            return Err(Error::InvalidDid("missing multicodec prefix".into()));
        }
        if bytes[0..2] != ED25519_MULTICODEC {
            return Err(Error::InvalidDid(format!(
                "expected Ed25519 multicodec (0xed01), got 0x{:02x}{:02x}",
                bytes[0], bytes[1]
            )));
        }

        // Extract public key
        let key_bytes = &bytes[2..];
        if key_bytes.len() != 32 {
            return Err(Error::InvalidDid(format!(
                "public key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(key_bytes);

        Ok(Self { public_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_did_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = Did::new(signing_key.verifying_key());

        let did_str = did.to_string();
        assert!(did_str.starts_with("did:key:z6Mk"));

        let parsed: Did = did_str.parse().unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn test_did_format() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = Did::new(signing_key.verifying_key());
        let did_str = did.to_string();

        // Should start with did:key:z (z = base58btc)
        assert!(did_str.starts_with("did:key:z"));

        // After z, should start with 6Mk (Ed25519 multicodec in base58)
        assert!(did_str.starts_with("did:key:z6Mk"));
    }

    #[test]
    fn test_invalid_did_method() {
        let result: Result<Did> = "did:web:example.com".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_multibase() {
        let result: Result<Did> = "did:key:invalidbase".parse();
        assert!(result.is_err());
    }
}
