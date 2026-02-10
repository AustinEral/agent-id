//! Decentralized Identifier (DID) handling.
//!
//! Format: `did:key:z<base58btc(multicodec_prefix + ed25519_public_key)>`
//!
//! Uses the did:key method (W3C standard) with Ed25519 keys.
//! - Multicodec prefix: 0xed01 (Ed25519 public key)
//! - Multibase prefix: z (base58btc)

use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;
use std::fmt;
use std::str::FromStr;

/// Ed25519 public key multicodec prefix (varint-encoded 0xed).
/// See: https://github.com/multiformats/multicodec
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Multibase prefix for base58btc.
const BASE58BTC_PREFIX: char = 'z';

/// A parsed DID (did:key method).
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

    /// Get the multibase-encoded key portion (without did:key: prefix).
    pub fn key_id(&self) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&ED25519_MULTICODEC);
        bytes.extend_from_slice(&self.public_key);
        format!("{}{}", BASE58BTC_PREFIX, bs58::encode(&bytes).into_string())
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
        // Parse did:key:z... format
        let key_part = s
            .strip_prefix("did:key:")
            .ok_or_else(|| Error::InvalidDid("must start with 'did:key:'".into()))?;

        // Check multibase prefix (z = base58btc)
        let encoded = key_part
            .strip_prefix(BASE58BTC_PREFIX)
            .ok_or_else(|| Error::InvalidDid("must use base58btc encoding (z prefix)".into()))?;

        // Decode base58
        let bytes = bs58::decode(encoded)
            .into_vec()
            .map_err(|e| Error::Base58(e.to_string()))?;

        // Check length: 2 byte prefix + 32 byte key
        if bytes.len() != 34 {
            return Err(Error::InvalidDid(format!(
                "expected 34 bytes, got {}",
                bytes.len()
            )));
        }

        // Check multicodec prefix
        if bytes[0..2] != ED25519_MULTICODEC {
            return Err(Error::InvalidDid(
                "unsupported key type (expected Ed25519 multicodec 0xed01)".into(),
            ));
        }

        // Extract public key
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[2..34]);

        // Validate it's a valid Ed25519 point
        VerifyingKey::from_bytes(&public_key)
            .map_err(|e| Error::InvalidDid(format!("invalid Ed25519 key: {}", e)))?;

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
        assert!(did_str.starts_with("did:key:z6Mk"), "got: {}", did_str);

        let parsed: Did = did_str.parse().unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn test_known_vector() {
        // Test vector from did:key spec
        // https://w3c-ccg.github.io/did-method-key/#test-vectors
        let did_str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let parsed: Did = did_str.parse().unwrap();
        assert_eq!(parsed.to_string(), did_str);
    }

    #[test]
    fn test_invalid_prefix() {
        let result: std::result::Result<Did, _> = "did:aip:1:abc".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_multibase() {
        // Wrong multibase prefix (not z)
        let result: std::result::Result<Did, _> =
            "did:key:f6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".parse();
        assert!(result.is_err());
    }
}
