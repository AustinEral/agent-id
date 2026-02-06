//! Decentralized Identifier (DID) handling.
//!
//! Format: `did:aip:<version>:<base58(ed25519_public_key)>`

use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;
use std::fmt;
use std::str::FromStr;

/// The current DID method version.
pub const DID_VERSION: u8 = 1;

/// A parsed AIP DID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    version: u8,
    public_key: [u8; 32],
}

impl Did {
    /// Create a new DID from a public key.
    pub fn new(public_key: VerifyingKey) -> Self {
        Self {
            version: DID_VERSION,
            public_key: public_key.to_bytes(),
        }
    }

    /// Get the version of this DID.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Get the public key.
    pub fn public_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.public_key).map_err(|e| Error::InvalidDid(e.to_string()))
    }

    /// Get the base58-encoded public key portion.
    pub fn key_id(&self) -> String {
        bs58::encode(&self.public_key).into_string()
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "did:aip:{}:{}",
            self.version,
            bs58::encode(&self.public_key).into_string()
        )
    }
}

impl FromStr for Did {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            return Err(Error::InvalidDid(format!(
                "expected 4 parts, got {}",
                parts.len()
            )));
        }
        if parts[0] != "did" {
            return Err(Error::InvalidDid("must start with 'did'".into()));
        }
        if parts[1] != "aip" {
            return Err(Error::InvalidDid("method must be 'aip'".into()));
        }

        let version: u8 = parts[2]
            .parse()
            .map_err(|_| Error::InvalidDid("invalid version".into()))?;

        let public_key = bs58::decode(parts[3])
            .into_vec()
            .map_err(|e| Error::Base58(e.to_string()))?;

        if public_key.len() != 32 {
            return Err(Error::InvalidDid(format!(
                "public key must be 32 bytes, got {}",
                public_key.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&public_key);

        Ok(Self {
            version,
            public_key: key_bytes,
        })
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
        assert!(did_str.starts_with("did:aip:1:"));

        let parsed: Did = did_str.parse().unwrap();
        assert_eq!(did, parsed);
    }
}
