//! JCS canonicalization and message signing.
//!
//! Uses RFC 8785 JSON Canonicalization Scheme for deterministic
//! JSON serialization, ensuring signatures are verifiable across
//! different implementations.

use crate::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Canonicalize a JSON value using JCS (RFC 8785).
///
/// This produces a deterministic byte representation suitable for signing.
/// The canonicalization follows RFC 8785 exactly, ensuring interoperability
/// with other AIP implementations.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|e| crate::Error::Validation(format!("JCS canonicalization failed: {}", e)))
}

/// SHA-256 hash of canonical JSON.
///
/// This is the standard way to prepare data for signing in AIP.
/// The value is first canonicalized using JCS, then hashed with SHA-256.
pub fn hash<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    let canonical = canonicalize(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_order() {
        let value = json!({"b": 2, "a": 1});
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, b"{\"a\":1,\"b\":2}");
    }

    #[test]
    fn test_nested_canonical() {
        let value = json!({"z": {"b": 2, "a": 1}, "a": []});
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, b"{\"a\":[],\"z\":{\"a\":1,\"b\":2}}");
    }

    #[test]
    fn test_hash_deterministic() {
        let value = json!({"hello": "world"});
        let hash1 = hash(&value).unwrap();
        let hash2 = hash(&value).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_unicode_handling() {
        // RFC 8785 specifies exact Unicode handling
        let value = json!({"emoji": "🎉", "text": "héllo"});
        let canonical = canonicalize(&value).unwrap();
        // Should produce consistent output regardless of input encoding
        let canonical_str = String::from_utf8(canonical).unwrap();
        assert!(canonical_str.contains("emoji"));
        assert!(canonical_str.contains("text"));
    }

    #[test]
    fn test_number_formatting() {
        // RFC 8785 specifies number serialization rules
        let value = json!({"int": 42, "float": 3.14});
        let canonical = canonicalize(&value).unwrap();
        let canonical_str = String::from_utf8(canonical).unwrap();
        assert!(canonical_str.contains("42"));
        assert!(canonical_str.contains("3.14"));
    }

    #[test]
    fn test_special_characters() {
        // Verify proper escaping of special characters
        let value = json!({"quote": "he said \"hello\"", "newline": "line1\nline2"});
        let canonical = canonicalize(&value).unwrap();
        let canonical_str = String::from_utf8(canonical).unwrap();
        // Escaped quote should appear as \"
        assert!(canonical_str.contains(r#"\""#));
        // Newline should appear as \n
        assert!(canonical_str.contains(r"\n"));
    }
}
