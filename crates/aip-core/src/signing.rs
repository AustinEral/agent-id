//! JCS canonicalization and message signing.

use crate::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Canonicalize a JSON value using JCS (RFC 8785).
///
/// This produces a deterministic byte representation suitable for signing.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // serde_json with sorted keys approximates JCS
    // For production, use a proper JCS library
    let json = serde_json::to_value(value)?;
    let canonical = serialize_canonical(&json);
    Ok(canonical.into_bytes())
}

/// SHA-256 hash of canonical JSON.
pub fn hash<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    let canonical = canonicalize(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hasher.finalize().into())
}

/// Serialize JSON value in canonical form (sorted keys, no whitespace).
fn serialize_canonical(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", escape_json_string(s)),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(serialize_canonical).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "\"{}\":{}",
                        escape_json_string(k),
                        serialize_canonical(&obj[*k])
                    )
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// Escape special characters in JSON strings.
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
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
}
