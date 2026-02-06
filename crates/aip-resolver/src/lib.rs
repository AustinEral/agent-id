//! DID Resolver for the Agent Identity Protocol.
//!
//! Resolves `did:aip:...` identifiers to DID Documents.

use aip_core::{DidDocument, Error as CoreError};
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("DID not found: {0}")]
    NotFound(String),

    #[error("Invalid document: {0}")]
    InvalidDocument(String),

    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    #[error("Storage error: {0}")]
    Storage(String),
}

pub type Result<T> = std::result::Result<T, ResolverError>;

/// A DID resolver that stores and retrieves DID Documents.
pub struct Resolver {
    /// In-memory storage (replace with database for production)
    documents: RwLock<HashMap<String, DidDocument>>,
}

impl Resolver {
    /// Create a new resolver with empty storage.
    pub fn new() -> Self {
        Self {
            documents: RwLock::new(HashMap::new()),
        }
    }

    /// Register a DID Document.
    ///
    /// The document must be signed and the signature must be valid.
    pub fn register(&self, document: DidDocument) -> Result<()> {
        // Verify the document signature
        document
            .verify()
            .map_err(|e| ResolverError::InvalidDocument(e.to_string()))?;

        let did = document.id.clone();

        let mut docs = self.documents.write().unwrap();
        docs.insert(did, document);

        Ok(())
    }

    /// Resolve a DID to its document.
    pub fn resolve(&self, did: &str) -> Result<DidDocument> {
        let docs = self.documents.read().unwrap();
        docs.get(did)
            .cloned()
            .ok_or_else(|| ResolverError::NotFound(did.to_string()))
    }

    /// Update a DID Document.
    ///
    /// The new document must be signed and have a newer `updated` timestamp.
    pub fn update(&self, document: DidDocument) -> Result<()> {
        // Verify the document signature
        document
            .verify()
            .map_err(|e| ResolverError::InvalidDocument(e.to_string()))?;

        let did = document.id.clone();

        let mut docs = self.documents.write().unwrap();

        // Check if document exists and new one is newer
        if let Some(existing) = docs.get(&did)
            && document.updated <= existing.updated
        {
            return Err(ResolverError::InvalidDocument(
                "Document is not newer than existing".to_string(),
            ));
        }

        docs.insert(did, document);

        Ok(())
    }

    /// Remove a DID Document.
    pub fn remove(&self, did: &str) -> Result<()> {
        let mut docs = self.documents.write().unwrap();
        docs.remove(did)
            .map(|_| ())
            .ok_or_else(|| ResolverError::NotFound(did.to_string()))
    }

    /// List all registered DIDs.
    pub fn list(&self) -> Vec<String> {
        let docs = self.documents.read().unwrap();
        docs.keys().cloned().collect()
    }

    /// Get the count of registered documents.
    pub fn count(&self) -> usize {
        self.documents.read().unwrap().len()
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_core::RootKey;

    #[test]
    fn test_register_and_resolve() {
        let resolver = Resolver::new();
        let key = RootKey::generate();

        let doc = DidDocument::new(&key)
            .with_handshake_endpoint("https://example.com/hs")
            .sign(&key)
            .unwrap();

        let did = doc.id.clone();

        resolver.register(doc).unwrap();

        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(resolved.id, did);
        assert_eq!(
            resolved.handshake_endpoint(),
            Some("https://example.com/hs")
        );
    }

    #[test]
    fn test_reject_unsigned() {
        let resolver = Resolver::new();
        let key = RootKey::generate();

        // Create unsigned document
        let doc = DidDocument::new(&key);

        // Should reject
        assert!(resolver.register(doc).is_err());
    }

    #[test]
    fn test_reject_tampered() {
        let resolver = Resolver::new();
        let key = RootKey::generate();

        let mut doc = DidDocument::new(&key).sign(&key).unwrap();

        // Tamper with document
        doc.controller = "did:aip:1:EVIL".to_string();

        // Should reject
        assert!(resolver.register(doc).is_err());
    }

    #[test]
    fn test_not_found() {
        let resolver = Resolver::new();

        let result = resolver.resolve("did:aip:1:nonexistent");
        assert!(matches!(result, Err(ResolverError::NotFound(_))));
    }

    #[test]
    fn test_update() {
        let resolver = Resolver::new();
        let key = RootKey::generate();

        let doc1 = DidDocument::new(&key).sign(&key).unwrap();
        let did = doc1.id.clone();

        resolver.register(doc1).unwrap();

        // Create updated document with new endpoint
        std::thread::sleep(std::time::Duration::from_millis(10));
        let doc2 = DidDocument::new(&key)
            .with_handshake_endpoint("https://new.example.com/hs")
            .sign(&key)
            .unwrap();

        resolver.update(doc2).unwrap();

        let resolved = resolver.resolve(&did).unwrap();
        assert_eq!(
            resolved.handshake_endpoint(),
            Some("https://new.example.com/hs")
        );
    }
}
