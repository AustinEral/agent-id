"""Tests for DID Document handling."""

import pytest
from agent_id import RootKey, DidDocument


class TestDidDocument:
    def test_new(self):
        """DidDocument.new() creates valid document."""
        key = RootKey.generate()
        doc = DidDocument.new(key)
        
        assert doc.did == key.did
        assert len(doc.verification_methods) == 1
        assert doc.proof is None  # Unsigned
    
    def test_to_dict(self):
        """Document can be serialized to dict."""
        key = RootKey.generate()
        doc = DidDocument.new(key)
        
        d = doc.to_dict()
        
        assert d["id"] == str(key.did)
        assert "@context" in d
        assert "verificationMethod" in d
    
    def test_with_handshake_endpoint(self):
        """Handshake endpoint can be added."""
        key = RootKey.generate()
        doc = DidDocument.new(key)
        doc = doc.with_handshake_endpoint("https://example.com/aip")
        
        assert len(doc.services) == 1
        assert doc.services[0].type == "AIPHandshake"
        assert doc.services[0].service_endpoint == "https://example.com/aip"
    
    def test_with_service(self):
        """Custom service can be added."""
        key = RootKey.generate()
        doc = DidDocument.new(key)
        doc = doc.with_service("agent", "AgentService", "https://example.com/agent")
        
        assert len(doc.services) == 1
        assert doc.services[0].type == "AgentService"
        assert doc.services[0].id == f"{key.did}#agent"
    
    def test_immutable_builder(self):
        """Builder methods return new documents."""
        key = RootKey.generate()
        doc1 = DidDocument.new(key)
        doc2 = doc1.with_handshake_endpoint("https://example.com")
        
        assert len(doc1.services) == 0
        assert len(doc2.services) == 1
    
    def test_sign(self):
        """Document can be signed."""
        key = RootKey.generate()
        doc = DidDocument.new(key)
        
        signed = doc.sign(key)
        
        assert signed.proof is not None
        assert "proofValue" in signed.proof
    
    def test_sign_wrong_key_fails(self):
        """Signing with wrong key raises error."""
        key1 = RootKey.generate()
        key2 = RootKey.generate()
        doc = DidDocument.new(key1)
        
        with pytest.raises(ValueError, match="doesn't match"):
            doc.sign(key2)
    
    def test_verify_valid(self):
        """Valid signature verifies."""
        key = RootKey.generate()
        doc = DidDocument.new(key).sign(key)
        
        assert doc.verify() is True
    
    def test_verify_unsigned_fails(self):
        """Verifying unsigned document raises error."""
        key = RootKey.generate()
        doc = DidDocument.new(key)
        
        with pytest.raises(ValueError, match="no proof"):
            doc.verify()
    
    def test_verify_after_modification_fails(self):
        """Modifying signed document invalidates signature."""
        key = RootKey.generate()
        doc = DidDocument.new(key).sign(key)
        
        # Add service after signing (proof is cleared)
        modified = doc.with_handshake_endpoint("https://example.com")
        
        # Proof was cleared, so verify should fail
        with pytest.raises(ValueError, match="no proof"):
            modified.verify()
    
    def test_services_in_dict(self):
        """Services appear in serialized dict."""
        key = RootKey.generate()
        doc = (
            DidDocument.new(key)
            .with_handshake_endpoint("https://example.com/aip")
            .with_service("agent", "AgentService", "https://example.com/agent")
        )
        
        d = doc.to_dict()
        
        assert "service" in d
        assert len(d["service"]) == 2
