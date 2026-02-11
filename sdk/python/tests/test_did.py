"""Tests for DID handling."""

import pytest
from agent_id import Did, RootKey


class TestDid:
    def test_from_public_key(self):
        """DID can be created from public key."""
        key = RootKey.generate()
        public_key = bytes(key.verify_key)
        
        did = Did.from_public_key(public_key)
        
        assert str(did).startswith("did:key:z")
        assert did.public_key == public_key
    
    def test_from_public_key_invalid_length(self):
        """Invalid public key length raises ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            Did.from_public_key(b"too short")
    
    def test_parse_valid(self):
        """Valid DID string can be parsed."""
        key = RootKey.generate()
        did_str = str(key.did)
        
        parsed = Did.parse(did_str)
        
        assert parsed == key.did
        assert parsed.public_key == key.did.public_key
    
    def test_parse_invalid_format(self):
        """Invalid DID format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid did:key format"):
            Did.parse("not-a-did")
        
        with pytest.raises(ValueError, match="Invalid did:key format"):
            Did.parse("did:web:example.com")
    
    def test_roundtrip(self):
        """DID can be converted to string and back."""
        key = RootKey.generate()
        original = key.did
        
        did_str = str(original)
        parsed = Did.parse(did_str)
        
        assert parsed == original
        assert parsed.public_key == original.public_key
    
    def test_frozen(self):
        """DID is immutable."""
        did = RootKey.generate().did
        
        with pytest.raises(AttributeError):
            did.value = "new value"  # type: ignore
