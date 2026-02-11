"""Tests for key generation and management."""

import pytest
from agent_id import RootKey, SessionKey


class TestRootKey:
    def test_generate(self):
        """RootKey.generate() creates a valid key."""
        key = RootKey.generate()
        
        assert key.did is not None
        assert str(key.did).startswith("did:key:z")
        assert len(key.to_bytes()) == 32
    
    def test_generate_unique(self):
        """Each generated key is unique."""
        key1 = RootKey.generate()
        key2 = RootKey.generate()
        
        assert key1.did != key2.did
        assert key1.to_bytes() != key2.to_bytes()
    
    def test_from_seed_deterministic(self):
        """Same seed produces same key."""
        seed = b"0" * 32
        
        key1 = RootKey.from_seed(seed)
        key2 = RootKey.from_seed(seed)
        
        assert key1.did == key2.did
        assert key1.to_bytes() == key2.to_bytes()
    
    def test_from_seed_invalid_length(self):
        """Invalid seed length raises ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            RootKey.from_seed(b"too short")
    
    def test_sign(self):
        """Signing produces a 64-byte signature."""
        key = RootKey.generate()
        message = b"test message"
        
        signature = key.sign(message)
        
        assert len(signature) == 64
    
    def test_sign_deterministic(self):
        """Same message produces same signature."""
        key = RootKey.from_seed(b"x" * 32)
        message = b"test message"
        
        sig1 = key.sign(message)
        sig2 = key.sign(message)
        
        assert sig1 == sig2
    
    def test_roundtrip_bytes(self):
        """Key can be exported and re-imported."""
        original = RootKey.generate()
        exported = original.to_bytes()
        restored = RootKey.from_bytes(exported)
        
        assert original.did == restored.did


class TestSessionKey:
    def test_generate(self):
        """SessionKey.generate() creates a valid key."""
        root = RootKey.generate()
        session = SessionKey.generate(root)
        
        assert session.root_did == root.did
        assert session.key_id.startswith("session-")
    
    def test_generate_with_custom_id(self):
        """Custom key ID is used."""
        root = RootKey.generate()
        session = SessionKey.generate(root, key_id="my-session")
        
        assert session.key_id == "my-session"
    
    def test_full_key_id(self):
        """full_key_id includes root DID."""
        root = RootKey.generate()
        session = SessionKey.generate(root, key_id="test")
        
        assert session.full_key_id == f"{root.did}#test"
    
    def test_sign(self):
        """Session key can sign messages."""
        root = RootKey.generate()
        session = SessionKey.generate(root)
        message = b"test message"
        
        signature = session.sign(message)
        
        assert len(signature) == 64
