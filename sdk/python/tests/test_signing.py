"""Tests for message signing and verification."""

import pytest
from agent_id import RootKey, sign_message, verify_message
from agent_id.signing import canonicalize, sign_with_metadata


class TestCanonicalize:
    def test_sorted_keys(self):
        """Keys are sorted in canonical JSON."""
        obj = {"z": 1, "a": 2, "m": 3}
        canonical = canonicalize(obj)
        
        # Keys should be alphabetically sorted
        assert canonical == b'{"a":2,"m":3,"z":1}'
    
    def test_no_whitespace(self):
        """Canonical JSON has no extra whitespace."""
        obj = {"key": "value", "nested": {"a": 1}}
        canonical = canonicalize(obj)
        
        assert b" " not in canonical
        assert b"\n" not in canonical
    
    def test_deterministic(self):
        """Same object always produces same bytes."""
        obj = {"hello": "world", "count": 42}
        
        c1 = canonicalize(obj)
        c2 = canonicalize(obj)
        
        assert c1 == c2


class TestSignVerify:
    def test_sign_and_verify(self):
        """Signed message can be verified."""
        key = RootKey.generate()
        message = {"action": "test", "value": 123}
        
        signature = sign_message(message, key)
        is_valid = verify_message(message, signature, key.did.public_key)
        
        assert is_valid
    
    def test_verify_wrong_key_fails(self):
        """Verification with wrong key fails."""
        key1 = RootKey.generate()
        key2 = RootKey.generate()
        message = {"action": "test"}
        
        signature = sign_message(message, key1)
        is_valid = verify_message(message, signature, key2.did.public_key)
        
        assert not is_valid
    
    def test_verify_modified_message_fails(self):
        """Verification of modified message fails."""
        key = RootKey.generate()
        message = {"action": "test", "value": 123}
        
        signature = sign_message(message, key)
        
        modified = {"action": "test", "value": 456}
        is_valid = verify_message(modified, signature, key.did.public_key)
        
        assert not is_valid
    
    def test_verify_invalid_signature_fails(self):
        """Invalid signature returns False (no exception)."""
        key = RootKey.generate()
        message = {"action": "test"}
        
        is_valid = verify_message(message, "not-valid-base64!", key.did.public_key)
        
        assert not is_valid


class TestSignWithMetadata:
    def test_attaches_proof(self):
        """sign_with_metadata attaches proof field."""
        key = RootKey.generate()
        message = {"type": "Test", "value": 42}
        
        signed = sign_with_metadata(message, key)
        
        assert "proof" in signed
        assert signed["proof"]["type"] == "Ed25519Signature2020"
        assert signed["proof"]["verificationMethod"] == f"{key.did}#root"
        assert "proofValue" in signed["proof"]
    
    def test_preserves_original_fields(self):
        """Original message fields are preserved."""
        key = RootKey.generate()
        message = {"type": "Test", "value": 42, "nested": {"a": 1}}
        
        signed = sign_with_metadata(message, key)
        
        assert signed["type"] == "Test"
        assert signed["value"] == 42
        assert signed["nested"] == {"a": 1}
