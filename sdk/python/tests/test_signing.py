"""Tests for signing and verification."""

import pytest

from agent_id import (
    InvalidSignatureError,
    RootKey,
    canonicalize,
    hash_canonical,
    sign_dict,
    verify_dict,
    verify_dict_strict,
)


class TestCanonicalize:
    def test_sorted_keys(self) -> None:
        """Keys are sorted in canonical JSON."""
        value = {"z": 1, "a": 2, "m": 3}
        canonical = canonicalize(value)

        assert canonical == b'{"a":2,"m":3,"z":1}'

    def test_no_whitespace(self) -> None:
        """Canonical JSON has no extra whitespace."""
        value = {"key": "value", "nested": {"a": 1}}
        canonical = canonicalize(value)

        assert b" " not in canonical
        assert b"\n" not in canonical

    def test_deterministic(self) -> None:
        """Same object always produces same bytes."""
        value = {"hello": "world", "count": 42}

        canonical_one = canonicalize(value)
        canonical_two = canonicalize(value)

        assert canonical_one == canonical_two

    def test_nested_canonical(self) -> None:
        """Nested objects are also sorted."""
        value = {"z": {"b": 2, "a": 1}, "a": []}
        canonical = canonicalize(value)

        assert canonical == b'{"a":[],"z":{"a":1,"b":2}}'


class TestHash:
    def test_hash_deterministic(self) -> None:
        """Same value produces same hash."""
        value = {"hello": "world"}

        hash_one = hash_canonical(value)
        hash_two = hash_canonical(value)

        assert hash_one == hash_two
        assert len(hash_one) == 32

    def test_hash_differs(self) -> None:
        """Different values produce different hashes."""
        hash_one = hash_canonical({"a": 1})
        hash_two = hash_canonical({"a": 2})

        assert hash_one != hash_two


class TestSignVerify:
    def test_sign_and_verify(self) -> None:
        """Signed message can be verified."""
        key = RootKey.generate()
        message = {"action": "test", "value": 123}

        signature = sign_dict(message, key)
        is_valid = verify_dict(message, signature, key.did.public_key)

        assert is_valid

    def test_verify_wrong_key(self) -> None:
        """Verification with wrong key fails."""
        key_one = RootKey.generate()
        key_two = RootKey.generate()
        message = {"action": "test"}

        signature = sign_dict(message, key_one)
        is_valid = verify_dict(message, signature, key_two.did.public_key)

        assert not is_valid

    def test_verify_modified_message(self) -> None:
        """Verification of modified message fails."""
        key = RootKey.generate()
        message = {"action": "test", "value": 123}

        signature = sign_dict(message, key)

        modified = {"action": "test", "value": 456}
        is_valid = verify_dict(modified, signature, key.did.public_key)

        assert not is_valid

    def test_verify_invalid_signature(self) -> None:
        """Invalid signature returns False."""
        key = RootKey.generate()
        message = {"action": "test"}

        is_valid = verify_dict(message, "not-valid-base64!", key.did.public_key)

        assert not is_valid


class TestVerifyStrict:
    def test_strict_raises(self) -> None:
        """Strict verification raises on failure."""
        key_one = RootKey.generate()
        key_two = RootKey.generate()
        message = {"action": "test"}

        signature = sign_dict(message, key_one)

        with pytest.raises(InvalidSignatureError, match="Payload hash"):
            verify_dict_strict(message, signature, key_two.did.public_key)

    def test_strict_passes(self) -> None:
        """Strict verification passes on valid signature."""
        key = RootKey.generate()
        message = {"action": "test"}

        signature = sign_dict(message, key)

        verify_dict_strict(message, signature, key.did.public_key)
