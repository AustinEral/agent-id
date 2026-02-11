"""Tests for key management."""

import pytest

from agent_id import KeyError, RootKey, SessionKey
from agent_id.signing import verify_bytes


class TestRootKey:
    def test_generate(self) -> None:
        """Generate creates valid key with DID."""
        key = RootKey.generate()

        assert key.did is not None
        assert str(key.did).startswith("did:key:z6Mk")
        assert len(key.to_bytes()) == 32

    def test_generate_unique(self) -> None:
        """Each generated key is unique."""
        key_one = RootKey.generate()
        key_two = RootKey.generate()

        assert key_one.did != key_two.did
        assert key_one.to_bytes() != key_two.to_bytes()

    def test_from_seed_deterministic(self) -> None:
        """Same seed produces same key."""
        seed = b"0" * 32

        key_one = RootKey.from_seed(seed)
        key_two = RootKey.from_seed(seed)

        assert key_one.did == key_two.did
        assert key_one.to_bytes() == key_two.to_bytes()

    def test_from_seed_invalid_length(self) -> None:
        """Invalid seed length raises KeyError."""
        with pytest.raises(KeyError, match="32 bytes"):
            RootKey.from_seed(b"too short")

    def test_sign(self) -> None:
        """Signing produces 64-byte signature."""
        key = RootKey.generate()
        message = b"test message"

        signature = key.sign(message)

        assert len(signature) == 64

    def test_sign_verify(self) -> None:
        """Signature can be verified."""
        key = RootKey.generate()
        message = b"hello world"

        signature = key.sign(message)
        public_key = bytes(key.verify_key)

        assert verify_bytes(message, signature, public_key)

    def test_roundtrip_bytes(self) -> None:
        """Key can be exported and reimported."""
        original = RootKey.generate()
        exported = original.to_bytes()
        restored = RootKey.from_bytes(exported)

        assert original.did == restored.did

    def test_repr_no_secrets(self) -> None:
        """Repr shows DID but not secrets."""
        key = RootKey.generate()
        repr_str = repr(key)

        assert "did:key:" in repr_str
        assert "secret" not in repr_str.lower()


class TestSessionKey:
    def test_generate(self) -> None:
        """Generate creates valid session key."""
        root = RootKey.generate()
        session = SessionKey.generate(root)

        assert session.root_did == root.did
        assert session.key_id.startswith("session-")

    def test_generate_custom_id(self) -> None:
        """Custom key ID is used."""
        root = RootKey.generate()
        session = SessionKey.generate(root, key_id="my-session")

        assert session.key_id == "my-session"

    def test_full_key_id(self) -> None:
        """full_key_id includes root DID."""
        root = RootKey.generate()
        session = SessionKey.generate(root, key_id="test")

        assert session.full_key_id == f"{root.did}#test"

    def test_sign(self) -> None:
        """Session key can sign messages."""
        root = RootKey.generate()
        session = SessionKey.generate(root)
        message = b"session message"

        signature = session.sign(message)

        assert len(signature) == 64
        assert verify_bytes(message, signature, bytes(session.verify_key))

    def test_repr_truncated_pubkey(self) -> None:
        """Repr shows truncated pubkey."""
        root = RootKey.generate()
        session = SessionKey.generate(root)
        repr_str = repr(session)

        assert "root=" in repr_str
        assert "pubkey=" in repr_str
        assert "..." in repr_str
