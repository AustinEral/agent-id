"""Key management for AIP identities.

Security:
- Keys use Ed25519 via PyNaCl (libsodium bindings)
- Debug representations only show public info (DID), not secrets
- Use secrets module for cryptographic randomness
"""

import secrets
from typing import Self

import base58
from nacl.signing import SigningKey, VerifyKey

from agent_id.did import Did
from agent_id.errors import KeyError


class RootKey:
    """A root identity key.

    This is the primary key that defines an agent's identity.
    Store securely and use sparingly.
    """

    __slots__ = ("_signing_key", "_did")

    def __init__(self, signing_key: SigningKey) -> None:
        self._signing_key = signing_key
        public_key = bytes(signing_key.verify_key)
        self._did = Did.from_public_key(public_key)

    @classmethod
    def generate(cls) -> Self:
        """Generate a new random root key."""
        signing_key = SigningKey.generate()
        return cls(signing_key)

    @classmethod
    def from_seed(cls, seed: bytes) -> Self:
        """Create from a 32-byte seed.

        Args:
            seed: Exactly 32 bytes of seed material.

        Raises:
            KeyError: If seed is not 32 bytes.
        """
        if len(seed) != 32:
            raise KeyError(f"seed must be 32 bytes, got {len(seed)}")
        signing_key = SigningKey(seed)
        return cls(signing_key)

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Create from raw private key bytes."""
        return cls.from_seed(key_bytes)

    @property
    def did(self) -> Did:
        """Get the DID for this root key."""
        return self._did

    @property
    def verify_key(self) -> VerifyKey:
        """Get the public verifying key."""
        return self._signing_key.verify_key

    def sign(self, message: bytes) -> bytes:
        """Sign a message. Returns 64-byte signature."""
        signed = self._signing_key.sign(message)
        return bytes(signed.signature)

    def to_bytes(self) -> bytes:
        """Export the secret key bytes.

        Warning: Handle with care. Zeroize when done.
        """
        return bytes(self._signing_key)

    def __repr__(self) -> str:
        return f"RootKey(did={self._did})"


class SessionKey:
    """A session key delegated from a root key.

    Used for day-to-day operations without exposing the root key.
    Should be short-lived and rotated frequently.
    """

    __slots__ = ("_signing_key", "_root_did", "_key_id")

    def __init__(self, signing_key: SigningKey, root_did: Did, key_id: str) -> None:
        self._signing_key = signing_key
        self._root_did = root_did
        self._key_id = key_id

    @classmethod
    def generate(cls, root_key: RootKey, key_id: str | None = None) -> Self:
        """Generate a new session key for a root identity.

        Args:
            root_key: The root key this session belongs to.
            key_id: Optional identifier. Auto-generated if not provided.
        """
        signing_key = SigningKey.generate()
        if key_id is None:
            key_id = f"session-{secrets.token_hex(4)}"
        return cls(signing_key, root_key.did, key_id)

    @property
    def root_did(self) -> Did:
        """Get the root DID this session key belongs to."""
        return self._root_did

    @property
    def key_id(self) -> str:
        """Get the key identifier."""
        return self._key_id

    @property
    def full_key_id(self) -> str:
        """Get the full key ID including root DID."""
        return f"{self._root_did}#{self._key_id}"

    @property
    def verify_key(self) -> VerifyKey:
        """Get the public verifying key."""
        return self._signing_key.verify_key

    def sign(self, message: bytes) -> bytes:
        """Sign a message. Returns 64-byte signature."""
        signed = self._signing_key.sign(message)
        return bytes(signed.signature)

    @property
    def public_key_base58(self) -> str:
        """Get the public key as base58."""
        return base58.b58encode(bytes(self._signing_key.verify_key)).decode("ascii")

    def __repr__(self) -> str:
        fingerprint = self.public_key_base58[:8]
        return f"SessionKey(root={self._root_did}, pubkey={fingerprint}...)"
