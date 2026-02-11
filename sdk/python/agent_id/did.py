"""Decentralized Identifier (DID) handling.

Format: did:key:z<base58btc(multicodec_prefix + ed25519_public_key)>

Uses the did:key method (W3C standard) with Ed25519 keys.
- Multicodec prefix: 0xed01 (Ed25519 public key)
- Multibase prefix: z (base58btc)
"""

from dataclasses import dataclass

import base58

from agent_id.errors import InvalidDIDError

# Ed25519 public key multicodec prefix (varint-encoded 0xed)
ED25519_MULTICODEC = bytes([0xED, 0x01])

# Multibase prefix for base58btc
BASE58BTC_PREFIX = "z"


@dataclass(frozen=True, slots=True)
class Did:
    """A parsed DID (did:key method).

    Attributes:
        public_key: The 32-byte Ed25519 public key.
    """

    public_key: bytes

    def __post_init__(self) -> None:
        if len(self.public_key) != 32:
            raise InvalidDIDError(f"public key must be 32 bytes, got {len(self.public_key)}")

    @classmethod
    def from_public_key(cls, public_key: bytes) -> "Did":
        """Create a DID from an Ed25519 public key."""
        return cls(public_key=public_key)

    @classmethod
    def parse(cls, did_string: str) -> "Did":
        """Parse a did:key string.

        Args:
            did_string: A did:key formatted string.

        Returns:
            A Did instance.

        Raises:
            InvalidDIDError: If the format is invalid.
        """
        prefix = "did:key:"
        if not did_string.startswith(prefix):
            raise InvalidDIDError("must start with 'did:key:'")

        key_part = did_string[len(prefix) :]

        if not key_part.startswith(BASE58BTC_PREFIX):
            raise InvalidDIDError("must use base58btc encoding (z prefix)")

        encoded = key_part[1:]

        try:
            decoded = base58.b58decode(encoded)
        except Exception as exc:
            raise InvalidDIDError(f"invalid base58 encoding: {exc}") from exc

        if len(decoded) != 34:
            raise InvalidDIDError(f"expected 34 bytes, got {len(decoded)}")

        if decoded[:2] != ED25519_MULTICODEC:
            raise InvalidDIDError("unsupported key type (expected Ed25519 multicodec 0xed01)")

        public_key = decoded[2:]
        return cls(public_key=public_key)

    @property
    def key_id(self) -> str:
        """Get the multibase-encoded key portion (without did:key: prefix)."""
        combined = ED25519_MULTICODEC + self.public_key
        encoded = base58.b58encode(combined).decode("ascii")
        return f"{BASE58BTC_PREFIX}{encoded}"

    def __str__(self) -> str:
        return f"did:key:{self.key_id}"

    def __repr__(self) -> str:
        return f"Did({self})"
