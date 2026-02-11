"""JCS canonicalization and message signing.

Uses RFC 8785 JSON Canonicalization Scheme for deterministic
JSON serialization, ensuring signatures are verifiable across
different implementations.
"""

import base64
import hashlib
import secrets
from typing import TYPE_CHECKING

import canonicaljson
from nacl.signing import VerifyKey

from agent_id.errors import InvalidSignatureError, SerializationError

if TYPE_CHECKING:
    from pydantic import BaseModel

    from agent_id.keys import RootKey, SessionKey


def canonicalize(value: dict) -> bytes:
    """Canonicalize a dict using JCS (RFC 8785).

    Returns deterministic bytes suitable for signing.
    """
    try:
        return canonicaljson.encode_canonical_json(value)
    except Exception as exc:
        raise SerializationError(f"JCS canonicalization failed: {exc}") from exc


def hash_canonical(value: dict) -> bytes:
    """SHA-256 hash of canonical JSON.

    This is the standard way to prepare data for signing in AIP.
    """
    canonical = canonicalize(value)
    return hashlib.sha256(canonical).digest()


def sign_bytes(message: bytes, key: "RootKey | SessionKey") -> bytes:
    """Sign raw bytes. Returns 64-byte signature."""
    return key.sign(message)


def sign_dict(value: dict, key: "RootKey | SessionKey") -> str:
    """Sign a dict using JCS canonicalization.

    Returns base64-encoded signature.
    """
    canonical = canonicalize(value)
    signature = key.sign(canonical)
    return base64.b64encode(signature).decode("ascii")


def sign_model(model: "BaseModel", key: "RootKey | SessionKey") -> str:
    """Sign a Pydantic model using JCS canonicalization.

    Returns base64-encoded signature.
    """
    value = model.model_dump(mode="json")
    return sign_dict(value, key)


def verify_bytes(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a signature on raw bytes.

    Uses constant-time comparison to prevent timing attacks.
    """
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except Exception:
        return False


def verify_dict(value: dict, signature_b64: str, public_key: bytes) -> bool:
    """Verify a signature on a dict.

    Args:
        value: The original dict.
        signature_b64: Base64-encoded signature.
        public_key: 32-byte Ed25519 public key.

    Returns:
        True if valid, False otherwise.
    """
    try:
        canonical = canonicalize(value)
        signature = base64.b64decode(signature_b64)
        return verify_bytes(canonical, signature, public_key)
    except Exception:
        return False


def verify_dict_strict(value: dict, signature_b64: str, public_key: bytes) -> None:
    """Verify a signature on a dict, raising on failure.

    Raises:
        InvalidSignatureError: If verification fails.
    """
    if not verify_dict(value, signature_b64, public_key):
        payload_hash = hash_canonical(value).hex()[:16]
        raise InvalidSignatureError(
            f"Signature verification failed. Payload hash: {payload_hash}..."
        )


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return secrets.compare_digest(a, b)
