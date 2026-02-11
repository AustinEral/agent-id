"""
Message signing and verification using JCS (RFC 8785) canonicalization.

All AIP signatures use:
1. JCS canonicalization of JSON objects
2. UTF-8 encoding to bytes
3. Ed25519 signing
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Union

import canonicaljson
from nacl.signing import VerifyKey

from agent_id.keys import RootKey, SessionKey


def canonicalize(obj: Dict[str, Any]) -> bytes:
    """
    Canonicalize a JSON object using JCS (RFC 8785).
    
    Args:
        obj: A JSON-serializable dictionary
        
    Returns:
        Canonical JSON as UTF-8 bytes
    """
    return canonicaljson.encode_canonical_json(obj)


def sign_message(
    message: Dict[str, Any],
    key: Union[RootKey, SessionKey],
) -> str:
    """
    Sign a JSON message with the given key.
    
    Args:
        message: A JSON-serializable dictionary
        key: The key to sign with (RootKey or SessionKey)
        
    Returns:
        Base64-encoded signature
    """
    canonical = canonicalize(message)
    signature = key.sign(canonical)
    return base64.b64encode(signature).decode("ascii")


def verify_message(
    message: Dict[str, Any],
    signature_b64: str,
    public_key: bytes,
) -> bool:
    """
    Verify a signed JSON message.
    
    Args:
        message: The original JSON message
        signature_b64: Base64-encoded signature
        public_key: 32-byte Ed25519 public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        canonical = canonicalize(message)
        signature = base64.b64decode(signature_b64)
        verify_key = VerifyKey(public_key)
        verify_key.verify(canonical, signature)
        return True
    except Exception:
        return False


def sign_with_metadata(
    message: Dict[str, Any],
    key: Union[RootKey, SessionKey],
) -> Dict[str, Any]:
    """
    Sign a message and return it with attached signature metadata.
    
    Args:
        message: A JSON-serializable dictionary
        key: The key to sign with
        
    Returns:
        The message with a 'proof' field containing signature info
    """
    # Determine key ID
    if isinstance(key, RootKey):
        key_id = f"{key.did}#root"
    else:
        key_id = key.full_key_id
    
    # Create message copy without proof for signing
    message_to_sign = {k: v for k, v in message.items() if k != "proof"}
    
    signature = sign_message(message_to_sign, key)
    
    # Return message with proof
    return {
        **message,
        "proof": {
            "type": "Ed25519Signature2020",
            "verificationMethod": key_id,
            "proofValue": signature,
        },
    }
