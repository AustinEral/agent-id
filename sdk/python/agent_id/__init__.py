"""Agent Identity Protocol - Python SDK.

Cryptographic identity and mutual authentication for AI agents.

Example:
    >>> from agent_id import RootKey
    >>> key = RootKey.generate()
    >>> print(key.did)
    did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y

For full documentation, see:
https://github.com/AustinEral/agent-id/tree/main/sdk/python
"""

from agent_id.did import Did
from agent_id.document import DidDocument, Service, VerificationMethod
from agent_id.errors import (
    AIPError,
    InvalidDIDError,
    InvalidSignatureError,
    KeyError,
    SerializationError,
    ValidationError,
)
from agent_id.keys import RootKey, SessionKey
from agent_id.signing import (
    canonicalize,
    constant_time_compare,
    hash_canonical,
    sign_bytes,
    sign_dict,
    sign_model,
    verify_bytes,
    verify_dict,
    verify_dict_strict,
)

__version__ = "0.1.0"

__all__ = [
    # Core
    "Did",
    "RootKey",
    "SessionKey",
    # Document
    "DidDocument",
    "Service",
    "VerificationMethod",
    # Signing
    "canonicalize",
    "constant_time_compare",
    "hash_canonical",
    "sign_bytes",
    "sign_dict",
    "sign_model",
    "verify_bytes",
    "verify_dict",
    "verify_dict_strict",
    # Errors
    "AIPError",
    "InvalidDIDError",
    "InvalidSignatureError",
    "KeyError",
    "SerializationError",
    "ValidationError",
]
