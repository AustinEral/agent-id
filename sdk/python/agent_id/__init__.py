"""
Agent Identity Protocol - Python SDK

Cryptographic identity and mutual authentication for AI agents.

Example:
    >>> from agent_id import RootKey
    >>> key = RootKey.generate()
    >>> print(key.did)
    did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y
"""

from agent_id.keys import RootKey, SessionKey
from agent_id.did import Did
from agent_id.signing import sign_message, verify_message
from agent_id.document import DidDocument

__version__ = "0.1.0"

__all__ = [
    "RootKey",
    "SessionKey", 
    "Did",
    "DidDocument",
    "sign_message",
    "verify_message",
]
