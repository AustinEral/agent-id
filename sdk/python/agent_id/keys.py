"""
Key management for Agent Identity Protocol.

Provides RootKey (long-lived identity key) and SessionKey (short-lived delegated key).
Uses Ed25519 for all cryptographic operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder

from agent_id.did import Did


@dataclass
class RootKey:
    """
    The root identity key for an agent.
    
    This is the long-lived key that defines the agent's identity (DID).
    Should be stored securely and used sparingly - prefer session keys
    for routine operations.
    
    Attributes:
        signing_key: The Ed25519 signing key (private)
        verify_key: The Ed25519 verify key (public)
        did: The agent's DID derived from the public key
    """
    
    signing_key: SigningKey
    verify_key: VerifyKey
    did: Did
    
    @classmethod
    def generate(cls) -> RootKey:
        """
        Generate a new random root key.
        
        Returns:
            A new RootKey with a fresh Ed25519 keypair
        """
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        public_key_bytes = bytes(verify_key)
        did = Did.from_public_key(public_key_bytes)
        
        return cls(
            signing_key=signing_key,
            verify_key=verify_key,
            did=did,
        )
    
    @classmethod
    def from_seed(cls, seed: bytes) -> RootKey:
        """
        Create a root key from a 32-byte seed.
        
        Args:
            seed: 32-byte seed for deterministic key generation
            
        Returns:
            A RootKey derived from the seed
            
        Raises:
            ValueError: If seed is not 32 bytes
        """
        if len(seed) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")
        
        signing_key = SigningKey(seed)
        verify_key = signing_key.verify_key
        public_key_bytes = bytes(verify_key)
        did = Did.from_public_key(public_key_bytes)
        
        return cls(
            signing_key=signing_key,
            verify_key=verify_key,
            did=did,
        )
    
    @classmethod
    def from_bytes(cls, private_key_bytes: bytes) -> RootKey:
        """
        Create a root key from raw private key bytes.
        
        Args:
            private_key_bytes: 32-byte Ed25519 private key
            
        Returns:
            A RootKey from the provided private key
        """
        return cls.from_seed(private_key_bytes)
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with this root key.
        
        Args:
            message: The message bytes to sign
            
        Returns:
            64-byte Ed25519 signature
        """
        signed = self.signing_key.sign(message, encoder=RawEncoder)
        return signed.signature
    
    def to_bytes(self) -> bytes:
        """
        Export the private key as bytes.
        
        Warning: Handle with care - this is the root identity!
        
        Returns:
            32-byte private key
        """
        return bytes(self.signing_key)
    
    def __repr__(self) -> str:
        return f"RootKey(did={self.did})"


@dataclass
class SessionKey:
    """
    A short-lived session key delegated from a root key.
    
    Session keys are used for routine operations to limit exposure
    of the root key. They should be rotated frequently.
    
    Attributes:
        signing_key: The Ed25519 signing key (private)
        verify_key: The Ed25519 verify key (public)
        root_did: The DID of the root key that delegated this session
        key_id: Identifier for this session key (e.g., "session-1")
    """
    
    signing_key: SigningKey
    verify_key: VerifyKey
    root_did: Did
    key_id: str
    
    @classmethod
    def generate(cls, root_key: RootKey, key_id: Optional[str] = None) -> SessionKey:
        """
        Generate a new session key delegated from a root key.
        
        Args:
            root_key: The root key to delegate from
            key_id: Optional identifier for this session key
            
        Returns:
            A new SessionKey
        """
        import secrets
        
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        
        if key_id is None:
            key_id = f"session-{secrets.token_hex(4)}"
        
        return cls(
            signing_key=signing_key,
            verify_key=verify_key,
            root_did=root_key.did,
            key_id=key_id,
        )
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with this session key.
        
        Args:
            message: The message bytes to sign
            
        Returns:
            64-byte Ed25519 signature
        """
        signed = self.signing_key.sign(message, encoder=RawEncoder)
        return signed.signature
    
    @property
    def full_key_id(self) -> str:
        """The full key ID including the root DID."""
        return f"{self.root_did}#{self.key_id}"
    
    def __repr__(self) -> str:
        return f"SessionKey(root={self.root_did}, id={self.key_id})"


def verify_signature(
    message: bytes,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """
    Verify an Ed25519 signature.
    
    Args:
        message: The original message bytes
        signature: The 64-byte signature
        public_key: The 32-byte public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except Exception:
        return False
