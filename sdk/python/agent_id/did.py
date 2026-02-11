"""
DID (Decentralized Identifier) handling for Agent Identity Protocol.

Uses the did:key method with Ed25519 public keys.
Format: did:key:z<base58btc(multicodec + ed25519_public_key)>
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import base58


# Multicodec prefix for Ed25519 public key
ED25519_MULTICODEC = bytes([0xED, 0x01])

# did:key pattern
DID_KEY_PATTERN = re.compile(r"^did:key:z([1-9A-HJ-NP-Za-km-z]+)$")


@dataclass(frozen=True)
class Did:
    """
    A Decentralized Identifier using the did:key method.
    
    Attributes:
        value: The full DID string (e.g., did:key:z6Mk...)
        public_key: The raw Ed25519 public key bytes (32 bytes)
    """
    
    value: str
    public_key: bytes
    
    @classmethod
    def from_public_key(cls, public_key: bytes) -> Did:
        """
        Create a DID from an Ed25519 public key.
        
        Args:
            public_key: 32-byte Ed25519 public key
            
        Returns:
            A Did instance
            
        Raises:
            ValueError: If public key is not 32 bytes
        """
        if len(public_key) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_key)}")
        
        # Encode: multicodec prefix + public key
        multicodec_key = ED25519_MULTICODEC + public_key
        
        # Base58btc encode (with 'z' prefix per multibase)
        encoded = base58.b58encode(multicodec_key).decode("ascii")
        
        did_value = f"did:key:z{encoded}"
        return cls(value=did_value, public_key=public_key)
    
    @classmethod
    def parse(cls, did_string: str) -> Did:
        """
        Parse a did:key string.
        
        Args:
            did_string: A did:key formatted string
            
        Returns:
            A Did instance
            
        Raises:
            ValueError: If the DID format is invalid
        """
        match = DID_KEY_PATTERN.match(did_string)
        if not match:
            raise ValueError(f"Invalid did:key format: {did_string}")
        
        # Decode base58btc (without 'z' prefix)
        encoded = match.group(1)
        decoded = base58.b58decode(encoded)
        
        # Verify multicodec prefix
        if not decoded.startswith(ED25519_MULTICODEC):
            raise ValueError(f"Expected Ed25519 multicodec prefix, got {decoded[:2].hex()}")
        
        public_key = decoded[len(ED25519_MULTICODEC):]
        
        if len(public_key) != 32:
            raise ValueError(f"Invalid public key length: {len(public_key)}")
        
        return cls(value=did_string, public_key=public_key)
    
    def __str__(self) -> str:
        return self.value
    
    def __repr__(self) -> str:
        return f"Did({self.value!r})"
