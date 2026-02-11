"""
DID Document handling for Agent Identity Protocol.

A DID Document describes an agent's identity, including:
- Verification methods (public keys)
- Service endpoints (how to reach the agent)
- Authentication methods
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agent_id.did import Did
from agent_id.keys import RootKey
from agent_id.signing import canonicalize, sign_message, verify_message


@dataclass
class VerificationMethod:
    """A verification method (public key) in a DID Document."""
    
    id: str
    type: str
    controller: str
    public_key_multibase: str


@dataclass
class Service:
    """A service endpoint in a DID Document."""
    
    id: str
    type: str
    service_endpoint: str


@dataclass
class DidDocument:
    """
    A DID Document describing an agent's identity.
    
    Example:
        >>> key = RootKey.generate()
        >>> doc = DidDocument.new(key)
        >>> doc = doc.with_handshake_endpoint("https://agent.example/aip")
        >>> signed_doc = doc.sign(key)
    """
    
    did: Did
    verification_methods: List[VerificationMethod] = field(default_factory=list)
    authentication: List[str] = field(default_factory=list)
    assertion_method: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    proof: Optional[Dict[str, Any]] = None
    
    @classmethod
    def new(cls, root_key: RootKey) -> DidDocument:
        """
        Create a new DID Document for a root key.
        
        Args:
            root_key: The agent's root key
            
        Returns:
            An unsigned DID Document
        """
        import base58
        
        did = root_key.did
        key_id = f"{did}#root"
        
        # Encode public key as multibase (z = base58btc)
        public_key_multibase = "z" + base58.b58encode(bytes(root_key.verify_key)).decode("ascii")
        
        verification_method = VerificationMethod(
            id=key_id,
            type="Ed25519VerificationKey2020",
            controller=str(did),
            public_key_multibase=public_key_multibase,
        )
        
        now = datetime.now(timezone.utc)
        
        return cls(
            did=did,
            verification_methods=[verification_method],
            authentication=[key_id],
            assertion_method=[key_id],
            created=now,
            updated=now,
        )
    
    def with_handshake_endpoint(self, endpoint: str) -> DidDocument:
        """
        Add a handshake service endpoint.
        
        Args:
            endpoint: The URL for AIP handshake
            
        Returns:
            A new DidDocument with the service added
        """
        service = Service(
            id=f"{self.did}#handshake",
            type="AIPHandshake",
            service_endpoint=endpoint,
        )
        
        return DidDocument(
            did=self.did,
            verification_methods=self.verification_methods,
            authentication=self.authentication,
            assertion_method=self.assertion_method,
            services=[*self.services, service],
            created=self.created,
            updated=datetime.now(timezone.utc),
            proof=None,  # Clear proof since document changed
        )
    
    def with_service(self, service_id: str, service_type: str, endpoint: str) -> DidDocument:
        """
        Add a custom service endpoint.
        
        Args:
            service_id: Short ID for the service (will be prefixed with DID)
            service_type: The service type
            endpoint: The service URL
            
        Returns:
            A new DidDocument with the service added
        """
        service = Service(
            id=f"{self.did}#{service_id}",
            type=service_type,
            service_endpoint=endpoint,
        )
        
        return DidDocument(
            did=self.did,
            verification_methods=self.verification_methods,
            authentication=self.authentication,
            assertion_method=self.assertion_method,
            services=[*self.services, service],
            created=self.created,
            updated=datetime.now(timezone.utc),
            proof=None,
        )
    
    def to_dict(self, include_proof: bool = True) -> Dict[str, Any]:
        """
        Convert to a JSON-serializable dictionary.
        
        Args:
            include_proof: Whether to include the proof field
            
        Returns:
            DID Document as a dictionary
        """
        doc: Dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://aip.network/v1",
            ],
            "id": str(self.did),
            "controller": str(self.did),
            "verificationMethod": [
                {
                    "id": vm.id,
                    "type": vm.type,
                    "controller": vm.controller,
                    "publicKeyMultibase": vm.public_key_multibase,
                }
                for vm in self.verification_methods
            ],
            "authentication": self.authentication,
            "assertionMethod": self.assertion_method,
        }
        
        if self.services:
            doc["service"] = [
                {
                    "id": s.id,
                    "type": s.type,
                    "serviceEndpoint": s.service_endpoint,
                }
                for s in self.services
            ]
        
        if self.created:
            doc["created"] = self.created.isoformat().replace("+00:00", "Z")
        
        if self.updated:
            doc["updated"] = self.updated.isoformat().replace("+00:00", "Z")
        
        if include_proof and self.proof:
            doc["proof"] = self.proof
        
        return doc
    
    def sign(self, key: RootKey) -> DidDocument:
        """
        Sign this DID Document.
        
        Args:
            key: The root key to sign with (must match document DID)
            
        Returns:
            A new DidDocument with proof attached
            
        Raises:
            ValueError: If key doesn't match document DID
        """
        if key.did != self.did:
            raise ValueError(f"Key DID {key.did} doesn't match document DID {self.did}")
        
        # Get document without proof for signing
        doc_dict = self.to_dict(include_proof=False)
        
        signature = sign_message(doc_dict, key)
        
        proof = {
            "type": "Ed25519Signature2020",
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "verificationMethod": f"{self.did}#root",
            "proofValue": signature,
        }
        
        return DidDocument(
            did=self.did,
            verification_methods=self.verification_methods,
            authentication=self.authentication,
            assertion_method=self.assertion_method,
            services=self.services,
            created=self.created,
            updated=self.updated,
            proof=proof,
        )
    
    def verify(self) -> bool:
        """
        Verify the document's signature.
        
        Returns:
            True if signature is valid
            
        Raises:
            ValueError: If document has no proof
        """
        if not self.proof:
            raise ValueError("Document has no proof to verify")
        
        # Get document without proof
        doc_dict = self.to_dict(include_proof=False)
        
        signature_b64 = self.proof.get("proofValue", "")
        
        return verify_message(doc_dict, signature_b64, self.did.public_key)
    
    def __repr__(self) -> str:
        signed = "signed" if self.proof else "unsigned"
        return f"DidDocument({self.did}, {signed})"
