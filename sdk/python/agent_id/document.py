"""DID Document handling for Agent Identity Protocol.

A DID Document describes an agent's identity, including:
- Verification methods (public keys)
- Service endpoints (how to reach the agent)
- Authentication methods
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Self

import base58

from agent_id.did import Did
from agent_id.errors import InvalidSignatureError, ValidationError
from agent_id.keys import RootKey
from agent_id.signing import canonicalize, verify_bytes


@dataclass(frozen=True, slots=True)
class VerificationMethod:
    """A verification method (public key) in a DID Document."""

    id: str
    type: str
    controller: str
    public_key_multibase: str


@dataclass(frozen=True, slots=True)
class Service:
    """A service endpoint in a DID Document."""

    id: str
    type: str
    service_endpoint: str


@dataclass(slots=True)
class DidDocument:
    """A DID Document describing an agent's identity."""

    did: Did
    verification_methods: list[VerificationMethod] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    assertion_method: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    created: datetime | None = None
    updated: datetime | None = None
    proof: dict | None = None

    @classmethod
    def new(cls, root_key: RootKey) -> Self:
        """Create a new DID Document for a root key."""
        did = root_key.did
        key_id = f"{did}#root"

        public_key_multibase = "z" + base58.b58encode(
            bytes(root_key.verify_key)
        ).decode("ascii")

        verification_method = VerificationMethod(
            id=key_id,
            type="Ed25519VerificationKey2020",
            controller=str(did),
            public_key_multibase=public_key_multibase,
        )

        now = datetime.now(UTC)

        return cls(
            did=did,
            verification_methods=[verification_method],
            authentication=[key_id],
            assertion_method=[key_id],
            created=now,
            updated=now,
        )

    def with_handshake_endpoint(self, endpoint: str) -> Self:
        """Add a handshake service endpoint. Returns new document."""
        service = Service(
            id=f"{self.did}#handshake",
            type="AIPHandshake",
            service_endpoint=endpoint,
        )
        return self._with_service(service)

    def with_service(self, service_id: str, service_type: str, endpoint: str) -> Self:
        """Add a custom service endpoint. Returns new document."""
        service = Service(
            id=f"{self.did}#{service_id}",
            type=service_type,
            service_endpoint=endpoint,
        )
        return self._with_service(service)

    def _with_service(self, service: Service) -> Self:
        """Internal: add a service and return new document."""
        return DidDocument(
            did=self.did,
            verification_methods=self.verification_methods,
            authentication=self.authentication,
            assertion_method=self.assertion_method,
            services=[*self.services, service],
            created=self.created,
            updated=datetime.now(UTC),
            proof=None,
        )

    def to_dict(self, include_proof: bool = True) -> dict:
        """Serialize to a JSON-compatible dict."""
        doc: dict = {
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
                    "id": svc.id,
                    "type": svc.type,
                    "serviceEndpoint": svc.service_endpoint,
                }
                for svc in self.services
            ]

        if self.created:
            doc["created"] = self.created.isoformat().replace("+00:00", "Z")

        if self.updated:
            doc["updated"] = self.updated.isoformat().replace("+00:00", "Z")

        if include_proof and self.proof:
            doc["proof"] = self.proof

        return doc

    def sign(self, key: RootKey) -> Self:
        """Sign this document. Returns new signed document."""
        if key.did != self.did:
            raise ValidationError(
                f"Key DID {key.did} doesn't match document DID {self.did}"
            )

        doc_dict = self.to_dict(include_proof=False)
        canonical = canonicalize(doc_dict)
        signature = key.sign(canonical)

        import base64

        proof = {
            "type": "Ed25519Signature2020",
            "created": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "verificationMethod": f"{self.did}#root",
            "proofValue": base64.b64encode(signature).decode("ascii"),
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
        """Verify the document's signature.

        Raises:
            ValidationError: If document has no proof.
            InvalidSignatureError: If signature is invalid.
        """
        if not self.proof:
            raise ValidationError("Document has no proof to verify")

        doc_dict = self.to_dict(include_proof=False)
        canonical = canonicalize(doc_dict)

        import base64

        signature = base64.b64decode(self.proof.get("proofValue", ""))

        if not verify_bytes(canonical, signature, self.did.public_key):
            raise InvalidSignatureError("Document signature verification failed")

        return True

    def __repr__(self) -> str:
        status = "signed" if self.proof else "unsigned"
        return f"DidDocument({self.did}, {status})"
