"""Tests for DID Document handling."""

import pytest

from agent_id import (
    DidDocument,
    InvalidSignatureError,
    RootKey,
    ValidationError,
)


class TestDidDocument:
    def test_new(self) -> None:
        """DidDocument.new creates valid document."""
        key = RootKey.generate()
        doc = DidDocument.new(key)

        assert doc.did == key.did
        assert len(doc.verification_methods) == 1
        assert doc.proof is None

    def test_to_dict(self) -> None:
        """Document can be serialized."""
        key = RootKey.generate()
        doc = DidDocument.new(key)

        result = doc.to_dict()

        assert result["id"] == str(key.did)
        assert "@context" in result
        assert "verificationMethod" in result

    def test_with_handshake_endpoint(self) -> None:
        """Handshake endpoint can be added."""
        key = RootKey.generate()
        doc = DidDocument.new(key)
        doc = doc.with_handshake_endpoint("https://example.com/aip")

        assert len(doc.services) == 1
        assert doc.services[0].type == "AIPHandshake"
        assert doc.services[0].service_endpoint == "https://example.com/aip"

    def test_with_service(self) -> None:
        """Custom service can be added."""
        key = RootKey.generate()
        doc = DidDocument.new(key)
        doc = doc.with_service("agent", "AgentService", "https://example.com/agent")

        assert len(doc.services) == 1
        assert doc.services[0].type == "AgentService"
        assert doc.services[0].id == f"{key.did}#agent"

    def test_immutable_builder(self) -> None:
        """Builder methods return new documents."""
        key = RootKey.generate()
        doc_one = DidDocument.new(key)
        doc_two = doc_one.with_handshake_endpoint("https://example.com")

        assert len(doc_one.services) == 0
        assert len(doc_two.services) == 1

    def test_sign(self) -> None:
        """Document can be signed."""
        key = RootKey.generate()
        doc = DidDocument.new(key)

        signed = doc.sign(key)

        assert signed.proof is not None
        assert "proofValue" in signed.proof

    def test_sign_wrong_key(self) -> None:
        """Signing with wrong key raises error."""
        key_one = RootKey.generate()
        key_two = RootKey.generate()
        doc = DidDocument.new(key_one)

        with pytest.raises(ValidationError, match="doesn't match"):
            doc.sign(key_two)

    def test_verify_valid(self) -> None:
        """Valid signature verifies."""
        key = RootKey.generate()
        doc = DidDocument.new(key).sign(key)

        assert doc.verify() is True

    def test_verify_unsigned(self) -> None:
        """Verifying unsigned document raises error."""
        key = RootKey.generate()
        doc = DidDocument.new(key)

        with pytest.raises(ValidationError, match="no proof"):
            doc.verify()

    def test_verify_tampered(self) -> None:
        """Tampered signature fails verification."""
        key = RootKey.generate()
        doc = DidDocument.new(key).sign(key)

        assert doc.proof is not None
        tampered_proof = dict(doc.proof)
        tampered_proof["proofValue"] = "tampered"

        tampered_doc = DidDocument(
            did=doc.did,
            verification_methods=doc.verification_methods,
            authentication=doc.authentication,
            assertion_method=doc.assertion_method,
            services=doc.services,
            created=doc.created,
            updated=doc.updated,
            proof=tampered_proof,
        )

        with pytest.raises(InvalidSignatureError):
            tampered_doc.verify()

    def test_services_in_dict(self) -> None:
        """Services appear in serialized dict."""
        key = RootKey.generate()
        doc = (
            DidDocument.new(key)
            .with_handshake_endpoint("https://example.com/aip")
            .with_service("agent", "AgentService", "https://example.com/agent")
        )

        result = doc.to_dict()

        assert "service" in result
        assert len(result["service"]) == 2

    def test_repr(self) -> None:
        """Repr shows signed status."""
        key = RootKey.generate()
        unsigned = DidDocument.new(key)
        signed = unsigned.sign(key)

        assert "unsigned" in repr(unsigned)
        assert "signed" in repr(signed)
