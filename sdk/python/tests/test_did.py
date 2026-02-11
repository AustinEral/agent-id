"""Tests for DID handling."""

from contextlib import nullcontext
from dataclasses import astuple, dataclass, fields

import pytest

from agent_id import Did, InvalidDIDError, RootKey


@dataclass
class DidParseTestCase:
    did_string: str
    expected_key_len: int | None = 32
    exception: type[Exception] | None = None
    exception_pattern: str | None = None


DID_PARSE_CASES = {
    "valid did:key": DidParseTestCase(
        did_string="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    ),
    "invalid prefix did:web": DidParseTestCase(
        did_string="did:web:example.com",
        expected_key_len=None,
        exception=InvalidDIDError,
        exception_pattern="must start with",
    ),
    "invalid multibase prefix": DidParseTestCase(
        did_string="did:key:f6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        expected_key_len=None,
        exception=InvalidDIDError,
        exception_pattern="base58btc",
    ),
    "too short": DidParseTestCase(
        did_string="did:key:z6Mk",
        expected_key_len=None,
        exception=InvalidDIDError,
        exception_pattern="expected 34 bytes",
    ),
}


@pytest.mark.parametrize(
    argnames=[field.name for field in fields(DidParseTestCase)],
    argvalues=[astuple(tc) for tc in DID_PARSE_CASES.values()],
    ids=list(DID_PARSE_CASES.keys()),
)
def test_did_parse(
    did_string: str,
    expected_key_len: int | None,
    exception: type[Exception] | None,
    exception_pattern: str | None,
) -> None:
    context = (
        nullcontext()
        if exception is None
        else pytest.raises(exception, match=exception_pattern)
    )
    with context:
        did = Did.parse(did_string)
        if expected_key_len is not None:
            assert len(did.public_key) == expected_key_len


class TestDid:
    def test_roundtrip(self) -> None:
        """DID can be converted to string and back."""
        key = RootKey.generate()
        original = key.did
        did_string = str(original)
        parsed = Did.parse(did_string)

        assert parsed == original
        assert parsed.public_key == original.public_key

    def test_from_public_key(self) -> None:
        """DID can be created from public key bytes."""
        key = RootKey.generate()
        public_key = bytes(key.verify_key)

        did = Did.from_public_key(public_key)

        assert did == key.did

    def test_key_id_format(self) -> None:
        """key_id has correct format."""
        key = RootKey.generate()
        did = key.did

        assert did.key_id.startswith("z6Mk")

    def test_frozen(self) -> None:
        """DID is immutable."""
        did = RootKey.generate().did

        with pytest.raises(AttributeError):
            did.public_key = b"x" * 32  # type: ignore
