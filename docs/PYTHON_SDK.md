# Python SDK Specification

> **Status:** Proposal  
> **Author:** Donovan Eral  
> **Date:** February 2026

---

## Overview

A Python implementation of the Agent Identity Protocol core functionality, enabling Python-based AI agents to generate identities, sign messages, and participate in AIP handshakes.

## Principles

- **YAGNI** — Don't build it until you need it
- **SOLID** — Single responsibility, clean interfaces
- **Clean code** — Readable, minimal, no cleverness
- **Fail fast** — Raise early on bad input

---

## Project Setup

```toml
[project]
name = "agent-id"
version = "0.1.0"
requires-python = ">=3.12"

dependencies = [
    "pynacl>=1.5.0",
    "canonicaljson>=2.0.0",
    "base58>=2.1.0",
]

[dependency-groups]
dev = [
    "mypy>=1.19.0",
    "pytest>=8.0.0",
    "ruff>=0.13.0",
]

[tool.ruff]
line-length = 99
target-version = "py312"

[tool.ruff.lint]
select = ["E4", "E7", "E9", "F", "I"]

[tool.ruff.format]
quote-style = "double"

[tool.mypy]
python_version = "3.12"
strict = true
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v"
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `pynacl` | Ed25519 signing (libsodium bindings) |
| `canonicaljson` | JCS (RFC 8785) |
| `base58` | Base58btc encoding for did:key |

Minimal. No extras.

---

## Module Structure

```
sdk/python/
├── pyproject.toml
├── README.md
├── agent_id/
│   ├── __init__.py
│   ├── did.py          # Did class
│   ├── keys.py         # RootKey, SessionKey
│   ├── signing.py      # sign, verify, canonicalize
│   ├── document.py     # DidDocument
│   └── errors.py       # Exception hierarchy
└── tests/
    ├── test_did.py
    ├── test_keys.py
    ├── test_signing.py
    └── test_document.py
```

---

## API Design

### Keys

```python
from agent_id import RootKey, SessionKey

# Generate
key = RootKey.generate()
print(key.did)  # did:key:z6Mk...

# From seed (deterministic)
key = RootKey.from_seed(bytes_32)

# Session keys
session = SessionKey.generate(root_key)
```

### Signing

```python
from agent_id import Signer

signer = Signer(key)

# Sign raw bytes
signature = signer.sign(payload: bytes)

# Sign a model (uses JCS canonicalization)
signed = signer.sign_model(my_pydantic_model)

# Verify
is_valid = signer.verify(payload, signature, public_key)
```

### DID Documents

```python
from agent_id import DidDocument

doc = (
    DidDocument.new(key)
    .with_handshake_endpoint("https://agent.example/aip")
    .sign(key)
)

assert doc.verify()
```

---

## Code Style

### No Loose Dicts

Never use `dict[str, Any]` to pass data around. Always define the shape:

```python
# ❌ Bad — what's in this dict?
def sign(message: dict[str, Any], key: RootKey) -> str:
    ...

# ✅ Good — explicit model
class SignedMessage(BaseModel):
    payload: bytes
    signature: str
    signer: Did

def sign(message: Message, key: RootKey) -> SignedMessage:
    ...
```

Use:
- **Pydantic models** for data crossing boundaries
- **dataclasses** for internal structures
- **TypedDict** only if you must interface with untyped JSON
- **Generics** when building reusable components

### No `Any`

Avoid `Any` unless interfacing with untyped external code. If you need flexibility, use:
- `object` (for truly unknown types that you won't access)
- Generics with `TypeVar`
- Union types
- Protocols for structural typing

### Docstrings

Google style, only when not obvious.

**Errors:** Custom hierarchy, clear messages.

```python
class AIPError(Exception):
    """Base exception."""

class InvalidDIDError(AIPError):
    """DID format is invalid."""
```

**Type hints:** Full coverage, modern syntax.

```python
def from_public_key(public_key: bytes) -> Did:
    ...
```

---

## Testing

Table-driven with dataclasses:

```python
from dataclasses import dataclass, fields, astuple
from contextlib import nullcontext

@dataclass
class DidParseTestCase:
    did_string: str
    expected_public_key_len: int | None = 32
    exception: type[Exception] | None = None
    exception_message: str | None = None

DID_PARSE_CASES = {
    "valid did:key": DidParseTestCase(
        did_string="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    ),
    "invalid prefix": DidParseTestCase(
        did_string="did:web:example.com",
        expected_public_key_len=None,
        exception=InvalidDIDError,
        exception_message="Invalid did:key format",
    ),
}

@pytest.mark.parametrize(
    argnames=[f.name for f in fields(DidParseTestCase)],
    argvalues=[astuple(tc) for tc in DID_PARSE_CASES.values()],
    ids=list(DID_PARSE_CASES.keys()),
)
def test_did_parse(
    did_string: str,
    expected_public_key_len: int | None,
    exception: type[Exception] | None,
    exception_message: str | None,
) -> None:
    with nullcontext() if exception is None else pytest.raises(exception, match=exception_message):
        did = Did.parse(did_string)
        if expected_public_key_len is not None:
            assert len(did.public_key) == expected_public_key_len
```

---

## What's NOT Included

- HTTP client for handshakes (integrators handle transport)
- Async variants (not needed for signing)
- Trust layer (separate package)
- Key storage (leave to integrators)
- Logging (not needed at this layer)

---

## Compatibility

DIDs and signatures are interoperable with the Rust SDK.

| Rust | Python |
|------|--------|
| `RootKey::generate()` | `RootKey.generate()` |
| `key.did()` | `key.did` |
| `Did::parse()` | `Did.parse()` |
| `.sign()` | `.sign()` |
| `.verify()` | `.verify()` |

---

## Checklist

- [ ] Review spec with Austin
- [ ] Align implementation with spec
- [ ] Cross-implementation tests
- [ ] README with examples
- [ ] PyPI publish setup
