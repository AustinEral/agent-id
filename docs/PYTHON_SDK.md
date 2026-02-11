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
from agent_id import sign, verify

signature = sign(message_dict, key)
is_valid = verify(message_dict, signature, public_key)
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

**Docstrings:** Google style, only when not obvious.

```python
def sign(message: dict[str, Any], key: RootKey) -> str:
    """Sign a message. Returns base64 signature."""
    ...
```

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
class SignTestCase:
    message: dict
    should_succeed: bool = True
    exception: type[Exception] | None = None

SIGN_CASES = {
    "simple": SignTestCase(message={"a": 1}),
    "empty": SignTestCase(message={}),
}

@pytest.mark.parametrize(
    argnames=[f.name for f in fields(SignTestCase)],
    argvalues=[astuple(tc) for tc in SIGN_CASES.values()],
    ids=list(SIGN_CASES.keys()),
)
def test_sign(message, should_succeed, exception):
    ...
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
