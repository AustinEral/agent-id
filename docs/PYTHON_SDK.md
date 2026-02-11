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
│   ├── signing.py      # Signer, verify, canonicalize
│   ├── document.py     # DidDocument
│   └── errors.py       # Exception hierarchy
└── tests/
    ├── test_did.py
    ├── test_keys.py
    ├── test_signing.py
    └── test_document.py
```

**Module size:** Split when a module does more than one thing, not by line count. Each module should have a single clear responsibility.

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
- **Pydantic models** for data crossing trust boundaries (validation needed)
- **dataclasses** for internal structures
- **TypedDict** for JSON schemas and API response shapes (no validation, just typing)
- **Generics** when building reusable components

### No `Any`

Avoid `Any` unless interfacing with untyped external code. If you need flexibility, use:
- `object` (for truly unknown types that you won't access)
- Generics with `TypeVar`
- Union types
- Protocols for structural typing

### Class Structure

Organize class members in this order:

```python
class MyClass:
    # 1. Class variables
    DEFAULT_TIMEOUT = 30

    # 2. __init__ and other dunders (__str__, __repr__, __eq__, etc.)
    def __init__(self, value: str) -> None:
        self._value = value

    def __repr__(self) -> str:
        return f"MyClass({self._value!r})"

    # 3. Class methods and static methods
    @classmethod
    def from_string(cls, s: str) -> "MyClass":
        return cls(s)

    # 4. Properties
    @property
    def value(self) -> str:
        return self._value

    # 5. Public methods
    def process(self) -> Result:
        return self._do_work()

    # 6. Private methods (at the bottom)
    def _do_work(self) -> Result:
        ...

    def _validate(self) -> None:
        ...
```

### Naming

- `_private` for internal functions/methods
- `UPPER_SNAKE` for constants
- No abbreviations except well-known: DID, JCS, JWT, etc.
- Class names: `PascalCase`
- Functions/methods: `snake_case`

**Function names:**
- **1 word preferred** — `sign`, `verify`, `parse`
- **2 words okay** — `sign_message`, `from_seed`
- **3 words max** — only if absolutely necessary
- **Never too general** — `process()`, `handle()`, `do()` are banned
- **Self-encapsulating** — the name tells you what it does

```python
# ❌ Bad
def process(data): ...
def do_thing(): ...
def handle_it(x): ...

# ✅ Good
def sign(payload): ...
def verify(signature): ...
def parse(did_string): ...
```

**Variable names:**
- **No single letters** — `x`, `i`, `d` are banned (except `_` for unused)
- **No numbers** — avoid `key1`, `sig2` unless genuinely meaningful
- **Descriptive** — a reader should understand without context

```python
# ❌ Bad
for i in keys:
    s = sign(i)

# ✅ Good
for key in keys:
    signature = sign(key)
```

### Comments

**No inline comments** unless absolutely necessary.

If you need a comment, the code isn't clear enough. Refactor first:

```python
# ❌ Bad — comment explains unclear code
x = data[0:32]  # extract the public key

# ✅ Good — code explains itself
public_key = data[0:32]

# ✅ Also good — extract to named function
public_key = extract_public_key(data)
```

Block comments are okay for **why**, never for **what**:

```python
# ✅ Okay — explains why
# Ed25519 public keys are always 32 bytes per RFC 8032
PUBLIC_KEY_LENGTH = 32

# ❌ Bad — explains what (obvious from code)
# Set the length to 32
PUBLIC_KEY_LENGTH = 32
```

### Docstrings

Google style, only when not obvious.

### Errors

Custom hierarchy with context-rich messages:

```python
class AIPError(Exception):
    """Base exception for agent-id."""

class InvalidDIDError(AIPError):
    """DID format is invalid."""

class SignatureVerificationError(AIPError):
    """Signature verification failed."""
```

Always include context in error messages:

```python
# ❌ Bad
raise SignatureVerificationError("invalid signature")

# ✅ Good
raise SignatureVerificationError(
    f"Signature verification failed for {did}. "
    f"Payload hash: {payload_hash[:16]}..."
)
```

Always chain exceptions:

```python
except SomeError as e:
    raise AIPError("Failed to parse DID document") from e
```

**Type hints:** Full coverage, modern syntax.

```python
def from_public_key(public_key: bytes) -> Did:
    ...
```

---

## Testing

**Coverage:** All public APIs must have tests. Aim for 90%+ on core modules.

**Table-driven with dataclasses:**

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

## Security

Crypto code requires extra care:

- **No `==` on secrets** — Use `secrets.compare_digest()` for timing-safe comparison
- **Use `secrets` module** — Never `random` for cryptographic values
- **Never log keys** — No private keys or signatures in log output
- **Fail closed** — Reject on any verification error, don't try to recover

```python
# ❌ Bad — timing attack
if signature == expected:
    ...

# ✅ Good
if secrets.compare_digest(signature, expected):
    ...
```

## Logging

Optional debug logging, off by default:

```python
import logging

logger = logging.getLogger(__name__)

def verify(...) -> bool:
    logger.debug("Verifying signature for %s", did)
    ...
```

Users enable with:
```python
logging.getLogger("agent_id").setLevel(logging.DEBUG)
```

Never log:
- Private keys
- Full signatures (truncate if needed for debugging)
- Secrets or tokens

## What's NOT Included

- HTTP client for handshakes (integrators handle transport)
- Async variants (not needed for signing)
- Trust layer (separate package)
- Key storage (leave to integrators)

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
