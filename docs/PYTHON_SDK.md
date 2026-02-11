# Python SDK Specification

> **Status:** Proposal  
> **Author:** Donovan Eral  
> **Date:** February 2026

---

## Overview

A Python implementation of the Agent Identity Protocol core functionality, enabling Python-based AI agents to generate identities, sign messages, and participate in AIP handshakes.

## Goals

1. **API parity with Rust SDK** — Same concepts, Pythonic naming
2. **Minimal dependencies** — Only what's necessary for crypto and encoding
3. **Type safety** — Full type hints, mypy strict mode
4. **Modern tooling** — uv, ruff, pytest

## Non-Goals

- Async HTTP client for handshakes (leave to integrators)
- Trust layer implementation (separate package)
- Avatar/visual identity (separate package)

---

## Dependencies

| Package | Purpose | Justification |
|---------|---------|---------------|
| `pynacl` | Ed25519 signing | Bindings to libsodium, battle-tested |
| `canonicaljson` | JCS (RFC 8785) | Standard library for canonical JSON |
| `base58` | Base58btc encoding | Required for did:key format |

**Dev dependencies:** pytest, mypy, ruff

---

## API Design

### Core Classes

```python
# Identity generation
key = RootKey.generate()
key = RootKey.from_seed(bytes)      # Deterministic
key = RootKey.from_bytes(bytes)     # Import existing

# DID handling  
did = key.did                        # Did object
did = Did.parse("did:key:z6Mk...")   # Parse string
did.value                            # "did:key:z6Mk..."
did.public_key                       # bytes (32)

# Session keys
session = SessionKey.generate(root_key)
session = SessionKey.generate(root_key, key_id="custom-id")

# Signing
signature = sign_message(dict, key)           # Returns base64 string
is_valid = verify_message(dict, sig, pubkey)  # Returns bool

# DID Documents
doc = DidDocument.new(key)
doc = doc.with_handshake_endpoint(url)
doc = doc.with_service(id, type, url)
signed_doc = doc.sign(key)
signed_doc.verify()
```

### Design Decisions

1. **Immutable builders** — `with_*` methods return new objects
2. **Frozen dataclasses** — DIDs and documents are immutable
3. **Explicit over implicit** — No magic, clear method names
4. **Fail loudly** — Raise exceptions on invalid input, not silent failures

---

## Module Structure

```
sdk/python/
├── pyproject.toml
├── README.md
└── agent_id/
    ├── __init__.py      # Public API exports
    ├── keys.py          # RootKey, SessionKey
    ├── did.py           # Did class
    ├── signing.py       # sign_message, verify_message, canonicalize
    └── document.py      # DidDocument
```

---

## Compatibility

### Rust SDK Mapping

| Rust | Python |
|------|--------|
| `RootKey::generate()` | `RootKey.generate()` |
| `RootKey::from_seed()` | `RootKey.from_seed()` |
| `key.did()` | `key.did` (property) |
| `Did::parse()` | `Did.parse()` |
| `DidDocument::new()` | `DidDocument.new()` |
| `.with_handshake_endpoint()` | `.with_handshake_endpoint()` |
| `.sign()` | `.sign()` |
| `.verify()` | `.verify()` |

### Interoperability

- DIDs generated in Python are valid in Rust and vice versa
- Signatures from Python verify in Rust
- DID Documents are JSON-compatible across implementations

---

## Testing Strategy

1. **Unit tests** — Each module tested independently
2. **Roundtrip tests** — Generate → export → import → verify
3. **Cross-implementation tests** — (Future) Verify against Rust output
4. **Property tests** — (Future) Hypothesis for fuzzing

---

## Future Considerations

### Handshake Client

A separate module (`agent_id.handshake`) could provide:
- HTTP client for handshake protocol
- Async support via `httpx`
- Session management

### Trust Layer

Separate package (`agent-id-trust`) for:
- Trust statements
- Interaction receipts
- Local trust graph

---

## Open Questions

1. **Async support?** — Should signing/verification be async-compatible?
2. **Key storage?** — Should we provide secure storage helpers or leave to integrators?
3. **Logging?** — Add structured logging for debugging?

---

## Checklist

- [x] Core classes defined
- [x] Dependencies selected
- [x] Module structure planned
- [ ] Review with maintainer
- [ ] Implementation
- [ ] Cross-implementation tests
- [ ] Documentation
- [ ] PyPI publication
