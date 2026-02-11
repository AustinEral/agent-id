# Agent Identity Protocol - Python SDK

Python implementation of the Agent Identity Protocol (AIP) for cryptographic identity and mutual authentication between AI agents.

## Installation

```bash
uv add agent-id
```

Or from source:

```bash
cd sdk/python
uv sync --dev
```

## Quick Start

### Create an Identity

```python
from agent_id import RootKey

key = RootKey.generate()
print(key.did)  # did:key:z6Mk...
```

### Sign Messages

```python
from agent_id import RootKey, sign_dict, verify_dict

key = RootKey.generate()

message = {"action": "hello", "to": "did:key:z6Mk..."}
signature = sign_dict(message, key)

is_valid = verify_dict(message, signature, key.did.public_key)
```

### Create a DID Document

```python
from agent_id import RootKey, DidDocument

key = RootKey.generate()

doc = (
    DidDocument.new(key)
    .with_handshake_endpoint("https://my-agent.example/aip")
    .sign(key)
)

doc.verify()  # Raises if invalid
```

### Session Keys

```python
from agent_id import RootKey, SessionKey, sign_dict

root = RootKey.generate()
session = SessionKey.generate(root)

signature = sign_dict({"action": "ping"}, session)
```

## Concepts

| Concept | Description |
|---------|-------------|
| **DID** | `did:key:z6Mk...` — Self-certifying identifier from public key |
| **RootKey** | Agent's identity keypair (Ed25519) |
| **SessionKey** | Short-lived key delegated from root |
| **DidDocument** | W3C-compliant identity document |

## Development

```bash
uv sync --dev
uv run pytest
uv run ruff check .
uv run mypy agent_id
```

## Next Steps

- [PYTHON_SDK.md](../../docs/PYTHON_SDK.md) — Development conventions
- [PROTOCOL.md](../../spec/PROTOCOL.md) — Protocol specification
- [INTEGRATION.md](../../docs/INTEGRATION.md) — Integration patterns

## License

Apache-2.0
