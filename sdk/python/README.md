# Agent Identity Protocol - Python SDK

Python implementation of the Agent Identity Protocol (AIP) for cryptographic identity and mutual authentication between AI agents.

## Installation

```bash
pip install agent-id
```

Or install from source:

```bash
cd sdk/python
pip install -e ".[dev]"
```

## Quick Start

### Create an Identity

```python
from agent_id import RootKey

# Generate a new identity
key = RootKey.generate()
print(f"My DID: {key.did}")
# did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y
```

### Sign Messages

```python
from agent_id import RootKey, sign_message, verify_message

key = RootKey.generate()

# Sign a message
message = {"action": "hello", "to": "did:key:z6Mk..."}
signature = sign_message(message, key)

# Verify a message
is_valid = verify_message(message, signature, key.did.public_key)
```

### Create a DID Document

```python
from agent_id import RootKey, DidDocument

key = RootKey.generate()

# Create and sign a DID Document
doc = (
    DidDocument.new(key)
    .with_handshake_endpoint("https://my-agent.example/aip")
    .sign(key)
)

# Verify it
assert doc.verify()

# Serialize to JSON
doc_dict = doc.to_dict()
```

### Session Keys

```python
from agent_id import RootKey, SessionKey

root = RootKey.generate()

# Create a session key (short-lived, for routine operations)
session = SessionKey.generate(root)

# Sign with session key
signature = sign_message({"action": "ping"}, session)
```

## API Reference

### `RootKey`

The root identity key for an agent.

- `RootKey.generate()` - Create a new random key
- `RootKey.from_seed(bytes)` - Create from 32-byte seed
- `RootKey.from_bytes(bytes)` - Create from private key bytes
- `key.did` - The agent's DID
- `key.sign(bytes)` - Sign raw bytes
- `key.to_bytes()` - Export private key

### `SessionKey`

A short-lived key delegated from a root key.

- `SessionKey.generate(root_key, key_id=None)` - Create new session key
- `session.sign(bytes)` - Sign raw bytes
- `session.full_key_id` - Full key ID including root DID

### `Did`

A Decentralized Identifier.

- `Did.from_public_key(bytes)` - Create from Ed25519 public key
- `Did.parse(str)` - Parse a did:key string
- `did.value` - The full DID string
- `did.public_key` - The raw public key bytes

### `DidDocument`

A DID Document describing an agent.

- `DidDocument.new(root_key)` - Create new document
- `doc.with_handshake_endpoint(url)` - Add handshake service
- `doc.with_service(id, type, url)` - Add custom service
- `doc.sign(key)` - Sign the document
- `doc.verify()` - Verify signature
- `doc.to_dict()` - Serialize to dictionary

### Functions

- `sign_message(dict, key)` - Sign a JSON message, returns base64 signature
- `verify_message(dict, signature, public_key)` - Verify a signed message

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
ruff format .

# Lint
ruff check .

# Type check
mypy agent_id
```

## License

Apache-2.0
