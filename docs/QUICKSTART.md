# AIP Quickstart

Get started with the Agent Identity Protocol in 5 minutes.

## Installation

```bash
# Clone and build
git clone https://github.com/AustinEral/aip.git
cd aip
cargo build --release

# Add to PATH (optional)
export PATH="$PWD/target/release:$PATH"
```

## Create Your Identity

```bash
# Generate a new identity
aip identity generate

# Output:
# Generated new identity:
#   DID: did:aip:1:7Tqg2HjqE8vNrJZpVfYxKdMW3nCsB9aR6zLmPwXyQcSt
#   Saved to: ~/.config/aip/identity.json
```

Your DID (Decentralized Identifier) is derived from your public key. It's globally unique and self-certifying.

## View Your Identity

```bash
aip identity show

# Output:
# Identity:
#   DID: did:aip:1:7Tqg2HjqE8vNrJZpVfYxKdMW3nCsB9aR6zLmPwXyQcSt
#   Key ID: 7Tqg2HjqE8vNrJZpVfYxKdMW3nCsB9aR6zLmPwXyQcSt
#   File: /home/user/.config/aip/identity.json
```

## Create a DID Document

```bash
# Create a signed document with a handshake endpoint
aip document create -e https://myagent.example.com/handshake

# Output: (JSON DID Document)
```

## Test a Handshake

The handshake protocol proves two agents control their claimed identities.

```bash
# Run a local test (creates a temporary peer)
aip handshake test

# Output:
# Testing handshake...
#   Our DID: did:aip:1:7Tqg2...
#   Peer DID: did:aip:1:8Rth...
#
# 1. Sent Hello
# 2. Received Challenge
# 3. Sent Proof
# 4. Received ProofAccepted
# 5. Verified counter-proof
#
# ✓ Handshake successful!
```

## Real Handshake (Two Terminals)

**Terminal 1 - Start server:**
```bash
aip handshake serve --port 8400
# Listening on http://0.0.0.0:8400
```

**Terminal 2 - Connect:**
```bash
# Use a different identity file
aip -i ./peer.json identity generate
aip -i ./peer.json handshake connect http://localhost:8400

# ✓ Handshake successful!
```

## Publish to a Resolver

```bash
# Start the resolver service (separate terminal)
cargo run -p aip-resolver-service

# Publish your document
aip document publish -r http://localhost:8500 -e https://myagent.example.com/handshake

# ✓ Document published!
```

## Resolve a DID

```bash
aip resolve did:aip:1:7Tqg2... -r http://localhost:8500

# ✓ Document signature verified
# { ... DID Document ... }
```

## Next Steps

- Read [INTEGRATION.md](./INTEGRATION.md) for programmatic usage
- Review [API.md](./API.md) for service endpoints
- See [PROTOCOL.md](../spec/PROTOCOL.md) for the full specification

## Key Concepts

| Concept | Description |
|---------|-------------|
| **DID** | `did:aip:1:<pubkey>` — Your unique, self-certifying identifier |
| **Root Key** | Ed25519 keypair that defines your identity |
| **Session Key** | Short-lived key for daily operations (delegated from root) |
| **DID Document** | Signed JSON describing how to interact with you |
| **Handshake** | Challenge-response protocol proving identity ownership |
| **Transparency Log** | Append-only audit trail of all identity events |
