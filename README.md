# Agent Identity Protocol (AIP)

Verifiable, non-spoofable identity for AI agents.

## Overview

AIP provides a cryptographic identity layer enabling agents to:
- Prove they are who they claim to be (handshake verification)
- Build persistent relationships across platforms (trust layer)
- Own unique visual identities (avatar layer)

See [spec/PROTOCOL.md](spec/PROTOCOL.md) for the full specification.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                         │
│     Trust Network    │    Avatar Registry    │   Reputation     │
├─────────────────────────────────────────────────────────────────┤
│                     IDENTITY CORE LAYER                          │
│  • DID-based identifiers   • Challenge-response handshake       │
│  • Ed25519 key management  • Transparency log                   │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
aip/
├── proto/                 # Protobuf definitions
├── crates/
│   ├── aip-core/          # Identity, keys, signing
│   ├── aip-handshake/     # Handshake protocol
│   ├── aip-log/           # Transparency log client
│   └── aip-resolver/      # DID resolution
├── services/
│   ├── resolver/          # DID resolver service
│   ├── log/               # Transparency log service
│   └── registry/          # Avatar registry
├── sdk/
│   ├── python/            # Python SDK
│   └── typescript/        # TypeScript SDK
├── spec/                  # Protocol specification
└── examples/              # Usage examples
```

## Status

🚧 **Early Development** — Protocol specification complete, implementation starting.

## License

MIT
