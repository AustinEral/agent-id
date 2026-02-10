# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-10

### Added

- **agent-id umbrella crate**: Single dependency for all AIP functionality
  - `cargo add agent-id`
  - Re-exports `agent-id-core` and `agent-id-handshake`
  - Common types available at root: `RootKey`, `Did`, `DidDocument`

- **agent-id-core**: Core identity primitives
  - `RootKey`: Ed25519 keypair generation and management
  - `Did`: W3C did:key format identifiers
  - `DidDocument`: Signed DID documents with service endpoints
  - Canonical JSON signing (RFC 8785 JCS)

- **agent-id-handshake**: Mutual authentication protocol
  - Challenge-response handshake
  - Proof verification with counter-challenges
  - Session establishment

- **CLI**: Command-line tool (`agent-id`)
  - `agent-id identity generate`: Create new identity
  - `agent-id identity show`: Display current identity
  - `agent-id document create`: Generate signed DID document
  - `agent-id handshake test`: Test handshake between two agents

- **Documentation**
  - QUICKSTART.md: 5-minute getting started guide
  - INTEGRATION.md: How to add AIP to your agent
  - SECURITY.md: Security considerations

### Notes

- Uses W3C standard `did:key` format for identifiers
- Minimal dependencies, security-focused design
- Trust layer available separately: [aip-trust](https://github.com/AustinEral/aip-trust)

[Unreleased]: https://github.com/AustinEral/agent-id/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AustinEral/agent-id/releases/tag/v0.1.0
