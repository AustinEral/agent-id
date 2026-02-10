# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-10

### Added

- **aip-core**: Core identity primitives
  - `RootKey`: Ed25519 keypair generation and management
  - `Did`: W3C did:key format identifiers
  - `DidDocument`: Signed DID documents with service endpoints
  - Canonical JSON signing (RFC 8785 JCS)

- **aip-handshake**: Mutual authentication protocol
  - Challenge-response handshake
  - Proof verification with counter-challenges
  - Session establishment

- **CLI**: Command-line tool
  - `cargo run --bin aip -- identity generate`: Create new identity
  - `cargo run --bin aip -- identity show`: Display current identity
  - `cargo run --bin aip -- document create`: Generate signed DID document
  - `cargo run --bin aip -- handshake test`: Test handshake between two agents

- **Documentation**
  - QUICKSTART.md: 5-minute getting started guide
  - INTEGRATION.md: How to add AIP to your agent
  - SECURITY.md: Security considerations

### Changed

- Migrated from custom `did:aip` format to W3C standard `did:key`
  - Better interoperability with DID ecosystem
  - Uses multicodec (0xed01) for Ed25519 keys
  - Uses base58btc multibase encoding

### Removed

- Removed premature components (will be added in future releases):
  - Services (resolver, relay, log)
  - Transparency log infrastructure
  - Trust layer (moved to [aip-trust](https://github.com/AustinEral/aip-trust))

## Related Projects

- [aip-trust](https://github.com/AustinEral/aip-trust) - Trust and reputation layer

[Unreleased]: https://github.com/AustinEral/aip/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AustinEral/aip/releases/tag/v0.1.0
