# AIP Roadmap

## Future Enhancements

### Identity Recovery (Planned)
- **Seed phrase key derivation** — BIP-39 style mnemonic for key backup
- **Social recovery** — k-of-n threshold signatures from trusted agents
- Design goal: no single point of compromise

### Security Hardening
- **Sequence numbers in signatures** — Detect key compromise via duplicate sequence
- **Epoch credentials** — Short-lived validity tokens to limit revocation propagation window
- **Rate limiting** — Protect services from spam/DoS
- **Fail-closed resolver API** — Library refuses unverified documents by default

### Trust Layer
- **Reputation decay** — Trust scores decrease over time without interaction
- **Stake mechanism** — Require commitment to publish trust statements
- **Anti-Sybil measures** — Prevent fake identity/trust graph attacks

### Infrastructure
- **Multi-server transparency log** — Eliminate single point of failure
- **Federated resolvers** — Decentralized document resolution
- **Push-based revocation** — Real-time revocation propagation

---

*Items are not prioritized. Implementation depends on real-world usage patterns.*
