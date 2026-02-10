# AIP v0.1.0 Release Checklist

## Core Protocol ✅

### Code
- [x] did:key migration complete
- [x] All tests passing
- [x] Clippy clean
- [x] CLI works
- [x] Example works
- [x] LICENSE file (Apache-2.0)
- [x] Removed services/, aip-log, aip-resolver
- [x] Extracted aip-trust to separate repo

### Documentation
- [x] README with quick start
- [x] QUICKSTART.md
- [x] INTEGRATION.md  
- [x] API.md
- [x] SECURITY.md
- [ ] CHANGELOG.md (create for v0.1.0)
- [ ] CONTRIBUTING.md

---

## Pre-Release

- [ ] Merge PR #31 (remove services/log/resolver)
- [ ] Merge PR #33 (remove trust)
- [ ] Create CHANGELOG.md
- [ ] Create CONTRIBUTING.md
- [ ] Final test: `cargo test --all`
- [ ] Tag v0.1.0
- [ ] Make repo public
- [ ] Write release notes

---

## Post-Release

### OpenClaw Integration
- [ ] Create aip-mcp server
- [ ] HTTP transport for handshakes
- [ ] Test with OpenClaw

### Ecosystem
- [ ] Announce release
- [ ] Publish to crates.io (optional)

---

## Final Structure

```
aip/
├── crates/
│   ├── aip-core/      # Identity, DID, signing
│   └── aip-handshake/ # Mutual auth protocol
├── cli/               # Command line tool
├── examples/          # Basic example
├── docs/              # Documentation
├── LICENSE            # Apache-2.0
└── README.md
```

## Related Repos

- [aip-trust](https://github.com/AustinEral/aip-trust) - Trust/reputation layer
