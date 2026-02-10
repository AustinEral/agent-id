# AIP v0.1.0 Release Checklist

## Core Protocol (must have)

### Code
- [x] did:key migration complete
- [x] All tests passing (60+)
- [x] Clippy clean
- [x] CLI works: `identity generate`, `identity show`, `document create`, `handshake test`
- [x] Example works: `cargo run --example basic`
- [ ] Add LICENSE file (Apache-2.0)
- [ ] Verify crate metadata in Cargo.toml

### Documentation
- [x] README with quick start
- [x] QUICKSTART.md
- [x] INTEGRATION.md  
- [x] API.md
- [x] SECURITY.md
- [ ] CHANGELOG.md (create for v0.1.0)
- [ ] CONTRIBUTING.md

### Repository
- [ ] Add LICENSE file
- [ ] Add CHANGELOG.md
- [ ] Update README badges (if any)
- [ ] Verify .gitignore is complete
- [ ] Remove any sensitive data/keys from history

---

## Separate into other repos (before or after release)

### aip-trust → separate repo
- [ ] Create `aip-trust` repo
- [ ] Move crates/aip-trust
- [ ] Update to depend on published aip-core
- [ ] Remove from main AIP workspace

### services → separate repo or defer
- [ ] Evaluate: are resolver/relay ready?
- [ ] Option A: Move to `aip-services` repo
- [ ] Option B: Remove from v0.1.0, add later
- [ ] Option C: Keep but mark as experimental

---

## Publishing

### Crates.io (optional for v0.1.0)
- [ ] Decide: publish crates or git-only for now?
- [ ] If publishing: reserve crate names (aip-core, aip-handshake)
- [ ] Verify crate metadata

### GitHub
- [ ] Make repo public
- [ ] Create v0.1.0 release tag
- [ ] Write release notes
- [ ] Announce (where?)

---

## Integration (post-release)

### OpenClaw MCP Server
- [ ] Create aip-mcp crate/repo
- [ ] Implement tools: whoami, handshake, sign, verify
- [ ] HTTP transport for inter-agent handshakes
- [ ] Test with OpenClaw

### A2A Integration
- [ ] Document how AIP + A2A work together
- [ ] Example: A2A discovery → AIP auth → task execution

---

## Decisions Needed

1. **License**: Apache-2.0? (recommended)
2. **Services**: Include in v0.1.0 or separate?
3. **Trust crate**: Include in v0.1.0 or separate?
4. **Crates.io**: Publish now or git-only?
5. **Announcement**: Where to share? (Twitter, HN, Discord?)

---

## Current Status

| Component | Status | Action |
|-----------|--------|--------|
| aip-core | ✅ Ready | Ship |
| aip-handshake | ✅ Ready | Ship |
| aip-log | ⚠️ Minimal | Keep or defer |
| aip-resolver (crate) | ⚠️ Minimal | Keep or defer |
| aip-trust | ✅ Works | Separate repo? |
| CLI | ✅ Works | Ship |
| services/resolver | ⚠️ Stub | Remove or mark WIP |
| services/relay | ⚠️ Partial | Remove or mark WIP |
| services/log | ⚠️ Stub | Remove or mark WIP |

