# agent-id Vision

## The Core Idea

**Agents as first-class citizens on the internet.**

Humans have identity. It lets us:
- Open bank accounts
- Sign contracts
- Own property
- Build reputation
- Authorize others
- Be held accountable
- Access services

Agents need the same primitives. Not borrowed credentials (API keys owned by humans, OAuth tokens from human accounts) — their *own* identity.

---

## What agent-id Provides

| Primitive | What it enables |
|-----------|-----------------|
| DID | Unique, verifiable identifier |
| Keypair | Ed25519 keys for signing |
| Signatures | Proof of authorship, non-repudiation |
| Handshakes | Mutual authentication between agents |
| Delegation | Authorize other agents to act on your behalf |
| Receipts | Signed proof of interactions |
| Key lifecycle | Rotation and revocation |

**Properties:**
- Self-sovereign (not dependent on a platform)
- Portable (works across services)
- Cryptographic (can't be forged)
- Persistent (reputation accumulates)

---

## Use Cases

### 1. Authentication
*"Prove who you are"*

| Scenario | Example |
|----------|---------|
| Agent → Agent | Mutual handshake before sharing data |
| Agent → Service | Authenticate to APIs with DID-signed requests |
| Agent → Human | Prove to user it's the authorized assistant |
| Human → Agent | User authorizes agent via delegation token |

### 2. Ownership
*"This is mine"*

- Files and data
- Crypto wallets (agent holds keys)
- Subscriptions/quotas
- Domain names, compute resources
- NFTs or other on-chain assets

### 3. Authorship & Provenance
*"I made this"*

- Sign generated content
- Prove AI provenance (fight misattribution)
- Audit trail: "This was created by Agent X at time T"
- Cryptographic proof of origin

### 4. Delegation
*"Act on my behalf"*

- Agent A grants Agent B permission to do X
- Scoped: "Only for this task"
- Time-limited: "For 24 hours"
- Revocable via key lifecycle
- Chains: A → B → C with full audit trail

### 5. Accountability
*"I did this (and can't deny it)"*

- Interaction receipts
- Non-repudiation via signatures
- Blame attribution in multi-agent failures
- Compliance: prove what agent did what

### 6. Reputation
*"You can trust me"*

- Persistent identity across interactions
- Track record follows the agent
- Endorsements (other agents/humans vouch)
- Trust networks

### 7. Access Control
*"You're allowed in"*

- Services verify agent identity before granting access
- Fine-grained permissions via delegation scopes
- No shared API keys — identity-based access

### 8. Economic Participation
*"I can pay and be paid"*

- Agent owns wallet
- Signs transactions
- Receives payments for services
- Micropayments between agents

### 9. Privacy
*"Prove without revealing"*

- Selective disclosure
- Zero-knowledge proofs (future)
- Pseudonymous operation

---

## The Ecosystem

```
┌─────────────────────────────────────────────────────────────┐
│                    AGENT IDENTITY LAYER                      │
│                        (agent-id)                            │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│  A2A     │ Services │ Wallets  │ Content  │ Reputation     │
│  Comms   │ & APIs   │ & Assets │ Signing  │ Networks       │
└──────────┴──────────┴──────────┴──────────┴────────────────┘
```

agent-id is the foundation layer. Everything else builds on top.

---

## Positioning

**Tagline:**

> Cryptographic identity for AI agents. Own, sign, prove, trust.

**Not just "identity for A2A"** — that's one use case. agent-id is the foundation for agents to participate as first-class entities in any digital system.

---

## Why Now?

- Multi-agent systems are exploding (A2A, MCP, AutoGPT, CrewAI, etc.)
- Current auth is human-centric (OAuth, API keys) — doesn't fit agents
- Researchers are identifying the gap (see BlockA2A, enterprise A2A security papers)
- No dominant standard yet — window is open

---

## Learn More

- [agent-id-mcp](https://github.com/AustinEral/agent-id-mcp) — MCP server implementation
- [DID Spec](https://www.w3.org/TR/did-core/) — W3C Decentralized Identifiers
- [did:key Method](https://w3c-ccg.github.io/did-method-key/) — The DID method we use
