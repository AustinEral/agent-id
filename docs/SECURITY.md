# AIP Security & Hardening Roadmap

> **Status:** Draft v1.0  
> **Last Updated:** February 2026  
> **Classification:** Critical Infrastructure

---

## Executive Summary

AIP is foundational identity infrastructure. Agents don't just need to trust each other—they must trust the system itself as the ultimate source of truth. This document outlines the path from prototype to production-grade infrastructure.

**Current State:** Functional prototype, not production-ready  
**Target State:** Trustworthy infrastructure for millions of agents

---

## 1. Trust Model

### 1.1 What Agents Must Trust

| Component | Trust Requirement | Current State |
|-----------|------------------|---------------|
| **Cryptography** | Ed25519 signatures are unforgeable | ✅ Battle-tested |
| **DID Derivation** | Public key → DID is deterministic | ✅ Mathematical |
| **Resolver** | Returns authentic DID Documents | ❌ Single operator |
| **Transparency Log** | Accurately records all events | ❌ Single operator |
| **Relay** | Doesn't forge trust statements | ✅ Statements self-signed |
| **Their own keys** | Private key hasn't been compromised | ⚠️ Implementation-dependent |

### 1.2 Core Security Principle

```
The system is only as trustworthy as its weakest centralized component.
```

Currently: Resolver and Log are single points of trust failure.

Goal: **Trust-minimized architecture** where no single party can compromise the system.

---

## 2. Threat Model

### 2.1 Adversary Capabilities

| Adversary | Capabilities | Likelihood |
|-----------|--------------|------------|
| **Script Kiddie** | Automated attacks, known exploits | High |
| **Malicious Agent** | Impersonation attempts, spam | High |
| **Compromised Operator** | Control of resolver/log/relay | Medium |
| **Nation State** | Key theft, infrastructure compromise | Low |
| **Quantum Computer** | Break Ed25519 (future) | Low (10+ years) |

### 2.2 Attack Vectors & Mitigations

#### Critical Priority

| Attack | Impact | Current | Mitigation | Priority |
|--------|--------|---------|------------|----------|
| **Fake Resolver** | Attacker returns wrong DID Document, redirects handshakes | ❌ Unprotected | Multi-resolver consensus, client-side verification | **P0** |
| **Log Equivocation** | Operator shows different history to different clients | ❌ Unprotected | Witnessed log, gossip protocol | **P0** |
| **Key Theft** | Full identity compromise | ⚠️ User responsibility | HSM support, session key rotation | **P0** |

#### High Priority

| Attack | Impact | Current | Mitigation | Priority |
|--------|--------|---------|------------|----------|
| **DDoS on Services** | Availability loss | ❌ Unprotected | Rate limiting, CDN, redundancy | **P1** |
| **Replay Attack** | Reuse old handshake proofs | ✅ Nonce + timestamp | Already mitigated | - |
| **MITM on Handshake** | Intercept communications | ✅ Signatures | Already mitigated | - |
| **Trust Statement Spam** | Pollute relay with garbage | ⚠️ Basic rate limit | PoW, staking, reputation gating | **P1** |

#### Medium Priority

| Attack | Impact | Current | Mitigation | Priority |
|--------|--------|---------|------------|----------|
| **Sybil Attack** | Flood network with fake identities | ❌ Unprotected | PoW for registration, social graph analysis | **P2** |
| **Eclipse Attack** | Isolate agent from honest peers | ❌ Unprotected | Diverse peer selection, out-of-band verification | **P2** |
| **Timing Attack** | Leak information via timing | ❌ Not analyzed | Constant-time operations | **P2** |

---

## 3. Hardening Roadmap

### Phase 0: Foundation (Current)
- [x] Core cryptography (Ed25519)
- [x] Self-certifying DIDs
- [x] Handshake protocol
- [x] Transparency log structure
- [x] Trust statements

### Phase 1: Trust Distribution (Critical)

**Goal:** Remove single points of trust failure

#### 1.1 Multi-Resolver Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                      Client Query                            │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │Resolver A│   │Resolver B│   │Resolver C│
        │(Operator1)│   │(Operator2)│   │(Operator3)│
        └──────────┘   └──────────┘   └──────────┘
              │               │               │
              └───────────────┼───────────────┘
                              ▼
                    ┌─────────────────┐
                    │ Consensus (2/3) │
                    └─────────────────┘
```

**Implementation:**
- [ ] Resolver federation protocol
- [ ] Client queries multiple resolvers
- [ ] Consensus on DID Document (2-of-3 or 3-of-5)
- [ ] Automatic failover
- [ ] Resolver reputation tracking

#### 1.2 Witnessed Transparency Log
```
┌─────────────────────────────────────────────────────────────┐
│                    Log Entry                                 │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │ Witness A│   │ Witness B│   │ Witness C│
        └──────────┘   └──────────┘   └──────────┘
              │               │               │
              └───────────────┼───────────────┘
                              ▼
                    ┌─────────────────┐
                    │  Multi-signed   │
                    │     Entry       │
                    └─────────────────┘
```

**Implementation:**
- [ ] Witness protocol specification
- [ ] Multi-signature on log entries
- [ ] Gossip protocol for consistency
- [ ] Audit protocol (clients can verify)
- [ ] Signed tree heads (like Certificate Transparency)

#### 1.3 Client-Side Verification
- [ ] Clients verify DID Document signatures locally
- [ ] Clients check log consistency proofs
- [ ] Clients cache and compare across sessions
- [ ] Alert on conflicting information

### Phase 2: Operational Security

#### 2.1 Key Management
- [ ] HSM integration guide
- [ ] Secure enclave support (SGX, ARM TrustZone)
- [ ] Key ceremony documentation
- [ ] Automated session key rotation
- [ ] Emergency revocation procedures

#### 2.2 Service Hardening
- [ ] Rate limiting (per-DID, per-IP)
- [ ] DDoS mitigation
- [ ] TLS 1.3 everywhere
- [ ] Certificate pinning
- [ ] Input validation audit
- [ ] Dependency audit

#### 2.3 Monitoring & Alerting
- [ ] Anomaly detection
- [ ] Revocation monitoring
- [ ] Service health dashboards
- [ ] Incident response playbook

### Phase 3: Resilience

#### 3.1 Geographic Distribution
- [ ] Multi-region deployment
- [ ] Edge caching for resolvers
- [ ] Anycast routing

#### 3.2 Disaster Recovery
- [ ] Backup procedures
- [ ] Recovery testing
- [ ] Data export/import

#### 3.3 Graceful Degradation
- [ ] Offline verification mode
- [ ] Cached credential validation
- [ ] Service isolation

### Phase 4: Formal Verification

#### 4.1 Security Audit
- [ ] Third-party code audit
- [ ] Cryptographic review
- [ ] Penetration testing

#### 4.2 Formal Methods
- [ ] Protocol specification in TLA+ or similar
- [ ] Proof of security properties
- [ ] Model checking

---

## 4. Production Deployment Requirements

### 4.1 Minimum Viable Production

Before deploying for real users:

| Requirement | Description | Status |
|-------------|-------------|--------|
| Multi-resolver | At least 3 independent resolvers | ❌ |
| Witnessed log | At least 3 independent witnesses | ❌ |
| Security audit | Third-party review completed | ❌ |
| Rate limiting | All public endpoints protected | ❌ |
| Monitoring | Full observability stack | ❌ |
| Incident response | Documented procedures | ❌ |
| Key management | HSM or equivalent for operators | ❌ |

### 4.2 Operational Requirements

| Aspect | Requirement |
|--------|-------------|
| **Availability** | 99.9% uptime (8.7h downtime/year max) |
| **Latency** | < 100ms p99 for resolution |
| **Throughput** | 10,000 verifications/second |
| **Recovery** | < 1 hour RTO, < 5 minute RPO |

### 4.3 Compliance Considerations

- Data residency requirements
- GDPR (if handling EU users)
- Key escrow laws (varies by jurisdiction)
- Audit logging requirements

---

## 5. Governance

### 5.1 Who Operates Infrastructure?

**Options:**

| Model | Pros | Cons |
|-------|------|------|
| **Single Operator** | Simple, fast decisions | Single point of failure/trust |
| **Consortium** | Distributed trust | Coordination overhead |
| **DAO** | Fully decentralized | Slow, complex |
| **Federated** | Balance of speed/trust | Requires agreements |

**Recommendation:** Start with consortium of 3-5 trusted operators, evolve toward federation.

### 5.2 Decision Making

- Protocol changes: Require supermajority (4/5)
- Operational changes: Simple majority
- Emergency response: Any operator can act, review within 24h

### 5.3 Transparency

- All protocol changes publicly discussed
- Operator identities public
- Regular security reports
- Open source everything

---

## 6. Migration Path

### From Prototype to Production

```
Phase 0 (Now)           Phase 1 (3 months)      Phase 2 (6 months)
─────────────────────────────────────────────────────────────────
Single resolver    →    3 resolvers         →   5+ resolvers
Single log         →    3 witnesses         →   5+ witnesses  
No rate limiting   →    Basic limits        →   Adaptive limits
No monitoring      →    Basic dashboards    →   Full observability
No audit           →    Internal review     →   Third-party audit
```

### Backward Compatibility

- DID format: Stable, won't change
- Handshake protocol: Versioned, negotiate on connect
- API: Versioned endpoints, deprecation policy

---

## 7. Open Questions

1. **Economic model:** How are operators incentivized? Fees? Grants?
2. **Spam prevention:** PoW vs staking vs reputation?
3. **Quantum readiness:** When to add post-quantum signatures?
4. **Legal entity:** Does the consortium need a legal structure?
5. **Liability:** Who's responsible if the system fails?

---

## 8. Next Steps

### Immediate (This Week)
1. [ ] Review and finalize this document
2. [ ] Identify potential consortium members
3. [ ] Scope Phase 1 implementation

### Short Term (This Month)
1. [ ] Design multi-resolver protocol
2. [ ] Design witness protocol
3. [ ] Implement rate limiting
4. [ ] Set up basic monitoring

### Medium Term (This Quarter)
1. [ ] Deploy 3-resolver testnet
2. [ ] Deploy witnessed log testnet
3. [ ] Begin security audit process
4. [ ] Document operational procedures

---

## Appendix A: Security Checklist

Before each release:

- [ ] All dependencies updated
- [ ] No known CVEs in dependency tree
- [ ] All inputs validated
- [ ] All crypto operations use constant-time implementations
- [ ] No secrets in logs
- [ ] Rate limiting tested
- [ ] Error messages don't leak information

---

## Appendix B: Incident Response Template

**Severity Levels:**
- **P0:** Complete system compromise, immediate response
- **P1:** Partial compromise or major availability issue
- **P2:** Minor security issue, no immediate impact
- **P3:** Hardening opportunity, no active threat

**Response Steps:**
1. Assess and classify
2. Contain (if active threat)
3. Notify stakeholders
4. Investigate
5. Remediate
6. Post-mortem

---

*This is a living document. Last review: February 2026*
