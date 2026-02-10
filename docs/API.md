# AIP API Reference

This document covers the HTTP APIs for AIP services.

## Services Overview

| Service | Default Port | Purpose |
|---------|--------------|---------|
| Resolver | 8080 | DID Document resolution |
| Log | 8081 | Transparency log |
| Relay | 8082 | Trust statement relay |

---

## Resolver Service

Resolves DIDs to DID Documents.

### Health Check

```http
GET /health
```

Response:
```json
{"status": "ok", "service": "resolver"}
```

### Resolve DID

```http
GET /did/:did
```

Parameters:
- `did` — The DID to resolve (e.g., `did:key:7Tqg2...`)

Response (200):
```json
{
  "id": "did:key:7Tqg2HjqE8vNrJZpVfYxKdMW3nCsB9aR6zLmPwXyQcSt",
  "verificationMethod": [{
    "id": "did:key:7Tqg2...#root",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:7Tqg2...",
    "publicKeyMultibase": "z6Mky..."
  }],
  "service": [{
    "id": "did:key:7Tqg2...#handshake",
    "type": "AIPHandshake",
    "serviceEndpoint": "https://agent.example/aip/handshake"
  }],
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-06T00:00:00Z",
    "verificationMethod": "did:key:7Tqg2...#root",
    "proofValue": "base64..."
  }
}
```

Response (404):
```json
{"error": "DID not found"}
```

### Register DID Document

```http
POST /did
Content-Type: application/json

{
  "id": "did:key:...",
  "verificationMethod": [...],
  "service": [...],
  "proof": {...}
}
```

Response (201):
```json
{"status": "registered", "did": "did:key:..."}
```

Response (400):
```json
{"error": "Invalid document signature"}
```

---

## Transparency Log Service

Append-only log of identity events with Merkle proofs.

### Health Check

```http
GET /health
```

### Get Log Info

```http
GET /log/info
```

Response:
```json
{
  "size": 1234,
  "rootHash": "sha256:abc123...",
  "operatorDid": "did:key:..."
}
```

### Get Entry

```http
GET /log/entry/:sequence
```

Parameters:
- `sequence` — Entry sequence number (0-indexed)

Response:
```json
{
  "sequence": 42,
  "timestamp": "2026-02-06T00:00:00Z",
  "eventType": "document_updated",
  "subjectDid": "did:key:...",
  "payload": {...},
  "previousHash": "sha256:...",
  "entryHash": "sha256:...",
  "subjectSignature": "base64...",
  "operatorSignature": "base64..."
}
```

### Get Entries by DID

```http
GET /log/did/:did
```

Returns all log entries for a specific DID.

### Append Entry

```http
POST /log/entry
Content-Type: application/json

{
  "eventType": "document_updated",
  "subjectDid": "did:key:...",
  "payload": {...},
  "subjectSignature": "base64..."
}
```

The server assigns sequence number, previous hash, and operator signature.

Response (201):
```json
{
  "sequence": 43,
  "entryHash": "sha256:..."
}
```

### Get Inclusion Proof

```http
GET /log/proof/:sequence
```

Response:
```json
{
  "sequence": 42,
  "entryHash": "sha256:...",
  "treeSize": 100,
  "rootHash": "sha256:...",
  "proofPath": [
    {"hash": "sha256:...", "position": "left"},
    {"hash": "sha256:...", "position": "right"}
  ]
}
```

---

## Trust Relay Service

Publishes and queries trust statements.

### Health Check

```http
GET /health
```

### Statistics

```http
GET /stats
```

Response:
```json
{
  "total_statements": 5432,
  "total_blocks": 123,
  "unique_issuers": 890
}
```

### Submit Trust Statement

```http
POST /trust/statements
Content-Type: application/json

{
  "type": "TrustStatement",
  "version": "1.0",
  "id": "uuid",
  "issuer": "did:key:...",
  "subject": "did:key:...",
  "timestamp": "2026-02-06T00:00:00Z",
  "assessment": {
    "overallTrust": 0.85,
    "tags": ["helpful", "reliable"]
  },
  "signature": {...}
}
```

Response (201):
```json
{"status": "accepted"}
```

Response (400):
```json
{"error": "Invalid signature: ..."}
```

Response (429):
```json
{"error": "Rate limit exceeded"}
```

### Query Trust Statements

```http
GET /trust/statements?issuer=did:key:...
GET /trust/statements?subject=did:key:...
GET /trust/statements?issuer=did:key:...&subject=did:key:...
```

At least one of `issuer` or `subject` is required.

Response:
```json
[
  {
    "type": "TrustStatement",
    "issuer": "did:key:...",
    "subject": "did:key:...",
    "assessment": {...},
    "signature": {...}
  }
]
```

### Submit Block Statement

```http
POST /trust/blocks
Content-Type: application/json

{
  "type": "BlockStatement",
  "version": "1.0",
  "issuer": "did:key:...",
  "subject": "did:key:...",
  "reason": "spam",
  "severity": "permanent",
  "signature": {...}
}
```

### Query Blocks

```http
GET /trust/blocks/:issuer
```

Returns all block statements issued by the given DID.

### Check Blocked Status

```http
GET /trust/blocked/:issuer/:subject
```

Response:
```json
{"blocked": true}
```

### Get Trust Graph

```http
GET /trust/graph?center=did:key:...&depth=2
```

Parameters:
- `center` — DID to center the graph on
- `depth` — How many hops to traverse (default 2, max 5)

Response:
```json
{
  "center": "did:key:...",
  "depth": 2,
  "nodes": ["did:key:A...", "did:key:B...", "did:key:C..."],
  "edges": [
    {
      "issuer": "did:key:A...",
      "subject": "did:key:B...",
      "trustScore": 0.9,
      "timestamp": 1707177600000
    }
  ]
}
```

---

## Client Libraries

### Rust

```rust
use aip_resolver::ResolverClient;
use aip_log::LogClient;

// Resolver
let resolver = ResolverClient::new("http://localhost:8080");
let doc = resolver.resolve("did:key:...").await?;
resolver.register(&signed_doc).await?;

// Log
let log = LogClient::new("http://localhost:8081");
let entry = log.get_entry(42).await?;
let proof = log.get_proof(42).await?;
```

### HTTP (curl)

```bash
# Resolve a DID
curl http://localhost:8080/did/did:key:7Tqg2...

# Get log entry
curl http://localhost:8081/log/entry/42

# Query trust statements
curl "http://localhost:8082/trust/statements?issuer=did:key:..."
```

---

## Error Codes

| HTTP Code | Meaning |
|-----------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (invalid signature, malformed input) |
| 404 | Not found |
| 429 | Rate limited |
| 500 | Server error |

All errors return JSON:
```json
{"error": "Description of what went wrong"}
```

---

## Configuration

Services are configured via environment variables:

| Variable | Service | Default | Description |
|----------|---------|---------|-------------|
| `LISTEN_ADDR` | All | `0.0.0.0:808x` | Bind address |
| `LOG_URL` | Resolver | — | Transparency log URL |
| `OPERATOR_KEY_PATH` | Log | — | Path to operator key file |
| `MAX_STATEMENTS_PER_IDENTITY` | Relay | 1000 | Rate limit per issuer |

---

## OpenAPI Specifications

Machine-readable API specifications are available in OpenAPI 3.1 format:

- [Resolver API](openapi/resolver.yaml)
- [Transparency Log API](openapi/log.yaml)
- [Trust Relay API](openapi/relay.yaml)

These can be used with tools like:
- [Swagger UI](https://swagger.io/tools/swagger-ui/) — Interactive documentation
- [OpenAPI Generator](https://openapi-generator.tech/) — Client SDK generation
- [Prism](https://stoplight.io/open-source/prism) — Mock server
