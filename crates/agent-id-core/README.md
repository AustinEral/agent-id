# agent-id-core

Core identity primitives for the [Agent Identity Protocol](https://github.com/AustinEral/agent-id).

## Features

- **RootKey**: Ed25519 keypair generation and management
- **Did**: W3C did:key format identifiers  
- **DidDocument**: Signed DID documents with service endpoints
- **Signing**: Canonical JSON signing (RFC 8785 JCS)

## Usage

```rust
use agent_id_core::RootKey;

let key = RootKey::generate();
println!("DID: {}", key.did());
// did:key:z6MktNWXFy7fn9kNfwfvD9e2rDK3RPetS4MRKtZH8AxQzg9y
```

## License

Apache-2.0
