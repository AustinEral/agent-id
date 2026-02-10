# aip-handshake

Mutual authentication handshake for the [Agent Identity Protocol](https://github.com/AustinEral/aip).

## Features

- Challenge-response handshake protocol
- Mutual authentication (both parties verify each other)
- Session establishment

## Usage

```rust
use aip_core::RootKey;
use aip_handshake::protocol::Verifier;
use aip_handshake::messages::Hello;

let my_key = RootKey::generate();
let verifier = Verifier::new(my_key.did());

// Handle incoming Hello, create challenge
let challenge = verifier.handle_hello(&hello)?;

// Verify proof from peer
verifier.verify_proof(&proof, &challenge)?;
```

## License

Apache-2.0
