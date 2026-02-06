# AIP Fuzz Testing

Fuzz testing infrastructure for the Agent Identity Protocol.

## Targets

| Target | Description |
|--------|-------------|
| `fuzz_did_parse` | Tests Did::from_str with arbitrary input |
| `fuzz_hello_deserialize` | Tests Hello message JSON parsing |
| `fuzz_challenge_deserialize` | Tests Challenge message JSON parsing |

## Requirements

Install cargo-fuzz:

```bash
cargo install cargo-fuzz
```

Fuzzing requires a nightly Rust toolchain:

```bash
rustup install nightly
```

## Running Fuzz Tests

Run a specific target:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_did_parse
```

Run for a specific duration (e.g., 60 seconds):

```bash
cargo +nightly fuzz run fuzz_did_parse -- -max_total_time=60
```

## Checking for Issues

List any crashes found:

```bash
cargo +nightly fuzz list
```

Reproduce a crash:

```bash
cargo +nightly fuzz run fuzz_did_parse artifacts/fuzz_did_parse/crash-...
```

## CI Integration

For CI, run each target briefly to check for obvious issues:

```bash
cargo +nightly fuzz run fuzz_did_parse -- -max_total_time=30
cargo +nightly fuzz run fuzz_hello_deserialize -- -max_total_time=30
cargo +nightly fuzz run fuzz_challenge_deserialize -- -max_total_time=30
```

## Adding New Targets

1. Create a new file in `fuzz_targets/`
2. Add a `[[bin]]` entry to `Cargo.toml`
3. Follow the existing pattern using `libfuzzer_sys::fuzz_target!`

Priority targets to add:
- Proof message deserialization
- Trust statement deserialization
- Base58/Base64 decoding paths
