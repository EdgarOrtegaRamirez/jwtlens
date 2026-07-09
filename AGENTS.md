# AGENTS.md — For AI Coding Agents

## Project Overview
JWTLens is a Rust CLI tool for JWT (JSON Web Token) inspection, validation, and security analysis. It provides a fast, offline alternative to online JWT debuggers.

## Build & Test
```bash
cargo build              # Build debug
cargo build --release    # Build release
cargo test               # Run all tests (16 integration tests)
cargo test -- --nocapture # Run tests with output visible
```

## Project Structure
- `src/main.rs` — CLI entry point using clap. Defines all subcommands: decode, validate, inspect, header, payload, generate
- `src/decode.rs` — JWT parsing: base64url decoding, segment extraction, registered claim descriptions
- `src/validate.rs` — Multi-check validation: structure, algorithm, expiry, nbf, iat, issuer, audience, signature
- `src/inspect.rs` — Deep security analysis with recommendations and severity levels
- `src/output.rs` — Text and JSON output formatting with colored terminal output
- `tests/integration.rs` — 16 integration tests covering all commands and edge cases

## Key Dependencies
- `clap` — CLI argument parsing
- `jsonwebtoken` — JWT encoding/decoding and signature verification
- `base64` — URL-safe base64 decoding
- `chrono` — Timestamp handling and formatting
- `serde_json` — JSON parsing and output
- `colored` — Terminal output coloring

## Architecture Notes
- JWT uses **unpadded base64url** encoding — always use `URL_SAFE_NO_PAD` engine
- The `--file` and `-f` flags are top-level clap args (must come before subcommand)
- Validation checks all run even when some fail — errors are accumulated
- Signature verification is optional (requires `--secret` flag)
- All crypto operations happen locally — no network calls

## Common Gotchas
- When adding new dependencies, update both `[dependencies]` and `[dev-dependencies]` in Cargo.toml
- For signature verification, the `jsonwebtoken` crate uses `EncodingKey` for generation and `DecodingKey` for verification
- JWT standard requires 3 dot-separated segments — anything else is invalid
- The `exp` claim is a Unix timestamp in seconds, not milliseconds