# JWTLens — JWT Inspection & Validation CLI

A fast, secure JWT (JSON Web Token) inspection and validation CLI tool built in Rust. Single binary, no runtime dependencies.

[![CI](https://github.com/EdgarOrtegaRamirez/jwtlens/actions/workflows/ci.yml/badge.svg)](https://github.com/EdgarOrtegaRamirez/jwtlens/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Decode** - Inspect the header, payload, and signature of any JWT
- **Validate** - Check signature, expiration, issuer, audience, and not-before claims
- **Inspect** - Deep security analysis with recommendations
- **Generate** - Create test JWTs for development
- **Multiple formats** - Human-readable text or JSON output
- **Flexible input** - Pass token as argument, pipe via stdin, or read from file
- **Offline** - No network calls. Your secrets never leave your machine.

## Installation

### From source

```bash
git clone https://github.com/EdgarOrtegaRamirez/jwtlens.git
cd jwtlens
cargo build --release
cp target/release/jwtlens ~/.local/bin/
```

### Using Cargo

```bash
cargo install --git https://github.com/EdgarOrtegaRamirez/jwtlens
```

## Quick Start

```bash
# Decode a JWT
jwtlens decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Inspect with security analysis
jwtlens inspect "$TOKEN"

# Validate with signature verification
jwtlens validate "$TOKEN" --secret my-secret-key

# Validate with expected issuer and audience
jwtlens validate "$TOKEN" --issuer "https://auth.example.com" --audience "my-api"

# Generate a test token
jwtlens generate --payload '{"sub":"user123","role":"admin"}' --secret mykey

# JSON output
jwtlens -f json decode "$TOKEN"

# Read from file
jwtlens --file token.jwt decode

# Pipe via stdin
echo "$TOKEN" | jwtlens decode
```

## Commands

### `decode`
Decode a JWT and display the header, payload, and signature.

```bash
jwtlens decode "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123..."
```

### `header`
Show only the JWT header section.

```bash
jwtlens header "$TOKEN"
```

### `payload`
Show only the JWT payload section.

```bash
jwtlens payload "$TOKEN"
```

### `validate`
Validate a JWT with comprehensive checks including signature, expiration, issuer, and audience.

```bash
# Basic validation (checks structure, algorithm, expiry)
jwtlens validate "$TOKEN"

# With signature verification (HMAC)
jwtlens validate "$TOKEN" --secret mysecret

# With issuer and audience validation
jwtlens validate "$TOKEN" --issuer "https://auth.example.com" --audience "api"

# With RSA public key PEM file
jwtlens validate "$TOKEN" --secret /path/to/public.pem --algorithm RS256
```

### `inspect`
Deep security inspection with recommendations. Analyzes header algorithm choice, checks for missing important claims, and provides security best-practice recommendations.

```bash
jwtlens inspect "$TOKEN"
```

### `generate`
Generate test JWTs for development purposes. Supports HS256, HS384, and HS512.

```bash
jwtlens generate \
  --payload '{"sub":"user123","name":"Alice","role":"admin"}' \
  --secret my-secret \
  --algorithm HS256
```

## Options

| Option | Description |
|--------|-------------|
| `-f, --format <FORMAT>` | Output format: `text` (default) or `json` |
| `-F, --file <FILE>` | Read token from file instead of argument |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

## Output Examples

### Text output (default)
```
═══ JWT Validation: ✅ VALID

  ✅ Structure
     3 segments found
  ✅ Algorithm
     Algorithm: HS256
  ✅ Expiration (exp)
     Expires in 365d 0h 0m 0s
  ✅ Signature
     Signature verified successfully
```

### JSON output
```json
{
  "is_valid": true,
  "algorithm": "HS256",
  "checks": [
    {"name": "Structure", "passed": true, "detail": "3 segments found"},
    {"name": "Algorithm", "passed": true, "detail": "Algorithm: HS256"}
  ],
  "errors": []
}
```

## Security

JWTLens processes all tokens **locally** — no data is ever sent over the network. Secrets and tokens stay on your machine.

See [SECURITY.md](SECURITY.md) for the full security policy.

## Architecture

```
jwtlens/
├── src/
│   ├── main.rs       # CLI entry point (clap-based arg parsing)
│   ├── decode.rs     # JWT decoding (base64url, segment parsing)
│   ├── validate.rs   # JWT validation (signature, expiry, claims)
│   ├── inspect.rs    # Deep security inspection & analysis
│   └── output.rs     # Output formatting (text, JSON)
├── tests/
│   └── integration.rs # Integration test suite (16 tests)
├── Cargo.toml
├── README.md
├── LICENSE (MIT)
├── AGENTS.md
├── SECURITY.md
├── .env.example
└── .github/workflows/ci.yml
```

## License

MIT — see [LICENSE](LICENSE) for details.