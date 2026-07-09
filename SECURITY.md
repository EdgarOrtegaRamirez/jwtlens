# Security Policy for JWTLens

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x     | ✅ Active development |

## Reporting a Vulnerability

JWTLens is a local CLI tool that processes JWT tokens entirely on your machine. It does not make network requests or phone home.

If you discover a security vulnerability:

1. **Do not** open a public GitHub issue
2. Email the repository maintainer or open a draft security advisory on GitHub
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Features

- **No network calls**: JWTLens processes all tokens locally
- **No data exfiltration**: Secrets and tokens never leave your machine
- **Signature verification**: Optional cryptographic validation of JWT signatures using HS256/HS384/HS512/RS256/RS384/RS512/ES256/ES384/EdDSA
- **Algorithm detection**: Warns about `alg: none` tokens and algorithm confusion attacks
- **Expiry validation**: Detects expired tokens
- **Claim validation**: Checks issuer and audience claims when provided

## Best Practices

When using JWTLens:

1. **Always validate signatures** in production: `jwtlens validate <token> --secret <key>`
2. **Never accept `alg: none` tokens** — JWTLens will flag these
3. **Use strong secrets** for HMAC algorithms (≥256 bits for HS256)
4. **Prefer asymmetric algorithms** (RS256/ES256/EdDSA) over HMAC in production
5. **Always set reasonable `exp` claims** on tokens you generate
6. **Use `jti` (JWT ID)** for token replay detection
7. **Verify the algorithm** — don't rely on the token header alone

## Cryptographic Audit

JWTLens uses the `jsonwebtoken` crate (v9.3.1) for all cryptographic operations, which in turn uses `ring` (v0.17.14) for HMAC, RSA, ECDSA, and EdDSA implementations. These are well-audited, widely-used Rust cryptography libraries.

## Known Security Considerations

- Token inspection via `decode` and `inspect` commands does NOT verify signatures — always use `validate --secret` for trust decisions
- The `generate` command is intended for **development/testing only** — never hardcode signing keys in production
- JWT best practices change over time — JWTLens recommendations reflect current industry standards