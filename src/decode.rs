// JWTLens - JWT Decoding Module

use anyhow::{Context, Result};
use base64::Engine;
use serde_json::Value;

/// Represents a decoded JWT with its three parts
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    #[allow(dead_code)]
    pub raw_token: String,
    pub header: Value,
    pub payload: Value,
    pub signature: String,
    pub signature_bytes: Vec<u8>,
}

/// Decode a JWT token into its constituent parts
pub fn decode_jwt(token: &str) -> Result<DecodedJwt> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!(
            "Invalid JWT format: expected 3 parts separated by dots, got {}",
            parts.len()
        );
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let header_json = decode_base64_json(header_b64).context("Failed to decode JWT header")?;
    let payload_json = decode_base64_json(payload_b64).context("Failed to decode JWT payload")?;

    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .context("Failed to decode JWT signature")?;

    Ok(DecodedJwt {
        raw_token: token.trim().to_string(),
        header: header_json,
        payload: payload_json,
        signature: signature_b64.to_string(),
        signature_bytes,
    })
}

/// Decode a base64url-encoded JSON string (JWT uses unpadded base64url)
fn decode_base64_json(encoded: &str) -> Result<Value> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = engine
        .decode(encoded)
        .with_context(|| format!("Invalid base64url encoding: '{}'", encoded))?;
    let json_str =
        String::from_utf8(bytes).with_context(|| "Invalid UTF-8 in decoded base64".to_string())?;
    let value: Value =
        serde_json::from_str(&json_str).with_context(|| format!("Invalid JSON: '{}'", json_str))?;
    Ok(value)
}

/// Get the registered claim names and their descriptions
pub fn get_claim_description(key: &str) -> &'static str {
    match key {
        "iss" => "Issuer: identifies the principal that issued the JWT",
        "sub" => "Subject: identifies the principal that is the subject of the JWT",
        "aud" => "Audience: identifies the recipients that the JWT is intended for",
        "exp" => "Expiration Time: the time after which the JWT must not be accepted",
        "nbf" => "Not Before: the time before which the JWT must not be accepted",
        "iat" => "Issued At: the time at which the JWT was issued",
        "jti" => "JWT ID: a unique identifier for the JWT",
        "typ" => "Type: the type of token (typically 'JWT')",
        "alg" => "Algorithm: the algorithm used to sign/encrypt the token",
        "kid" => "Key ID: a hint indicating which key was used to sign the token",
        _ => "",
    }
}
