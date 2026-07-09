// JWTLens - JWT Validation Module

use crate::decode::decode_jwt;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, EncodingKey, Validation};
use serde_json::Value;

/// Result of JWT validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub token: String,
    pub is_valid: bool,
    pub checks: Vec<ValidationCheck>,
    pub header_alg: String,
    pub errors: Vec<String>,
}

/// Individual validation check
#[derive(Debug, Clone)]
pub struct ValidationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Validate a JWT token
pub fn validate_jwt(
    token: &str,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
    secret: Option<&str>,
    algorithm_str: &str,
) -> Result<ValidationResult> {
    let decoded = decode_jwt(token)?;
    let mut checks = Vec::new();
    let mut errors = Vec::new();

    // 1. Check structure (3 parts)
    let parts: Vec<&str> = token.trim().split('.').collect();
    checks.push(ValidationCheck {
        name: "Structure".to_string(),
        passed: parts.len() == 3,
        detail: format!("{} segments found", parts.len()),
    });
    if parts.len() != 3 {
        errors.push("JWT must have exactly 3 dot-separated segments".to_string());
    }

    // 2. Check algorithm
    let alg = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    checks.push(ValidationCheck {
        name: "Algorithm".to_string(),
        passed: alg != "none" && alg != "unknown",
        detail: format!("Algorithm: {}", alg),
    });
    if alg == "none" {
        errors.push("WARNING: Algorithm is 'none' — token has no signature!".to_string());
    }

    // 3. Check expiry
    let _exp_ok = check_expiry(&decoded.payload, &mut checks, &mut errors);

    // 4. Check Not Before (nbf)
    check_nbf(&decoded.payload, &mut checks);

    // 5. Check Issued At (iat)
    check_iat(&decoded.payload, &mut checks);

    // 6. Check issuer
    check_issuer(&decoded.payload, expected_issuer, &mut checks, &mut errors);

    // 7. Check audience
    check_audience(
        &decoded.payload,
        expected_audience,
        &mut checks,
        &mut errors,
    );

    // 8. Check signature if secret provided
    if let Some(secret_key) = secret {
        let sig_ok = verify_signature(token, secret_key, algorithm_str);
        checks.push(ValidationCheck {
            name: "Signature".to_string(),
            passed: sig_ok.is_ok(),
            detail: match &sig_ok {
                Ok(_) => "Signature verified successfully".to_string(),
                Err(e) => format!("Signature verification failed: {}", e),
            },
        });
        if sig_ok.is_err() {
            errors.push(format!("Signature verification failed"));
        }
    } else {
        checks.push(ValidationCheck {
            name: "Signature".to_string(),
            passed: true,
            detail: "Skipped (no --secret provided, use --secret to verify)".to_string(),
        });
    }

    let is_valid = errors.is_empty();
    Ok(ValidationResult {
        token: token.to_string(),
        is_valid,
        checks,
        header_alg: alg.to_string(),
        errors,
    })
}

fn check_expiry(
    payload: &Value,
    checks: &mut Vec<ValidationCheck>,
    errors: &mut Vec<String>,
) -> bool {
    match payload.get("exp") {
        Some(exp_val) => {
            let exp_ts = exp_val.as_i64().unwrap_or(0);
            let now = Utc::now().timestamp();
            let remaining = exp_ts - now;
            let expired = remaining <= 0;
            let detail = if expired {
                format!("Expired {} ago", format_duration(-remaining))
            } else {
                format!("Expires in {}", format_duration(remaining))
            };
            checks.push(ValidationCheck {
                name: "Expiration (exp)".to_string(),
                passed: !expired,
                detail,
            });
            if expired {
                errors.push("Token has expired".to_string());
            }
            !expired
        }
        None => {
            checks.push(ValidationCheck {
                name: "Expiration (exp)".to_string(),
                passed: false,
                detail: "No exp claim — token never expires".to_string(),
            });
            false
        }
    }
}

fn check_nbf(payload: &Value, checks: &mut Vec<ValidationCheck>) {
    match payload.get("nbf") {
        Some(nbf_val) => {
            let nbf_ts = nbf_val.as_i64().unwrap_or(0);
            let now = Utc::now().timestamp();
            let ready = now >= nbf_ts;
            checks.push(ValidationCheck {
                name: "Not Before (nbf)".to_string(),
                passed: ready,
                detail: if ready {
                    "Token is valid (current time is after nbf)".to_string()
                } else {
                    format!(
                        "Token not yet valid (starts in {})",
                        format_duration(nbf_ts - now)
                    )
                },
            });
        }
        None => {
            checks.push(ValidationCheck {
                name: "Not Before (nbf)".to_string(),
                passed: true,
                detail: "No nbf claim (not required)".to_string(),
            });
        }
    }
}

fn check_iat(payload: &Value, checks: &mut Vec<ValidationCheck>) {
    match payload.get("iat") {
        Some(iat_val) => {
            let iat_ts = iat_val.as_i64().unwrap_or(0);
            let issued_at = DateTime::from_timestamp(iat_ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "invalid".to_string());
            checks.push(ValidationCheck {
                name: "Issued At (iat)".to_string(),
                passed: true,
                detail: format!("Issued at: {}", issued_at),
            });
        }
        None => {
            checks.push(ValidationCheck {
                name: "Issued At (iat)".to_string(),
                passed: true,
                detail: "No iat claim (not required)".to_string(),
            });
        }
    }
}

fn check_issuer(
    payload: &Value,
    expected: Option<&str>,
    checks: &mut Vec<ValidationCheck>,
    errors: &mut Vec<String>,
) {
    let actual = payload.get("iss").and_then(|v| v.as_str());
    match (actual, expected) {
        (None, _) => {
            checks.push(ValidationCheck {
                name: "Issuer (iss)".to_string(),
                passed: expected.is_none(),
                detail: "No iss claim".to_string(),
            });
        }
        (Some(iss), None) => {
            checks.push(ValidationCheck {
                name: "Issuer (iss)".to_string(),
                passed: true,
                detail: format!("Issuer: {}", iss),
            });
        }
        (Some(iss), Some(exp)) => {
            let matched = iss == exp;
            checks.push(ValidationCheck {
                name: "Issuer (iss)".to_string(),
                passed: matched,
                detail: format!("Expected '{}', got '{}'", exp, iss),
            });
            if !matched {
                errors.push(format!(
                    "Issuer mismatch: expected '{}', got '{}'",
                    exp, iss
                ));
            }
        }
    }
}

fn check_audience(
    payload: &Value,
    expected: Option<&str>,
    checks: &mut Vec<ValidationCheck>,
    errors: &mut Vec<String>,
) {
    let actual = payload.get("aud").and_then(|v| v.as_str());
    match (actual, expected) {
        (None, _) => {
            checks.push(ValidationCheck {
                name: "Audience (aud)".to_string(),
                passed: expected.is_none(),
                detail: "No aud claim".to_string(),
            });
        }
        (Some(aud), None) => {
            checks.push(ValidationCheck {
                name: "Audience (aud)".to_string(),
                passed: true,
                detail: format!("Audience: {}", aud),
            });
        }
        (Some(aud), Some(exp)) => {
            let matched = aud == exp;
            checks.push(ValidationCheck {
                name: "Audience (aud)".to_string(),
                passed: matched,
                detail: format!("Expected '{}', got '{}'", exp, aud),
            });
            if !matched {
                errors.push(format!(
                    "Audience mismatch: expected '{}', got '{}'",
                    exp, aud
                ));
            }
        }
    }
}

fn verify_signature(token: &str, secret: &str, algorithm_str: &str) -> Result<()> {
    let alg = algorithm_str.to_uppercase();
    let decoding_alg = match alg.as_str() {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "ED25519" => Algorithm::EdDSA,
        other => anyhow::bail!("Unsupported algorithm: {}", other),
    };

    // Try as PEM file first, then as raw secret
    let key = if secret.starts_with("-----BEGIN")
        || secret.ends_with(".pem")
        || secret.contains('\n')
    {
        if secret.ends_with(".pem") {
            let pem_data = std::fs::read_to_string(secret).context("Failed to read PEM file")?;
            match decoding_alg {
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                    DecodingKey::from_rsa_pem(pem_data.as_bytes())?
                }
                Algorithm::ES256 | Algorithm::ES384 => {
                    DecodingKey::from_ec_pem(pem_data.as_bytes())?
                }
                Algorithm::EdDSA => DecodingKey::from_ed_pem(pem_data.as_bytes())?,
                _ => DecodingKey::from_secret(secret.as_bytes()),
            }
        } else {
            match decoding_alg {
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                    DecodingKey::from_rsa_pem(secret.as_bytes())?
                }
                Algorithm::ES256 | Algorithm::ES384 => {
                    DecodingKey::from_ec_pem(secret.as_bytes())?
                }
                Algorithm::EdDSA => DecodingKey::from_ed_pem(secret.as_bytes())?,
                _ => DecodingKey::from_secret(secret.as_bytes()),
            }
        }
    } else {
        DecodingKey::from_secret(secret.as_bytes())
    };

    let mut validation = Validation::new(decoding_alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;

    decode::<Value>(token, &key, &validation).context("Signature verification failed")?;

    Ok(())
}

/// Generate a test JWT token
pub fn generate_token(payload_json: &str, secret: &str, algorithm_str: &str) -> Result<String> {
    let alg = algorithm_str.to_uppercase();
    let header_alg = match alg.as_str() {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        other => anyhow::bail!(
            "Unsupported algorithm for generation: {}. Only HS256/HS384/HS512 supported.",
            other
        ),
    };

    let claims: Value = serde_json::from_str(payload_json).context("Invalid JSON payload")?;

    let key = EncodingKey::from_secret(secret.as_bytes());
    let token = jsonwebtoken::encode(&jsonwebtoken::Header::new(header_alg), &claims, &key)?;

    Ok(token)
}

fn format_duration(seconds: i64) -> String {
    let abs_secs = seconds.unsigned_abs();
    let days = abs_secs / 86400;
    let hours = (abs_secs % 86400) / 3600;
    let minutes = (abs_secs % 3600) / 60;
    let secs = abs_secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!("{}s", secs));
    }
    parts.join(" ")
}