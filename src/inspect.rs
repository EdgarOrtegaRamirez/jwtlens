// JWTLens - JWT Deep Inspection Module

use crate::decode::{decode_jwt, get_claim_description, DecodedJwt};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Security inspection report for a JWT
#[derive(Debug, Clone)]
pub struct InspectionReport {
    pub token: String,
    pub header_analysis: Vec<Insight>,
    pub payload_analysis: Vec<Insight>,
    pub security_issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub summary: String,
}

/// A single insight about the token
#[derive(Debug, Clone)]
pub struct Insight {
    pub field: String,
    pub value: String,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Deep inspect a JWT for security issues and insights
pub fn inspect_jwt(token: &str) -> Result<InspectionReport> {
    let decoded = decode_jwt(token)?;
    let mut header_analysis = Vec::new();
    let mut payload_analysis = Vec::new();
    let mut security_issues = Vec::new();
    let mut recommendations = Vec::new();

    // Analyze header
    analyze_header(
        &decoded,
        &mut header_analysis,
        &mut security_issues,
        &mut recommendations,
    );

    // Analyze payload
    analyze_payload(
        &decoded,
        &mut payload_analysis,
        &mut security_issues,
        &mut recommendations,
    );

    // Summary
    let summary = if security_issues.is_empty() {
        "No security issues detected".to_string()
    } else {
        format!("Found {} security issue(s)", security_issues.len())
    };

    Ok(InspectionReport {
        token: token.to_string(),
        header_analysis,
        payload_analysis,
        security_issues,
        recommendations,
        summary,
    })
}

fn analyze_header(
    decoded: &DecodedJwt,
    analysis: &mut Vec<Insight>,
    issues: &mut Vec<String>,
    recommendations: &mut Vec<String>,
) {
    let header = &decoded.header;

    // Algorithm analysis
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let (alg_severity, alg_note) = match alg {
        "none" => {
            issues.push("Algorithm is 'none' — token has no cryptographic signature".to_string());
            recommendations.push(
                "Never accept 'alg: none' tokens in production. Always validate signature."
                    .to_string(),
            );
            (
                Severity::Critical,
                "No signature — token is trivially forgeable".to_string(),
            )
        }
        "HS256" | "HS384" | "HS512" => (
            Severity::Info,
            "Symmetric HMAC algorithm — requires shared secret".to_string(),
        ),
        "RS256" | "RS384" | "RS512" => (
            Severity::Info,
            "Asymmetric RSA algorithm — uses public/private key pair".to_string(),
        ),
        "ES256" | "ES384" | "ES512" => (
            Severity::Info,
            "Asymmetric ECDSA algorithm — uses public/private key pair".to_string(),
        ),
        "EdDSA" => (
            Severity::Info,
            "Edwards-curve Digital Signature Algorithm".to_string(),
        ),
        other => {
            issues.push(format!("Unknown or weak algorithm: {}", other));
            (Severity::Warning, "Unrecognized algorithm".to_string())
        }
    };
    analysis.push(Insight {
        field: "Algorithm (alg)".to_string(),
        value: format!("{} — {}", alg, alg_note),
        severity: alg_severity,
    });

    // Token type
    let typ = header
        .get("typ")
        .and_then(|v| v.as_str())
        .unwrap_or("not specified");
    analysis.push(Insight {
        field: "Type (typ)".to_string(),
        value: typ.to_string(),
        severity: Severity::Info,
    });

    // Key ID
    if let Some(kid) = header.get("kid").and_then(|v| v.as_str()) {
        analysis.push(Insight {
            field: "Key ID (kid)".to_string(),
            value: kid.to_string(),
            severity: Severity::Info,
        });
    }

    // Content type
    if let Some(cty) = header.get("cty").and_then(|v| v.as_str()) {
        analysis.push(Insight {
            field: "Content Type (cty)".to_string(),
            value: cty.to_string(),
            severity: Severity::Info,
        });
    }

    // Header size
    let header_json = serde_json::to_string(header).unwrap_or_default();
    analysis.push(Insight {
        field: "Header Size".to_string(),
        value: format!("{} bytes", header_json.len()),
        severity: Severity::Info,
    });

    // Check for algorithm confusion risk
    if alg.starts_with("HS") {
        let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
        if typ.to_lowercase() != "jwt" && !typ.is_empty() {
            issues.push(
                "Non-standard 'typ' claim may indicate algorithm confusion attack".to_string(),
            );
            recommendations
                .push("Use 'typ': 'JWT' to prevent algorithm confusion attacks".to_string());
        }
    }
}

fn analyze_payload(
    decoded: &DecodedJwt,
    analysis: &mut Vec<Insight>,
    issues: &mut Vec<String>,
    recommendations: &mut Vec<String>,
) {
    let payload = &decoded.payload;

    // Check all registered claims
    let registered_claims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];
    let mut found_registered = Vec::new();

    for claim in &registered_claims {
        if let Some(val) = payload.get(claim) {
            found_registered.push(*claim);
            let display = match val {
                Value::String(s) => s.clone(),
                Value::Number(n) => format!("{}", n),
                Value::Array(arr) => format!("{:?}", arr),
                _ => format!("{}", val),
            };

            // For timestamps, convert to human-readable
            let enriched = if let Some(ts) = val.as_i64() {
                match *claim {
                    "exp" | "nbf" | "iat" => {
                        if let Some(dt) = DateTime::from_timestamp(ts, 0) {
                            format!("{} ({})", display, dt.format("%Y-%m-%d %H:%M:%S UTC"))
                        } else {
                            display
                        }
                    }
                    _ => display,
                }
            } else {
                display
            };

            let desc = get_claim_description(claim);

            // Expiry special handling
            let severity = match *claim {
                "exp" => {
                    let now = Utc::now().timestamp();
                    if let Some(ts) = val.as_i64() {
                        if ts <= now {
                            Severity::Critical
                        } else {
                            Severity::Info
                        }
                    } else {
                        Severity::Warning
                    }
                }
                _ => Severity::Info,
            };

            analysis.push(Insight {
                field: format!("{} ({})", claim, desc),
                value: enriched,
                severity,
            });
        }
    }

    // Check for missing important claims
    if !found_registered.contains(&"exp") {
        issues.push("Token has no expiration (exp) claim — it never expires".to_string());
        recommendations
            .push("Always include an 'exp' claim with a reasonable expiration time".to_string());
    }
    if !found_registered.contains(&"iat") {
        recommendations
            .push("Consider including 'iat' (Issued At) for token lifecycle tracking".to_string());
    }
    if !found_registered.contains(&"jti") {
        recommendations
            .push("Consider including 'jti' (JWT ID) for token replay detection".to_string());
    }

    // Custom claims
    let custom_claims: Vec<String> = payload
        .as_object()
        .map(|obj| {
            obj.keys()
                .filter(|k| !registered_claims.contains(&k.as_str()))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    if !custom_claims.is_empty() {
        analysis.push(Insight {
            field: "Custom Claims".to_string(),
            value: format!(
                "{} custom claim(s): {}",
                custom_claims.len(),
                custom_claims.join(", ")
            ),
            severity: Severity::Info,
        });
    }

    // Payload size
    let payload_json = serde_json::to_string(payload).unwrap_or_default();
    analysis.push(Insight {
        field: "Payload Size".to_string(),
        value: format!("{} bytes", payload_json.len()),
        severity: Severity::Info,
    });
}