// JWTLens - Output Formatting Module

use crate::decode::{get_claim_description, DecodedJwt};
use crate::inspect::{InspectionReport, Insight, Severity};
use crate::validate::ValidationResult;
use colored::*;
use serde_json::{json, Value};

/// Print decoded JWT
pub fn print_decoded(decoded: &DecodedJwt, is_json: bool) {
    if is_json {
        let output = json!({
            "header": decoded.header,
            "payload": decoded.payload,
            "signature": decoded.signature,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!("{}", "═══ JWT Decoded ═══".cyan().bold());
    println!();

    // Header
    println!("{}", "── Header ──".yellow().bold());
    print_json_value(&decoded.header, 0);
    println!();

    // Payload
    println!("{}", "── Payload ──".green().bold());
    print_json_value(&decoded.payload, 0);
    println!();

    // Signature
    println!("{}", "── Signature ──".blue().bold());
    if decoded.signature_bytes.len() <= 32 {
        println!("  Hex: {}", hex::encode(&decoded.signature_bytes));
    } else {
        println!(
            "  Hex: {}... ({} bytes)",
            hex::encode(&decoded.signature_bytes[..16]),
            decoded.signature_bytes.len()
        );
    }
    println!("  Raw (base64url): {}", decoded.signature);
}

/// Print just the header
pub fn print_header(decoded: &DecodedJwt, is_json: bool) {
    if is_json {
        println!("{}", serde_json::to_string_pretty(&decoded.header).unwrap());
    } else {
        println!("{}", "JWT Header:".yellow().bold());
        print_json_value(&decoded.header, 0);
    }
}

/// Print just the payload
pub fn print_payload(decoded: &DecodedJwt, is_json: bool) {
    if is_json {
        println!("{}", serde_json::to_string_pretty(&decoded.payload).unwrap());
    } else {
        println!("{}", "JWT Payload:".green().bold());
        print_json_value(&decoded.payload, 0);
    }
}

/// Print validation results
pub fn print_validation(result: &ValidationResult, is_json: bool) {
    if is_json {
        let checks: Vec<Value> = result
            .checks
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "passed": c.passed,
                    "detail": c.detail,
                })
            })
            .collect();

        let output = json!({
            "is_valid": result.is_valid,
            "algorithm": result.header_alg,
            "checks": checks,
            "errors": result.errors,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    let status = if result.is_valid {
        "✅ VALID".green().bold()
    } else {
        "❌ INVALID".red().bold()
    };
    println!("{} {}", "═══ JWT Validation:".cyan().bold(), status);
    println!();

    for check in &result.checks {
        let icon = if check.passed { "✅" } else { "❌" };
        let color = if check.passed { "green" } else { "red" };
        println!("  {} {}", icon, check.name.color(color).bold());
        println!("     {}", check.detail);
    }

    if !result.errors.is_empty() {
        println!();
        println!("{}", "Errors:".red().bold());
        for err in &result.errors {
            println!("  ❌ {}", err.red());
        }
    }
}

/// Print inspection report
pub fn print_inspection(report: &InspectionReport, is_json: bool) {
    if is_json {
        let header_insights: Vec<Value> = report
            .header_analysis
            .iter()
            .map(|i| insight_to_json(i))
            .collect();
        let payload_insights: Vec<Value> = report
            .payload_analysis
            .iter()
            .map(|i| insight_to_json(i))
            .collect();

        let output = json!({
            "summary": report.summary,
            "header_analysis": header_insights,
            "payload_analysis": payload_insights,
            "security_issues": report.security_issues,
            "recommendations": report.recommendations,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!("{}", "═══ JWT Deep Inspection ═══".cyan().bold());
    println!();

    // Summary
    println!("{}", "Summary:".bold());
    println!("  {}", report.summary);
    println!();

    // Header analysis
    println!("{}", "── Header Analysis ──".yellow().bold());
    for insight in &report.header_analysis {
        print_insight(insight);
    }
    println!();

    // Payload analysis
    println!("{}", "── Payload Analysis ──".green().bold());
    for insight in &report.payload_analysis {
        print_insight(insight);
    }
    println!();

    // Security issues
    if !report.security_issues.is_empty() {
        println!("{}", "── Security Issues ──".red().bold());
        for issue in &report.security_issues {
            println!("  ⚠  {}", issue.red());
        }
        println!();
    }

    // Recommendations
    if !report.recommendations.is_empty() {
        println!("{}", "── Recommendations ──".blue().bold());
        for rec in &report.recommendations {
            println!("  💡 {}", rec.blue());
        }
        println!();
    }
}

fn insight_to_json(insight: &Insight) -> Value {
    let severity_str = match insight.severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    };
    json!({
        "field": insight.field,
        "value": insight.value,
        "severity": severity_str,
    })
}

fn print_insight(insight: &Insight) {
    let color = match insight.severity {
        Severity::Info => "white",
        Severity::Warning => "yellow",
        Severity::Critical => "red",
    };
    let icon = match insight.severity {
        Severity::Info => "ℹ",
        Severity::Warning => "⚠",
        Severity::Critical => "🔴",
    };
    println!("  {} {}", icon, insight.field.color(color).bold());
    println!("     {}", insight.value);
}

fn print_json_value(value: &Value, indent: usize) {
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let prefix = "  ".repeat(indent + 1);
                let desc = get_claim_description(key);
                if !desc.is_empty() {
                    println!("{}{}: \t{}  ({})", prefix, key.cyan(), format_value(val), desc.dimmed());
                } else {
                    println!("{}{}: \t{}", prefix, key.cyan(), format_value(val));
                }
            }
        }
        _ => {
            let prefix = "  ".repeat(indent + 1);
            println!("{}{}", prefix, value);
        }
    }
}

fn format_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => format!("{}", n),
        Value::Bool(b) => format!("{}", b),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(|v| format_value(v)).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Null => "null".to_string(),
        _ => format!("{}", value),
    }
}