// JWTLens - Integration Tests

use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_jwtlens");

/// Helper to run jwtlens and capture output
fn run(args: &[&str]) -> (String, String, bool) {
    let output = Command::new(BINARY)
        .args(args)
        .output()
        .expect("Failed to execute jwtlens");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    (stdout, stderr, success)
}

/// Generate a test token
fn generate_token() -> String {
    let payload = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":9999999999}"#;
    let (stdout, _, success) = run(&[
        "generate",
        "--payload",
        payload,
        "--secret",
        "mysecret",
        "--algorithm",
        "HS256",
    ]);
    assert!(success, "Failed to generate token: {}", stdout);
    stdout.trim().to_string()
}

#[test]
fn test_generate_token() {
    let token = generate_token();
    // JWT tokens have 3 dot-separated parts
    assert_eq!(token.chars().filter(|&c| c == '.').count(), 2);
    assert!(token.starts_with("eyJ")); // base64url-encoded JSON starts with 'eyJ' for '{"'
}

#[test]
fn test_decode_token() {
    let token = generate_token();
    let (stdout, _, success) = run(&["decode", &token]);
    assert!(success, "decode failed");
    assert!(stdout.contains("═══ JWT Decoded ═══"));
    assert!(stdout.contains("HS256"));
    assert!(stdout.contains("John Doe"));
    assert!(stdout.contains("1234567890"));
}

#[test]
fn test_header_command() {
    let token = generate_token();
    let (stdout, _, success) = run(&["header", &token]);
    assert!(success);
    assert!(stdout.contains("HS256"));
    assert!(stdout.contains("JWT"));
}

#[test]
fn test_payload_command() {
    let token = generate_token();
    let (stdout, _, success) = run(&["payload", &token]);
    assert!(success);
    assert!(stdout.contains("John Doe"));
    assert!(stdout.contains("1234567890"));
}

#[test]
fn test_inspect_token() {
    let token = generate_token();
    let (stdout, _, success) = run(&["inspect", &token]);
    assert!(success, "inspect failed");
    assert!(stdout.contains("═══ JWT Deep Inspection ═══"));
    assert!(stdout.contains("Algorithm (alg)"));
    assert!(stdout.contains("Payload Size"));
}

#[test]
fn test_validate_no_secret() {
    let token = generate_token();
    let (stdout, _, success) = run(&["validate", &token]);
    assert!(success, "validate should succeed without secret");
    assert!(stdout.contains("✅ VALID"));
    assert!(stdout.contains("Skipped"));
}

#[test]
fn test_validate_with_secret() {
    let token = generate_token();
    let (stdout, _, success) = run(&["validate", &token, "--secret", "mysecret"]);
    assert!(success);
    assert!(stdout.contains("✅ VALID"));
    assert!(stdout.contains("Signature verified successfully"));
}

#[test]
fn test_validate_wrong_secret() {
    let token = generate_token();
    let (stdout, _, _success) = run(&["validate", &token, "--secret", "wrongsecret"]);
    // Should still succeed (returns validation result, not error)
    assert!(stdout.contains("❌ INVALID") || stdout.contains("failed"));
}

#[test]
fn test_json_output() {
    let token = generate_token();
    let (stdout, _, success) = run(&["-f", "json", "decode", &token]);
    assert!(success);
    // JSON output should be parseable
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Should be valid JSON");
    assert!(parsed.get("header").is_some());
    assert!(parsed.get("payload").is_some());
}

#[test]
fn test_invalid_token() {
    let (_stdout, _stderr, success) = run(&["decode", "not-a-valid-jwt"]);
    assert!(!success, "Should fail for invalid JWT");
}

#[test]
fn test_expired_token() {
    // Create a token with an expired exp claim
    let payload = r#"{"sub":"test","exp":1000000000}"#;
    let (stdout, _, success) = run(&[
        "generate",
        "--payload",
        payload,
        "--secret",
        "mysecret",
        "--algorithm",
        "HS256",
    ]);
    assert!(success);
    let token = stdout.trim().to_string();

    let (val_stdout, _, val_success) = run(&["validate", &token]);
    assert!(val_success, "validate should succeed: {}", val_stdout);
    assert!(
        val_stdout.contains("Expired") || val_stdout.contains("❌"),
        "Should detect expired token: {}",
        val_stdout
    );
}

#[test]
fn test_validate_with_issuer() {
    let payload = r#"{"iss":"https://auth.example.com","sub":"user1"}"#;
    let (stdout, _, success) = run(&[
        "generate",
        "--payload",
        payload,
        "--secret",
        "mysecret",
        "--algorithm",
        "HS256",
    ]);
    assert!(success);
    let token = stdout.trim().to_string();

    // Validate without issuer flag — should display issuer
    let (val_out, _, _) = run(&["validate", &token]);
    assert!(
        val_out.contains("Issuer: https://auth.example.com"),
        "Should show issuer claim: {}",
        val_out
    );

    // Validate with correct issuer — should match
    let (val_out2, _, _) = run(&[
        "validate",
        &token,
        "--issuer",
        "https://auth.example.com",
    ]);
    assert!(
        val_out2.contains("Expected 'https://auth.example.com', got 'https://auth.example.com'"),
        "Should match issuer: {}",
        val_out2
    );

    // Validate with wrong issuer — should mismatch
    let (val_out3, _, _) = run(&[
        "validate",
        &token,
        "--issuer",
        "https://wrong.example.com",
    ]);
    assert!(
        val_out3.contains("Issuer mismatch"),
        "Should show mismatch: {}",
        val_out3
    );
}

#[test]
fn test_stdin_pipe() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let token = generate_token();
    let mut child = Command::new(BINARY)
        .arg("decode")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn jwtlens");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(token.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("═══ JWT Decoded ═══"));
}

#[test]
fn test_file_input() {
    use std::io::Write;
    let token = generate_token();
    let mut temp_file = tempfile::NamedTempFile::new().unwrap();
    write!(temp_file, "{}", token).unwrap();
    let path = temp_file.path().to_str().unwrap();

    // --file is a top-level arg, must come before subcommand
    let (stdout, _, success) = run(&["--file", path, "decode"]);
    assert!(success, "file input failed: {}", stdout);
    assert!(stdout.contains("═══ JWT Decoded ═══"));
}

#[test]
fn test_version_flag() {
    let (stdout, _, success) = run(&["--version"]);
    assert!(success);
    assert!(stdout.contains("jwtlens"));
}

#[test]
fn test_help_flag() {
    let (stdout, _, success) = run(&["--help"]);
    assert!(success);
    assert!(stdout.contains("jwtlens"));
    assert!(stdout.contains("decode"));
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("inspect"));
    assert!(stdout.contains("generate"));
}