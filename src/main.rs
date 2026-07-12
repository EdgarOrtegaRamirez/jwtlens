// JWTLens - JWT Inspection & Validation CLI
// Main entry point

use anyhow::Result;
use clap::{Parser, Subcommand};

mod decode;
mod inspect;
mod output;
mod validate;

/// JWTLens: A fast, secure JWT inspection & validation CLI tool
#[derive(Parser)]
#[command(name = "jwtlens")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Output format (text, json)
    #[arg(short = 'f', long, default_value = "text", value_parser = clap::builder::PossibleValuesParser::new(["text", "json"]))]
    format: String,

    /// Path to a file containing the JWT (alternative to passing as argument)
    #[arg(short = 'F', long)]
    file: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode a JWT and show its header and payload
    Decode {
        /// The JWT token string to decode
        token: Option<String>,
    },
    /// Validate a JWT (signature, expiry, issuer, audience)
    Validate {
        /// The JWT token string to validate
        token: Option<String>,

        /// Expected issuer (iss claim)
        #[arg(long)]
        issuer: Option<String>,

        /// Expected audience (aud claim)
        #[arg(long)]
        audience: Option<String>,

        /// Secret key or public key PEM file for signature validation
        #[arg(long)]
        secret: Option<String>,

        /// Algorithm to use for validation (default: HS256)
        #[arg(long, default_value = "HS256")]
        algorithm: String,
    },
    /// Deep inspect a JWT with security analysis
    Inspect {
        /// The JWT token string to inspect
        token: Option<String>,
    },
    /// Show only the header section
    Header {
        /// The JWT token string
        token: Option<String>,
    },
    /// Show only the payload section
    Payload {
        /// The JWT token string
        token: Option<String>,
    },
    /// Generate a new JWT for testing
    Generate {
        /// Payload JSON string
        #[arg(short, long)]
        payload: String,

        /// Signing secret key
        #[arg(short, long)]
        secret: String,

        /// Algorithm (HS256, HS384, HS512)
        #[arg(short, long, default_value = "HS256")]
        algorithm: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let is_json = cli.format == "json";

    // Resolve token from argument, file, or stdin
    let resolve_token = |token: Option<String>| -> Result<String> {
        match token {
            Some(t) => Ok(t),
            None => match &cli.file {
                Some(path) => Ok(std::fs::read_to_string(path)?.trim().to_string()),
                None => {
                    // Try reading from stdin
                    use std::io::Read;
                    let mut buf = String::new();
                    let stdin = std::io::stdin();
                    let mut handle = stdin.lock();
                    if handle.read_to_string(&mut buf).is_ok() && !buf.trim().is_empty() {
                        Ok(buf.trim().to_string())
                    } else {
                        anyhow::bail!("No JWT token provided. Use positional argument, --file, or pipe via stdin.")
                    }
                }
            },
        }
    };

    match &cli.command {
        Commands::Decode { token } => {
            let token = resolve_token(token.clone())?;
            let decoded = decode::decode_jwt(&token)?;
            output::print_decoded(&decoded, is_json);
        }
        Commands::Validate {
            token,
            issuer,
            audience,
            secret,
            algorithm,
        } => {
            let token = resolve_token(token.clone())?;
            let result = validate::validate_jwt(
                &token,
                issuer.as_deref(),
                audience.as_deref(),
                secret.as_deref(),
                algorithm,
            )?;
            output::print_validation(&result, is_json);
        }
        Commands::Inspect { token } => {
            let token = resolve_token(token.clone())?;
            let report = inspect::inspect_jwt(&token)?;
            output::print_inspection(&report, is_json);
        }
        Commands::Header { token } => {
            let token = resolve_token(token.clone())?;
            let decoded = decode::decode_jwt(&token)?;
            output::print_header(&decoded, is_json);
        }
        Commands::Payload { token } => {
            let token = resolve_token(token.clone())?;
            let decoded = decode::decode_jwt(&token)?;
            output::print_payload(&decoded, is_json);
        }
        Commands::Generate {
            payload,
            secret,
            algorithm,
        } => {
            let token = validate::generate_token(payload, secret, algorithm)?;
            if is_json {
                println!("{}", serde_json::json!({ "token": token }));
            } else {
                println!("{}", token);
            }
        }
    }

    Ok(())
}
