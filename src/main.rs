// Main CLI entry point for Doppel
// Uses clap for argument parsing

use clap::{Arg, Command};
use doppel::models::{CollectionParser, Endpoint};
use doppel::parsers::{BrunoParser, PostmanParser, OpenApiParser};
use doppel::engine::AttackEngine;
use doppel::verdict::{decide_verdict, Verdict};
use doppel::ollama::OllamaAnalyzer;
use doppel::auth::{StaticTokenAuth, AuthStrategy};
use doppel::params::substitute_params;
use doppel::mutator::mutate_param;
use doppel::response_analysis::analyze_response_soft_fails;
use doppel::reporting::{export_csv, export_markdown};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};

/// Extract user ID from JWT token by decoding the payload
fn extract_user_id_from_jwt(token: &str) -> Option<String> {
    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode the payload (second part)
    let payload = parts[1];

    // JWT uses base64url encoding without padding
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let payload_str = String::from_utf8(decoded).ok()?;

    // Parse as JSON
    let json: Value = serde_json::from_str(&payload_str).ok()?;

    // Try common JWT claim names for user ID
    if let Some(user_id) = json.get("userId").or_else(|| json.get("user_id"))
        .or_else(|| json.get("sub"))
        .or_else(|| json.get("id")) {
        if let Some(id_str) = user_id.as_str() {
            return Some(id_str.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_user_id_sub() {
        // header.payload.signature ; payload contains {"sub":"user_42"}
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r"{".as_bytes());
        // build a fake token with base64 payload for sub
        let fake_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"sub\":\"user_42\"}");
        let token = format!("aaa.{}.ccc", fake_payload);
        let id = extract_user_id_from_jwt(&token);
        assert_eq!(id.unwrap(), "user_42");
    }
}

#[tokio::main]
async fn main() {
    let matches = Command::new("doppel")
        .version("0.1.0")
        .author("Jake Abendroth")
        .about("Automated BOLA/IDOR vulnerability scanner for APIs")
        .after_help("EXAMPLES:\n  doppel --input my.postman.json --base-url http://localhost:3000 --attacker-token TOKEN --victim-id 123\n  doppel -i bruno/ -b http://api/ -a TOKEN -v 456 --no-mutational-fuzzing --no-pii-analysis\n\nOPTIONS:\n  --no-mutational-fuzzing   Disable mutational fuzzing\n  --no-pii-analysis         Disable Ollama PII analysis\n  --no-soft-fail-analysis   Disable soft fail response analysis\n  --csv-report              Output CSV report (default: on)\n  --markdown-report         Output Markdown report (default: on)\n  --pdf-report              Output PDF report (default: off)")
        .arg(Arg::new("input")
            .short('i')
            .long("input")
            .required(true)
            .num_args(1)
            .help("Path to collection directory or file (Bruno, Postman, or OpenAPI)"))
        .arg(Arg::new("base_url")
            .short('b')
            .long("base-url")
            .required(true)
            .num_args(1)
            .help("Base URL of the target API"))
        .arg(Arg::new("attacker_token")
            .short('a')
            .long("attacker-token")
            .required(true)
            .num_args(1)
            .help("JWT or token for the attacker user"))
        .arg(Arg::new("victim_id")
            .short('v')
            .long("victim-id")
            .required(true)
            .num_args(1)
            .help("User ID or resource ID of the victim"))
        .arg(Arg::new("ollama_model")
            .long("ollama-model")
            .num_args(1)
            .default_value("llama2")
            .help("Ollama model to use for PII detection"))
        .arg(Arg::new("no_mutational_fuzzing")
            .long("no-mutational-fuzzing")
            .action(clap::ArgAction::SetTrue)
            .help("Disable mutational fuzzing"))
        .arg(Arg::new("no_pii_analysis")
            .long("no-pii-analysis")
            .action(clap::ArgAction::SetTrue)
            .help("Disable Ollama PII analysis"))
        .arg(Arg::new("no_soft_fail_analysis")
            .long("no-soft-fail-analysis")
            .action(clap::ArgAction::SetTrue)
            .help("Disable soft fail response analysis"))
        .arg(Arg::new("csv_report")
            .long("csv-report")
            .action(clap::ArgAction::SetTrue)
            .help("Output CSV report (default: on)"))
        .arg(Arg::new("markdown_report")
            .long("markdown-report")
            .action(clap::ArgAction::SetTrue)
            .help("Output Markdown report (default: on)"))
        .arg(Arg::new("pdf_report")
            .long("pdf-report")
            .action(clap::ArgAction::SetTrue)
            .help("Output PDF report (default: off)"))
        .get_matches();


    let input = matches.get_one::<String>("input").expect("input is required");
    let base_url = matches.get_one::<String>("base_url").expect("base_url is required");
    let attacker_token = matches.get_one::<String>("attacker_token").expect("attacker_token is required");
    let victim_id = matches.get_one::<String>("victim_id").expect("victim_id is required");
    let ollama_model = matches.get_one::<String>("ollama_model").map(|s| s.as_str()).unwrap_or("llama2");
    let mutational_fuzzing = !matches.get_flag("no_mutational_fuzzing");
    let pii_analysis = !matches.get_flag("no_pii_analysis");
    let soft_fail_analysis = !matches.get_flag("no_soft_fail_analysis");
    let csv_report = matches.get_flag("csv_report") || (!matches.get_flag("markdown_report") && !matches.get_flag("pdf_report"));
    let markdown_report = matches.get_flag("markdown_report") || (!matches.get_flag("csv_report") && !matches.get_flag("pdf_report"));
    let pdf_report = matches.get_flag("pdf_report");

    // Extract attacker ID from JWT token
    let attacker_id = extract_user_id_from_jwt(attacker_token);
    if let Some(ref id) = attacker_id {
        println!("Extracted attacker ID from JWT: {}", id);
    } else {
        println!("Warning: Could not extract user ID from JWT token. Verdict logic may be less accurate.");
    }

    // Select parser based on file extension
    let parser: Box<dyn CollectionParser> = if Path::new(input).is_dir() {
        Box::new(BrunoParser)
    } else if input.ends_with(".json") {
        // Heuristic: .json could be Postman or OpenAPI
        // Try OpenAPI first, fallback to Postman
        let openapi = OpenApiParser;
        match openapi.parse(input) {
            Ok(endpoints) if !endpoints.is_empty() => Box::new(OpenApiParser),
            Ok(_) | Err(_) => Box::new(PostmanParser),
        }
    } else {
        eprintln!("Unsupported input type: {}. Use a Bruno directory or Postman/OpenAPI .json file.", input);
        std::process::exit(2);
    };

    // Parse endpoints
    let endpoints = parser.parse(input).unwrap_or_else(|e| {
        eprintln!("Failed to parse collection: {}", e);
        std::process::exit(1);
    });
    println!("Discovered {} endpoints.", endpoints.len());

    // Initialize attack engine, authentication, and Ollama analyzer
    let engine = AttackEngine::new();
    let auth = StaticTokenAuth { token: attacker_token.to_string() };
    let ollama = OllamaAnalyzer::new(ollama_model.to_string());

    let mut results = Vec::new();

    // Attack each endpoint with mutational fuzzing and advanced param handling

    for endpoint in endpoints {
        // If endpoint.path already contains full URL (from OpenAPI servers), use it directly
        // Otherwise, prepend base_url
        let base_path = if endpoint.path.starts_with("http://") || endpoint.path.starts_with("https://") {
            endpoint.path.clone()
        } else {
            format!("{}{}", base_url, endpoint.path)
        };

        let method = format!("{:?}", endpoint.method);
        let fuzz_inputs = if mutational_fuzzing { mutate_param(&victim_id) } else { vec![victim_id.to_string()] };
        for mutated in fuzz_inputs {
            // Categorize parameters by type
            let mut path_params = HashMap::new();
            let mut query_params = HashMap::new();
            let mut body_params = HashMap::new();

            for p in &endpoint.params {
                // Detect parameter type based on naming convention
                if p.starts_with("body.") {
                    // Body parameter (e.g., "body.firstName")
                    let param_name = p.strip_prefix("body.").unwrap_or(p);
                    body_params.insert(param_name.to_string(), mutated.clone());
                } else if base_path.contains(&format!("{{{}}}", p)) {
                    // Path parameter (e.g., "id" in "/users/{id}")
                    path_params.insert(p.clone(), mutated.clone());
                } else {
                    // Query parameter
                    query_params.insert(p.clone(), mutated.clone());
                }
            }

            // Replace path parameters in URL
            let mut url = base_path.clone();
            for (param_name, param_value) in &path_params {
                url = url.replace(&format!("{{{}}}", param_name), param_value);
            }

            // Build request with authentication
            let mut req = engine.client.request(method.parse().unwrap(), &url);
            req = auth.apply_auth(req);

            // Add query parameters
            for (k, v) in &query_params {
                req = req.query(&[(k, v)]);
            }

            // Add body parameters as JSON
            if !body_params.is_empty() {
                req = req.json(&body_params);
            }

            match req.send().await {
                Ok(resp) => {
                    // Read response body text once
                    let status = resp.status().as_u16();
                    let body_text = resp.text().await.unwrap_or_default();
                    let verdict = decide_verdict(
                        status,
                        &body_text,
                        attacker_id.as_deref(),
                        Some(victim_id.as_str())
                    );
                    let mut result_str = match verdict {
                        Verdict::Vulnerable => "VULNERABLE".to_string(),
                        Verdict::Secure => "SECURE".to_string(),
                        Verdict::Uncertain => "UNCERTAIN".to_string(),
                    };
                    // Response analysis for soft fails and binary
                    if soft_fail_analysis {
                        if let Some(soft_fail) = analyze_response_soft_fails(&body_text) {
                            result_str.push_str(&format!(" | {}", soft_fail));
                        }
                    }
                    // PII analysis for vulnerable (attempt JSON parse)
                    if pii_analysis {
                        if let Verdict::Vulnerable = verdict {
                            if let Ok(json) = serde_json::from_str::<Value>(&body_text) {
                                if let Ok(analysis) = ollama.analyze_response(&json).await {
                                    result_str.push_str(&format!(" | PII: {}", analysis));
                                }
                            }
                        }
                    }
                    println!("[{}] {}: {}", result_str, method, url);
                    results.push((method.clone(), url.clone(), result_str));
                }
                Err(e) => {
                    println!("[ERROR] {}: {}: {}", method, url, e);
                    results.push((method.clone(), url.clone(), format!("ERROR: {}", e)));
                }
            }
        }
    }

    // Export results
    if csv_report { export_csv(&results); }
    if markdown_report { export_markdown(&results); }
    if pdf_report { /* TODO: export_pdf(&results); */ }
    // TODO: Export SARIF, etc.
}
