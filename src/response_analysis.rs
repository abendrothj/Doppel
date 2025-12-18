// Response analysis for BOLA-Fuzz
// Heuristics for soft fails and binary/file detection

/// Analyze the response body text for soft-fail heuristics and binary detection.
pub fn analyze_response_soft_fails(body: &str) -> Option<String> {
    if body.contains("error") || body.contains("not allowed") || body.contains("denied") {
        Some("Soft fail detected: error message present".to_string())
    } else if !body.is_empty() && !body.starts_with('{') && !body.starts_with('[') {
        Some("Possible binary or file response".to_string())
    } else {
        None
    }
}
