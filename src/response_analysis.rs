// Response Analysis for Doppel
//
// Detects soft-fail patterns and binary responses that may indicate
// authorization working correctly despite a 200 OK status code.
//
// Soft fails: Server returns 200 OK but includes error message
// Binary responses: Non-JSON data (images, files, etc.)

/// Soft-fail detection keywords (case-insensitive)
const SOFT_FAIL_KEYWORDS: &[&str] = &[
    "error",
    "not allowed",
    "denied",
    "forbidden",
    "unauthorized",
    "permission",
    "access denied",
    "not authorized",
    "invalid",
    "failed",
    "rejected",
    "not permitted",
];

/// Analyze the response body for soft-fail heuristics and binary detection.
///
/// Returns Some(description) if a soft-fail or binary is detected, None otherwise.
pub fn analyze_response_soft_fails(body: &str) -> Option<String> {
    // Case-insensitive error keyword detection
    let body_lower = body.to_lowercase();
    for keyword in SOFT_FAIL_KEYWORDS {
        if body_lower.contains(keyword) {
            return Some(format!("Soft fail: '{}'", keyword));
        }
    }

    // Improved binary/non-JSON detection
    if is_likely_binary(body) {
        return Some("Binary or non-text response".to_string());
    }

    // Flag unstructured responses only if they're substantial (likely file content)
    // Short plain text responses (< 50 chars) are likely just simple messages
    if !is_structured_data(body) && !body.is_empty() && body.len() > 50 {
        return Some("Possible file or non-JSON response".to_string());
    }

    None
}

/// Check if response body is likely binary data
fn is_likely_binary(body: &str) -> bool {
    // Null bytes are definitive binary indicator
    if body.contains('\0') {
        return true;
    }

    // Empty is not binary
    if body.is_empty() {
        return false;
    }

    // Check for high ratio of non-printable ASCII characters
    let non_printable = body
        .chars()
        .filter(|c| !c.is_ascii() || (c.is_ascii_control() && !c.is_ascii_whitespace()))
        .count();

    let ratio = non_printable as f32 / body.len() as f32;
    ratio > 0.3 // More than 30% non-printable = likely binary
}

/// Check if response body appears to be structured data (JSON, XML, HTML)
fn is_structured_data(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return true; // Empty is technically structured (valid JSON: "")
    }

    // JSON
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return true;
    }

    // XML/HTML
    if trimmed.starts_with('<') && trimmed.ends_with('>') {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soft_fail_case_insensitive() {
        // Lowercase
        assert!(analyze_response_soft_fails("error occurred").is_some());

        // Uppercase
        assert!(analyze_response_soft_fails("ERROR OCCURRED").is_some());

        // Mixed case
        assert!(analyze_response_soft_fails("Access Denied").is_some());
    }

    #[test]
    fn test_soft_fail_keywords() {
        let test_cases = vec![
            ("error", true),
            ("forbidden", true),
            ("unauthorized", true),
            ("permission denied", true),
            ("success", false),
            ("data loaded", false),
        ];

        for (body, should_detect) in test_cases {
            let result = analyze_response_soft_fails(body);
            assert_eq!(
                result.is_some(),
                should_detect,
                "Body '{}' detection mismatch",
                body
            );
        }
    }

    #[test]
    fn test_json_not_flagged_as_binary() {
        assert!(analyze_response_soft_fails(r#"{"key":"value"}"#).is_none());
        assert!(analyze_response_soft_fails(r#"[1,2,3]"#).is_none());
    }

    #[test]
    fn test_xml_detected_as_structured() {
        assert!(is_structured_data("<?xml version='1.0'?><root></root>"));
        assert!(is_structured_data("<html><body>test</body></html>"));
    }

    #[test]
    fn test_binary_detection() {
        // Null byte = binary
        assert!(is_likely_binary("data\0binary"));

        // Normal text = not binary
        assert!(!is_likely_binary("normal text response"));

        // High ratio of control characters = binary
        let binary_like = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a";
        assert!(is_likely_binary(binary_like));
    }

    #[test]
    fn test_empty_response() {
        assert!(analyze_response_soft_fails("").is_none());
        assert!(!is_likely_binary(""));
        assert!(is_structured_data(""));
    }

    #[test]
    fn test_plain_text_detection() {
        // Long unstructured text should be flagged (possible file content)
        let plain_text = "This is a long plain text response that might be file content. It goes on and on with no structure whatsoever.";
        assert!(analyze_response_soft_fails(plain_text).is_some());
        assert!(!is_structured_data(plain_text));

        // Short plain text should NOT be flagged
        let short_text = "success";
        assert!(analyze_response_soft_fails(short_text).is_none());
    }
}
