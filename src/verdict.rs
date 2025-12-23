// Verdict engine for Doppel
// Decides if a response is vulnerable, secure, or uncertain

use serde_json::Value;

pub enum Verdict {
    Vulnerable,
    Secure,
    Uncertain,
}

/// Decide verdict from HTTP status and response body.
///
/// A proper BOLA check requires:
/// 1. 200 OK with victim's data = VULNERABLE
/// 2. 200 OK with attacker's own data = SECURE (proper authorization)
/// 3. 403/401 = SECURE (proper access control)
/// 4. 400 = SECURE (proper input validation)
/// 5. 404 = Context-dependent (could be authorization or missing resource)
///
/// This function analyzes the response to determine if victim data is leaked.
pub fn decide_verdict(status: u16, body: &str, attacker_id: Option<&str>, victim_id: Option<&str>) -> Verdict {
    match status {
        // Access denied - properly secured
        401 | 403 => Verdict::Secure,

        // Bad request - proper input validation
        400 => Verdict::Secure,

        // Success response - need to check whose data is returned
        200 | 201 => {
            // If we have both attacker and victim IDs, analyze the response
            if let (Some(attacker), Some(victim)) = (attacker_id, victim_id) {
                analyze_response_ownership(body, attacker, victim)
            } else {
                // Fallback to old behavior if IDs not provided
                Verdict::Uncertain
            }
        }

        // Resource not found - context-dependent
        404 => analyze_404_context(body),

        // Other status codes (5xx, etc.)
        _ => Verdict::Uncertain,
    }
}

/// Analyze 404 responses for context clues about authorization.
///
/// A 404 can mean:
/// 1. Resource truly doesn't exist → Uncertain
/// 2. Resource exists but is hidden due to authorization → Secure
/// 3. Generic "not found" message → Uncertain
fn analyze_404_context(body: &str) -> Verdict {
    let body_lower = body.to_lowercase();

    // Check for authorization-related messages in 404 response
    let auth_keywords = [
        "unauthorized",
        "forbidden",
        "access denied",
        "not authorized",
        "permission",
        "not allowed",
    ];

    for keyword in &auth_keywords {
        if body_lower.contains(keyword) {
            // 404 with auth message suggests proper authorization
            return Verdict::Secure;
        }
    }

    // Generic 404 - can't determine if it's authorization or missing resource
    Verdict::Uncertain
}

/// Analyze response body to determine if it contains victim or attacker data.
fn analyze_response_ownership(body: &str, attacker_id: &str, victim_id: &str) -> Verdict {
    // Try to parse as JSON
    let json: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            // If not JSON, do string-based analysis
            return analyze_text_ownership(body, attacker_id, victim_id);
        }
    };

    // First check identity fields (id, userId, user_id, etc.)
    // These are the critical fields that indicate resource ownership
    let has_victim_identity = contains_identifier_in_identity_fields(&json, victim_id);
    let has_attacker_identity = contains_identifier_in_identity_fields(&json, attacker_id);

    if has_victim_identity {
        // Found victim's ID in identity fields - VULNERABLE!
        Verdict::Vulnerable
    } else if has_attacker_identity {
        // Only found attacker's ID in identity fields - SECURE
        Verdict::Secure
    } else {
        // No clear identity match - check if it's an error response
        if is_error_response(&json) {
            Verdict::Secure
        } else {
            // Might be public data or data without clear ownership
            Verdict::Uncertain
        }
    }
}

/// Field classification for weighted identity matching
#[derive(Debug, PartialEq)]
enum FieldWeight {
    Critical,  // id, userId, user_id - direct resource ownership
    Metadata,  // created_by, updated_by - metadata fields (could be public)
}

/// Classify identity field by importance
fn classify_identity_field(field_name: &str) -> Option<FieldWeight> {
    // Critical fields - direct ownership indicators
    const CRITICAL_FIELDS: &[&str] = &[
        "id", "userId", "user_id", "uid", "ownerId", "owner_id",
        "account_id", "accountId",
    ];

    // Metadata fields - could be public information
    const METADATA_FIELDS: &[&str] = &[
        "created_by", "createdBy", "updated_by", "updatedBy",
        "author_id", "authorId", "modified_by", "modifiedBy",
    ];

    if CRITICAL_FIELDS.contains(&field_name) {
        Some(FieldWeight::Critical)
    } else if METADATA_FIELDS.contains(&field_name) {
        Some(FieldWeight::Metadata)
    } else {
        None
    }
}

/// Result of identity field search with weight information
#[derive(Debug)]
struct IdentityMatch {
    found: bool,
    weight: Option<FieldWeight>,
}

/// Check for identifier in identity-specific fields with weighting.
/// This prevents false positives where the victim ID appears in user-editable data.
fn contains_identifier_in_identity_fields(value: &Value, identifier: &str) -> bool {
    match find_identifier_with_weight(value, identifier) {
        Some(IdentityMatch { found: true, weight: Some(FieldWeight::Critical) }) => true,
        _ => false,
    }
}

/// Find identifier and return its field weight for nuanced verdict
fn find_identifier_with_weight(value: &Value, identifier: &str) -> Option<IdentityMatch> {
    // All identity fields (critical + metadata)
    const ALL_IDENTITY_FIELDS: &[&str] = &[
        "id", "userId", "user_id", "uid", "owner_id", "ownerId",
        "created_by", "createdBy", "updated_by", "updatedBy",
        "author_id", "authorId", "account_id", "accountId",
        "modified_by", "modifiedBy",
    ];

    match value {
        Value::Object(obj) => {
            // Check if this object has identity fields
            for field_name in ALL_IDENTITY_FIELDS {
                if let Some(field_value) = obj.get(*field_name) {
                    if let Some(s) = field_value.as_str() {
                        if s == identifier {
                            let weight = classify_identity_field(field_name);
                            return Some(IdentityMatch {
                                found: true,
                                weight,
                            });
                        }
                    }
                }
            }

            // Recursively check nested objects and arrays
            for (key, val) in obj {
                // Skip user-editable fields that might contain arbitrary data
                let is_editable_field = matches!(
                    key.as_str(),
                    "firstName" | "lastName" | "first_name" | "last_name" |
                    "name" | "email" | "phone" | "phoneNumber" | "phone_number" |
                    "address" | "bio" | "description" | "notes" | "content" |
                    "message" | "text" | "title" | "dateOfBirth" | "date_of_birth"
                );

                if !is_editable_field {
                    match val {
                        Value::Object(_) | Value::Array(_) => {
                            if let Some(match_result) = find_identifier_with_weight(val, identifier) {
                                if match_result.found {
                                    return Some(match_result);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            None
        }
        Value::Array(arr) => {
            for item in arr {
                if let Some(match_result) = find_identifier_with_weight(item, identifier) {
                    if match_result.found {
                        return Some(match_result);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Recursively search for an identifier in JSON value
#[allow(dead_code)]
fn contains_identifier(value: &Value, identifier: &str) -> bool {
    match value {
        Value::String(s) => s.contains(identifier),
        Value::Array(arr) => arr.iter().any(|v| contains_identifier(v, identifier)),
        Value::Object(obj) => obj.values().any(|v| contains_identifier(v, identifier)),
        _ => false,
    }
}

/// Check if JSON response is an error response
fn is_error_response(value: &Value) -> bool {
    if let Value::Object(obj) = value {
        // Check for common error indicators
        if let Some(success) = obj.get("success") {
            if success == &Value::Bool(false) {
                return true;
            }
        }
        if obj.contains_key("error") || obj.contains_key("message") {
            return true;
        }
    }
    false
}

/// Fallback text-based analysis for non-JSON responses
fn analyze_text_ownership(body: &str, attacker_id: &str, victim_id: &str) -> Verdict {
    let has_victim = body.contains(victim_id);
    let has_attacker = body.contains(attacker_id);

    if has_victim {
        Verdict::Vulnerable
    } else if has_attacker {
        Verdict::Secure
    } else {
        Verdict::Uncertain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Status Code Tests
    // ============================================

    #[test]
    fn test_verdict_401_unauthorized() {
        let verdict = decide_verdict(401, "", Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_403_forbidden() {
        let verdict = decide_verdict(403, "", Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_400_bad_request() {
        let verdict = decide_verdict(400, "", Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_404_generic() {
        // Generic 404 - uncertain
        let verdict = decide_verdict(404, "Not found", Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    #[test]
    fn test_verdict_404_with_auth_message() {
        // 404 with auth-related message - likely proper authorization
        let verdict = decide_verdict(404, "Resource not found: access denied", Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_404_with_unauthorized() {
        // 404 with "unauthorized" - proper authorization
        let verdict = decide_verdict(404, "404: Unauthorized to view this resource", Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_500_server_error() {
        let verdict = decide_verdict(500, "", Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    // ============================================
    // Identity Field Detection Tests
    // ============================================

    #[test]
    fn test_verdict_200_with_victim_id() {
        let body = r#"{"id":"victim_123","name":"Victim User"}"#;
        let verdict = decide_verdict(200, body, Some("attacker_456"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_verdict_200_with_attacker_id() {
        let body = r#"{"id":"attacker_456","name":"Attacker User"}"#;
        let verdict = decide_verdict(200, body, Some("attacker_456"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_200_with_user_id() {
        let body = r#"{"userId":"victim_123","name":"Victim"}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_verdict_200_with_owner_id() {
        let body = r#"{"ownerId":"victim_123","data":"sensitive"}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_verdict_200_with_created_by_metadata() {
        // Metadata field (created_by) - now treated as non-critical
        // This could be a public post where created_by is visible to all
        let body = r#"{"postId":"123","created_by":"victim_123","title":"Public Post"}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        // NOTE: With field weighting, metadata fields alone don't trigger VULNERABLE
        // They need a critical field match for definitive vulnerability
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    #[test]
    fn test_verdict_200_with_critical_id_field() {
        // Critical field (id) - definitive ownership indicator
        let body = r#"{"id":"victim_123","created_by":"victim_123","title":"Document"}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    // ============================================
    // Nested JSON Tests
    // ============================================

    #[test]
    fn test_verdict_nested_victim_id() {
        let body = r#"{"data":{"user":{"id":"victim_123"}}}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_verdict_array_with_victim_id() {
        let body = r#"{"users":[{"id":"victim_123"},{"id":"other_user"}]}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_verdict_deeply_nested() {
        let body = r#"{"level1":{"level2":{"level3":{"userId":"victim_123"}}}}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    // ============================================
    // False Positive Prevention Tests
    // ============================================

    #[test]
    fn test_verdict_victim_id_in_name_field() {
        // Victim ID appears in user-editable field - should NOT be flagged
        let body = r#"{"id":"attacker_456","name":"victim_123"}"#;
        let verdict = decide_verdict(200, body, Some("attacker_456"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_victim_id_in_email_field() {
        // Victim ID in email field - should NOT be flagged
        let body = r#"{"id":"attacker","email":"victim_123@example.com"}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_victim_id_in_bio() {
        // Victim ID in bio field - should NOT be flagged
        let body = r#"{"id":"attacker","bio":"Hello from victim_123"}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    // ============================================
    // Error Response Tests
    // ============================================

    #[test]
    fn test_verdict_200_with_error_field() {
        let body = r#"{"error":"Not found","success":false}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_200_with_success_false() {
        let body = r#"{"success":false,"message":"Access denied"}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    // ============================================
    // Text-based Fallback Tests
    // ============================================

    #[test]
    fn test_verdict_plain_text_with_victim_id() {
        let body = "User: victim_123\nData: sensitive information";
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_verdict_plain_text_with_attacker_id() {
        let body = "User: attacker_456\nData: your own information";
        let verdict = decide_verdict(200, body, Some("attacker_456"), Some("victim_123"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_plain_text_no_ids() {
        let body = "Generic response with no user identifiers";
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    // ============================================
    // Edge Cases
    // ============================================

    #[test]
    fn test_verdict_200_without_ids() {
        let body = r#"{"data":"something"}"#;
        let verdict = decide_verdict(200, body, None, None);
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    #[test]
    fn test_verdict_200_with_only_attacker_id() {
        let body = r#"{"id":"attacker"}"#;
        let verdict = decide_verdict(200, body, Some("attacker"), None);
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    #[test]
    fn test_verdict_empty_body() {
        let verdict = decide_verdict(200, "", Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    #[test]
    fn test_verdict_malformed_json() {
        let body = "{invalid json";
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    // ============================================
    // Real-world Scenario Tests
    // ============================================

    #[test]
    fn test_verdict_user_profile_vulnerable() {
        let body = r#"{
            "userId": "victim_789",
            "firstName": "Jane",
            "lastName": "Doe",
            "email": "jane@example.com",
            "ssn": "123-45-6789"
        }"#;
        let verdict = decide_verdict(200, body, Some("attacker_456"), Some("victim_789"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_verdict_user_profile_secure() {
        let body = r#"{
            "userId": "attacker_456",
            "firstName": "John",
            "lastName": "Smith",
            "email": "john@example.com"
        }"#;
        let verdict = decide_verdict(200, body, Some("attacker_456"), Some("victim_789"));
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_verdict_order_list_vulnerable() {
        let body = r#"{
            "orders": [
                {"orderId": "001", "userId": "victim_789", "amount": 100},
                {"orderId": "002", "userId": "victim_789", "amount": 200}
            ]
        }"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim_789"));
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_verdict_public_data() {
        let body = r#"{
            "postId": "123",
            "title": "Public Blog Post",
            "content": "Everyone can read this"
        }"#;
        let verdict = decide_verdict(200, body, Some("attacker"), Some("victim"));
        assert!(matches!(verdict, Verdict::Uncertain));
    }

    // ============================================
    // Helper Function Tests
    // ============================================

    #[test]
    fn test_is_error_response_with_error_field() {
        let json: Value = serde_json::from_str(r#"{"error":"Something went wrong"}"#).unwrap();
        assert!(is_error_response(&json));
    }

    #[test]
    fn test_is_error_response_with_message_field() {
        let json: Value = serde_json::from_str(r#"{"message":"Error occurred"}"#).unwrap();
        assert!(is_error_response(&json));
    }

    #[test]
    fn test_is_error_response_with_success_false() {
        let json: Value = serde_json::from_str(r#"{"success":false}"#).unwrap();
        assert!(is_error_response(&json));
    }

    #[test]
    fn test_is_not_error_response() {
        let json: Value = serde_json::from_str(r#"{"success":true,"data":"valid"}"#).unwrap();
        assert!(!is_error_response(&json));
    }

    #[test]
    fn test_contains_identifier_in_identity_fields() {
        let json: Value = serde_json::from_str(r#"{"id":"user_123","name":"Test"}"#).unwrap();
        assert!(contains_identifier_in_identity_fields(&json, "user_123"));
        assert!(!contains_identifier_in_identity_fields(&json, "other_id"));
    }

    #[test]
    fn test_analyze_text_ownership_victim() {
        let verdict = analyze_text_ownership("User victim_123", "attacker", "victim_123");
        assert!(matches!(verdict, Verdict::Vulnerable));
    }

    #[test]
    fn test_analyze_text_ownership_attacker() {
        let verdict = analyze_text_ownership("User attacker_456", "attacker_456", "victim");
        assert!(matches!(verdict, Verdict::Secure));
    }

    #[test]
    fn test_analyze_text_ownership_neither() {
        let verdict = analyze_text_ownership("User other_user", "attacker", "victim");
        assert!(matches!(verdict, Verdict::Uncertain));
    }
}
