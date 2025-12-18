// Verdict engine for BOLA-Fuzz
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
/// 5. 404 = UNCERTAIN (resource might not exist)
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

        // Resource not found - uncertain (might be proper authorization or missing resource)
        404 => Verdict::Uncertain,

        // Other status codes (5xx, etc.)
        _ => Verdict::Uncertain,
    }
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

/// Check for identifier in identity-specific fields only.
/// This prevents false positives where the victim ID appears in user-editable data.
fn contains_identifier_in_identity_fields(value: &Value, identifier: &str) -> bool {
    // Identity field names that indicate resource ownership
    const IDENTITY_FIELDS: &[&str] = &[
        "id", "userId", "user_id", "uid", "owner_id", "ownerId",
        "created_by", "createdBy", "updated_by", "updatedBy",
        "author_id", "authorId", "account_id", "accountId"
    ];

    match value {
        Value::Object(obj) => {
            // Check if this object has identity fields
            for field_name in IDENTITY_FIELDS {
                if let Some(field_value) = obj.get(*field_name) {
                    if let Some(s) = field_value.as_str() {
                        if s == identifier {
                            return true;
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
                            if contains_identifier_in_identity_fields(val, identifier) {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            false
        }
        Value::Array(arr) => {
            arr.iter().any(|v| contains_identifier_in_identity_fields(v, identifier))
        }
        _ => false,
    }
}

/// Recursively search for an identifier in JSON value
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
