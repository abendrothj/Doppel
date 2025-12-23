// Parameter Classification & Risk Scoring
//
// STATIC ANALYSIS of API parameter names to identify BOLA/IDOR vulnerability candidates.
// This module does NOT manipulate parameter values (see params.rs for that).
//
// Responsibilities:
// - Classify parameter types (UserId, ResourceId, UUID, Email, etc.)
// - Calculate BOLA risk scores (0-100) based on multiple factors
// - Assign confidence levels to classifications
// - Pattern matching using optimized regex
//
// This is the INTELLIGENCE layer that understands what parameters mean semantically.
//
// Example:
//   Input:  name="userId", path="/api/users/{userId}", method="GET"
//   Output: DetectedParameter {
//             type: UserId,
//             risk_score: 95,
//             confidence: VeryHigh
//           }
//
// Used by: param_analyzer.rs for endpoint-level analysis

use regex::Regex;
use lazy_static::lazy_static;

/// Parameter type classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamType {
    /// User or entity identifier (high BOLA risk)
    UserId,
    /// Resource identifier (high BOLA risk)
    ResourceId,
    /// UUID format identifier
    Uuid,
    /// Numeric ID
    NumericId,
    /// Email address
    Email,
    /// Date/DateTime
    DateTime,
    /// Boolean flag
    Boolean,
    /// Generic string
    String,
    /// Numeric value
    Number,
    /// Array/List
    Array,
    /// Nested object
    Object,
    /// Unknown type
    Unknown,
}

/// Confidence level for parameter classification
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    VeryHigh,  // 90-100% confidence
    High,      // 70-89% confidence
    Medium,    // 40-69% confidence
    Low,       // 20-39% confidence
    VeryLow,   // 0-19% confidence
}

impl Confidence {
    pub fn as_score(&self) -> u8 {
        match self {
            Confidence::VeryHigh => 95,
            Confidence::High => 80,
            Confidence::Medium => 55,
            Confidence::Low => 30,
            Confidence::VeryLow => 10,
        }
    }
}

/// Represents a detected parameter with metadata
#[derive(Debug, Clone)]
pub struct DetectedParameter {
    pub name: String,
    pub param_type: ParamType,
    pub confidence: Confidence,
    pub bola_risk_score: u8,  // 0-100, higher = more likely to be BOLA vulnerable
    pub context: ParameterContext,
}

/// Context information about where and how the parameter is used
#[derive(Debug, Clone)]
pub struct ParameterContext {
    pub endpoint_path: String,
    pub http_method: String,
    pub location: crate::models::ParameterLocation,
    pub is_required: bool,
    pub related_resources: Vec<String>,  // e.g., "user", "account", "order"
}

lazy_static! {
    // Common ID-related parameter names (case-insensitive)
    static ref USER_ID_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)^(user_?id|userid|uid)$").unwrap(),
        Regex::new(r"(?i)^(owner_?id|ownerid)$").unwrap(),
        Regex::new(r"(?i)^(created_?by|createdby)$").unwrap(),
        Regex::new(r"(?i)^(author_?id|authorid)$").unwrap(),
        Regex::new(r"(?i)^(member_?id|memberid)$").unwrap(),
    ];

    static ref RESOURCE_ID_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)^(account_?id|accountid)$").unwrap(),
        Regex::new(r"(?i)^(order_?id|orderid)$").unwrap(),
        Regex::new(r"(?i)^(transaction_?id|transactionid|txn_?id)$").unwrap(),
        Regex::new(r"(?i)^(document_?id|documentid|doc_?id)$").unwrap(),
        Regex::new(r"(?i)^(message_?id|messageid|msg_?id)$").unwrap(),
        Regex::new(r"(?i)^(project_?id|projectid)$").unwrap(),
        Regex::new(r"(?i)^(post_?id|postid)$").unwrap(),
        Regex::new(r"(?i)^(comment_?id|commentid)$").unwrap(),
        Regex::new(r"(?i)^(file_?id|fileid)$").unwrap(),
        Regex::new(r"(?i)^(payment_?id|paymentid)$").unwrap(),
    ];

    static ref GENERIC_ID_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)^id$").unwrap(),
        Regex::new(r"(?i)^.*_?id$").unwrap(),
        Regex::new(r"(?i)^.*id$").unwrap(),
    ];

    // UUID pattern (8-4-4-4-12 format)
    static ref UUID_PATTERN: Regex = Regex::new(
        r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ).unwrap();

    // Email pattern
    static ref EMAIL_PATTERN: Regex = Regex::new(
        r"(?i)^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
    ).unwrap();

    // Date/DateTime patterns
    static ref DATE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)^(created_?at|createdat)$").unwrap(),
        Regex::new(r"(?i)^(updated_?at|updatedat)$").unwrap(),
        Regex::new(r"(?i)^(deleted_?at|deletedat)$").unwrap(),
        Regex::new(r"(?i)^(date|datetime|timestamp)$").unwrap(),
        Regex::new(r"(?i)^.*_?(date|time)$").unwrap(),
    ];

    // Resource type extraction from endpoint paths
    static ref RESOURCE_PATTERN: Regex = Regex::new(
        r"/([a-z]+)(?:/\{[^}]+\}|$)"
    ).unwrap();
}

/// Main parameter detector
pub struct ParameterDetector;

impl ParameterDetector {
    /// Analyze a parameter and classify it with confidence scoring
    pub fn analyze_parameter(
        name: &str,
        endpoint_path: &str,
        http_method: &str,
        location: crate::models::ParameterLocation,
        is_required: bool,
    ) -> DetectedParameter {
        let param_type = Self::classify_type(name);
        let confidence = Self::calculate_confidence(name, &param_type, endpoint_path, &location);
        let bola_risk_score = Self::calculate_bola_risk(
            name,
            &param_type,
            endpoint_path,
            http_method,
            &location,
            is_required,
        );
        let related_resources = Self::extract_related_resources(endpoint_path);

        DetectedParameter {
            name: name.to_string(),
            param_type,
            confidence,
            bola_risk_score,
            context: ParameterContext {
                endpoint_path: endpoint_path.to_string(),
                http_method: http_method.to_string(),
                location,
                is_required,
                related_resources,
            },
        }
    }

    /// Classify parameter type based on name and patterns
    fn classify_type(name: &str) -> ParamType {
        // Check for user ID patterns (highest priority)
        for pattern in USER_ID_PATTERNS.iter() {
            if pattern.is_match(name) {
                return ParamType::UserId;
            }
        }

        // Check for resource ID patterns
        for pattern in RESOURCE_ID_PATTERNS.iter() {
            if pattern.is_match(name) {
                return ParamType::ResourceId;
            }
        }

        // Check for UUID format
        if name.to_lowercase().contains("uuid") || name.to_lowercase().contains("guid") {
            return ParamType::Uuid;
        }

        // Check for generic ID patterns
        for pattern in GENERIC_ID_PATTERNS.iter() {
            if pattern.is_match(name) {
                // Try to determine if it's numeric
                if name.to_lowercase().contains("num") || name.chars().any(|c| c.is_ascii_digit()) {
                    return ParamType::NumericId;
                }
                return ParamType::ResourceId;  // Default to resource ID for generic IDs
            }
        }

        // Check for email
        if name.to_lowercase().contains("email") || name.to_lowercase().contains("mail") {
            return ParamType::Email;
        }

        // Check for date/time
        for pattern in DATE_PATTERNS.iter() {
            if pattern.is_match(name) {
                return ParamType::DateTime;
            }
        }

        // Check for boolean
        if name.to_lowercase().starts_with("is_")
            || name.to_lowercase().starts_with("has_")
            || name.to_lowercase().starts_with("can_")
            || name.to_lowercase().ends_with("_flag")
        {
            return ParamType::Boolean;
        }

        ParamType::Unknown
    }

    /// Calculate confidence level for the classification
    fn calculate_confidence(
        name: &str,
        param_type: &ParamType,
        endpoint_path: &str,
        location: &crate::models::ParameterLocation,
    ) -> Confidence {
        let mut score = 0u8;

        // Base confidence from type classification
        match param_type {
            ParamType::UserId => score += 40,
            ParamType::ResourceId => score += 35,
            ParamType::Uuid => score += 30,
            ParamType::NumericId => score += 25,
            ParamType::Email => score += 30,
            ParamType::DateTime => score += 20,
            ParamType::Boolean => score += 20,
            _ => score += 10,
        }

        // Boost confidence if parameter name matches endpoint resource
        let resources = Self::extract_related_resources(endpoint_path);
        for resource in &resources {
            if name.to_lowercase().contains(&resource.to_lowercase()) {
                score += 20;
                break;
            }
        }

        // Path parameters are more likely to be IDs
        if matches!(location, crate::models::ParameterLocation::Path) {
            score += 25;
        }

        // Exact name matches get high confidence
        if matches!(param_type, ParamType::UserId | ParamType::ResourceId) {
            if name.eq_ignore_ascii_case("id")
                || name.eq_ignore_ascii_case("userId")
                || name.eq_ignore_ascii_case("user_id")
            {
                score += 20;
            }
        }

        // Convert score to confidence level
        match score {
            90..=100 => Confidence::VeryHigh,
            70..=89 => Confidence::High,
            40..=69 => Confidence::Medium,
            20..=39 => Confidence::Low,
            _ => Confidence::VeryLow,
        }
    }

    /// Calculate BOLA risk score (0-100, higher = more likely vulnerable)
    fn calculate_bola_risk(
        name: &str,
        param_type: &ParamType,
        endpoint_path: &str,
        http_method: &str,
        location: &crate::models::ParameterLocation,
        is_required: bool,
    ) -> u8 {
        let mut risk_score = 0u8;

        // Base risk from parameter type
        match param_type {
            ParamType::UserId => risk_score += 40,
            ParamType::ResourceId => risk_score += 35,
            ParamType::Uuid => risk_score += 30,
            ParamType::NumericId => risk_score += 30,
            ParamType::Email => risk_score += 15,
            _ => risk_score += 5,
        }

        // HTTP method impact
        match http_method.to_uppercase().as_str() {
            "GET" => risk_score += 25,      // Read operations are high risk
            "DELETE" => risk_score += 20,   // Delete operations are high risk
            "PUT" | "PATCH" => risk_score += 15,  // Update operations are medium risk
            "POST" => risk_score += 10,     // Create operations are lower risk
            _ => {}
        }

        // Path parameters in GET/DELETE are very high risk
        if matches!(location, crate::models::ParameterLocation::Path)
            && matches!(http_method.to_uppercase().as_str(), "GET" | "DELETE")
        {
            risk_score += 20;
        }

        // Required parameters are more important
        if is_required {
            risk_score += 10;
        }

        // Paths containing "user", "account", "profile" are high risk
        let high_risk_resources = ["user", "account", "profile", "transaction", "payment", "order"];
        for resource in &high_risk_resources {
            if endpoint_path.to_lowercase().contains(resource) {
                risk_score += 15;
                break;
            }
        }

        // Parameters named exactly "id" in path position are very high risk
        if name.eq_ignore_ascii_case("id")
            && matches!(location, crate::models::ParameterLocation::Path)
        {
            risk_score += 10;
        }

        risk_score.min(100)
    }

    /// Extract resource names from endpoint path
    fn extract_related_resources(endpoint_path: &str) -> Vec<String> {
        let mut resources = Vec::new();

        for cap in RESOURCE_PATTERN.captures_iter(endpoint_path) {
            if let Some(resource) = cap.get(1) {
                let resource_name = resource.as_str().to_string();
                // Filter out common non-resource path segments
                if !["api", "v1", "v2", "v3", "public", "private"].contains(&resource_name.as_str())
                {
                    resources.push(resource_name);
                }
            }
        }

        resources
    }

    /// Prioritize parameters for BOLA testing (returns sorted by risk score)
    pub fn prioritize_parameters(params: Vec<DetectedParameter>) -> Vec<DetectedParameter> {
        let mut sorted = params;
        sorted.sort_by(|a, b| b.bola_risk_score.cmp(&a.bola_risk_score));
        sorted
    }

    /// Filter parameters to only high-risk BOLA candidates
    pub fn filter_high_risk(params: Vec<DetectedParameter>, min_risk_score: u8) -> Vec<DetectedParameter> {
        params
            .into_iter()
            .filter(|p| p.bola_risk_score >= min_risk_score)
            .collect()
    }

    /// Check if a parameter value looks like a valid ID
    pub fn is_valid_id_format(value: &str, param_type: &ParamType) -> bool {
        match param_type {
            ParamType::Uuid => UUID_PATTERN.is_match(value),
            ParamType::NumericId => value.chars().all(|c| c.is_ascii_digit()),
            ParamType::Email => EMAIL_PATTERN.is_match(value),
            ParamType::UserId | ParamType::ResourceId => {
                // Accept alphanumeric with underscores, hyphens
                !value.is_empty()
                    && value
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            }
            _ => !value.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ParameterLocation;

    #[test]
    fn test_classify_user_id() {
        assert_eq!(ParameterDetector::classify_type("userId"), ParamType::UserId);
        assert_eq!(ParameterDetector::classify_type("user_id"), ParamType::UserId);
        assert_eq!(ParameterDetector::classify_type("uid"), ParamType::UserId);
        assert_eq!(ParameterDetector::classify_type("ownerId"), ParamType::UserId);
    }

    #[test]
    fn test_classify_resource_id() {
        assert_eq!(
            ParameterDetector::classify_type("accountId"),
            ParamType::ResourceId
        );
        assert_eq!(
            ParameterDetector::classify_type("orderId"),
            ParamType::ResourceId
        );
        assert_eq!(
            ParameterDetector::classify_type("transactionId"),
            ParamType::ResourceId
        );
    }

    #[test]
    fn test_classify_generic_id() {
        assert_eq!(ParameterDetector::classify_type("id"), ParamType::ResourceId);
        assert_eq!(
            ParameterDetector::classify_type("postId"),
            ParamType::ResourceId
        );
    }

    #[test]
    fn test_bola_risk_calculation() {
        let param = ParameterDetector::analyze_parameter(
            "userId",
            "/api/users/{userId}",
            "GET",
            ParameterLocation::Path,
            true,
        );
        assert!(param.bola_risk_score >= 80, "userId in GET path should be very high risk");

        let param2 = ParameterDetector::analyze_parameter(
            "name",
            "/api/posts",
            "POST",
            ParameterLocation::Body,
            false,
        );
        assert!(param2.bola_risk_score < 35, "Name in POST body should be low risk (got: {})", param2.bola_risk_score);
    }

    #[test]
    fn test_extract_resources() {
        let resources = ParameterDetector::extract_related_resources("/api/users/{id}/orders/{orderId}");
        assert!(resources.contains(&"users".to_string()));
        assert!(resources.contains(&"orders".to_string()));
        assert!(!resources.contains(&"api".to_string()));
    }

    #[test]
    fn test_prioritization() {
        let params = vec![
            ParameterDetector::analyze_parameter(
                "name",
                "/api/users/{id}",
                "POST",
                ParameterLocation::Body,
                false,
            ),
            ParameterDetector::analyze_parameter(
                "userId",
                "/api/users/{userId}",
                "GET",
                ParameterLocation::Path,
                true,
            ),
            ParameterDetector::analyze_parameter(
                "email",
                "/api/users",
                "GET",
                ParameterLocation::Query,
                false,
            ),
        ];

        let prioritized = ParameterDetector::prioritize_parameters(params);
        assert_eq!(prioritized[0].name, "userId", "userId should be highest priority");
    }

    #[test]
    fn test_confidence_calculation() {
        let param = ParameterDetector::analyze_parameter(
            "userId",
            "/api/users/{userId}",
            "GET",
            ParameterLocation::Path,
            true,
        );
        assert!(
            matches!(param.confidence, Confidence::VeryHigh | Confidence::High),
            "userId in path should have high confidence"
        );
    }

    #[test]
    fn test_valid_id_formats() {
        assert!(ParameterDetector::is_valid_id_format(
            "550e8400-e29b-41d4-a716-446655440000",
            &ParamType::Uuid
        ));
        assert!(ParameterDetector::is_valid_id_format("12345", &ParamType::NumericId));
        assert!(ParameterDetector::is_valid_id_format(
            "user@example.com",
            &ParamType::Email
        ));
        assert!(ParameterDetector::is_valid_id_format("user_123", &ParamType::UserId));
    }

    #[test]
    fn test_filter_high_risk() {
        let params = vec![
            ParameterDetector::analyze_parameter(
                "userId",
                "/api/users/{userId}",
                "GET",
                ParameterLocation::Path,
                true,
            ),
            ParameterDetector::analyze_parameter(
                "name",
                "/api/users",
                "POST",
                ParameterLocation::Body,
                false,
            ),
        ];

        let high_risk = ParameterDetector::filter_high_risk(params, 50);
        assert_eq!(high_risk.len(), 1);
        assert_eq!(high_risk[0].name, "userId");
    }
}
