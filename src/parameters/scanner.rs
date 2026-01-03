// Endpoint-Level Parameter Analysis
//
// INTEGRATION layer that applies parameter classification to entire endpoints.
// This bridges param_detector.rs (classification) with main.rs (scanning).
//
// Responsibilities:
// - Analyze all parameters in an endpoint
// - Filter parameters by risk threshold
// - Prioritize parameters for testing
// - Generate human-readable summaries
// - Infer parameter locations from naming conventions
//
// This module operates at the ENDPOINT level, while param_detector.rs
// operates at the individual PARAMETER level.
//
// Example:
//   Input:  Endpoint { path: "/api/users/{userId}", params: ["userId"] }
//   Output: Vec<DetectedParameter> filtered by risk threshold
//
// Used by: main.rs during scan planning and execution

use super::classifier::{DetectedParameter, ParameterDetector};
use crate::models::{Endpoint, ParameterLocation};

/// Analyze all parameters in an endpoint and return prioritized list
pub fn analyze_endpoint_parameters(endpoint: &Endpoint) -> Vec<DetectedParameter> {
    let mut detected_params = Vec::new();
    let method_str = format!("{}", endpoint.method);

    for param_name in &endpoint.params {
        // Determine parameter location based on naming convention and endpoint structure
        let location = infer_parameter_location(param_name, &endpoint.path);

        // Use detector to analyze the parameter
        let detected = ParameterDetector::analyze_parameter(
            param_name,
            &endpoint.path,
            &method_str,
            location,
            true, // Assume required for now (parsers can improve this)
        );

        detected_params.push(detected);
    }

    // Return prioritized by BOLA risk score
    ParameterDetector::prioritize_parameters(detected_params)
}

/// Infer parameter location from naming convention
fn infer_parameter_location(param_name: &str, endpoint_path: &str) -> ParameterLocation {
    // Body parameters are prefixed with "body."
    if param_name.starts_with("body.") {
        return ParameterLocation::Body;
    }

    // Check if parameter appears in path template
    let cleaned_name = param_name.strip_prefix("body.").unwrap_or(param_name);
    if endpoint_path.contains(&format!("{{{}}}", cleaned_name)) {
        return ParameterLocation::Path;
    }

    // Default to query parameter
    ParameterLocation::Query
}

/// Get only high-risk BOLA parameters from an endpoint
pub fn get_high_risk_params(endpoint: &Endpoint, min_risk_score: u8) -> Vec<DetectedParameter> {
    let all_params = analyze_endpoint_parameters(endpoint);
    ParameterDetector::filter_high_risk(all_params, min_risk_score)
}

/// Get a summary report of parameter analysis for an endpoint
pub fn get_parameter_summary(endpoint: &Endpoint) -> String {
    let params = analyze_endpoint_parameters(endpoint);

    if params.is_empty() {
        return format!(
            "{} {} - No parameters detected",
            endpoint.method, endpoint.path
        );
    }

    let mut summary = format!(
        "{} {} - {} parameter(s):\n",
        endpoint.method,
        endpoint.path,
        params.len()
    );

    for param in params.iter().take(5) {
        // Limit to top 5
        summary.push_str(&format!(
            "  - {} (risk: {}, type: {:?}, confidence: {:?})\n",
            param.name, param.bola_risk_score, param.param_type, param.confidence
        ));
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Method;

    #[test]
    fn test_analyze_endpoint_with_user_id() {
        let endpoint = Endpoint::new(
            Method::GET,
            "/api/users/{userId}".to_string(),
            Some("Get user by ID".to_string()),
            vec!["userId".to_string()],
        );

        let params = analyze_endpoint_parameters(&endpoint);
        assert_eq!(params.len(), 1);
        assert!(
            params[0].bola_risk_score > 70,
            "userId in GET should be high risk"
        );
    }

    #[test]
    fn test_high_risk_filtering() {
        let endpoint = Endpoint::new(
            Method::POST,
            "/api/users".to_string(),
            Some("Create user".to_string()),
            vec![
                "body.name".to_string(),
                "body.email".to_string(),
                "body.userId".to_string(),
            ],
        );

        let high_risk = get_high_risk_params(&endpoint, 50);
        // userId should be high risk, name and email should be lower
        assert!(high_risk.len() >= 1);
        assert!(high_risk.iter().any(|p| p.name == "body.userId"));
    }

    #[test]
    fn test_parameter_location_inference() {
        assert_eq!(
            infer_parameter_location("userId", "/users/{userId}"),
            ParameterLocation::Path
        );
        assert_eq!(
            infer_parameter_location("body.name", "/users"),
            ParameterLocation::Body
        );
        assert_eq!(
            infer_parameter_location("search", "/users"),
            ParameterLocation::Query
        );
    }

    #[test]
    fn test_prioritization() {
        let endpoint = Endpoint::new(
            Method::GET,
            "/api/users/{id}/posts/{postId}".to_string(),
            None,
            vec!["id".to_string(), "postId".to_string(), "limit".to_string()],
        );

        let params = analyze_endpoint_parameters(&endpoint);
        // id and postId should be higher priority than limit
        assert!(params[0].bola_risk_score > params[2].bola_risk_score);
        assert!(params[1].bola_risk_score > params[2].bola_risk_score);
    }
}
