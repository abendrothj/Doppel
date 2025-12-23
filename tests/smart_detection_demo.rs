// Demo test showing smart parameter detection in action
use doppel::parameters::{analyze_endpoint_parameters, get_high_risk_params, ParameterDetector};
use doppel::models::{Endpoint, Method, ParameterLocation};

#[test]
fn demo_smart_detection_on_realistic_api() {
    println!("\n=== Smart Parameter Detection Demo ===\n");

    // Simulate a realistic REST API with mixed endpoints
    let endpoints = vec![
        // High-risk: User profile access
        Endpoint::new(
            Method::GET,
            "/api/v1/users/{userId}".to_string(),
            Some("Get user profile".to_string()),
            vec!["userId".to_string()],
        ),
        // High-risk: Account details
        Endpoint::new(
            Method::GET,
            "/api/v1/accounts/{accountId}".to_string(),
            Some("Get account".to_string()),
            vec!["accountId".to_string()],
        ),
        // Medium-risk: Order creation with user ID in body
        Endpoint::new(
            Method::POST,
            "/api/v1/orders".to_string(),
            Some("Create order".to_string()),
            vec!["body.userId".to_string(), "body.items".to_string()],
        ),
        // Low-risk: Generic search endpoint
        Endpoint::new(
            Method::GET,
            "/api/v1/search".to_string(),
            Some("Search".to_string()),
            vec!["query".to_string(), "limit".to_string(), "offset".to_string()],
        ),
        // High-risk: Delete user
        Endpoint::new(
            Method::DELETE,
            "/api/v1/users/{id}".to_string(),
            Some("Delete user".to_string()),
            vec!["id".to_string()],
        ),
    ];

    let mut total_params = 0;
    let mut high_risk_params = 0;

    for endpoint in &endpoints {
        let all_params = analyze_endpoint_parameters(endpoint);
        let high_risk = get_high_risk_params(endpoint, 50); // Default threshold

        total_params += all_params.len();
        high_risk_params += high_risk.len();

        println!("{} {} - {} parameters", endpoint.method, endpoint.path, all_params.len());

        for param in &all_params {
            let marker = if param.bola_risk_score >= 50 { "✓ TESTING" } else { "✗ SKIPPING" };
            println!(
                "  {} {} (risk: {}, type: {:?}, confidence: {:?})",
                marker, param.name, param.bola_risk_score, param.param_type, param.confidence
            );
        }
        println!();
    }

    println!("=== Summary ===");
    println!("Total parameters: {}", total_params);
    println!("High-risk (tested): {}", high_risk_params);
    println!("Low-risk (skipped): {}", total_params - high_risk_params);
    println!("Efficiency gain: {:.1}% reduction in tests\n",
             (total_params - high_risk_params) as f32 / total_params as f32 * 100.0);

    // Assertions to verify smart detection works correctly
    assert!(total_params > 0, "Should detect parameters");
    assert!(high_risk_params > 0, "Should identify high-risk parameters");
    assert!(high_risk_params < total_params, "Should filter out some low-risk parameters");

    // Verify specific high-risk parameters are detected
    let user_endpoint = &endpoints[0];
    let user_params = analyze_endpoint_parameters(user_endpoint);
    assert_eq!(user_params.len(), 1);
    assert!(user_params[0].bola_risk_score >= 80, "userId in GET /users should be very high risk");

    // Verify search endpoint parameters are low risk
    let search_endpoint = &endpoints[3];
    let search_params = analyze_endpoint_parameters(search_endpoint);
    assert_eq!(search_params.len(), 3);
    for param in &search_params {
        assert!(param.bola_risk_score < 50, "{} should be low risk", param.name);
    }
}

#[test]
fn demo_risk_score_distribution() {
    println!("\n=== Risk Score Distribution ===\n");

    // Test various parameter types across different contexts
    let test_cases = vec![
        ("userId", "/api/users/{userId}", "GET", ParameterLocation::Path, true),
        ("userId", "/api/users", "POST", ParameterLocation::Body, true),
        ("accountId", "/api/accounts/{accountId}", "DELETE", ParameterLocation::Path, true),
        ("orderId", "/api/orders/{orderId}", "GET", ParameterLocation::Path, true),
        ("id", "/api/items/{id}", "PUT", ParameterLocation::Path, true),
        ("email", "/api/users", "GET", ParameterLocation::Query, false),
        ("search", "/api/posts", "GET", ParameterLocation::Query, false),
        ("limit", "/api/posts", "GET", ParameterLocation::Query, false),
        ("name", "/api/users", "POST", ParameterLocation::Body, false),
    ];

    let mut very_high_risk = 0;
    let mut high_risk = 0;
    let mut medium_risk = 0;
    let mut low_risk = 0;

    for (name, path, method, location, required) in test_cases {
        let param = ParameterDetector::analyze_parameter(name, path, method, location.clone(), required);

        let risk_category = match param.bola_risk_score {
            80..=100 => { very_high_risk += 1; "VERY HIGH" },
            60..=79 => { high_risk += 1; "HIGH" },
            30..=59 => { medium_risk += 1; "MEDIUM" },
            _ => { low_risk += 1; "LOW" },
        };

        println!(
            "{:15} {:30} {:6} {:10?} → Risk: {:3} ({:9}) Type: {:?}",
            name, path, method, location, param.bola_risk_score, risk_category, param.param_type
        );
    }

    println!("\n=== Distribution ===");
    println!("Very High Risk (80-100): {}", very_high_risk);
    println!("High Risk (60-79):       {}", high_risk);
    println!("Medium Risk (30-59):     {}", medium_risk);
    println!("Low Risk (0-29):         {}\n", low_risk);

    // Verify we have good distribution
    assert!(very_high_risk >= 2, "Should have some very high risk parameters");
    assert!(low_risk >= 2, "Should have some low risk parameters");
}

#[test]
fn demo_confidence_levels() {
    println!("\n=== Confidence Level Examples ===\n");

    let test_cases = vec![
        // Very High Confidence
        ("userId", "/api/users/{userId}", "User ID in users endpoint"),
        ("user_id", "/api/profiles/{user_id}", "Snake case user ID"),
        ("accountId", "/api/accounts/{accountId}", "Account ID in accounts endpoint"),

        // High Confidence
        ("id", "/api/users/{id}", "Generic ID in specific context"),
        ("postId", "/api/blog/posts/{postId}", "Post ID in posts endpoint"),

        // Medium/Low Confidence
        ("uuid", "/api/resources/{uuid}", "UUID without context"),
        ("identifier", "/api/data/{identifier}", "Generic identifier"),
    ];

    for (name, path, description) in test_cases {
        let param = ParameterDetector::analyze_parameter(
            name,
            path,
            "GET",
            ParameterLocation::Path,
            true,
        );

        println!(
            "{:12} → Confidence: {:8?} (score: {}) - {}",
            name, param.confidence, param.confidence.as_score(), description
        );
    }
    println!();
}
