/// Unit tests for core Doppel modules
/// Tests models, utilities, and helper functions
use doppel::models::{Endpoint, Method, Parameter, ParameterLocation};

#[test]
fn test_method_display() {
    // Test that Method enum can be converted to string
    assert_eq!(Method::GET.to_string(), "GET");
    assert_eq!(Method::POST.to_string(), "POST");
    assert_eq!(Method::PUT.to_string(), "PUT");
    assert_eq!(Method::DELETE.to_string(), "DELETE");
    assert_eq!(Method::PATCH.to_string(), "PATCH");
    assert_eq!(Method::OPTIONS.to_string(), "OPTIONS");
    assert_eq!(Method::HEAD.to_string(), "HEAD");
}

#[test]
fn test_method_equality() {
    // Test that Method enum can be compared
    assert_eq!(Method::GET, Method::GET);
    assert_ne!(Method::GET, Method::POST);

    let method1 = Method::POST;
    let method2 = Method::POST;
    assert_eq!(method1, method2);
}

#[test]
fn test_method_clone() {
    // Test that Method can be cloned
    let method1 = Method::GET;
    let method2 = method1.clone();
    assert_eq!(method1, method2);
}

#[test]
fn test_endpoint_creation() {
    // Test creating a basic endpoint
    let endpoint = Endpoint::new(
        Method::GET,
        "/api/users".to_string(),
        Some("Get all users".to_string()),
        vec!["page".to_string(), "limit".to_string()],
    );

    assert_eq!(endpoint.method, Method::GET);
    assert_eq!(endpoint.path, "/api/users");
    assert_eq!(endpoint.description, Some("Get all users".to_string()));
    assert_eq!(endpoint.params.len(), 2);
    assert!(endpoint.params.contains(&"page".to_string()));
    assert!(endpoint.params.contains(&"limit".to_string()));
}

#[test]
fn test_endpoint_without_description() {
    // Test creating an endpoint without description
    let endpoint = Endpoint::new(Method::POST, "/api/users".to_string(), None, vec![]);

    assert_eq!(endpoint.method, Method::POST);
    assert_eq!(endpoint.description, None);
    assert_eq!(endpoint.params.len(), 0);
}

#[test]
fn test_endpoint_with_body_params() {
    // Test endpoint with body parameters
    let endpoint = Endpoint::new(
        Method::POST,
        "/api/users".to_string(),
        Some("Create user".to_string()),
        vec![
            "body.name".to_string(),
            "body.email".to_string(),
            "body.age".to_string(),
        ],
    );

    assert_eq!(endpoint.params.len(), 3);
    assert!(endpoint.params.iter().any(|p| p.contains("body.name")));
    assert!(endpoint.params.iter().any(|p| p.contains("body.email")));
    assert!(endpoint.params.iter().any(|p| p.contains("body.age")));
}

#[test]
fn test_endpoint_with_path_params() {
    // Test endpoint with path parameters
    let endpoint = Endpoint::new(
        Method::GET,
        "/api/users/{id}".to_string(),
        None,
        vec!["id".to_string()],
    );

    assert!(endpoint.path.contains("{id}"));
    assert!(endpoint.params.contains(&"id".to_string()));
}

#[test]
fn test_endpoint_clone() {
    // Test that endpoints can be cloned
    let endpoint1 = Endpoint::new(
        Method::GET,
        "/api/test".to_string(),
        Some("Test endpoint".to_string()),
        vec!["param1".to_string()],
    );

    let endpoint2 = endpoint1.clone();

    assert_eq!(endpoint1.method, endpoint2.method);
    assert_eq!(endpoint1.path, endpoint2.path);
    assert_eq!(endpoint1.description, endpoint2.description);
    assert_eq!(endpoint1.params.len(), endpoint2.params.len());
}

#[test]
fn test_parameter_creation() {
    // Test creating structured parameters
    let param = Parameter {
        name: "user_id".to_string(),
        location: ParameterLocation::Path,
        required: true,
        schema_type: Some("string".to_string()),
    };

    assert_eq!(param.name, "user_id");
    assert_eq!(param.location, ParameterLocation::Path);
    assert_eq!(param.required, true);
}

#[test]
fn test_parameter_locations() {
    // Test different parameter locations
    let path_param = Parameter {
        name: "id".to_string(),
        location: ParameterLocation::Path,
        required: true,
        schema_type: Some("string".to_string()),
    };

    let query_param = Parameter {
        name: "filter".to_string(),
        location: ParameterLocation::Query,
        required: false,
        schema_type: Some("string".to_string()),
    };

    let body_param = Parameter {
        name: "data".to_string(),
        location: ParameterLocation::Body,
        required: true,
        schema_type: Some("object".to_string()),
    };

    let header_param = Parameter {
        name: "Authorization".to_string(),
        location: ParameterLocation::Header,
        required: true,
        schema_type: Some("string".to_string()),
    };

    assert_eq!(path_param.location, ParameterLocation::Path);
    assert_eq!(query_param.location, ParameterLocation::Query);
    assert_eq!(body_param.location, ParameterLocation::Body);
    assert_eq!(header_param.location, ParameterLocation::Header);
}

#[test]
fn test_parameter_required_flag() {
    // Test required vs optional parameters
    let required_param = Parameter {
        name: "id".to_string(),
        location: ParameterLocation::Path,
        required: true,
        schema_type: Some("string".to_string()),
    };

    let optional_param = Parameter {
        name: "page".to_string(),
        location: ParameterLocation::Query,
        required: false,
        schema_type: Some("integer".to_string()),
    };

    assert_eq!(required_param.required, true);
    assert_eq!(optional_param.required, false);
}

#[test]
fn test_endpoint_with_mixed_params() {
    // Test endpoint with multiple types of parameters
    let endpoint = Endpoint::new(
        Method::POST,
        "/api/users/{id}/posts".to_string(),
        Some("Create post for user".to_string()),
        vec![
            "id".to_string(),           // path param
            "published".to_string(),    // query param
            "body.title".to_string(),   // body param
            "body.content".to_string(), // body param
        ],
    );

    assert_eq!(endpoint.params.len(), 4);
    assert!(endpoint.path.contains("{id}"));
}

#[test]
fn test_endpoint_with_array_params() {
    // Test endpoint with array parameters
    let endpoint = Endpoint::new(
        Method::POST,
        "/api/batch".to_string(),
        None,
        vec![
            "body.items[0]".to_string(),
            "body.items[0].id".to_string(),
            "body.items[0].name".to_string(),
        ],
    );

    assert!(endpoint.params.iter().any(|p| p.contains("[0]")));
    assert!(endpoint.params.iter().any(|p| p.contains("items[0].id")));
}

#[test]
fn test_endpoint_with_special_characters() {
    // Test that endpoints handle special characters in paths
    let endpoint = Endpoint::new(
        Method::GET,
        "/api/search?q=test&filter=active".to_string(),
        None,
        vec![],
    );

    assert!(endpoint.path.contains("?"));
    assert!(endpoint.path.contains("&"));
}

#[test]
fn test_endpoint_empty_params() {
    // Test endpoint with no parameters
    let endpoint = Endpoint::new(
        Method::GET,
        "/api/health".to_string(),
        Some("Health check".to_string()),
        vec![],
    );

    assert_eq!(endpoint.params.len(), 0);
    assert!(endpoint.params.is_empty());
}

#[test]
fn test_endpoint_large_param_list() {
    // Test endpoint with many parameters
    let mut params = Vec::new();
    for i in 0..100 {
        params.push(format!("param{}", i));
    }

    let endpoint = Endpoint::new(
        Method::POST,
        "/api/complex".to_string(),
        None,
        params.clone(),
    );

    assert_eq!(endpoint.params.len(), 100);
    assert!(endpoint.params.contains(&"param0".to_string()));
    assert!(endpoint.params.contains(&"param99".to_string()));
}

#[test]
fn test_parameter_clone() {
    // Test that parameters can be cloned
    let param1 = Parameter {
        name: "test".to_string(),
        location: ParameterLocation::Query,
        required: true,
        schema_type: Some("string".to_string()),
    };

    let param2 = param1.clone();

    assert_eq!(param1.name, param2.name);
    assert_eq!(param1.location, param2.location);
    assert_eq!(param1.required, param2.required);
}

#[test]
fn test_parameter_location_equality() {
    // Test parameter location comparison
    assert_eq!(ParameterLocation::Path, ParameterLocation::Path);
    assert_eq!(ParameterLocation::Query, ParameterLocation::Query);
    assert_eq!(ParameterLocation::Body, ParameterLocation::Body);
    assert_eq!(ParameterLocation::Header, ParameterLocation::Header);

    assert_ne!(ParameterLocation::Path, ParameterLocation::Query);
    assert_ne!(ParameterLocation::Body, ParameterLocation::Header);
}
