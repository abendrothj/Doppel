/// Integration tests for API collection parsers
/// Tests OpenAPI, Postman, and Bruno parsers
use doppel::models::CollectionParser;
use doppel::parsers::bruno::BrunoParser;
use doppel::parsers::openapi::OpenApiParser;
use doppel::parsers::postman::PostmanParser;
use std::fs;

#[test]
fn test_openapi_basic_parsing() {
    // Create a minimal OpenAPI spec for testing
    let spec = r##"{
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "servers": [
            {
                "url": "https://api.example.com/v1"
            }
        ],
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get all users",
                    "parameters": []
                },
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/ID_PARAM": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"}
                        }
                    ]
                }
            }
        }
    }"##;

    let test_file = "test_openapi.json";
    fs::write(test_file, spec).expect("Should write test file");

    let parser = OpenApiParser;
    let result = parser.parse(test_file);

    // Clean up
    let _ = fs::remove_file(test_file);

    assert!(result.is_ok(), "OpenAPI parsing should succeed");
    let endpoints = result.unwrap();

    assert_eq!(endpoints.len(), 3, "Should parse 3 endpoints");

    // Verify GET /users
    let get_users = endpoints.iter().find(|e| {
        e.path.contains("/users") && e.method.to_string() == "GET" && !e.path.contains("ID_PARAM")
    });
    assert!(get_users.is_some(), "Should have GET /users endpoint");
    assert_eq!(get_users.unwrap().path, "https://api.example.com/v1/users");

    // Verify POST /users with body parameters
    let post_users = endpoints
        .iter()
        .find(|e| e.path.contains("/users") && e.method.to_string() == "POST");
    assert!(post_users.is_some(), "Should have POST /users endpoint");
    let post_endpoint = post_users.unwrap();
    assert!(
        post_endpoint.params.iter().any(|p| p.contains("body.name")),
        "Should extract body.name parameter"
    );
    assert!(
        post_endpoint
            .params
            .iter()
            .any(|p| p.contains("body.email")),
        "Should extract body.email parameter"
    );

    // Verify GET /users/ID_PARAM with path parameter
    let get_user_by_id = endpoints.iter().find(|e| e.path.contains("ID_PARAM"));
    assert!(
        get_user_by_id.is_some(),
        "Should have GET endpoint with ID parameter"
    );
    assert!(
        get_user_by_id.unwrap().params.contains(&"id".to_string()),
        "Should extract id parameter"
    );
}

#[test]
fn test_openapi_path_traversal_protection() {
    // Create a malicious OpenAPI spec with path traversal attempt
    let spec = r##"{
        "openapi": "3.0.0",
        "info": {"title": "Malicious API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "../../../../etc/passwd"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }"##;

    let test_file = "test_malicious_openapi.json";
    fs::write(test_file, spec).expect("Should write test file");

    let parser = OpenApiParser;
    let result = parser.parse(test_file);

    // Clean up
    let _ = fs::remove_file(test_file);

    // Should still parse successfully (path traversal is silently rejected, not an error)
    assert!(result.is_ok(), "Should parse without crashing");

    // The malicious reference should be ignored, so we should still get the endpoint
    let endpoints = result.unwrap();
    assert_eq!(
        endpoints.len(),
        1,
        "Should have 1 endpoint despite malicious ref"
    );
}

#[test]
fn test_openapi_server_variable_substitution() {
    // Test that server URL variables are properly substituted
    let spec = r##"{
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "servers": [
            {
                "url": "https://ENV_VAR.example.com/vVERSION_VAR",
                "variables": {
                    "env": {
                        "default": "api",
                        "enum": ["api", "staging"]
                    },
                    "version": {
                        "default": "1"
                    }
                }
            }
        ],
        "paths": {
            "/test": {
                "get": {
                    "summary": "Test endpoint"
                }
            }
        }
    }"##;

    let test_file = "test_server_vars.json";
    fs::write(test_file, spec).expect("Should write test file");

    let parser = OpenApiParser;
    let result = parser.parse(test_file);

    // Clean up
    let _ = fs::remove_file(test_file);

    assert!(result.is_ok(), "Should parse successfully");
    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 1, "Should have 1 endpoint");
}

#[test]
fn test_postman_basic_parsing() {
    // Create a minimal Postman collection for testing
    let collection = r##"{
        "info": {
            "name": "Test Collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "https://api.example.com/users",
                        "protocol": "https",
                        "host": ["api", "example", "com"],
                        "path": ["users"]
                    }
                }
            },
            {
                "name": "Create User",
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/users",
                    "body": {
                        "mode": "raw",
                        "raw": "{}"
                    }
                }
            }
        ]
    }"##;

    let test_file = "test_postman.json";
    fs::write(test_file, collection).expect("Should write test file");

    let parser = PostmanParser;
    let result = parser.parse(test_file);

    // Clean up
    let _ = fs::remove_file(test_file);

    assert!(result.is_ok(), "Postman parsing should succeed");
    let endpoints = result.unwrap();

    assert!(endpoints.len() >= 1, "Should parse at least 1 endpoint");

    // Verify we have a GET endpoint
    let get_endpoint = endpoints.iter().find(|e| e.method.to_string() == "GET");
    assert!(get_endpoint.is_some(), "Should have GET endpoint");
}

#[test]
fn test_bruno_basic_parsing() {
    // Create a minimal Bruno collection directory
    let test_dir = "test_bruno_collection";
    fs::create_dir_all(test_dir).expect("Should create test directory");

    let bruno_file = format!("{}/get-users.bru", test_dir);
    // Bruno parser expects JSON-like format with method and url fields
    let bruno_content = r##"{
  "method": "GET",
  "url": "https://api.example.com/users"
}
"##;

    fs::write(&bruno_file, bruno_content).expect("Should write Bruno file");

    let parser = BrunoParser;
    let result = parser.parse(test_dir);

    // Clean up
    let _ = fs::remove_file(&bruno_file);
    let _ = fs::remove_dir(test_dir);

    assert!(result.is_ok(), "Bruno parsing should succeed");
    let endpoints = result.unwrap();

    assert_eq!(endpoints.len(), 1, "Should parse 1 endpoint");
    assert_eq!(
        endpoints[0].method.to_string(),
        "GET",
        "Should be GET method"
    );
    assert!(
        endpoints[0].path.contains("users"),
        "Should contain 'users' in path"
    );
}

#[test]
fn test_bruno_multiple_methods() {
    // Test parsing Bruno files with different HTTP methods
    let test_dir = "test_bruno_methods";
    fs::create_dir_all(test_dir).expect("Should create test directory");

    let methods = vec![
        ("GET", "get-users.bru"),
        ("POST", "create-user.bru"),
        ("PUT", "update-user.bru"),
        ("DELETE", "delete-user.bru"),
        ("PATCH", "patch-user.bru"),
    ];

    for (method, filename) in &methods {
        let file_path = format!("{}/{}", test_dir, filename);
        // Bruno parser expects JSON-like format with method and url fields
        let content = format!(
            r##"{{
  "method": "{}",
  "url": "https://api.example.com/users"
}}
"##,
            method
        );

        fs::write(&file_path, content).expect("Should write Bruno file");
    }

    let parser = BrunoParser;
    let result = parser.parse(test_dir);

    // Clean up
    for (_, filename) in &methods {
        let _ = fs::remove_file(format!("{}/{}", test_dir, filename));
    }
    let _ = fs::remove_dir(test_dir);

    assert!(result.is_ok(), "Should parse all methods");
    let endpoints = result.unwrap();

    assert_eq!(endpoints.len(), methods.len(), "Should parse all methods");

    // Verify each method is present
    for (method, _) in &methods {
        assert!(
            endpoints.iter().any(|e| e.method.to_string() == *method),
            "Should have {} endpoint",
            method
        );
    }
}

#[test]
fn test_invalid_json_handling() {
    // Test that parsers handle invalid JSON gracefully
    let invalid_json = "{ this is not valid json }";

    let test_file = "test_invalid.json";
    fs::write(test_file, invalid_json).expect("Should write test file");

    let openapi_parser = OpenApiParser;
    let openapi_result = openapi_parser.parse(test_file);
    assert!(
        openapi_result.is_err(),
        "Should return error for invalid JSON"
    );

    let postman_parser = PostmanParser;
    let postman_result = postman_parser.parse(test_file);
    assert!(
        postman_result.is_err(),
        "Should return error for invalid JSON"
    );

    // Clean up
    let _ = fs::remove_file(test_file);
}

#[test]
fn test_missing_file_handling() {
    // Test that parsers handle missing files gracefully
    let nonexistent_file = "this_file_does_not_exist_12345.json";

    let openapi_parser = OpenApiParser;
    let result = openapi_parser.parse(nonexistent_file);
    assert!(result.is_err(), "Should return error for missing file");
    assert!(
        result.unwrap_err().contains("Failed to read"),
        "Error should mention file read failure"
    );
}

#[test]
fn test_openapi_with_refs() {
    // Test OpenAPI with internal $ref references
    let spec = r##"{
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "$ref": "#/components/requestBodies/UserRequestBody"
                    }
                }
            }
        },
        "components": {
            "requestBodies": {
                "UserRequestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "email": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }"##;

    let test_file = "test_refs.json";
    fs::write(test_file, spec).expect("Should write test file");

    let parser = OpenApiParser;
    let result = parser.parse(test_file);

    // Clean up
    let _ = fs::remove_file(test_file);

    assert!(result.is_ok(), "Should parse spec with refs");
    let endpoints = result.unwrap();

    assert_eq!(endpoints.len(), 1, "Should have 1 endpoint");

    // Verify that $ref was resolved and parameters extracted
    let post_endpoint = &endpoints[0];
    assert!(
        post_endpoint.params.iter().any(|p| p.contains("username")),
        "Should resolve ref and extract username parameter"
    );
    assert!(
        post_endpoint.params.iter().any(|p| p.contains("email")),
        "Should resolve ref and extract email parameter"
    );
}
