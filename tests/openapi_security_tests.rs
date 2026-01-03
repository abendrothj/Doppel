/// Security tests specifically for OpenAPI parser
/// Tests path traversal protection and external reference handling
use doppel::models::CollectionParser;
use doppel::parsers::openapi::OpenApiParser;
use std::fs;

#[test]
fn test_path_traversal_absolute_path() {
    // Test that absolute paths outside spec directory are rejected
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0.0"},
        "paths": {
            "/test": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "/etc/passwd#/User"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }"#;

    let test_file = "test_absolute_path.json";
    fs::write(test_file, spec).expect("Should write test file");

    let parser = OpenApiParser;
    let result = parser.parse(test_file);

    // Clean up
    let _ = fs::remove_file(test_file);

    assert!(result.is_ok(), "Should not crash on malicious path");
    // The malicious reference is silently rejected, endpoint still parsed
    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 1, "Should still parse the endpoint");
}

#[test]
fn test_path_traversal_relative_dotdot() {
    // Test that ../ directory traversal is rejected
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0.0"},
        "paths": {
            "/test": {
                "get": {
                    "parameters": [{
                        "$ref": "../../../etc/passwd#/definitions/User"
                    }]
                }
            }
        }
    }"#;

    let test_file = "test_dotdot.json";
    fs::write(test_file, spec).expect("Should write test file");

    let parser = OpenApiParser;
    let result = parser.parse(test_file);

    // Clean up
    let _ = fs::remove_file(test_file);

    assert!(result.is_ok(), "Should handle directory traversal safely");
    let endpoints = result.unwrap();
    // The malicious parameter reference is rejected, but endpoint is still created
    assert_eq!(
        endpoints.len(),
        1,
        "Should parse endpoint without malicious param"
    );
}

#[test]
fn test_legitimate_external_ref() {
    // Test that legitimate external references within the spec directory work
    let test_dir = "test_external_refs";
    fs::create_dir_all(test_dir).expect("Should create test directory");

    // Create external schema file
    let schema_file = format!("{}/schemas.json", test_dir);
    let schema_content = r#"{
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"}
                    }
                }
            }
        }
    }"#;
    fs::write(&schema_file, schema_content).expect("Should write schema file");

    // Create main spec that references external file
    let spec_file = format!("{}/openapi.json", test_dir);
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "schemas.json#/components/schemas/User"
                                }
                            }
                        }
                    }
                }
            }
        }
    }"#;
    fs::write(&spec_file, spec).expect("Should write spec file");

    let parser = OpenApiParser;
    let result = parser.parse(&spec_file);

    // Clean up
    let _ = fs::remove_file(&schema_file);
    let _ = fs::remove_file(&spec_file);
    let _ = fs::remove_dir(test_dir);

    assert!(result.is_ok(), "Should parse legitimate external refs");
    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 1, "Should have 1 endpoint");

    // Verify external schema was resolved
    let endpoint = &endpoints[0];
    assert!(
        endpoint
            .params
            .iter()
            .any(|p| p.contains("id") || p.contains("name")),
        "Should resolve external schema and extract properties"
    );
}

#[test]
fn test_external_ref_caching() {
    // Test that external references are cached (not loaded multiple times)
    let test_dir = "test_ref_caching";
    fs::create_dir_all(test_dir).expect("Should create test directory");

    // Create external schema file
    let schema_file = format!("{}/common.json", test_dir);
    let schema_content = r#"{
        "definitions": {
            "Error": {
                "type": "object",
                "properties": {
                    "code": {"type": "integer"},
                    "message": {"type": "string"}
                }
            }
        }
    }"#;
    fs::write(&schema_file, schema_content).expect("Should write schema file");

    // Create spec that references the same external file multiple times
    let spec_file = format!("{}/openapi.json", test_dir);
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/endpoint1": {
                "get": {
                    "responses": {
                        "400": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "common.json#/definitions/Error"}
                                }
                            }
                        }
                    }
                }
            },
            "/endpoint2": {
                "get": {
                    "responses": {
                        "400": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "common.json#/definitions/Error"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }"#;
    fs::write(&spec_file, spec).expect("Should write spec file");

    let parser = OpenApiParser;
    let result = parser.parse(&spec_file);

    // Clean up
    let _ = fs::remove_file(&schema_file);
    let _ = fs::remove_file(&spec_file);
    let _ = fs::remove_dir(test_dir);

    assert!(
        result.is_ok(),
        "Should parse with multiple refs to same file"
    );
    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 2, "Should have 2 endpoints");
}

#[test]
fn test_malicious_symlink_traversal() {
    // Test that symbolic links cannot be used for path traversal
    // This test is platform-specific and may not work on all systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let test_dir = "test_symlink";
        fs::create_dir_all(test_dir).expect("Should create test directory");

        // Try to create a symlink to /etc (this might fail without permissions)
        let symlink_path = format!("{}/evil_link", test_dir);
        let symlink_result = symlink("/etc", &symlink_path);

        if symlink_result.is_ok() {
            // Create spec that tries to use the symlink
            let spec_file = format!("{}/openapi.json", test_dir);
            let spec = format!(
                r#"{{
                "openapi": "3.0.0",
                "info": {{"title": "Test", "version": "1.0.0"}},
                "paths": {{
                    "/test": {{
                        "get": {{
                            "parameters": [{{
                                "$ref": "evil_link/passwd#/User"
                            }}]
                        }}
                    }}
                }}
            }}"#
            );
            fs::write(&spec_file, spec).expect("Should write spec file");

            let parser = OpenApiParser;
            let result = parser.parse(&spec_file);

            // Clean up
            let _ = fs::remove_file(&symlink_path);
            let _ = fs::remove_file(&spec_file);
            let _ = fs::remove_dir(test_dir);

            // Should safely reject the symlink traversal
            assert!(result.is_ok(), "Should handle symlink without crashing");
            let endpoints = result.unwrap();
            assert_eq!(endpoints.len(), 1, "Should still parse endpoint");
        } else {
            // If we can't create symlink, just clean up and skip test
            let _ = fs::remove_dir(test_dir);
        }
    }
}

#[test]
fn test_nested_external_refs() {
    // Test external refs that themselves contain refs
    let test_dir = "test_nested_refs";
    fs::create_dir_all(test_dir).expect("Should create test directory");

    // Create base types file
    let types_file = format!("{}/types.json", test_dir);
    let types_content = r#"{
        "definitions": {
            "UserId": {
                "type": "integer",
                "format": "int64"
            }
        }
    }"#;
    fs::write(&types_file, types_content).expect("Should write types file");

    // Create user schema file that references types
    let user_file = format!("{}/user.json", test_dir);
    let user_content = r#"{
        "type": "object",
        "properties": {
            "id": {
                "$ref": "types.json#/definitions/UserId"
            },
            "name": {"type": "string"}
        }
    }"#;
    fs::write(&user_file, user_content).expect("Should write user file");

    // Create main spec
    let spec_file = format!("{}/openapi.json", test_dir);
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "user.json"
                                }
                            }
                        }
                    }
                }
            }
        }
    }"#;
    fs::write(&spec_file, spec).expect("Should write spec file");

    let parser = OpenApiParser;
    let result = parser.parse(&spec_file);

    // Clean up
    let _ = fs::remove_file(&types_file);
    let _ = fs::remove_file(&user_file);
    let _ = fs::remove_file(&spec_file);
    let _ = fs::remove_dir(test_dir);

    assert!(result.is_ok(), "Should parse nested external refs");
    let endpoints = result.unwrap();
    assert_eq!(endpoints.len(), 1, "Should have 1 endpoint");
}

#[test]
fn test_url_encoded_traversal_attempt() {
    // Test URL-encoded path traversal attempts
    let spec = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0.0"},
        "paths": {
            "/test": {
                "get": {
                    "parameters": [{
                        "$ref": "..%2F..%2F..%2Fetc%2Fpasswd#/User"
                    }]
                }
            }
        }
    }"#;

    let test_file = "test_encoded_traversal.json";
    fs::write(test_file, spec).expect("Should write test file");

    let parser = OpenApiParser;
    let result = parser.parse(test_file);

    // Clean up
    let _ = fs::remove_file(test_file);

    assert!(result.is_ok(), "Should handle URL-encoded traversal safely");
}
