// OpenAPI/Swagger parser for Doppel
// Uses serde_json to parse openapi.json files

use serde_json::Value;
use crate::models::{Endpoint, Method, CollectionParser};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct OpenApiParser;

impl OpenApiParser {
    // Resolve $ref including external file references
    // Supports:
    // - Local refs: "#/components/schemas/Foo"
    // - External file refs: "file.json#/path/to/schema"
    // - External relative refs: "./schemas/user.json#/definitions/User"
    fn resolve_ref<'a>(
        root: &'a Value,
        ref_str: &str,
        base_path: Option<&Path>,
        external_cache: &mut HashMap<PathBuf, Value>
    ) -> Option<Value> {
        // Check for external file reference
        if let Some((file_part, pointer_part)) = ref_str.split_once('#') {
            if !file_part.is_empty() {
                // External file reference
                return OpenApiParser::resolve_external_ref(file_part, pointer_part, base_path, external_cache);
            } else {
                // Local reference starting with "#/"
                return OpenApiParser::resolve_local_ref(root, pointer_part).map(|v| v.clone());
            }
        }

        // No '#' found, treat as external file without pointer
        if !ref_str.starts_with("#") {
            return OpenApiParser::resolve_external_ref(ref_str, "", base_path, external_cache);
        }

        None
    }

    // Resolve local JSON Pointer refs like "#/components/schemas/Foo"
    fn resolve_local_ref<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
        if !pointer.starts_with("/") {
            return None;
        }
        let path = &pointer[1..]; // Skip leading "/"
        let parts = path.split('/').map(|s| s.replace("~1", "/").replace("~0", "~"));
        let mut cur = root;
        for p in parts {
            if let Some(obj) = cur.get(&p) {
                cur = obj;
            } else {
                return None;
            }
        }
        Some(cur)
    }

    // Resolve external file reference
    fn resolve_external_ref(
        file_path: &str,
        pointer: &str,
        base_path: Option<&Path>,
        cache: &mut HashMap<PathBuf, Value>
    ) -> Option<Value> {
        // Resolve relative path
        let resolved_path = if let Some(base) = base_path {
            base.parent()?.join(file_path)
        } else {
            PathBuf::from(file_path)
        };

        // Normalize path
        let canonical_path = resolved_path.canonicalize().ok()?;

        // Security: Prevent path traversal attacks
        // Ensure the resolved path is within the spec directory
        if let Some(base) = base_path {
            if let Some(spec_dir) = base.parent() {
                if let Ok(canonical_spec_dir) = spec_dir.canonicalize() {
                    if !canonical_path.starts_with(&canonical_spec_dir) {
                        eprintln!("Security warning: Rejected external reference attempting path traversal: {}", file_path);
                        return None;
                    }
                }
            }
        }

        // Check cache first
        if !cache.contains_key(&canonical_path) {
            // Load external file
            let data = std::fs::read_to_string(&canonical_path).ok()?;
            let json: Value = serde_json::from_str(&data).ok()?;
            cache.insert(canonical_path.clone(), json);
        }

        let external_doc = cache.get(&canonical_path)?;

        // If pointer is empty, return entire document
        if pointer.is_empty() {
            return Some(external_doc.clone());
        }

        // Resolve pointer within external document
        OpenApiParser::resolve_local_ref(external_doc, pointer).map(|v| v.clone())
    }

    // If server URL contains variables like {env}, replace with defaults when available
    fn server_with_vars(server: &Value) -> Option<String> {
        let url = server.get("url")?.as_str()?;
        let mut result = url.to_string();
        if let Some(vars) = server.get("variables").and_then(|v| v.as_object()) {
            for (k, v) in vars {
                if let Some(def) = v.get("default").and_then(|d| d.as_str()) {
                    result = result.replace(&format!("{{{}}}", k), def);
                }
            }
        }
        Some(result)
    }
}

impl CollectionParser for OpenApiParser {
    fn parse(&self, file_path: &str) -> Result<Vec<Endpoint>, String> {
        let data = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read {}: {}", file_path, e))?;
        let json: Value = serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;
        let mut endpoints = Vec::new();
        let mut external_cache: HashMap<PathBuf, Value> = HashMap::new();
        let spec_file_path = Path::new(file_path);

        // Prefer servers[0].url and substitute variables if present
        let base_url = json.get("servers")
            .and_then(|s| s.as_array())
            .and_then(|arr| arr.get(0))
            .and_then(|srv| OpenApiParser::server_with_vars(srv))
            .map(|s| s.trim_end_matches('/').to_string());

        if let Some(paths) = json.get("paths") {
            if let Some(map) = paths.as_object() {
                for (path, methods) in map {
                    if let Some(methods_map) = methods.as_object() {
                        for (method, details) in methods_map {
                            let method_enum = match method.to_uppercase().as_str() {
                                "GET" => Method::GET,
                                "POST" => Method::POST,
                                "PUT" => Method::PUT,
                                "DELETE" => Method::DELETE,
                                "PATCH" => Method::PATCH,
                                "OPTIONS" => Method::OPTIONS,
                                "HEAD" => Method::HEAD,
                                _ => continue,
                            };

                            let mut params = Vec::new();

                            // collect parameters (may be local or $ref)
                            if let Some(parameters) = details.get("parameters") {
                                if let Some(arr) = parameters.as_array() {
                                    for p in arr {
                                        if let Some(r) = p.get("$ref").and_then(|r| r.as_str()) {
                                            if let Some(resolved) = OpenApiParser::resolve_ref(&json, r, Some(spec_file_path), &mut external_cache) {
                                                if let Some(name) = resolved.get("name").and_then(|n| n.as_str()) {
                                                    params.push(name.to_string());
                                                }
                                            }
                                        } else if let Some(name) = p.get("name").and_then(|n| n.as_str()) {
                                            params.push(name.to_string());
                                        }
                                    }
                                }
                            }

                            // path-level parameters
                            if let Some(path_obj) = map.get(path) {
                                if let Some(path_params) = path_obj.get("parameters") {
                                    if let Some(arr) = path_params.as_array() {
                                        for p in arr {
                                            if let Some(r) = p.get("$ref").and_then(|r| r.as_str()) {
                                                if let Some(resolved) = OpenApiParser::resolve_ref(&json, r, Some(spec_file_path), &mut external_cache) {
                                                    if let Some(name) = resolved.get("name").and_then(|n| n.as_str()) {
                                                        if !params.contains(&name.to_string()) {
                                                            params.push(name.to_string());
                                                        }
                                                    }
                                                }
                                            } else if let Some(name) = p.get("name").and_then(|n| n.as_str()) {
                                                if !params.contains(&name.to_string()) {
                                                    params.push(name.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // handle requestBody with support for multiple content types
                            if let Some(rb) = details.get("requestBody") {
                                // if it's a $ref, resolve it
                                let rb_obj = if let Some(r) = rb.get("$ref").and_then(|r| r.as_str()) {
                                    OpenApiParser::resolve_ref(&json, r, Some(spec_file_path), &mut external_cache).unwrap_or_else(|| rb.clone())
                                } else {
                                    rb.clone()
                                };
                                if let Some(content) = rb_obj.get("content") {
                                    // Support multiple content types
                                    let content_types = vec![
                                        "application/json",
                                        "application/x-www-form-urlencoded",
                                        "multipart/form-data",
                                        "application/xml",
                                        "text/plain"
                                    ];

                                    for content_type in content_types {
                                        if let Some(media_type_obj) = content.get(content_type) {
                                            if let Some(schema) = media_type_obj.get("schema") {
                                                // if schema is a $ref, resolve
                                                let schema_obj = if let Some(r) = schema.get("$ref").and_then(|r| r.as_str()) {
                                                    OpenApiParser::resolve_ref(&json, r, Some(spec_file_path), &mut external_cache).unwrap_or_else(|| schema.clone())
                                                } else {
                                                    schema.clone()
                                                };

                                                // Handle oneOf/allOf/anyOf
                                                let schemas_to_process = if let Some(one_of) = schema_obj.get("oneOf").and_then(|v| v.as_array()) {
                                                    one_of.iter().collect::<Vec<_>>()
                                                } else if let Some(all_of) = schema_obj.get("allOf").and_then(|v| v.as_array()) {
                                                    all_of.iter().collect::<Vec<_>>()
                                                } else if let Some(any_of) = schema_obj.get("anyOf").and_then(|v| v.as_array()) {
                                                    any_of.iter().collect::<Vec<_>>()
                                                } else {
                                                    vec![&schema_obj]
                                                };

                                                for sub_schema in schemas_to_process {
                                                    // Resolve nested $ref
                                                    let resolved_schema = if let Some(r) = sub_schema.get("$ref").and_then(|r| r.as_str()) {
                                                        OpenApiParser::resolve_ref(&json, r, Some(spec_file_path), &mut external_cache).unwrap_or_else(|| sub_schema.clone())
                                                    } else {
                                                        sub_schema.clone()
                                                    };

                                                    if let Some(props) = resolved_schema.get("properties") {
                                                        if let Some(map_props) = props.as_object() {
                                                            for (pname, prop_val) in map_props {
                                                                // Handle nested schemas
                                                                let param_name = format!("body.{}", pname);
                                                                if !params.contains(&param_name) {
                                                                    params.push(param_name);
                                                                }

                                                                // Handle array types
                                                                if let Some(prop_type) = prop_val.get("type").and_then(|t| t.as_str()) {
                                                                    if prop_type == "array" {
                                                                        let array_param = format!("body.{}[0]", pname);
                                                                        if !params.contains(&array_param) {
                                                                            params.push(array_param);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    } else if resolved_schema.get("type").and_then(|t| t.as_str()) == Some("array") {
                                                        // Handle array body
                                                        if !params.contains(&"__body__[0]".to_string()) {
                                                            params.push("__body__[0]".to_string());
                                                        }
                                                    } else {
                                                        // generic body marker
                                                        if !params.contains(&"__body__".to_string()) {
                                                            params.push("__body__".to_string());
                                                        }
                                                    }
                                                }
                                            }
                                            break; // Use first available content type
                                        }
                                    }
                                }
                            }

                            let full_path = if let Some(bp) = &base_url {
                                format!("{}{}", bp, path)
                            } else {
                                path.clone()
                            };

                            endpoints.push(Endpoint::new(
                                method_enum,
                                full_path,
                                details.get("summary").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                params,
                            ));
                        }
                    }
                }
            }
        }
        Ok(endpoints)
    }
}
