// Postman collection parser for BOLA-Fuzz
// Uses serde_json to recursively parse Postman Collection v2.1 exports

use serde_json::Value;
use crate::models::{Endpoint, Method, CollectionParser};

pub struct PostmanParser;

impl CollectionParser for PostmanParser {
    fn parse(&self, file_path: &str) -> Result<Vec<Endpoint>, String> {
        let data = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read {}: {}", file_path, e))?;
        let json: Value = serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;
        let mut endpoints = Vec::new();
        if let Some(items) = json.get("item") {
            parse_items(items, &mut endpoints);
        }
        Ok(endpoints)
    }
}

fn parse_items(items: &Value, endpoints: &mut Vec<Endpoint>) {
    if let Some(array) = items.as_array() {
        for item in array {
            if let Some(request) = item.get("request") {
                if let Some(method) = request.get("method").and_then(|m| m.as_str()) {
                    if let Some(url) = request.get("url") {
                        let path = if let Some(raw) = url.get("raw").and_then(|r| r.as_str()) {
                            raw.to_string()
                        } else {
                            continue;
                        };
                        let method = match method {
                            "GET" => Method::GET,
                            "POST" => Method::POST,
                            "PUT" => Method::PUT,
                            "DELETE" => Method::DELETE,
                            "PATCH" => Method::PATCH,
                            "OPTIONS" => Method::OPTIONS,
                            "HEAD" => Method::HEAD,
                            _ => continue,
                        };
                        endpoints.push(Endpoint::new(
                            method,
                            path,
                            item.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()),
                            vec![],
                        ));
                    }
                }
            }
            if let Some(sub_items) = item.get("item") {
                parse_items(sub_items, endpoints);
            }
        }
    }
}
