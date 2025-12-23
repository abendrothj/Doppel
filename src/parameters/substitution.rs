// Parameter Value Substitution
//
// RUNTIME parameter value manipulation for JSON request bodies.
// Handles nested objects and arrays during fuzzing mutations.
//
// This module is responsible for REPLACING parameter values in JSON structures
// at runtime during attack execution. It does NOT classify or analyze parameters
// (see param_detector.rs and param_analyzer.rs for that).
//
// Example:
//   Input:  {"userId": "attacker_123", "nested": {"id": "old"}}
//   Map:    {"userId" => "victim_456", "id" => "victim_456"}
//   Output: {"userId": "victim_456", "nested": {"id": "victim_456"}}
//
// Used by: main.rs during request building and fuzzing

use serde_json::Value;

pub fn substitute_params(json: &mut Value, param_map: &std::collections::HashMap<String, String>) {
    match json {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if let Some(new_val) = param_map.get(k) {
                    *v = Value::String(new_val.clone());
                } else {
                    substitute_params(v, param_map);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                substitute_params(v, param_map);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn substitute_simple_key() {
        let mut v = json!({ "userId": "OLD", "nested": { "id": "OLD" } });
        let mut map = std::collections::HashMap::new();
        map.insert("userId".to_string(), "NEW_USER".to_string());
        map.insert("id".to_string(), "NEW_ID".to_string());
        substitute_params(&mut v, &map);
        assert_eq!(v["userId"], json!("NEW_USER"));
        assert_eq!(v["nested"]["id"], json!("NEW_ID"));
    }
}
