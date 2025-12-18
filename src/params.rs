// Advanced parameter handling for BOLA-Fuzz
// Supports nested/complex parameters in JSON bodies, arrays, and objects

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
