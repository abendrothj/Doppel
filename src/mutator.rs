// Mutational fuzzing for Doppel
// Injects common attack payloads into parameters

pub fn mutate_param(param: &str) -> Vec<String> {
    vec![
        param.to_string(),
        "' OR 1=1 --".to_string(),
        "<script>alert(1)</script>".to_string(),
        "-1".to_string(),
        "".to_string(),
        "null".to_string(),
    ]
}
