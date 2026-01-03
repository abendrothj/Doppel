// Mutational fuzzing for Doppel
// Generates BOLA-specific mutations based on parameter type

/// Generate BOLA-focused mutations for a parameter.
/// These mutations test for broken object level authorization by trying:
/// - Adjacent IDs (e.g., user_123 → user_122, user_124)
/// - Common privileged IDs (0, 1, admin)
/// - Boundary values (-1, empty)
pub fn mutate_param(param: &str) -> Vec<String> {
    let mut mutations = vec![param.to_string()]; // Always include original

    // Try to detect ID pattern and generate smart mutations
    if let Some(adjacent) = generate_adjacent_ids(param, 2) {
        mutations.extend(adjacent);
    }

    // Add common BOLA test values
    mutations.extend(vec![
        "0".to_string(),     // Often admin/system user
        "1".to_string(),     // Often first user
        "admin".to_string(), // Common admin identifier
        "-1".to_string(),    // Out of bounds test
        "".to_string(),      // Empty value
        "null".to_string(),  // Null string test
    ]);

    // Deduplicate
    mutations.sort();
    mutations.dedup();
    mutations
}

/// Generate adjacent IDs by detecting and modifying numeric suffixes.
///
/// Examples:
/// - "user_123" → ["user_122", "user_124"]
/// - "456" → ["455", "457"]
/// - "id-789" → ["id-788", "id-790"]
fn generate_adjacent_ids(param: &str, range: usize) -> Option<Vec<String>> {
    // Try to extract base and numeric suffix
    let (base, number) = extract_base_and_number(param)?;

    let mut adjacent = Vec::new();

    // Generate IDs in range [number - range, number + range], excluding original
    for offset in -(range as i64)..=(range as i64) {
        if offset == 0 {
            continue; // Skip original
        }

        let new_num = (number as i64).saturating_add(offset);
        if new_num < 0 {
            continue; // Skip negative numbers
        }

        // Preserve leading zeros if present
        let formatted = if has_leading_zeros(param, number) {
            format!("{}{:0width$}", base, new_num, width = count_digits(number))
        } else {
            format!("{}{}", base, new_num)
        };

        adjacent.push(formatted);
    }

    if adjacent.is_empty() {
        None
    } else {
        Some(adjacent)
    }
}

/// Extract base string and trailing number from parameter.
///
/// Examples:
/// - "user_123" → Some(("user_", 123))
/// - "id-456" → Some(("id-", 456))
/// - "789" → Some(("", 789))
/// - "abc" → None
fn extract_base_and_number(param: &str) -> Option<(&str, usize)> {
    // Find the last contiguous sequence of digits
    let mut num_start = None;

    for (i, ch) in param.char_indices().rev() {
        if ch.is_ascii_digit() {
            num_start = Some(i);
        } else {
            break;
        }
    }

    let num_start = num_start?;

    // Extract number part
    let num_str = &param[num_start..];
    let number = num_str.parse::<usize>().ok()?;

    // Extract base part
    let base = &param[..num_start];

    Some((base, number))
}

/// Check if the number has leading zeros in the original string
fn has_leading_zeros(param: &str, _number: usize) -> bool {
    if let Some((_, num_str_start)) = extract_base_and_number(param) {
        let num_str = &param[param.len() - count_digits(num_str_start)..];
        return num_str.starts_with('0') && num_str.len() > 1;
    }
    false
}

/// Count decimal digits in a number
fn count_digits(n: usize) -> usize {
    if n == 0 {
        1
    } else {
        (n as f64).log10().floor() as usize + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Base and Number Extraction Tests
    // ============================================

    #[test]
    fn test_extract_base_and_number_underscore() {
        let result = extract_base_and_number("user_123");
        assert_eq!(result, Some(("user_", 123)));
    }

    #[test]
    fn test_extract_base_and_number_hyphen() {
        let result = extract_base_and_number("id-456");
        assert_eq!(result, Some(("id-", 456)));
    }

    #[test]
    fn test_extract_base_and_number_pure_numeric() {
        let result = extract_base_and_number("789");
        assert_eq!(result, Some(("", 789)));
    }

    #[test]
    fn test_extract_base_and_number_no_number() {
        let result = extract_base_and_number("username");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_base_and_number_leading_zeros() {
        let result = extract_base_and_number("user_007");
        assert_eq!(result, Some(("user_", 7)));
    }

    // ============================================
    // Adjacent ID Generation Tests
    // ============================================

    #[test]
    fn test_generate_adjacent_ids_basic() {
        let result = generate_adjacent_ids("user_123", 2);
        assert!(result.is_some());
        let adjacent = result.unwrap();
        assert!(adjacent.contains(&"user_121".to_string()));
        assert!(adjacent.contains(&"user_122".to_string()));
        assert!(adjacent.contains(&"user_124".to_string()));
        assert!(adjacent.contains(&"user_125".to_string()));
        assert!(!adjacent.contains(&"user_123".to_string())); // Original excluded
    }

    #[test]
    fn test_generate_adjacent_ids_pure_number() {
        let result = generate_adjacent_ids("456", 1);
        assert!(result.is_some());
        let adjacent = result.unwrap();
        assert!(adjacent.contains(&"455".to_string()));
        assert!(adjacent.contains(&"457".to_string()));
    }

    #[test]
    fn test_generate_adjacent_ids_boundary() {
        // Test boundary at 0
        let result = generate_adjacent_ids("user_1", 2);
        assert!(result.is_some());
        let adjacent = result.unwrap();
        assert!(!adjacent.contains(&"user_-1".to_string())); // No negatives
        assert!(adjacent.contains(&"user_2".to_string()));
        assert!(adjacent.contains(&"user_3".to_string()));
    }

    #[test]
    fn test_generate_adjacent_ids_no_number() {
        let result = generate_adjacent_ids("username", 2);
        assert!(result.is_none());
    }

    // ============================================
    // Full Mutation Tests
    // ============================================

    #[test]
    fn test_mutate_param_with_numeric_id() {
        let mutations = mutate_param("user_123");

        // Should include original
        assert!(mutations.contains(&"user_123".to_string()));

        // Should include adjacent IDs
        assert!(mutations.contains(&"user_121".to_string()));
        assert!(mutations.contains(&"user_122".to_string()));
        assert!(mutations.contains(&"user_124".to_string()));
        assert!(mutations.contains(&"user_125".to_string()));

        // Should include common test values
        assert!(mutations.contains(&"0".to_string()));
        assert!(mutations.contains(&"1".to_string()));
        assert!(mutations.contains(&"admin".to_string()));
        assert!(mutations.contains(&"-1".to_string()));
        assert!(mutations.contains(&"".to_string()));
        assert!(mutations.contains(&"null".to_string()));
    }

    #[test]
    fn test_mutate_param_without_number() {
        let mutations = mutate_param("username");

        // Should include original
        assert!(mutations.contains(&"username".to_string()));

        // Should include common test values (no adjacent IDs)
        assert!(mutations.contains(&"0".to_string()));
        assert!(mutations.contains(&"1".to_string()));
        assert!(mutations.contains(&"admin".to_string()));
    }

    #[test]
    fn test_mutate_param_pure_number() {
        let mutations = mutate_param("456");

        // Should include original
        assert!(mutations.contains(&"456".to_string()));

        // Should include adjacent
        assert!(mutations.contains(&"455".to_string()));
        assert!(mutations.contains(&"457".to_string()));
    }

    #[test]
    fn test_mutate_param_no_duplicates() {
        // If "1" is both adjacent and common value, should appear only once
        let mutations = mutate_param("user_2");

        let count_ones = mutations.iter().filter(|m| *m == "1").count();
        assert_eq!(count_ones, 1, "Should have exactly one '1' mutation");
    }

    // ============================================
    // Edge Cases
    // ============================================

    #[test]
    fn test_count_digits() {
        assert_eq!(count_digits(0), 1);
        assert_eq!(count_digits(5), 1);
        assert_eq!(count_digits(42), 2);
        assert_eq!(count_digits(123), 3);
        assert_eq!(count_digits(9999), 4);
    }

    #[test]
    fn test_mutate_param_empty_string() {
        let mutations = mutate_param("");
        // Should handle gracefully
        assert!(mutations.contains(&"".to_string()));
    }

    #[test]
    fn test_mutate_param_uuid_format() {
        // UUIDs don't end with simple numbers, should fall back to generic mutations
        let mutations = mutate_param("550e8400-e29b-41d4-a716-446655440000");
        assert!(mutations.contains(&"550e8400-e29b-41d4-a716-446655440000".to_string()));
        // Should still have common values
        assert!(mutations.contains(&"0".to_string()));
        assert!(mutations.contains(&"admin".to_string()));
    }
}
