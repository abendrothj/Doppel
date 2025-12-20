/// Security tests for Doppel
/// Tests CSV injection protection, path traversal prevention, and other security features

use std::fs;
use std::path::Path;

#[test]
fn test_csv_injection_protection() {
    // Test that CSV fields starting with dangerous characters are properly escaped
    let results = vec![
        ("GET".to_string(), "/api/users".to_string(), "=HYPERLINK(\"http://evil.com\")".to_string()),
        ("POST".to_string(), "/api/data".to_string(), "+cmd|'/C calc'!A1".to_string()),
        ("DELETE".to_string(), "/api/items".to_string(), "-2+3+cmd|'/C calc'!A1".to_string()),
        ("PUT".to_string(), "/api/update".to_string(), "@SUM(1+1)*cmd|'/C calc'!A1".to_string()),
        ("PATCH".to_string(), "/api/modify".to_string(), "\t=1+1".to_string()),
    ];

    let csv_filename = doppel::reporting::export_csv(&results)
        .expect("CSV export should succeed");

    // Read the CSV file
    let content = fs::read_to_string(&csv_filename)
        .expect("Should be able to read CSV file");

    // Verify that dangerous characters are escaped with single quote prefix
    assert!(content.contains("\"'=HYPERLINK"), "CSV should escape = prefix");
    assert!(content.contains("\"'+cmd"), "CSV should escape + prefix");
    assert!(content.contains("\"'-2+3"), "CSV should escape - prefix");
    assert!(content.contains("\"'@SUM"), "CSV should escape @ prefix");
    assert!(content.contains("\"'\t=1+1"), "CSV should escape tab prefix");

    // Verify header is not escaped
    assert!(content.starts_with("Method,URL,Result\n"), "CSV header should be intact");

    // Clean up
    let _ = fs::remove_file(&csv_filename);
}

#[test]
fn test_csv_normal_content_not_escaped() {
    // Test that normal content is not unnecessarily escaped
    let results = vec![
        ("GET".to_string(), "/api/users/123".to_string(), "SAFE: No vulnerability".to_string()),
        ("POST".to_string(), "/api/data".to_string(), "VULNERABLE: BOLA detected".to_string()),
    ];

    let csv_filename = doppel::reporting::export_csv(&results)
        .expect("CSV export should succeed");

    let content = fs::read_to_string(&csv_filename)
        .expect("Should be able to read CSV file");

    // Verify normal content without dangerous prefixes is not quoted
    assert!(content.contains("GET,/api/users/123,SAFE: No vulnerability"),
        "Normal content should not be unnecessarily escaped");

    // Clean up
    let _ = fs::remove_file(&csv_filename);
}

#[test]
fn test_csv_comma_and_quote_escaping() {
    // Test that commas and quotes are properly escaped
    let results = vec![
        ("GET".to_string(), "/api/test,comma".to_string(), "Result with \"quotes\"".to_string()),
    ];

    let csv_filename = doppel::reporting::export_csv(&results)
        .expect("CSV export should succeed");

    let content = fs::read_to_string(&csv_filename)
        .expect("Should be able to read CSV file");

    // Verify comma causes field to be quoted
    assert!(content.contains("\"/api/test,comma\""), "Comma should cause quoting");

    // Verify quotes are escaped with double quotes
    assert!(content.contains("\"Result with \"\"quotes\"\"\""), "Quotes should be doubled");

    // Clean up
    let _ = fs::remove_file(&csv_filename);
}

#[test]
fn test_csv_empty_fields() {
    // Test that empty fields are handled correctly
    let results = vec![
        ("".to_string(), "".to_string(), "".to_string()),
    ];

    let csv_filename = doppel::reporting::export_csv(&results)
        .expect("CSV export should succeed");

    let content = fs::read_to_string(&csv_filename)
        .expect("Should be able to read CSV file");

    // Should have header plus one empty line
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2, "Should have header and one data row");
    assert_eq!(lines[1], ",,", "Empty fields should result in commas only");

    // Clean up
    let _ = fs::remove_file(&csv_filename);
}

#[test]
fn test_report_filenames_have_timestamps() {
    // Test that exported files have timestamps to prevent overwrites
    let results = vec![("GET".to_string(), "/api/test".to_string(), "SAFE".to_string())];

    let csv_filename1 = doppel::reporting::export_csv(&results)
        .expect("First CSV export should succeed");

    // Small delay to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let csv_filename2 = doppel::reporting::export_csv(&results)
        .expect("Second CSV export should succeed");

    // Verify filenames are different
    assert_ne!(csv_filename1, csv_filename2, "Subsequent exports should have different filenames");

    // Verify both files exist
    assert!(Path::new(&csv_filename1).exists(), "First file should exist");
    assert!(Path::new(&csv_filename2).exists(), "Second file should exist");

    // Verify filename format
    assert!(csv_filename1.starts_with("doppel_report_"), "Should have correct prefix");
    assert!(csv_filename1.ends_with(".csv"), "Should have .csv extension");
    assert!(csv_filename1.len() > 20, "Filename should include timestamp");

    // Clean up
    let _ = fs::remove_file(&csv_filename1);
    let _ = fs::remove_file(&csv_filename2);
}

#[test]
fn test_markdown_export_structure() {
    // Test that markdown export creates proper structure
    let results = vec![
        ("GET".to_string(), "/api/users/1".to_string(), "VULNERABLE: BOLA".to_string()),
        ("POST".to_string(), "/api/data".to_string(), "SAFE".to_string()),
    ];

    let md_filename = doppel::reporting::export_markdown(&results)
        .expect("Markdown export should succeed");

    let content = fs::read_to_string(&md_filename)
        .expect("Should be able to read markdown file");

    // Verify markdown structure
    assert!(content.starts_with("# Doppel Report\n"), "Should have header");
    assert!(content.contains("- **GET** /api/users/1: VULNERABLE: BOLA"), "Should contain first result");
    assert!(content.contains("- **POST** /api/data: SAFE"), "Should contain second result");

    // Clean up
    let _ = fs::remove_file(&md_filename);
}

#[test]
fn test_multiple_vulnerabilities_export() {
    // Test exporting a realistic set of scan results
    let results = vec![
        ("GET".to_string(), "/api/users/1".to_string(), "VULNERABLE: BOLA detected".to_string()),
        ("GET".to_string(), "/api/users/2".to_string(), "VULNERABLE: BOLA detected".to_string()),
        ("GET".to_string(), "/api/posts/1".to_string(), "VULNERABLE: IDOR detected".to_string()),
        ("DELETE".to_string(), "/api/users/1".to_string(), "VULNERABLE: Unauthorized deletion".to_string()),
        ("GET".to_string(), "/api/public/info".to_string(), "SAFE: No vulnerability".to_string()),
    ];

    let csv_filename = doppel::reporting::export_csv(&results)
        .expect("CSV export should succeed");
    let md_filename = doppel::reporting::export_markdown(&results)
        .expect("Markdown export should succeed");

    // Verify both files exist
    assert!(Path::new(&csv_filename).exists(), "CSV file should exist");
    assert!(Path::new(&md_filename).exists(), "Markdown file should exist");

    // Verify CSV has correct number of lines (header + 5 results)
    let csv_content = fs::read_to_string(&csv_filename).expect("Should read CSV");
    assert_eq!(csv_content.lines().count(), 6, "Should have header + 5 data rows");

    // Verify markdown has all results
    let md_content = fs::read_to_string(&md_filename).expect("Should read markdown");
    assert_eq!(md_content.lines().filter(|l| l.starts_with("- ")).count(), 5,
        "Should have 5 result lines");

    // Clean up
    let _ = fs::remove_file(&csv_filename);
    let _ = fs::remove_file(&md_filename);
}
