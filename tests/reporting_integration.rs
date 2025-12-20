use std::fs;

#[test]
fn reporting_exports_create_files() {
    // call the reporting functions
    let results = vec![("GET".to_string(), "/api/users/1".to_string(), "VULNERABLE".to_string())];

    // Use the library functions - they now return filenames with timestamps
    let csv_filename = doppel::reporting::export_csv(&results)
        .expect("CSV export should succeed");
    let md_filename = doppel::reporting::export_markdown(&results)
        .expect("Markdown export should succeed");

    // Check files exist with the returned filenames
    assert!(fs::metadata(&csv_filename).is_ok(), "CSV file should exist: {}", csv_filename);
    assert!(fs::metadata(&md_filename).is_ok(), "Markdown file should exist: {}", md_filename);

    // Verify filenames contain timestamp pattern
    assert!(csv_filename.starts_with("doppel_report_"));
    assert!(csv_filename.ends_with(".csv"));
    assert!(md_filename.starts_with("doppel_report_"));
    assert!(md_filename.ends_with(".md"));

    // Clean up
    let _ = fs::remove_file(&csv_filename);
    let _ = fs::remove_file(&md_filename);
}
