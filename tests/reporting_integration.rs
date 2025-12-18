use std::fs;

#[test]
fn reporting_exports_create_files() {
    // call the reporting functions
    let results = vec![("GET".to_string(), "/api/users/1".to_string(), "VULNERABLE".to_string())];

    // Use the library functions
    doppel::reporting::export_csv(&results);
    doppel::reporting::export_markdown(&results);

    // Check files exist
    assert!(fs::metadata("doppel_report.csv").is_ok());
    assert!(fs::metadata("doppel_report.md").is_ok());

    // Clean up
    let _ = fs::remove_file("doppel_report.csv");
    let _ = fs::remove_file("doppel_report.md");
}
