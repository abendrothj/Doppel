// Reporting and output for Doppel
// Supports CSV, Markdown, and PDF export (PDF stub)

use std::fs::File;
use std::io::Write;

pub fn export_csv(results: &[(String, String, String)]) {
    let mut file = File::create("doppel_report.csv").unwrap();
    writeln!(file, "Method,URL,Result").unwrap();
    for (method, url, verdict) in results {
        writeln!(file, "{},{},{}", method, url, verdict).unwrap();
    }
}

pub fn export_markdown(results: &[(String, String, String)]) {
    let mut file = File::create("doppel_report.md").unwrap();
    writeln!(file, "# Doppel Report\n").unwrap();
    for (method, url, verdict) in results {
        writeln!(file, "- **{}** {}: {}", method, url, verdict).unwrap();
    }
}

pub fn export_pdf(_results: &[(String, String, String)]) {
    // Stub: PDF export not implemented
}
