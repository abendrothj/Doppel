// Reporting and output for Doppel
// Supports CSV, Markdown, and PDF export (PDF stub)

use chrono::Local;
use std::fs::File;
use std::io::Write;

/// Escape CSV field to prevent formula injection attacks
/// Cells starting with =, +, -, @, or tab are prefixed with single quote
fn escape_csv_field(field: &str) -> String {
    if field.is_empty() {
        return String::new();
    }

    let first_char = field.chars().next().unwrap();
    let needs_escaping = matches!(first_char, '=' | '+' | '-' | '@' | '\t');

    // Also escape if field contains comma or quotes
    if needs_escaping || field.contains(',') || field.contains('"') {
        if needs_escaping {
            // Prefix with single quote to prevent formula injection
            format!("\"'{}\"", field.replace('"', "\"\""))
        } else {
            // Standard CSV escaping
            format!("\"{}\"", field.replace('"', "\"\""))
        }
    } else {
        field.to_string()
    }
}

pub fn export_csv(results: &[(String, String, String)]) -> Result<String, std::io::Error> {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("doppel_report_{}.csv", timestamp);
    let mut file = File::create(&filename)?;

    writeln!(file, "Method,URL,Result")?;
    for (method, url, verdict) in results {
        writeln!(
            file,
            "{},{},{}",
            escape_csv_field(method),
            escape_csv_field(url),
            escape_csv_field(verdict)
        )?;
    }

    Ok(filename)
}

pub fn export_markdown(results: &[(String, String, String)]) -> Result<String, std::io::Error> {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("doppel_report_{}.md", timestamp);
    let mut file = File::create(&filename)?;

    writeln!(file, "# Doppel Report\n")?;
    for (method, url, verdict) in results {
        writeln!(file, "- **{}** {}: {}", method, url, verdict)?;
    }

    Ok(filename)
}

pub fn export_pdf(_results: &[(String, String, String)]) {
    // Stub: PDF export not implemented
}
