// Bruno collection parser for Doppel
// Uses walkdir and regex to extract endpoints from .bru files

use crate::models::{CollectionParser, Endpoint, Method};
use lazy_static::lazy_static;
use regex::Regex;
use walkdir::WalkDir;

lazy_static! {
    static ref METHOD_REGEX: Regex =
        Regex::new(r#"method"\s*:\s*"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)"#)
            .expect("Failed to compile METHOD_REGEX");
    static ref URL_REGEX: Regex =
        Regex::new(r#"url"\s*:\s*"([^"]+)"#).expect("Failed to compile URL_REGEX");
}

pub struct BrunoParser;

impl CollectionParser for BrunoParser {
    fn parse(&self, dir_path: &str) -> Result<Vec<Endpoint>, String> {
        let mut endpoints = Vec::new();

        for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().extension().is_some_and(|ext| ext == "bru") {
                let content = std::fs::read_to_string(entry.path())
                    .map_err(|e| format!("Failed to read {:?}: {}", entry.path(), e))?;
                let method = METHOD_REGEX
                    .captures(&content)
                    .and_then(|cap| cap.get(1))
                    .map(|m| m.as_str().to_string());
                let url = URL_REGEX
                    .captures(&content)
                    .and_then(|cap| cap.get(1))
                    .map(|u| u.as_str().to_string());
                if let (Some(method), Some(url)) = (method, url) {
                    let method = match method.as_str() {
                        "GET" => Method::GET,
                        "POST" => Method::POST,
                        "PUT" => Method::PUT,
                        "DELETE" => Method::DELETE,
                        "PATCH" => Method::PATCH,
                        "OPTIONS" => Method::OPTIONS,
                        "HEAD" => Method::HEAD,
                        _ => continue,
                    };
                    endpoints.push(Endpoint::new(method, url, None, vec![]));
                }
            }
        }
        Ok(endpoints)
    }
}
