// Ollama Integration for Local PII Detection
//
// Uses a local LLM (Ollama) to analyze JSON responses for sensitive PII.
// This is a PRIVACY-FIRST implementation that only communicates with localhost.
//
// Security features:
// - Hardcoded localhost URL (no external calls)
// - Timeout protection (30s default)
// - Prompt injection protection (structured format)
// - Response validation
// - Optional caching for efficiency

use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

const OLLAMA_URL: &str = "http://localhost:11434/api/generate";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Result of PII analysis
#[derive(Debug, Clone)]
pub struct PiiAnalysis {
    pub contains_pii: bool,
    pub raw_response: String,
}

/// Ollama analyzer for PII detection with caching and timeout support
pub struct OllamaAnalyzer {
    client: Client,
    model: String,
    cache: Mutex<HashMap<String, PiiAnalysis>>,
}

impl OllamaAnalyzer {
    /// Create a new Ollama analyzer with timeout
    pub fn new(model: String) -> Self {
        Self::with_timeout(model, DEFAULT_TIMEOUT_SECS)
    }

    /// Create a new Ollama analyzer with custom timeout
    pub fn with_timeout(model: String, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("Failed to create HTTP client for Ollama");

        Self {
            client,
            model,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Warm up the Ollama model (loads model into memory)
    pub async fn warmup(&self) -> Result<(), String> {
        let test_json = serde_json::json!({"test": "warmup"});
        let _ = self.analyze_response(&test_json).await?;
        Ok(())
    }

    /// Analyze JSON response for PII with caching
    pub async fn analyze_response(&self, json_body: &Value) -> Result<PiiAnalysis, String> {
        // Check cache first
        let cache_key = format!("{:?}", json_body);
        if let Ok(cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        // Perform analysis
        let analysis = self.analyze_uncached(json_body).await?;

        // Cache result
        if let Ok(mut cache) = self.cache.lock() {
            // Limit cache size to prevent memory issues
            if cache.len() >= 1000 {
                cache.clear(); // Simple eviction strategy
            }
            cache.insert(cache_key, analysis.clone());
        }

        Ok(analysis)
    }

    /// Internal: Analyze without caching
    async fn analyze_uncached(&self, json_body: &Value) -> Result<PiiAnalysis, String> {
        // Construct prompt with injection protection
        // Use structured format to prevent LLM from being tricked by JSON content
        let prompt = format!(
            "You are a PII detection system. Analyze the following JSON for personally identifiable information.\n\
             \n\
             PII includes: names, email addresses, phone numbers, SSN, credit card numbers, physical addresses, dates of birth.\n\
             \n\
             Respond with ONLY 'YES' if PII is present, or 'NO' if no PII is found.\n\
             Do not explain or provide additional commentary.\n\
             \n\
             JSON to analyze:\n\
             ```json\n\
             {}\n\
             ```\n\
             \n\
             Contains PII (YES or NO)?",
            json_body
        );

        let req_body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false
        });

        // Send request with timeout
        let resp = self
            .client
            .post(OLLAMA_URL)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| format!("Ollama request failed: {}", e))?;

        // Parse response
        let resp_json: Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Ollama response: {}", e))?;

        // Validate response structure
        let response_text = resp_json
            .get("response")
            .and_then(|v| v.as_str())
            .ok_or("Invalid Ollama response format: missing 'response' field")?;

        // Parse response (case-insensitive YES/NO)
        let contains_pii = response_text.trim().to_uppercase().starts_with("YES");

        Ok(PiiAnalysis {
            contains_pii,
            raw_response: response_text.to_string(),
        })
    }

    /// Clear the analysis cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// Get cache statistics
    pub fn cache_size(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_analyzer_creation() {
        let analyzer = OllamaAnalyzer::new("llama3".to_string());
        assert_eq!(analyzer.model, "llama3");
        assert_eq!(analyzer.cache_size(), 0);
    }

    #[test]
    fn test_ollama_url_is_localhost() {
        // Ensure hardcoded URL is localhost only (security check)
        assert!(
            OLLAMA_URL.starts_with("http://localhost:")
                || OLLAMA_URL.starts_with("http://127.0.0.1:"),
            "Ollama URL must be localhost only for security"
        );
    }

    #[test]
    fn test_cache_operations() {
        let analyzer = OllamaAnalyzer::new("llama3".to_string());
        assert_eq!(analyzer.cache_size(), 0);

        // Manually add to cache for testing
        if let Ok(mut cache) = analyzer.cache.lock() {
            cache.insert(
                "test".to_string(),
                PiiAnalysis {
                    contains_pii: true,
                    raw_response: "YES".to_string(),
                },
            );
        }
        assert_eq!(analyzer.cache_size(), 1);

        analyzer.clear_cache();
        assert_eq!(analyzer.cache_size(), 0);
    }

    #[tokio::test]
    #[ignore] // Requires Ollama running locally
    async fn test_pii_analysis_with_ollama() {
        let analyzer = OllamaAnalyzer::new("llama3".to_string());

        // Test with JSON containing obvious PII
        let json_with_pii = serde_json::json!({
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789"
        });

        let result = analyzer.analyze_response(&json_with_pii).await;
        assert!(result.is_ok(), "Analysis should succeed");

        if let Ok(analysis) = result {
            // Should detect PII
            assert!(analysis.contains_pii, "Should detect PII in test data");
        }
    }

    #[tokio::test]
    #[ignore] // Requires Ollama running locally
    async fn test_cache_effectiveness() {
        let analyzer = OllamaAnalyzer::new("llama3".to_string());

        let json = serde_json::json!({"test": "data"});

        // First call - cache miss
        let result1 = analyzer.analyze_response(&json).await;
        assert!(result1.is_ok());
        assert_eq!(analyzer.cache_size(), 1);

        // Second call - cache hit
        let result2 = analyzer.analyze_response(&json).await;
        assert!(result2.is_ok());
        assert_eq!(analyzer.cache_size(), 1); // Cache size unchanged
    }
}
