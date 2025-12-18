// Ollama integration for Doppel
// Uses a local LLM (Ollama) to analyze JSON responses for sensitive PII

use reqwest::Client;
use serde_json::Value;

pub struct OllamaAnalyzer {
    pub client: Client,
    pub model: String,
}

impl OllamaAnalyzer {
    pub fn new(model: String) -> Self {
        Self {
            client: Client::new(),
            model,
        }
    }

    pub async fn analyze_response(&self, json_body: &Value) -> Result<String, reqwest::Error> {
        let prompt = format!("Does this JSON contain sensitive PII? {}", json_body);
        let req_body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false
        });
        let resp = self.client.post("http://localhost:11434/api/generate")
            .json(&req_body)
            .send()
            .await?;
        let resp_json: Value = resp.json().await?;
        Ok(resp_json.to_string())
    }
}
