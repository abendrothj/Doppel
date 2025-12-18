// Async HTTP engine for BOLA-Fuzz
// Uses reqwest and tokio for concurrent requests

use reqwest::{Client, Response};
use std::collections::HashMap;

pub struct AttackEngine {
    pub client: Client,
}

impl AttackEngine {
    pub fn new() -> Self {
        let client = Client::builder()
            .pool_max_idle_per_host(10)
            .build()
            .unwrap();
        Self { client }
    }

    pub async fn send_request(&self, method: &str, url: &str, token: &str, params: &HashMap<String, String>) -> Result<Response, reqwest::Error> {
        let mut req = self.client.request(method.parse().unwrap(), url);
        req = req.bearer_auth(token);
        for (k, v) in params {
            req = req.query(&[(k, v)]);
        }
        req.send().await
    }
}
