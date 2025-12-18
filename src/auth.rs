// Authentication strategies for Doppel
// Supports static tokens, API keys, OAuth2, cookies, and session-based auth

pub enum AuthType {
    StaticToken(String),
    ApiKey(String),
    OAuth2 { client_id: String, client_secret: String, token_url: String },
    Cookie(String),
    Session(String),
}

pub trait AuthStrategy {
    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder;
}

pub struct StaticTokenAuth {
    pub token: String,
}

impl AuthStrategy for StaticTokenAuth {
    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.bearer_auth(&self.token)
    }
}
// TODO: Implement other strategies
