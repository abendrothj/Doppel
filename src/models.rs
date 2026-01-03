// Core data models and traits for Doppel

use std::fmt;

/// Supported HTTP methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    OPTIONS,
    HEAD,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::GET => write!(f, "GET"),
            Method::POST => write!(f, "POST"),
            Method::PUT => write!(f, "PUT"),
            Method::DELETE => write!(f, "DELETE"),
            Method::PATCH => write!(f, "PATCH"),
            Method::OPTIONS => write!(f, "OPTIONS"),
            Method::HEAD => write!(f, "HEAD"),
        }
    }
}

/// Parameter location in the request
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterLocation {
    Path,
    Query,
    Body,
    Header,
}

/// Represents a parameter for an endpoint
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub schema_type: Option<String>, // e.g., "string", "integer", "object"
}

/// Represents an API endpoint
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub method: Method,
    pub path: String,
    pub description: Option<String>,
    pub params: Vec<String>, // Used for simple parameter list
    #[allow(dead_code)]
    pub parameters: Vec<Parameter>, // New: structured parameters (future use)
}

impl Endpoint {
    /// Create a new endpoint with empty parameters list
    pub fn new(
        method: Method,
        path: String,
        description: Option<String>,
        params: Vec<String>,
    ) -> Self {
        Self {
            method,
            path,
            description,
            params,
            parameters: Vec::new(), // Default to empty for now
        }
    }
}

/// Trait for parsing API collections (Bruno, Postman, etc.)
pub trait CollectionParser {
    /// Parse a collection file and return a list of endpoints
    fn parse(&self, file_path: &str) -> Result<Vec<Endpoint>, String>;
}
