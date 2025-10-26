use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Paginated response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub links: PaginationLinks,
    pub meta: PaginationMeta,
}

/// Pagination links
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationLinks {
    pub first: Option<String>,
    pub last: Option<String>,
    pub prev: Option<String>,
    pub next: Option<String>,
}

/// Pagination metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    pub current_page: u32,
    pub from: Option<u32>,
    pub last_page: u32,
    pub path: Option<String>,
    pub per_page: u32,
    pub to: Option<u32>,
    pub total: u32,
}

/// Single resource response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceResponse<T> {
    pub data: T,
}

/// Gateway resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    pub id: String,
    pub code: String,
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub authorized_by: Option<AuthorizedByInfo>,
    pub created_at: String,
    pub updated_at: String,
}

/// User who authorized a gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedByInfo {
    pub id: String,
    pub name: String,
    pub email: String,
}

/// Service resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    pub gateway_id: String,
    pub name: String,
    pub service_type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Endpoint resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub path: String,
    pub methods: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Backend resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub timeout_seconds: Option<u32>,
    #[serde(default)]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Pipeline resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    pub id: String,
    pub endpoint_id: String,
    pub backend_id: String,
    pub name: String,
    #[serde(default)]
    pub order: Option<u32>,
    #[serde(default)]
    pub middleware_ids: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Middleware resource  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Middleware {
    pub id: String,
    pub name: String,
    pub middleware_type: String,
    #[serde(default)]
    pub config: Option<HashMap<String, serde_json::Value>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Transform resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transform {
    pub id: String,
    pub name: String,
    pub transform_type: String,
    #[serde(default)]
    pub config: Option<HashMap<String, serde_json::Value>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Policy resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub policy_type: String,
    #[serde(default)]
    pub rules: Option<HashMap<String, serde_json::Value>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Network resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub id: String,
    pub gateway_id: String,
    pub domain: String,
    #[serde(default)]
    pub dns_config: Option<HashMap<String, serde_json::Value>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Authentication resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authentication {
    pub id: String,
    pub name: String,
    pub auth_type: String,
    #[serde(default)]
    pub config: Option<HashMap<String, serde_json::Value>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Full gateway configuration (for downloading complete config)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfiguration {
    pub gateway: Gateway,
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub backends: Vec<Backend>,
    #[serde(default)]
    pub pipelines: Vec<Pipeline>,
    #[serde(default)]
    pub middlewares: Vec<Middleware>,
    #[serde(default)]
    pub transforms: Vec<Transform>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    #[serde(default)]
    pub networks: Vec<Network>,
}
