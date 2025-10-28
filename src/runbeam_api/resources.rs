use serde::{Deserialize, Serialize};

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
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub pipelines_path: Option<String>,
    #[serde(default)]
    pub transforms_path: Option<String>,
    #[serde(default)]
    pub jwks_cache_duration_hours: Option<u32>,
    #[serde(default)]
    pub management_enabled: Option<bool>,
    #[serde(default)]
    pub management_base_path: Option<String>,
    #[serde(default)]
    pub management_network_id: Option<String>,
    #[serde(default)]
    pub dns: Option<Vec<String>>,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
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
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub gateway_id: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Endpoint resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub gateway_id: Option<String>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Backend resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub gateway_id: Option<String>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u32>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Pipeline resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub description: String,
    pub team_id: String,
    pub gateway_id: Option<String>,
    #[serde(default)]
    pub networks: Option<Vec<String>>,
    #[serde(default)]
    pub endpoints: Option<serde_json::Value>,
    #[serde(default)]
    pub backends: Option<serde_json::Value>,
    #[serde(default)]
    pub middleware: Option<serde_json::Value>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Middleware resource  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Middleware {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub middleware_type: String,
    #[serde(default)]
    pub options: Option<serde_json::Value>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Transform resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transform {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub gateway_id: String,
    #[serde(default)]
    pub options: Option<TransformOptions>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Transform options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformOptions {
    pub instructions: Option<String>,
}

/// Policy resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub enabled: u32,
    pub team_id: String,
    pub gateway_id: String,
    #[serde(default)]
    pub rules: Option<serde_json::Value>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Network resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub gateway_id: Option<String>,
    pub enable_wireguard: bool,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub http: Option<HttpConfig>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// HTTP configuration for network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub bind_address: Option<String>,
    pub bind_port: Option<u16>,
}

/// Authentication resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authentication {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    pub code: Option<String>,
    pub name: String,
    pub team_id: Option<String>,
    pub gateway_id: Option<String>,
    #[serde(default)]
    pub options: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
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
