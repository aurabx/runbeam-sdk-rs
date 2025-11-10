use serde::{Deserialize, Serialize};

/// Paginated response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    #[serde(default)]
    pub links: Option<PaginationLinks>,
    #[serde(default)]
    pub meta: Option<PaginationMeta>,
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
    #[serde(default)]
    pub links: Option<Vec<serde_json::Value>>,  // Laravel pagination links array
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
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub id: Option<String>,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub gateway_id: Option<String>,
    pub enable_wireguard: bool,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default, alias = "http")]
    pub tcp_config: Option<TcpConfig>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// TCP configuration for network - used by all protocol adapters (HTTP, DIMSE, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConfig {
    pub bind_address: Option<String>,
    pub bind_port: Option<u16>,
}

/// Runbeam Cloud integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Runbeam {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub id: Option<String>,
    pub code: String,
    pub name: String,
    pub team_id: String,
    pub gateway_id: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub cloud_api_base_url: Option<String>,
    #[serde(default)]
    pub poll_interval_secs: Option<u32>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Authentication resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authentication {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub id: Option<String>,
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
    #[serde(default)]
    pub runbeam: Option<Runbeam>,
}

/// Change resource for configuration change tracking (API v1.0)
/// 
/// This represents a configuration change that needs to be applied to a gateway.
/// The API returns two different levels of detail:
/// 
/// 1. ChangeMetadata (list view) - returned from `/api/harmony/changes` endpoints
///    Contains: id, status, type, gateway_id, created_at
/// 
/// 2. ChangeResource (detail view) - returned from `/api/harmony/changes/{change}` endpoint  
///    Contains all metadata fields plus: pipeline_id, toml_config, metadata, timestamps, error info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub id: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub gateway_id: String,
    #[serde(default)]
    pub pipeline_id: Option<String>,
    /// TOML configuration content (only present in detail view)
    #[serde(default)]
    pub toml_config: Option<String>,
    /// Additional metadata (only present in detail view)
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
    #[serde(default)]
    pub acknowledged_at: Option<String>,
    #[serde(default)]
    pub applied_at: Option<String>,
    #[serde(default)]
    pub failed_at: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub error_details: Option<serde_json::Value>,
}

/// Response from the base URL discovery endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseUrlResponse {
    /// Base URL for the Harmony API (e.g., https://runbeam.lndo.site/api)
    pub base_url: String,
    /// Optional path for changes API (e.g., "/")
    #[serde(default)]
    pub changes_path: Option<String>,
    /// Optional fully resolved URL (base_url + changes_path)
    #[serde(default)]
    pub full_url: Option<String>,
}

/// Request payload for acknowledging multiple changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcknowledgeChangesRequest {
    pub change_ids: Vec<String>,
}

/// Request payload for reporting a failed change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeFailedRequest {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
}

/// Response from acknowledging multiple changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcknowledgeChangesResponse {
    pub acknowledged: Vec<String>,
    pub failed: Vec<String>,
}

/// Response from marking a change as applied or failed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeStatusResponse {
    pub success: bool,
    pub message: String,
}

/// Type alias for change applied response
pub type ChangeAppliedResponse = ChangeStatusResponse;

/// Type alias for change failed response  
pub type ChangeFailedResponse = ChangeStatusResponse;
