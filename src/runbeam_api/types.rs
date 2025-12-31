use serde::{Deserialize, Serialize};
use std::fmt;

/// Runbeam API error type
///
/// Represents all possible errors that can occur when interacting with
/// the Runbeam Cloud API or performing related operations.
#[derive(Debug)]
pub enum RunbeamError {
    /// JWT validation failed
    JwtValidation(String),
    /// API request failed (network, HTTP, or response parsing error)
    Api(ApiError),
    /// Token storage operation failed
    Storage(crate::storage::StorageError),
    /// Configuration error
    Config(String),
    /// TOML validation failed
    Validation(crate::validation::ValidationError),
}

impl fmt::Display for RunbeamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunbeamError::JwtValidation(msg) => write!(f, "JWT validation failed: {}", msg),
            RunbeamError::Api(err) => write!(f, "API error: {}", err),
            RunbeamError::Storage(err) => write!(f, "Storage error: {}", err),
            RunbeamError::Config(msg) => write!(f, "Configuration error: {}", msg),
            RunbeamError::Validation(err) => write!(f, "Validation error: {}", err),
        }
    }
}

impl std::error::Error for RunbeamError {}

impl From<ApiError> for RunbeamError {
    fn from(err: ApiError) -> Self {
        RunbeamError::Api(err)
    }
}

impl From<crate::storage::StorageError> for RunbeamError {
    fn from(err: crate::storage::StorageError) -> Self {
        RunbeamError::Storage(err)
    }
}

impl From<jsonwebtoken::errors::Error> for RunbeamError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        RunbeamError::JwtValidation(err.to_string())
    }
}

impl From<crate::validation::ValidationError> for RunbeamError {
    fn from(err: crate::validation::ValidationError) -> Self {
        RunbeamError::Validation(err)
    }
}

/// API-specific errors
#[derive(Debug)]
pub enum ApiError {
    /// Network error (connection, timeout, etc.)
    Network(String),
    /// HTTP error with status code
    Http { status: u16, message: String },
    /// Failed to parse response
    Parse(String),
    /// Request building failed
    Request(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Network(msg) => write!(f, "Network error: {}", msg),
            ApiError::Http { status, message } => {
                write!(f, "HTTP {} error: {}", status, message)
            }
            ApiError::Parse(msg) => write!(f, "Parse error: {}", msg),
            ApiError::Request(msg) => write!(f, "Request error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            ApiError::Network("Request timeout".to_string())
        } else if err.is_connect() {
            ApiError::Network(format!("Connection failed: {}", err))
        } else if let Some(status) = err.status() {
            ApiError::Http {
                status: status.as_u16(),
                message: err.to_string(),
            }
        } else {
            ApiError::Network(err.to_string())
        }
    }
}

/// User information from JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
}

/// User authentication token (JWT)
///
/// This token is used for authenticating user actions with the Runbeam Cloud API.
/// It has a shorter lifespan than machine tokens and is typically issued after
/// a user successfully logs in via the browser-based OAuth flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserToken {
    /// JWT token for API authentication
    pub token: String,
    /// Token expiration timestamp (seconds since Unix epoch)
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// User information from JWT claims
    #[serde(default)]
    pub user: Option<UserInfo>,
}

impl UserToken {
    /// Create a new user token
    pub fn new(token: String, expires_at: Option<i64>, user: Option<UserInfo>) -> Self {
        Self {
            token,
            expires_at,
            user,
        }
    }
}

/// Team information from JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamInfo {
    pub id: String,
    pub name: String,
}

/// Gateway information returned from authorize endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub id: String,
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub authorized_by: Option<AuthorizedBy>,
}

/// User who authorized the gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedBy {
    pub id: String,
    pub name: String,
    pub email: String,
}

/// Response from Runbeam Cloud authorize endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub machine_token: String,
    pub expires_in: f64,
    pub expires_at: String,
    pub gateway: GatewayInfo,
    #[serde(default)]
    pub abilities: Vec<String>,
}

/// Request payload for storing/updating Harmony configuration
///
/// This is used by the `harmony.update` endpoint to send TOML configuration
/// from Harmony instances back to Runbeam Cloud for storage as database models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfigRequest {
    /// Type of configuration being stored ("gateway", "pipeline", or "transform")
    #[serde(rename = "type")]
    pub config_type: String,
    /// Optional ID for updating existing resources (omitted for creates)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// TOML configuration content
    pub config: String,
}

/// Response from storing/updating Harmony configuration
///
/// The API returns UpdateSuccessResource format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfigResponse {
    /// Success flag
    pub success: bool,
    /// Success message
    pub message: String,
    /// Response data with model and change info
    pub data: StoreConfigModel,
}

/// Model information from store config response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfigModel {
    /// Model ID (ULID)
    pub id: String,
    /// Model type ("gateway", "pipeline", "transform")
    #[serde(rename = "type")]
    pub model_type: String,
    /// Action taken ("created", "updated")
    pub action: String,
}

/// Mesh information returned from Runbeam Cloud API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshInfo {
    /// Unique mesh identifier (ULID)
    pub id: String,
    /// Human-readable mesh name
    pub name: String,
    /// Protocol type for mesh communication (http, http3)
    #[serde(rename = "type")]
    pub mesh_type: String,
    /// Mesh provider (local, runbeam)
    pub provider: String,
    /// Authentication type for mesh members (currently only "jwt")
    #[serde(default = "default_auth_type")]
    pub auth_type: String,
    /// JWT secret for HS256 symmetric key authentication (local provider)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_secret: Option<String>,
    /// Path to RSA private key (PEM) for RS256 JWT signing (local provider)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_private_key_path: Option<String>,
    /// Path to RSA public key (PEM) for RS256 JWT verification (local provider)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_public_key_path: Option<String>,
    /// List of ingress definition names
    #[serde(default)]
    pub ingress: Vec<String>,
    /// List of egress definition names
    #[serde(default)]
    pub egress: Vec<String>,
    /// Whether the mesh is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
}

/// Mesh ingress information - allows other mesh members to send requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshIngressInfo {
    /// Unique ingress identifier (ULID)
    pub id: String,
    /// Human-readable ingress name
    pub name: String,
    /// Protocol type for incoming mesh requests (http, http3)
    #[serde(rename = "type")]
    pub ingress_type: String,
    /// Pipeline name that owns this ingress (required)
    pub pipeline: String,
    /// Mode: 'default' allows all requests, 'mesh' requires valid mesh authentication
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Optional endpoint override. If omitted, the first endpoint in the pipeline is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// List of URLs that map to this ingress
    #[serde(default)]
    pub urls: Vec<String>,
    /// Whether the ingress is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
}

/// Mesh egress information - allows sending requests to other mesh members
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEgressInfo {
    /// Unique egress identifier (ULID)
    pub id: String,
    /// Human-readable egress name
    pub name: String,
    /// Protocol type for outgoing mesh requests (http, http3)
    #[serde(rename = "type")]
    pub egress_type: String,
    /// Pipeline name that owns this egress (required)
    pub pipeline: String,
    /// Mode: 'default' allows all destinations, 'mesh' requires destination to match a mesh ingress
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Optional backend override. If omitted, the first backend in the pipeline is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Whether the egress is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_mode() -> String {
    "default".to_string()
}

fn default_auth_type() -> String {
    "jwt".to_string()
}

fn default_poll_interval() -> u32 {
    30
}

// ========================================================================================
// RESOURCE RESOLUTION TYPES
// ========================================================================================

/// Response from resolving a resource reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResourceResponse {
    /// The resolved resource data
    pub data: ResolvedResource,
    /// Resolution metadata
    pub meta: ResolutionMeta,
}

/// Metadata about the resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionMeta {
    /// Provider that resolved this resource
    pub provider: String,
    /// When the resolution occurred
    pub resolved_at: String,
}

/// A resolved resource (type varies based on resource type)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedResource {
    /// Resource type (ingress, egress, pipeline, etc.)
    #[serde(rename = "type")]
    pub resource_type: String,
    /// Resource ID (ULID)
    pub id: String,
    /// Resource name
    pub name: String,
    /// Team ID
    #[serde(default)]
    pub team_id: Option<String>,
    /// Whether the resource is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Gateway ID (for gateway-scoped resources)
    #[serde(default)]
    pub gateway_id: Option<String>,
    /// Pipeline ID (for pipeline-scoped resources)
    #[serde(default)]
    pub pipeline_id: Option<String>,
    /// Mesh ID (for mesh ingress/egress)
    #[serde(default)]
    pub mesh_id: Option<String>,
    /// URLs (for ingress resources)
    #[serde(default)]
    pub urls: Vec<String>,
    /// Protocol (http, http3, etc.)
    #[serde(default)]
    pub protocol: Option<String>,
    /// Mode (default, mesh)
    #[serde(default)]
    pub mode: Option<String>,
    /// Backend ID (for egress resources)
    #[serde(default)]
    pub backend_id: Option<String>,
    /// Service ID (for endpoints/backends)
    #[serde(default)]
    pub service_id: Option<String>,
    /// Endpoint ID (for ingress resources)
    #[serde(default)]
    pub endpoint_id: Option<String>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// Provider (for mesh resources)
    #[serde(default)]
    pub provider: Option<String>,
    /// Auth type (for mesh resources)
    #[serde(default)]
    pub auth_type: Option<String>,
}

// ========================================================================================
// PROVIDER TYPES
// ========================================================================================

/// Provider configuration for resource resolution
///
/// Providers define how resources are resolved - either locally from config files
/// or remotely from a provider API (e.g., Runbeam Cloud).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Base URL for provider API. Required for remote providers, omitted for 'local'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    /// Whether this provider is active
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Polling interval in seconds for change detection
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u32,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            api: None,
            enabled: true,
            poll_interval_secs: 30,
        }
    }
}

/// Type of resource being referenced
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    Ingress,
    Egress,
    Pipeline,
    Endpoint,
    Backend,
    Mesh,
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceType::Ingress => write!(f, "ingress"),
            ResourceType::Egress => write!(f, "egress"),
            ResourceType::Pipeline => write!(f, "pipeline"),
            ResourceType::Endpoint => write!(f, "endpoint"),
            ResourceType::Backend => write!(f, "backend"),
            ResourceType::Mesh => write!(f, "mesh"),
        }
    }
}

impl std::str::FromStr for ResourceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ingress" => Ok(ResourceType::Ingress),
            "egress" => Ok(ResourceType::Egress),
            "pipeline" => Ok(ResourceType::Pipeline),
            "endpoint" => Ok(ResourceType::Endpoint),
            "backend" => Ok(ResourceType::Backend),
            "mesh" => Ok(ResourceType::Mesh),
            _ => Err(format!("Unknown resource type: {}", s)),
        }
    }
}

/// How to look up the resource
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupBy {
    /// Lookup by ULID
    Id(String),
    /// Lookup by name
    Name(String),
}

/// Parsed resource reference
///
/// Supports multiple formats:
/// - `name` -> local.name.{name}
/// - `local.name.{name}` -> explicit local lookup
/// - `{provider}.id.{id}` -> provider-wide ID lookup
/// - `{provider}.{team}.id.{id}` -> team-scoped ID lookup  
/// - `{provider}.{team}.{type}.name.{name}` -> full path lookup
/// - `{provider}.{team}.{type}.id.{id}` -> full path lookup by ID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceReference {
    /// Provider name (e.g., "local", "runbeam")
    pub provider: String,
    /// Optional team identifier
    pub team: Option<String>,
    /// Optional resource type
    pub resource_type: Option<ResourceType>,
    /// How to look up the resource
    pub lookup: LookupBy,
}

impl ResourceReference {
    /// Parse a resource reference string
    ///
    /// # Examples
    /// ```
    /// use runbeam_sdk::runbeam_api::types::ResourceReference;
    ///
    /// // Bare name -> local.name.{name}
    /// let r = ResourceReference::parse("my_ingress").unwrap();
    /// assert_eq!(r.provider, "local");
    ///
    /// // Full path
    /// let r = ResourceReference::parse("runbeam.acme.ingress.name.patient_api").unwrap();
    /// assert_eq!(r.provider, "runbeam");
    /// ```
    pub fn parse(input: &str) -> Result<Self, String> {
        let parts: Vec<&str> = input.split('.').collect();

        match parts.len() {
            // Bare name: "my_ingress" -> local.name.my_ingress
            1 => Ok(ResourceReference {
                provider: "local".to_string(),
                team: None,
                resource_type: None,
                lookup: LookupBy::Name(parts[0].to_string()),
            }),

            // "local.name.{name}" or "{provider}.id.{id}"
            3 => {
                let provider = parts[0];
                match parts[1] {
                    "name" => Ok(ResourceReference {
                        provider: provider.to_string(),
                        team: None,
                        resource_type: None,
                        lookup: LookupBy::Name(parts[2].to_string()),
                    }),
                    "id" => Ok(ResourceReference {
                        provider: provider.to_string(),
                        team: None,
                        resource_type: None,
                        lookup: LookupBy::Id(parts[2].to_string()),
                    }),
                    _ => Err(format!(
                        "Invalid reference format: expected 'name' or 'id', got '{}'",
                        parts[1]
                    )),
                }
            }

            // "{provider}.{team}.id.{id}"
            4 => {
                let provider = parts[0];
                let team = parts[1];
                match parts[2] {
                    "id" => Ok(ResourceReference {
                        provider: provider.to_string(),
                        team: Some(team.to_string()),
                        resource_type: None,
                        lookup: LookupBy::Id(parts[3].to_string()),
                    }),
                    _ => Err(format!(
                        "Invalid reference format: expected 'id' at position 2, got '{}'",
                        parts[2]
                    )),
                }
            }

            // "{provider}.{team}.{type}.name.{name}" or "{provider}.{team}.{type}.id.{id}"
            5 => {
                let provider = parts[0];
                let team = parts[1];
                let resource_type: ResourceType = parts[2].parse()?;
                match parts[3] {
                    "name" => Ok(ResourceReference {
                        provider: provider.to_string(),
                        team: Some(team.to_string()),
                        resource_type: Some(resource_type),
                        lookup: LookupBy::Name(parts[4].to_string()),
                    }),
                    "id" => Ok(ResourceReference {
                        provider: provider.to_string(),
                        team: Some(team.to_string()),
                        resource_type: Some(resource_type),
                        lookup: LookupBy::Id(parts[4].to_string()),
                    }),
                    _ => Err(format!(
                        "Invalid reference format: expected 'name' or 'id', got '{}'",
                        parts[3]
                    )),
                }
            }

            _ => Err(format!(
                "Invalid reference format: unexpected number of parts ({})",
                parts.len()
            )),
        }
    }

    /// Check if this reference is for local resolution only
    pub fn is_local(&self) -> bool {
        self.provider == "local"
    }

    /// Convert back to string representation
    pub fn to_reference_string(&self) -> String {
        let lookup_str = match &self.lookup {
            LookupBy::Id(id) => format!("id.{}", id),
            LookupBy::Name(name) => format!("name.{}", name),
        };

        match (&self.team, &self.resource_type) {
            (Some(team), Some(rt)) => format!("{}.{}.{}.{}", self.provider, team, rt, lookup_str),
            (Some(team), None) => format!("{}.{}.{}", self.provider, team, lookup_str),
            (None, _) => {
                // For local with name lookup, can use shorthand
                if self.provider == "local" {
                    if let LookupBy::Name(name) = &self.lookup {
                        return name.clone();
                    }
                }
                format!("{}.{}", self.provider, lookup_str)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_config_request_with_id() {
        let request = StoreConfigRequest {
            config_type: "gateway".to_string(),
            id: Some("01k8ek6h9aahhnrv3benret1nn".to_string()),
            config: "[proxy]\nid = \"test\"\n".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"type\":\"gateway\""));
        assert!(json.contains("\"id\":\"01k8ek6h9aahhnrv3benret1nn\""));
        assert!(json.contains("\"config\":"));
        assert!(json.contains("[proxy]"));

        // Test deserialization
        let deserialized: StoreConfigRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.config_type, "gateway");
        assert_eq!(
            deserialized.id,
            Some("01k8ek6h9aahhnrv3benret1nn".to_string())
        );
    }

    #[test]
    fn test_store_config_request_without_id() {
        let request = StoreConfigRequest {
            config_type: "pipeline".to_string(),
            id: None,
            config: "[pipeline]\nname = \"test\"\n".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"type\":\"pipeline\""));
        assert!(json.contains("\"config\":"));
        // Should not contain the id field when None
        assert!(!json.contains("\"id\""));

        // Test deserialization
        let deserialized: StoreConfigRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.config_type, "pipeline");
        assert_eq!(deserialized.id, None);
    }

    #[test]
    fn test_store_config_request_type_field_rename() {
        // Test that the "type" field is correctly serialized despite the field being named config_type
        let json = r#"{"type":"transform","config":"[transform]\nname = \"test\"\n"}"#;
        let request: StoreConfigRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.config_type, "transform");
        assert_eq!(request.id, None);
    }

    #[test]
    fn test_store_config_response() {
        let json = r#"{
            "success": true,
            "message": "Gateway configuration updated successfully",
            "data": {
                "id": "01k9npa4tatmwddk66xxpcr2r0",
                "type": "gateway",
                "action": "updated"
            }
        }"#;

        let response: StoreConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.success, true);
        assert!(response.message.contains("updated successfully"));
        assert_eq!(response.data.id, "01k9npa4tatmwddk66xxpcr2r0");
        assert_eq!(response.data.model_type, "gateway");
        assert_eq!(response.data.action, "updated");
    }

    // ========================================================================================
    // RESOURCE REFERENCE TESTS
    // ========================================================================================

    #[test]
    fn test_resource_reference_bare_name() {
        let r = ResourceReference::parse("my_ingress").unwrap();
        assert_eq!(r.provider, "local");
        assert_eq!(r.team, None);
        assert_eq!(r.resource_type, None);
        assert_eq!(r.lookup, LookupBy::Name("my_ingress".to_string()));
        assert!(r.is_local());
    }

    #[test]
    fn test_resource_reference_local_name() {
        let r = ResourceReference::parse("local.name.fhir_api").unwrap();
        assert_eq!(r.provider, "local");
        assert_eq!(r.team, None);
        assert_eq!(r.resource_type, None);
        assert_eq!(r.lookup, LookupBy::Name("fhir_api".to_string()));
        assert!(r.is_local());
    }

    #[test]
    fn test_resource_reference_provider_id() {
        let r = ResourceReference::parse("runbeam.id.01JGXYZ123ABC").unwrap();
        assert_eq!(r.provider, "runbeam");
        assert_eq!(r.team, None);
        assert_eq!(r.resource_type, None);
        assert_eq!(r.lookup, LookupBy::Id("01JGXYZ123ABC".to_string()));
        assert!(!r.is_local());
    }

    #[test]
    fn test_resource_reference_team_id() {
        let r = ResourceReference::parse("runbeam.acme.id.01JGXYZ123ABC").unwrap();
        assert_eq!(r.provider, "runbeam");
        assert_eq!(r.team, Some("acme".to_string()));
        assert_eq!(r.resource_type, None);
        assert_eq!(r.lookup, LookupBy::Id("01JGXYZ123ABC".to_string()));
    }

    #[test]
    fn test_resource_reference_full_path_name() {
        let r = ResourceReference::parse("runbeam.acme_health.ingress.name.patient_api").unwrap();
        assert_eq!(r.provider, "runbeam");
        assert_eq!(r.team, Some("acme_health".to_string()));
        assert_eq!(r.resource_type, Some(ResourceType::Ingress));
        assert_eq!(r.lookup, LookupBy::Name("patient_api".to_string()));
    }

    #[test]
    fn test_resource_reference_full_path_id() {
        let r = ResourceReference::parse("runbeam.partner_lab.egress.id.01JGXYZ").unwrap();
        assert_eq!(r.provider, "runbeam");
        assert_eq!(r.team, Some("partner_lab".to_string()));
        assert_eq!(r.resource_type, Some(ResourceType::Egress));
        assert_eq!(r.lookup, LookupBy::Id("01JGXYZ".to_string()));
    }

    #[test]
    fn test_resource_reference_all_types() {
        assert!(ResourceReference::parse("runbeam.t.ingress.name.x").unwrap().resource_type == Some(ResourceType::Ingress));
        assert!(ResourceReference::parse("runbeam.t.egress.name.x").unwrap().resource_type == Some(ResourceType::Egress));
        assert!(ResourceReference::parse("runbeam.t.pipeline.name.x").unwrap().resource_type == Some(ResourceType::Pipeline));
        assert!(ResourceReference::parse("runbeam.t.endpoint.name.x").unwrap().resource_type == Some(ResourceType::Endpoint));
        assert!(ResourceReference::parse("runbeam.t.backend.name.x").unwrap().resource_type == Some(ResourceType::Backend));
        assert!(ResourceReference::parse("runbeam.t.mesh.name.x").unwrap().resource_type == Some(ResourceType::Mesh));
    }

    #[test]
    fn test_resource_reference_invalid_format() {
        assert!(ResourceReference::parse("runbeam.team.invalid.name.x").is_err());
        assert!(ResourceReference::parse("a.b").is_err());
        assert!(ResourceReference::parse("a.b.c.d.e.f").is_err());
    }

    #[test]
    fn test_resource_reference_to_string() {
        // Bare name shorthand
        let r = ResourceReference::parse("my_ingress").unwrap();
        assert_eq!(r.to_reference_string(), "my_ingress");

        // Full path
        let r = ResourceReference::parse("runbeam.acme.ingress.name.patient_api").unwrap();
        assert_eq!(r.to_reference_string(), "runbeam.acme.ingress.name.patient_api");

        // Provider ID
        let r = ResourceReference::parse("runbeam.id.01JGXYZ").unwrap();
        assert_eq!(r.to_reference_string(), "runbeam.id.01JGXYZ");
    }

    #[test]
    fn test_provider_config_default() {
        let config = ProviderConfig::default();
        assert_eq!(config.api, None);
        assert_eq!(config.enabled, true);
        assert_eq!(config.poll_interval_secs, 30);
    }

    #[test]
    fn test_provider_config_serde() {
        let json = r#"{"api":"https://app.runbeam.io","enabled":true,"poll_interval_secs":60}"#;
        let config: ProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.api, Some("https://app.runbeam.io".to_string()));
        assert_eq!(config.enabled, true);
        assert_eq!(config.poll_interval_secs, 60);
    }
}
