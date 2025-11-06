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
}

impl fmt::Display for RunbeamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunbeamError::JwtValidation(msg) => write!(f, "JWT validation failed: {}", msg),
            RunbeamError::Api(err) => write!(f, "API error: {}", err),
            RunbeamError::Storage(err) => write!(f, "Storage error: {}", err),
            RunbeamError::Config(msg) => write!(f, "Configuration error: {}", msg),
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

/// Config change summary from list endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub id: String,
    pub status: String,
    #[serde(rename = "type")]
    pub change_type: String,
    pub gateway_id: String,
    #[serde(default)]
    pub pipeline_id: Option<String>,
    pub created_at: String,
}

/// Detailed config change with full content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChangeDetail {
    pub id: String,
    pub status: String,
    #[serde(rename = "type")]
    pub change_type: String,
    pub gateway_id: String,
    #[serde(default)]
    pub pipeline_id: Option<String>,
    pub toml_config: String,
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

/// Response after acknowledging/reporting config change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChangeAck {
    pub success: bool,
    #[serde(default)]
    pub message: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfigResponse {
    /// HTTP status code (200 on success)
    pub status: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_change_deserialization() {
        let json = r#"{
            "id": "01k8vdq9wrcrezzbdpbjwsfwnz",
            "status": "queued",
            "type": "gateway",
            "gateway_id": "01k8ek6h9aahhnrv3benret1nn",
            "pipeline_id": null,
            "created_at": "2025-10-30T20:42:36.000000Z"
        }"#;

        let change: ConfigChange = serde_json::from_str(json).unwrap();
        assert_eq!(change.id, "01k8vdq9wrcrezzbdpbjwsfwnz");
        assert_eq!(change.status, "queued");
        assert_eq!(change.change_type, "gateway");
        assert_eq!(change.gateway_id, "01k8ek6h9aahhnrv3benret1nn");
        assert_eq!(change.pipeline_id, None);
        assert_eq!(change.created_at, "2025-10-30T20:42:36.000000Z");
    }

    #[test]
    fn test_config_change_with_pipeline_deserialization() {
        let json = r#"{
            "id": "01k8xyz123456789",
            "status": "applied",
            "type": "pipeline",
            "gateway_id": "01k8ek6h9aahhnrv3benret1nn",
            "pipeline_id": "01k8pipeline123",
            "created_at": "2025-10-30T21:00:00.000000Z"
        }"#;

        let change: ConfigChange = serde_json::from_str(json).unwrap();
        assert_eq!(change.change_type, "pipeline");
        assert_eq!(change.pipeline_id, Some("01k8pipeline123".to_string()));
    }

    #[test]
    fn test_config_change_detail_deserialization() {
        let json = r#"{
            "id": "01k8vdq9wrcrezzbdpbjwsfwnz",
            "status": "queued",
            "type": "gateway",
            "gateway_id": "01k8ek6h9aahhnrv3benret1nn",
            "pipeline_id": null,
            "toml_config": "[proxy]\nid = \"test\"\n",
            "metadata": {"gateway_name": "test-gateway"},
            "created_at": "2025-10-30T20:42:36.000000Z",
            "acknowledged_at": null,
            "applied_at": null,
            "failed_at": null,
            "error_message": null,
            "error_details": null
        }"#;

        let detail: ConfigChangeDetail = serde_json::from_str(json).unwrap();
        assert_eq!(detail.id, "01k8vdq9wrcrezzbdpbjwsfwnz");
        assert_eq!(detail.status, "queued");
        assert_eq!(detail.change_type, "gateway");
        assert_eq!(detail.toml_config, "[proxy]\nid = \"test\"\n");
        assert!(detail.metadata.is_some());
        assert!(detail.acknowledged_at.is_none());
        assert!(detail.applied_at.is_none());
        assert!(detail.failed_at.is_none());
    }

    #[test]
    fn test_config_change_detail_with_timestamps() {
        let json = r#"{
            "id": "01k8vdq9wrcrezzbdpbjwsfwnz",
            "status": "applied",
            "type": "gateway",
            "gateway_id": "01k8ek6h9aahhnrv3benret1nn",
            "pipeline_id": null,
            "toml_config": "[proxy]\nid = \"test\"\n",
            "metadata": null,
            "created_at": "2025-10-30T20:42:36.000000Z",
            "acknowledged_at": "2025-10-30T20:42:40.000000Z",
            "applied_at": "2025-10-30T20:42:45.000000Z",
            "failed_at": null,
            "error_message": null,
            "error_details": null
        }"#;

        let detail: ConfigChangeDetail = serde_json::from_str(json).unwrap();
        assert_eq!(detail.status, "applied");
        assert_eq!(
            detail.acknowledged_at,
            Some("2025-10-30T20:42:40.000000Z".to_string())
        );
        assert_eq!(
            detail.applied_at,
            Some("2025-10-30T20:42:45.000000Z".to_string())
        );
        assert!(detail.failed_at.is_none());
    }

    #[test]
    fn test_config_change_detail_with_error() {
        let json = r#"{
            "id": "01k8vdq9wrcrezzbdpbjwsfwnz",
            "status": "failed",
            "type": "gateway",
            "gateway_id": "01k8ek6h9aahhnrv3benret1nn",
            "pipeline_id": null,
            "toml_config": "[proxy]\nid = \"test\"\n",
            "metadata": null,
            "created_at": "2025-10-30T20:42:36.000000Z",
            "acknowledged_at": "2025-10-30T20:42:40.000000Z",
            "applied_at": null,
            "failed_at": "2025-10-30T20:42:45.000000Z",
            "error_message": "Invalid TOML syntax",
            "error_details": {"line": 5, "column": 10}
        }"#;

        let detail: ConfigChangeDetail = serde_json::from_str(json).unwrap();
        assert_eq!(detail.status, "failed");
        assert_eq!(
            detail.failed_at,
            Some("2025-10-30T20:42:45.000000Z".to_string())
        );
        assert_eq!(
            detail.error_message,
            Some("Invalid TOML syntax".to_string())
        );
        assert!(detail.error_details.is_some());
        assert!(detail.applied_at.is_none());
    }

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
        let response = StoreConfigResponse { status: 200 };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":200"));

        // Test deserialization
        let deserialized: StoreConfigResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, 200);
    }
}
