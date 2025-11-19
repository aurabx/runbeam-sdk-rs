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
}
