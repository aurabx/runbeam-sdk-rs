//! Runbeam SDK
//!
//! A Rust library for integrating with the Runbeam Cloud API.
//!
//! This SDK provides:
//! - JWT token validation with RS256 and JWKS caching
//! - Laravel Sanctum API token support
//! - Runbeam Cloud API client for gateway authorization
//! - Secure token storage via OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager)
//! - Type definitions for API requests/responses and error handling
//!
//! # Authentication Methods
//!
//! The SDK supports two authentication methods:
//!
//! ## JWT Tokens (Legacy)
//!
//! JWT tokens with RS256 signature validation. The SDK performs local validation
//! using public keys fetched from JWKS endpoints. Use this method when you need
//! local token validation and claim extraction.
//!
//! ## Laravel Sanctum API Tokens
//!
//! Laravel Sanctum API tokens (format: `{id}|{token}`) are passed directly to the
//! server for validation. Use this method for simpler authentication flows where
//! local token validation is not required.
//!
//! # Example (JWT Authentication)
//!
//! ```no_run
//! use runbeam_sdk::{
//!     RunbeamClient,
//!     validate_jwt_token,
//!     save_token,
//!     load_token,
//!     MachineToken,
//!     storage::{KeyringStorage, StorageBackend},
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Validate a user JWT token
//! let claims = validate_jwt_token("eyJhbGci...", 24).await?;
//!
//! // Create API client from JWT issuer
//! let client = RunbeamClient::new(claims.api_base_url());
//!
//! // Authorize a gateway and get machine token
//! let response = client.authorize_gateway(
//!     "eyJhbGci...",
//!     "gateway-123",
//!     None,
//!     None
//! ).await?;
//!
//! // Save machine token securely
//! let storage = KeyringStorage::new("runbeam");
//! let machine_token = MachineToken::new(
//!     response.machine_token,
//!     response.expires_at,
//!     response.gateway.id,
//!     response.gateway.code,
//!     response.abilities,
//! );
//! save_token(&storage, &machine_token).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Example (Sanctum Authentication)
//!
//! ```no_run
//! use runbeam_sdk::{
//!     RunbeamClient,
//!     save_token,
//!     MachineToken,
//!     storage::{KeyringStorage, StorageBackend},
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create API client with base URL
//! let client = RunbeamClient::new("https://api.runbeam.io");
//!
//! // Authorize a gateway with Sanctum token (no validation needed)
//! let response = client.authorize_gateway(
//!     "1|abc123def456...",  // Sanctum API token
//!     "gateway-123",
//!     None,
//!     None
//! ).await?;
//!
//! // Save machine token securely
//! let storage = KeyringStorage::new("runbeam");
//! let machine_token = MachineToken::new(
//!     response.machine_token,
//!     response.expires_at,
//!     response.gateway.id,
//!     response.gateway.code,
//!     response.abilities,
//! );
//! save_token(&storage, &machine_token).await?;
//! # Ok(())
//! # }
//! ```

pub mod runbeam_api;
pub mod storage;

// Re-export commonly used types and functions
pub use runbeam_api::{
    client::RunbeamClient,
    jwt::{extract_bearer_token, validate_jwt_token, JwtClaims},
    resources::{
        Authentication, Backend, Endpoint, Gateway, GatewayConfiguration, Middleware, Network,
        PaginatedResponse, PaginationLinks, PaginationMeta, Pipeline, Policy, ResourceResponse,
        Service, Transform,
    },
    token_storage::{clear_token, load_token, save_token, MachineToken},
    types::{ApiError, AuthorizeResponse, GatewayInfo, RunbeamError, TeamInfo, UserInfo},
};
