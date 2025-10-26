//! Runbeam SDK
//!
//! A Rust library for integrating with the Runbeam Cloud API.
//!
//! This SDK provides:
//! - JWT token validation with RS256 and JWKS caching
//! - Runbeam Cloud API client for gateway authorization
//! - Secure token storage via OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager)
//! - Type definitions for API requests/responses and error handling
//!
//! # Example
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

pub mod runbeam_api;
pub mod storage;

// Re-export commonly used types and functions
pub use runbeam_api::{
    client::RunbeamClient,
    jwt::{validate_jwt_token, extract_bearer_token, JwtClaims},
    resources::{
        Gateway, Service, Endpoint, Backend, Pipeline, Middleware, Transform,
        Policy, Network, Authentication, GatewayConfiguration,
        PaginatedResponse, ResourceResponse, PaginationLinks, PaginationMeta,
    },
    token_storage::{save_token, load_token, clear_token, MachineToken},
    types::{ApiError, RunbeamError, AuthorizeResponse, GatewayInfo, UserInfo, TeamInfo},
};
