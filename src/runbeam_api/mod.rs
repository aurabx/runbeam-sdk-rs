/// Runbeam Cloud API integration module
///
/// This module provides functionality for integrating Harmony with Runbeam Cloud,
/// including JWT validation, API client, and token storage.
///
/// ## Authentication Methods
///
/// This SDK supports two authentication methods:
///
/// ### JWT Token Authentication (Legacy)
///
/// JWT tokens with RS256 signature validation using JWKS endpoint discovery.
/// The SDK performs local validation of JWT tokens before passing them to the API.
///
/// ### Laravel Sanctum API Token Authentication
///
/// Laravel Sanctum API tokens (format: `{id}|{token}`) are passed directly to the
/// server for validation without local verification. This method is recommended for
/// simpler authentication flows where local token validation is not required.
///
/// ## Authorization Flow (JWT)
///
/// 1. CLI calls Harmony Management API with user JWT token
/// 2. Harmony validates JWT locally (verifies signature and extracts claims)
/// 3. Harmony calls Runbeam Cloud API with user JWT to exchange for machine token
/// 4. Runbeam Cloud issues machine-scoped token (30-day expiry)
/// 5. Harmony stores machine token locally for future API calls
///
/// ## Authorization Flow (Sanctum)
///
/// 1. CLI calls Harmony Management API with user Sanctum API token
/// 2. Harmony passes token directly to Runbeam Cloud API (no local validation)
/// 3. Runbeam Cloud validates token and issues machine-scoped token (30-day expiry)
/// 4. Harmony stores machine token locally for future API calls
///
/// All API methods accept both JWT and Sanctum tokens interchangeably.
pub mod client;
pub mod jwt;
pub mod resources;
pub mod token_storage;
pub mod types;

pub use client::RunbeamClient;
pub use jwt::{validate_jwt_token, JwtClaims};
pub use resources::*;
pub use token_storage::{clear_token, load_token, save_token, save_token_with_key, MachineToken};
pub use types::{
    ApiError, RunbeamError, StoreConfigRequest, StoreConfigResponse,
};
