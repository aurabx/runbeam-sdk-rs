use crate::runbeam_api::types::{
    ApiError, AuthorizeResponse, RunbeamError, StoreConfigRequest, StoreConfigResponse,
};
use serde::Serialize;

/// HTTP client for Runbeam Cloud API
///
/// This client handles all communication with the Runbeam Cloud control plane,
/// including gateway authorization and future component loading.
#[derive(Debug, Clone)]
pub struct RunbeamClient {
    /// Base URL for the Runbeam Cloud API (from JWT iss claim)
    base_url: String,
    /// HTTP client for making requests
    client: reqwest::Client,
}

/// Request payload for gateway authorization
#[derive(Debug, Serialize)]
struct AuthorizeRequest {
    /// JWT token from the user (will be sent in body per Laravel API spec)
    token: String,
    /// Gateway code (instance ID)
    gateway_code: String,
    /// Optional machine public key for secure communication
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_public_key: Option<String>,
    /// Optional metadata about the gateway (array of strings per v1.1 API spec)
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Vec<String>>,
}

impl RunbeamClient {
    /// Create a new Runbeam Cloud API client
    ///
    /// # Arguments
    ///
    /// * `base_url` - The Runbeam Cloud API base URL (extracted from JWT iss claim)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// ```
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into();
        tracing::debug!("Creating RunbeamClient with base URL: {}", base_url);

        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Authorize a gateway and obtain a machine-scoped token
    ///
    /// This method exchanges a user authentication token (either JWT or Laravel Sanctum)
    /// for a machine-scoped token that the gateway can use for autonomous API access.
    /// The machine token has a 30-day expiry (configured server-side).
    ///
    /// # Authentication
    ///
    /// This method accepts both JWT tokens and Laravel Sanctum API tokens:
    /// - **JWT tokens**: Validated locally with RS256 signature verification (legacy behavior)
    /// - **Sanctum tokens**: Passed directly to server for validation (format: `{id}|{token}`)
    ///
    /// The token is passed to the Runbeam Cloud API in both the Authorization header
    /// and request body, where final validation and authorization occurs.
    ///
    /// # Arguments
    ///
    /// * `user_token` - The user's JWT or Sanctum API token from CLI authentication
    /// * `gateway_code` - The gateway instance ID
    /// * `machine_public_key` - Optional public key for secure communication
    /// * `metadata` - Optional metadata about the gateway (array of strings)
    ///
    /// # Returns
    ///
    /// Returns `Ok(AuthorizeResponse)` with machine token and gateway details,
    /// or `Err(RunbeamError)` if authorization fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    ///
    /// // Using JWT token
    /// let response = client.authorize_gateway(
    ///     "eyJhbGci...",
    ///     "gateway-123",
    ///     None,
    ///     None
    /// ).await?;
    ///
    /// // Using Sanctum token
    /// let response = client.authorize_gateway(
    ///     "1|abc123def456...",
    ///     "gateway-123",
    ///     None,
    ///     None
    /// ).await?;
    ///
    /// println!("Machine token: {}", response.machine_token);
    /// println!("Expires at: {}", response.expires_at);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn authorize_gateway(
        &self,
        user_token: impl Into<String>,
        gateway_code: impl Into<String>,
        machine_public_key: Option<String>,
        metadata: Option<Vec<String>>,
    ) -> Result<AuthorizeResponse, RunbeamError> {
        let user_token = user_token.into();
        let gateway_code = gateway_code.into();

        tracing::info!(
            "Authorizing gateway with Runbeam Cloud: gateway_code={}",
            gateway_code
        );

        // Construct the authorization endpoint URL
        let url = format!("{}/harmony/authorize", self.base_url);

        // Build request payload
        let payload = AuthorizeRequest {
            token: user_token.clone(),
            gateway_code: gateway_code.clone(),
            machine_public_key,
            metadata,
        };

        tracing::debug!("Sending authorization request to: {}", url);

        // Make the request
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", user_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to send authorization request: {}", e);
                ApiError::from(e)
            })?;

        let status = response.status();
        tracing::debug!("Received response with status: {}", status);

        // Handle error responses
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            tracing::error!(
                "Authorization failed: HTTP {} - {}",
                status.as_u16(),
                error_body
            );

            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        // Parse successful response
        let auth_response: AuthorizeResponse = response.json().await.map_err(|e| {
            tracing::error!("Failed to parse authorization response: {}", e);
            ApiError::Parse(format!("Failed to parse response JSON: {}", e))
        })?;

        tracing::info!(
            "Gateway authorized successfully: gateway_id={}, expires_at={}",
            auth_response.gateway.id,
            auth_response.expires_at
        );

        tracing::debug!(
            "Machine token length: {}",
            auth_response.machine_token.len()
        );
        tracing::debug!("Gateway abilities: {:?}", auth_response.abilities);

        Ok(auth_response)
    }

    /// Get the base URL for this client
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// List all pending configuration changes (admin/user view)
    ///
    /// This endpoint lists ALL changes across the system and is intended for
    /// administrative and user interfaces. Gateway instances should use
    /// `list_changes_for_gateway` instead.
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - Authentication token (JWT, Sanctum, or machine token)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// let changes = client.list_changes("user_jwt_or_sanctum_token").await?;
    /// println!("Found {} changes across all gateways", changes.data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_changes(
        &self,
        token: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::PaginatedResponse<crate::runbeam_api::resources::Change>,
        RunbeamError,
    > {
        let url = format!("{}/harmony/changes", self.base_url);

        tracing::debug!("Listing all changes from: {}", url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("Failed to list changes: HTTP {} - {}", status, error_body);
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse changes response: {}", e);
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// List pending configuration changes for a specific gateway
    ///
    /// This endpoint returns changes specific to a gateway and is what Harmony
    /// Proxy instances should call when polling for configuration updates
    /// (typically every 30 seconds).
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - Authentication token (JWT, Sanctum, or machine token)
    /// * `gateway_id` - The gateway ID to list changes for
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// let changes = client.list_changes_for_gateway(
    ///     "machine_token_abc123",
    ///     "01JBXXXXXXXXXXXXXXXXXXXXXXXXXX"
    /// ).await?;
    /// println!("Found {} pending changes for this gateway", changes.data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_changes_for_gateway(
        &self,
        token: impl Into<String>,
        gateway_id: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::PaginatedResponse<crate::runbeam_api::resources::Change>,
        RunbeamError,
    > {
        let gateway_id = gateway_id.into();
        let url = format!("{}/harmony/changes/{}", self.base_url, gateway_id);

        tracing::debug!("Listing changes for gateway {} from: {}", gateway_id, url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!(
                "Failed to list changes for gateway {}: HTTP {} - {}",
                gateway_id,
                status,
                error_body
            );
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        let response_text = response.text().await.map_err(|e| {
            tracing::error!("Failed to read response body: {}", e);
            RunbeamError::Api(ApiError::Parse(format!("Failed to read response: {}", e)))
        })?;

        serde_json::from_str(&response_text).map_err(|e| {
            tracing::error!("Failed to parse changes response: {} - Response body: {}", e, response_text);
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {} - Body: {}", e, response_text)))
        })
    }

    /// Get detailed information about a specific configuration change
    ///
    /// Retrieve full details of a change including TOML configuration content,
    /// metadata, and status information.
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - Authentication token (JWT, Sanctum, or machine token)
    /// * `change_id` - The change ID to retrieve
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// let change = client.get_change("machine_token_abc123", "change-123").await?;
    /// 
    /// if let Some(toml_config) = &change.data.toml_config {
    ///     println!("TOML config:\n{}", toml_config);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_change(
        &self,
        token: impl Into<String>,
        change_id: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::ResourceResponse<crate::runbeam_api::resources::Change>,
        RunbeamError,
    > {
        let change_id = change_id.into();
        let url = format!("{}/harmony/change/{}", self.base_url, change_id);

        tracing::debug!("Getting change {} from: {}", change_id, url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("Failed to get change: HTTP {} - {}", status, error_body);
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse change response: {}", e);
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// List all gateways for the authenticated team
    ///
    /// Returns a paginated list of gateways.
    ///
    /// # Authentication
    ///
    /// Accepts either JWT tokens or Laravel Sanctum API tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT or Sanctum API token for authentication
    pub async fn list_gateways(
        &self,
        token: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::PaginatedResponse<crate::runbeam_api::resources::Gateway>,
        RunbeamError,
    > {
        let url = format!("{}/gateways", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// Get a specific gateway by ID or code
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT, Sanctum API token, or machine token for authentication
    /// * `gateway_id` - The gateway ID or code
    pub async fn get_gateway(
        &self,
        token: impl Into<String>,
        gateway_id: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::ResourceResponse<crate::runbeam_api::resources::Gateway>,
        RunbeamError,
    > {
        let url = format!("{}/gateways/{}", self.base_url, gateway_id.into());

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// List all services for the authenticated team
    ///
    /// Returns a paginated list of services across all gateways.
    ///
    /// # Authentication
    ///
    /// Accepts either JWT tokens or Laravel Sanctum API tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT or Sanctum API token for authentication
    pub async fn list_services(
        &self,
        token: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::PaginatedResponse<crate::runbeam_api::resources::Service>,
        RunbeamError,
    > {
        let url = format!("{}/api/services", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// Get a specific service by ID
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT, Sanctum API token, or machine token for authentication
    /// * `service_id` - The service ID
    pub async fn get_service(
        &self,
        token: impl Into<String>,
        service_id: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::ResourceResponse<crate::runbeam_api::resources::Service>,
        RunbeamError,
    > {
        let url = format!("{}/api/services/{}", self.base_url, service_id.into());

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// List all endpoints for the authenticated team
    ///
    /// # Authentication
    ///
    /// Accepts either JWT tokens or Laravel Sanctum API tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT or Sanctum API token for authentication
    pub async fn list_endpoints(
        &self,
        token: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::PaginatedResponse<crate::runbeam_api::resources::Endpoint>,
        RunbeamError,
    > {
        let url = format!("{}/api/endpoints", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// List all backends for the authenticated team
    ///
    /// # Authentication
    ///
    /// Accepts either JWT tokens or Laravel Sanctum API tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT or Sanctum API token for authentication
    pub async fn list_backends(
        &self,
        token: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::PaginatedResponse<crate::runbeam_api::resources::Backend>,
        RunbeamError,
    > {
        let url = format!("{}/api/backends", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// List all pipelines for the authenticated team
    ///
    /// # Authentication
    ///
    /// Accepts either JWT tokens or Laravel Sanctum API tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT or Sanctum API token for authentication
    pub async fn list_pipelines(
        &self,
        token: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::PaginatedResponse<crate::runbeam_api::resources::Pipeline>,
        RunbeamError,
    > {
        let url = format!("{}/api/pipelines", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// Get a specific transform by ID
    ///
    /// Retrieve transform details including the JOLT specification stored in
    /// the `options.instructions` field. Used by Harmony Proxy to download
    /// transform specifications when applying cloud-sourced pipeline configurations.
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT, Sanctum API token, or machine token for authentication
    /// * `transform_id` - The transform ID (ULID format)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// let transform = client.get_transform("machine_token", "01k81xczrw551e1qj9rgrf0319").await?;
    ///
    /// // Extract JOLT specification
    /// if let Some(options) = &transform.data.options {
    ///     if let Some(instructions) = &options.instructions {
    ///         println!("JOLT spec: {}", instructions);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_transform(
        &self,
        token: impl Into<String>,
        transform_id: impl Into<String>,
    ) -> Result<
        crate::runbeam_api::resources::ResourceResponse<crate::runbeam_api::resources::Transform>,
        RunbeamError,
    > {
        let transform_id = transform_id.into();
        let url = format!("{}/api/transforms/{}", self.base_url, transform_id);

        tracing::debug!("Getting transform {} from: {}", transform_id, url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("Failed to get transform: HTTP {} - {}", status, error_body);
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse transform response: {}", e);
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    // ========== Change Management API Methods (v1.2) ==========

    /// Get the base URL for the changes API
    ///
    /// Service discovery endpoint that returns the base URL for the changes API.
    /// Harmony Proxy instances can call this to discover the API location dynamically.
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - Authentication token (JWT, Sanctum, or machine token)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// let response = client.get_base_url("machine_token_abc123").await?;
    /// println!("Changes API base URL: {}", response.base_url);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_base_url(
        &self,
        token: impl Into<String>,
    ) -> Result<crate::runbeam_api::resources::BaseUrlResponse, RunbeamError> {
        let token = token.into();
        // Try both with and without "/api" to support configs that provide either
        let candidates = [
            format!("{}/api/harmony/base-url", self.base_url),
            format!("{}/harmony/base-url", self.base_url),
        ];

        let mut last_err: Option<RunbeamError> = None;
        for url in candidates {
            tracing::debug!("Getting base URL from: {}", url);
            let resp = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await;

            let response = match resp {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(ApiError::from(e).into());
                    continue;
                }
            };

            if !response.status().is_success() {
                let status = response.status();
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                tracing::warn!(
                    "Base URL discovery attempt failed: HTTP {} - {} (url: {})",
                    status,
                    error_body,
                    url
                );
                last_err = Some(RunbeamError::Api(ApiError::Http {
                    status: status.as_u16(),
                    message: error_body,
                }));
                continue;
            }

            let parsed = response.json().await.map_err(|e| {
                tracing::warn!("Failed to parse base URL response from {}: {}", url, e);
                RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
            });
            if parsed.is_ok() {
                return parsed;
            } else {
                last_err = Some(parsed.err().unwrap());
            }
        }

        Err(last_err.unwrap_or_else(|| RunbeamError::Api(ApiError::Request(
            "Base URL discovery failed for all candidates".to_string(),
        ))))
    }

    /// Discover and return a new client with the resolved base URL
    pub async fn discover_base_url(
        &self,
        token: impl Into<String>,
    ) -> Result<Self, RunbeamError> {
        let resp = self.get_base_url(token).await?;
        let discovered = resp
            .full_url
            .or_else(|| Some(resp.base_url))
            .unwrap();
        tracing::info!("Discovered Runbeam API base URL: {}", discovered);
        Ok(Self::new(discovered))
    }


    /// Acknowledge receipt of multiple configuration changes
    ///
    /// Bulk acknowledge that changes have been received. Gateways should call this
    /// immediately after retrieving changes to update their status from "pending"
    /// to "acknowledged".
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - Authentication token (JWT, Sanctum, or machine token)
    /// * `change_ids` - Vector of change IDs to acknowledge
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// let change_ids = vec!["change-1".to_string(), "change-2".to_string()];
    /// client.acknowledge_changes("machine_token_abc123", change_ids).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn acknowledge_changes(
        &self,
        token: impl Into<String>,
        change_ids: Vec<String>,
    ) -> Result<crate::runbeam_api::resources::AcknowledgeChangesResponse, RunbeamError> {
        let url = format!("{}/harmony/changes/acknowledge", self.base_url);

        tracing::info!("Acknowledging {} changes", change_ids.len());
        tracing::debug!("Change IDs: {:?}", change_ids);

        let payload = crate::runbeam_api::resources::AcknowledgeChangesRequest { change_ids };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!(
                "Failed to acknowledge changes: HTTP {} - {}",
                status,
                error_body
            );
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse acknowledge response: {}", e);
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// Mark a configuration change as successfully applied
    ///
    /// Report that a change has been successfully applied to the gateway configuration.
    /// This updates the change status to "applied".
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - Authentication token (JWT, Sanctum, or machine token)
    /// * `change_id` - The change ID that was applied
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// client.mark_change_applied("machine_token_abc123", "change-123").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn mark_change_applied(
        &self,
        token: impl Into<String>,
        change_id: impl Into<String>,
    ) -> Result<crate::runbeam_api::resources::ChangeAppliedResponse, RunbeamError> {
        let change_id = change_id.into();
        let url = format!("{}/harmony/changes/{}/applied", self.base_url, change_id);

        tracing::info!("Marking change {} as applied", change_id);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!(
                "Failed to mark change as applied: HTTP {} - {}",
                status,
                error_body
            );
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse applied response: {}", e);
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// Mark a configuration change as failed with error details
    ///
    /// Report that a change failed to apply, including error details for troubleshooting.
    /// This updates the change status to "failed" and stores the error information.
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - Authentication token (JWT, Sanctum, or machine token)
    /// * `change_id` - The change ID that failed
    /// * `error` - Error message describing what went wrong
    /// * `details` - Optional additional error details
    ///
    /// # Example
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// client.mark_change_failed(
    ///     "machine_token_abc123",
    ///     "change-123",
    ///     "Failed to parse configuration".to_string(),
    ///     Some(vec!["Invalid JSON syntax at line 42".to_string()])
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn mark_change_failed(
        &self,
        token: impl Into<String>,
        change_id: impl Into<String>,
        error: String,
        details: Option<Vec<String>>,
    ) -> Result<crate::runbeam_api::resources::ChangeFailedResponse, RunbeamError> {
        let change_id = change_id.into();
        let url = format!("{}/harmony/changes/{}/failed", self.base_url, change_id);

        tracing::warn!("Marking change {} as failed: {}", change_id, error);
        if let Some(ref details) = details {
            tracing::debug!("Failure details: {:?}", details);
        }

        let payload = crate::runbeam_api::resources::ChangeFailedRequest { error, details };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(ApiError::from)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!(
                "Failed to mark change as failed: HTTP {} - {}",
                status,
                error_body
            );
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse failed response: {}", e);
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// Store or update Harmony configuration in Runbeam Cloud
    ///
    /// This method sends TOML configuration from Harmony instances back to Runbeam Cloud
    /// where it is parsed and stored as database models. This is the inverse of the TOML
    /// generation/download API - it enables Harmony to push configuration updates to the cloud.
    ///
    /// # Authentication
    ///
    /// Accepts JWT tokens, Sanctum API tokens, or machine tokens. The token is passed
    /// to the server for validation without local verification.
    ///
    /// # Arguments
    ///
    /// * `token` - Authentication token (JWT, Sanctum, or machine token)
    /// * `config_type` - Type of configuration ("gateway", "pipeline", or "transform")
    /// * `id` - Optional resource ID for updates (omit for new resources)
    /// * `config` - TOML configuration content as a string
    ///
    /// # Returns
    ///
    /// Returns `Ok(StoreConfigResponse)` with status 200 on success, or `Err(RunbeamError)`
    /// if the operation fails (404 for not found, 422 for validation errors).
    ///
    /// # Examples
    ///
    /// ## Creating a new gateway configuration
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// let toml_config = r#"
    /// [proxy]
    /// id = "gateway-123"
    /// name = "Production Gateway"
    /// "#;
    ///
    /// let response = client.store_config(
    ///     "machine_token_abc123",
    ///     "gateway",
    ///     None,  // No ID = create new
    ///     toml_config
    /// ).await?;
    ///
    /// println!("Configuration stored successfully: {}", response.status);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Updating an existing pipeline configuration
    ///
    /// ```no_run
    /// use runbeam_sdk::RunbeamClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RunbeamClient::new("http://runbeam.lndo.site");
    /// let toml_config = r#"
    /// [pipeline]
    /// name = "Updated Pipeline"
    /// description = "Modified configuration"
    /// "#;
    ///
    /// let response = client.store_config(
    ///     "machine_token_abc123",
    ///     "pipeline",
    ///     Some("01k8pipeline123".to_string()),  // With ID = update existing
    ///     toml_config
    /// ).await?;
    ///
    /// println!("Configuration updated successfully: {}", response.status);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn store_config(
        &self,
        token: impl Into<String>,
        config_type: impl Into<String>,
        id: Option<String>,
        config: impl Into<String>,
    ) -> Result<StoreConfigResponse, RunbeamError> {
        let config_type = config_type.into();
        let config = config.into();
        let url = format!("{}/harmony/update", self.base_url);

        tracing::info!(
            "Storing {} configuration to Runbeam Cloud (id: {:?})",
            config_type,
            id
        );
        tracing::debug!("Configuration length: {} bytes", config.len());

        let payload = StoreConfigRequest {
            config_type: config_type.clone(),
            id: id.clone(),
            config,
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.into()))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to send store config request: {}", e);
                ApiError::from(e)
            })?;

        let status = response.status();
        tracing::debug!("Received response with status: {}", status);

        // Handle error responses
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            tracing::error!(
                "Store config failed: HTTP {} - {}",
                status.as_u16(),
                error_body
            );

            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        // Parse successful response (UpdateSuccessResource format)
        let response_data = response.json::<StoreConfigResponse>().await.map_err(|e| {
            tracing::error!("Failed to parse store config response: {}", e);
            ApiError::Parse(format!("Failed to parse response: {}", e))
        })?;

        tracing::info!(
            "Configuration stored successfully: type={}, id={:?}, action={}",
            config_type,
            id,
            response_data.data.model.action
        );

        Ok(response_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = RunbeamClient::new("http://example.com");
        assert_eq!(client.base_url(), "http://example.com");
    }

    #[test]
    fn test_client_creation_with_string() {
        let base_url = String::from("http://example.com");
        let client = RunbeamClient::new(base_url);
        assert_eq!(client.base_url(), "http://example.com");
    }

    #[test]
    fn test_authorize_request_serialization() {
        let request = AuthorizeRequest {
            token: "test_token".to_string(),
            gateway_code: "gw123".to_string(),
            machine_public_key: Some("pubkey123".to_string()),
            metadata: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"token\":\"test_token\""));
        assert!(json.contains("\"gateway_code\":\"gw123\""));
        assert!(json.contains("\"machine_public_key\":\"pubkey123\""));
    }

    #[test]
    fn test_authorize_request_serialization_without_optional_fields() {
        let request = AuthorizeRequest {
            token: "test_token".to_string(),
            gateway_code: "gw123".to_string(),
            machine_public_key: None,
            metadata: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"token\":\"test_token\""));
        assert!(json.contains("\"gateway_code\":\"gw123\""));
        // Should not contain the optional fields
        assert!(!json.contains("machine_public_key"));
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn test_change_serialization() {
        use crate::runbeam_api::resources::Change;

        // Test Change with metadata (list view)
        let change_metadata = Change {
            id: "01JBXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            status: Some("pending".to_string()),
            resource_type: "gateway".to_string(),
            gateway_id: "01JBXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            pipeline_id: None,
            toml_config: None,
            metadata: None,
            created_at: "2025-01-07T01:00:00+00:00".to_string(),
            acknowledged_at: None,
            applied_at: None,
            failed_at: None,
            error_message: None,
            error_details: None,
        };

        let json = serde_json::to_string(&change_metadata).unwrap();
        assert!(json.contains("\"id\":\"01JBXXXXXXXXXXXXXXXXXXXXXXXXXX\""));
        assert!(json.contains("\"gateway_id\":\"01JBXXXXXXXXXXXXXXXXXXXXXXXXXX\""));
        assert!(json.contains("\"type\":\"gateway\""));

        // Test deserialization
        let deserialized: Change = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "01JBXXXXXXXXXXXXXXXXXXXXXXXXXX");
        assert_eq!(deserialized.status, Some("pending".to_string()));
        assert_eq!(deserialized.resource_type, "gateway");

        // Test Change with full details (detail view)
        let change_detail = Change {
            id: "01JBXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            status: Some("applied".to_string()),
            resource_type: "gateway".to_string(),
            gateway_id: "01JBXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            pipeline_id: None,
            toml_config: Some("[proxy]\nname = \"test\"".to_string()),
            metadata: Some(serde_json::json!({"gateway_name": "test-gateway"})),
            created_at: "2025-01-07T01:00:00+00:00".to_string(),
            acknowledged_at: Some("2025-01-07T01:00:05+00:00".to_string()),
            applied_at: Some("2025-01-07T01:00:10+00:00".to_string()),
            failed_at: None,
            error_message: None,
            error_details: None,
        };

        let json = serde_json::to_string(&change_detail).unwrap();
        assert!(json.contains("toml_config"));
        assert!(json.contains("acknowledged_at"));
        assert!(json.contains("applied_at"));

        // Test deserialization of detail view
        let deserialized: Change = serde_json::from_str(&json).unwrap();
        assert!(deserialized.toml_config.is_some());
        assert!(deserialized.acknowledged_at.is_some());
        assert!(deserialized.applied_at.is_some());
    }

    #[test]
    fn test_acknowledge_changes_request_serialization() {
        use crate::runbeam_api::resources::AcknowledgeChangesRequest;

        let request = AcknowledgeChangesRequest {
            change_ids: vec![
                "change-1".to_string(),
                "change-2".to_string(),
                "change-3".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"change_ids\""));
        assert!(json.contains("\"change-1\""));
        assert!(json.contains("\"change-2\""));
        assert!(json.contains("\"change-3\""));

        // Test deserialization
        let deserialized: AcknowledgeChangesRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.change_ids.len(), 3);
        assert_eq!(deserialized.change_ids[0], "change-1");
    }

    #[test]
    fn test_change_failed_request_serialization() {
        use crate::runbeam_api::resources::ChangeFailedRequest;

        // Test with details
        let request_with_details = ChangeFailedRequest {
            error: "Configuration parse error".to_string(),
            details: Some(vec![
                "Invalid JSON at line 42".to_string(),
                "Missing required field 'name'".to_string(),
            ]),
        };

        let json = serde_json::to_string(&request_with_details).unwrap();
        assert!(json.contains("\"error\":\"Configuration parse error\""));
        assert!(json.contains("\"details\""));
        assert!(json.contains("Invalid JSON at line 42"));

        // Test without details (should omit the field)
        let request_without_details = ChangeFailedRequest {
            error: "Unknown error".to_string(),
            details: None,
        };

        let json = serde_json::to_string(&request_without_details).unwrap();
        assert!(json.contains("\"error\":\"Unknown error\""));
        assert!(!json.contains("\"details\"")); // Should be omitted due to skip_serializing_if

        // Test deserialization
        let deserialized: ChangeFailedRequest =
            serde_json::from_str(&serde_json::to_string(&request_with_details).unwrap()).unwrap();
        assert_eq!(deserialized.error, "Configuration parse error");
        assert!(deserialized.details.is_some());
        assert_eq!(deserialized.details.unwrap().len(), 2);
    }

    #[test]
    fn test_base_url_response_serialization() {
        use crate::runbeam_api::resources::BaseUrlResponse;

        let response = BaseUrlResponse {
            base_url: "https://api.runbeam.io".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"base_url\":\"https://api.runbeam.io\""));

        // Test deserialization
        let deserialized: BaseUrlResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.base_url, "https://api.runbeam.io");
    }

    #[test]
    fn test_store_config_request_serialization_with_id() {
        let request = StoreConfigRequest {
            config_type: "gateway".to_string(),
            id: Some("01k8ek6h9aahhnrv3benret1nn".to_string()),
            config: "[proxy]\nid = \"test\"\n".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        // Verify field renaming: config_type -> "type"
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
    fn test_store_config_request_serialization_without_id() {
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
    fn test_store_config_request_field_rename() {
        // Test that the "type" JSON field correctly maps to config_type
        let json = r#"{"type":"transform","config":"[transform]\nname = \"test\"\n"}"#;
        let request: StoreConfigRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.config_type, "transform");
        assert_eq!(request.id, None);

        // Serialize back and verify it uses "type" not "config_type"
        let serialized = serde_json::to_string(&request).unwrap();
        assert!(serialized.contains("\"type\":"));
        assert!(!serialized.contains("\"config_type\":"));
    }

    #[test]
    fn test_store_config_response_serialization() {
        let response = StoreConfigResponse { status: 200 };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":200"));

        // Test deserialization
        let deserialized: StoreConfigResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, 200);
    }

    #[test]
    fn test_acknowledge_changes_response_serialization() {
        use crate::runbeam_api::resources::AcknowledgeChangesResponse;

        // Test successful acknowledgment
        let response = AcknowledgeChangesResponse {
            acknowledged: vec![
                "change-1".to_string(),
                "change-2".to_string(),
                "change-3".to_string(),
            ],
            failed: vec![],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"acknowledged\":"));
        assert!(json.contains("\"failed\":"));
        assert!(json.contains("change-1"));

        // Test deserialization
        let deserialized: AcknowledgeChangesResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.acknowledged.len(), 3);
        assert_eq!(deserialized.failed.len(), 0);

        // Test partial failure
        let response_with_failures = AcknowledgeChangesResponse {
            acknowledged: vec!["change-1".to_string()],
            failed: vec!["change-2".to_string(), "change-3".to_string()],
        };

        let json = serde_json::to_string(&response_with_failures).unwrap();
        let deserialized: AcknowledgeChangesResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.acknowledged.len(), 1);
        assert_eq!(deserialized.failed.len(), 2);
    }

    #[test]
    fn test_change_status_response_serialization() {
        use crate::runbeam_api::resources::{
            ChangeAppliedResponse, ChangeFailedResponse, ChangeStatusResponse,
        };

        // Test ChangeStatusResponse
        let response = ChangeStatusResponse {
            success: true,
            message: "Change marked as applied".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"message\":\"Change marked as applied\""));

        // Test deserialization
        let deserialized: ChangeStatusResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.success, true);
        assert_eq!(deserialized.message, "Change marked as applied");

        // Test ChangeAppliedResponse (type alias)
        let applied_response: ChangeAppliedResponse = ChangeStatusResponse {
            success: true,
            message: "Change marked as applied".to_string(),
        };

        let json = serde_json::to_string(&applied_response).unwrap();
        let deserialized: ChangeAppliedResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.success, true);

        // Test ChangeFailedResponse (type alias)
        let failed_response: ChangeFailedResponse = ChangeStatusResponse {
            success: true,
            message: "Change marked as failed".to_string(),
        };

        let json = serde_json::to_string(&failed_response).unwrap();
        let deserialized: ChangeFailedResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.success, true);
        assert_eq!(deserialized.message, "Change marked as failed");
    }
}
