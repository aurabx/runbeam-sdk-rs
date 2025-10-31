use crate::runbeam_api::types::{
    ApiError, AuthorizeResponse, ConfigChange, ConfigChangeAck, ConfigChangeDetail, RunbeamError,
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
        let url = format!("{}/api/harmony/authorize", self.base_url);

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

    /// List pending config changes for a gateway
    ///
    /// # Arguments
    ///
    /// * `gateway_token` - Machine token for the gateway
    pub async fn list_config_changes(
        &self,
        gateway_token: impl Into<String>,
    ) -> Result<Vec<ConfigChange>, RunbeamError> {
        let url = format!("{}/api/harmony/config-changes", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", gateway_token.into()))
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

    /// Get detailed config change content
    ///
    /// # Arguments
    ///
    /// * `gateway_token` - Machine token for the gateway
    /// * `change_id` - ID of the config change
    pub async fn get_config_change(
        &self,
        gateway_token: impl Into<String>,
        change_id: impl Into<String>,
    ) -> Result<ConfigChangeDetail, RunbeamError> {
        let url = format!(
            "{}/api/harmony/config-changes/{}",
            self.base_url,
            change_id.into()
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", gateway_token.into()))
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

    /// Acknowledge receipt of a config change
    ///
    /// # Arguments
    ///
    /// * `gateway_token` - Machine token for the gateway
    /// * `change_id` - ID of the config change
    pub async fn acknowledge_config_change(
        &self,
        gateway_token: impl Into<String>,
        change_id: impl Into<String>,
    ) -> Result<ConfigChangeAck, RunbeamError> {
        let url = format!(
            "{}/api/harmony/config-changes/{}/acknowledge",
            self.base_url,
            change_id.into()
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", gateway_token.into()))
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

    /// Report successful application of a config change
    ///
    /// # Arguments
    ///
    /// * `gateway_token` - Machine token for the gateway
    /// * `change_id` - ID of the config change
    pub async fn report_config_applied(
        &self,
        gateway_token: impl Into<String>,
        change_id: impl Into<String>,
    ) -> Result<ConfigChangeAck, RunbeamError> {
        let url = format!(
            "{}/api/harmony/config-changes/{}/applied",
            self.base_url,
            change_id.into()
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", gateway_token.into()))
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

    /// Report failed application of a config change
    ///
    /// # Arguments
    ///
    /// * `gateway_token` - Machine token for the gateway
    /// * `change_id` - ID of the config change
    /// * `error` - Error message describing the failure
    pub async fn report_config_failed(
        &self,
        gateway_token: impl Into<String>,
        change_id: impl Into<String>,
        error: impl Into<String>,
    ) -> Result<ConfigChangeAck, RunbeamError> {
        let url = format!(
            "{}/api/harmony/config-changes/{}/failed",
            self.base_url,
            change_id.into()
        );

        #[derive(Serialize)]
        struct FailurePayload {
            error: String,
        }

        let payload = FailurePayload {
            error: error.into(),
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", gateway_token.into()))
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
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
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
        let url = format!("{}/api/gateways", self.base_url);

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
        let url = format!("{}/api/gateways/{}", self.base_url, gateway_id.into());

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
        let url = format!("{}/gateway/base-url", self.base_url);

        tracing::debug!("Getting base URL from: {}", url);

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
            tracing::error!("Failed to get base URL: HTTP {} - {}", status, error_body);
            return Err(RunbeamError::Api(ApiError::Http {
                status: status.as_u16(),
                message: error_body,
            }));
        }

        response.json().await.map_err(|e| {
            tracing::error!("Failed to parse base URL response: {}", e);
            RunbeamError::Api(ApiError::Parse(format!("Failed to parse response: {}", e)))
        })
    }

    /// List pending configuration changes for the authenticated gateway
    ///
    /// Retrieve queued configuration changes that are ready to be applied.
    /// Gateways typically poll this endpoint every 30 seconds to check for updates.
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
    /// let changes = client.list_changes("machine_token_abc123").await?;
    /// println!("Found {} pending changes", changes.data.len());
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
        let url = format!("{}/gateway/changes", self.base_url);

        tracing::debug!("Listing changes from: {}", url);

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

    /// Get details of a specific configuration change
    ///
    /// Retrieve detailed information about a specific change by its ID.
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
    /// println!("Change status: {}", change.data.status);
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
        let url = format!("{}/gateway/changes/{}", self.base_url, change_id);

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
    ) -> Result<serde_json::Value, RunbeamError> {
        let url = format!("{}/gateway/changes/acknowledge", self.base_url);

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
    ) -> Result<serde_json::Value, RunbeamError> {
        let change_id = change_id.into();
        let url = format!("{}/gateway/changes/{}/applied", self.base_url, change_id);

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
    ) -> Result<serde_json::Value, RunbeamError> {
        let change_id = change_id.into();
        let url = format!("{}/gateway/changes/{}/failed", self.base_url, change_id);

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

        let change = Change {
            id: "change-123".to_string(),
            resource_type: "change".to_string(),
            gateway_id: "gateway-456".to_string(),
            status: "pending".to_string(),
            operation: "create".to_string(),
            change_resource_type: "endpoint".to_string(),
            resource_id: "endpoint-789".to_string(),
            payload: serde_json::json!({"name": "test-endpoint"}),
            error: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&change).unwrap();
        assert!(json.contains("\"id\":\"change-123\""));
        assert!(json.contains("\"gateway_id\":\"gateway-456\""));
        assert!(json.contains("\"status\":\"pending\""));
        assert!(json.contains("\"operation\":\"create\""));

        // Test deserialization
        let deserialized: Change = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "change-123");
        assert_eq!(deserialized.status, "pending");
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
}
