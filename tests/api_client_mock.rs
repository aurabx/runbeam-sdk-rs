//! API Client Mock Tests (Starter Examples)
//!
//! This file provides starter examples for testing the RunbeamClient HTTP methods
//! using wiremock for HTTP mocking. These tests verify API client behavior without
//! making real network calls.
//!
//! To use this file:
//! 1. Add `wiremock = "0.6"` to [dev-dependencies] in Cargo.toml
//! 2. Rename this file to `api_client_mock.rs`
//! 3. Run: `cargo test --test api_client_mock`
//!
//! Each test follows this pattern:
//! 1. Start a mock HTTP server
//! 2. Configure expected request/response
//! 3. Create RunbeamClient pointing to mock server
//! 4. Make API call
//! 5. Assert response is correct

use runbeam_sdk::RunbeamClient;
use serde_json::json;
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

// ============================================================================
// Authorization Tests
// ============================================================================

#[tokio::test]
async fn test_authorize_gateway_success_with_jwt() {
    // Start mock HTTP server
    let mock_server = MockServer::start().await;

    // Configure mock response
    let response_body = json!({
        "machine_token": "machine_token_abc123",
        "expires_in": 2592000.0,
        "expires_at": "2024-12-01T00:00:00Z",
        "gateway": {
            "id": "gateway-001",
            "code": "test-gateway",
            "name": "Test Gateway"
        },
        "abilities": ["harmony:send", "harmony:receive"]
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/authorize"))
        .and(header("Authorization", "Bearer eyJhbGci..."))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1) // Expect this to be called exactly once
        .mount(&mock_server)
        .await;

    // Create client pointing to mock server
    let client = RunbeamClient::new(mock_server.uri());

    // Make API call
    let result = client
        .authorize_gateway("eyJhbGci...", "test-gateway", None, None)
        .await;

    // Assert success
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.machine_token, "machine_token_abc123");
    assert_eq!(response.gateway.id, "gateway-001");
    assert_eq!(response.gateway.code, "test-gateway");
    assert_eq!(response.abilities.len(), 2);
}

#[tokio::test]
async fn test_authorize_gateway_success_with_sanctum_token() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "machine_token": "machine_token_xyz789",
        "expires_in": 2592000.0,
        "expires_at": "2024-12-01T00:00:00Z",
        "gateway": {
            "id": "gateway-002",
            "code": "sanctum-gateway",
            "name": "Sanctum Gateway"
        },
        "abilities": ["harmony:send"]
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/authorize"))
        .and(header("Authorization", "Bearer 1|abc123def456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client
        .authorize_gateway("1|abc123def456", "sanctum-gateway", None, None)
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.machine_token, "machine_token_xyz789");
    assert_eq!(response.gateway.code, "sanctum-gateway");
}

#[tokio::test]
async fn test_authorize_gateway_with_optional_parameters() {
    let mock_server = MockServer::start().await;

    let expected_request = json!({
        "token": "test_token",
        "gateway_code": "test-gateway",
        "machine_public_key": "pubkey123",
        "metadata": ["version:1.0", "hostname:test-host"]
    });

    let response_body = json!({
        "machine_token": "machine_token_with_metadata",
        "expires_in": 2592000.0,
        "expires_at": "2024-12-01T00:00:00Z",
        "gateway": {
            "id": "gateway-003",
            "code": "test-gateway",
            "name": "Test Gateway with Metadata"
        },
        "abilities": []
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/authorize"))
        .and(body_json(&expected_request))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client
        .authorize_gateway(
            "test_token",
            "test-gateway",
            Some("pubkey123".to_string()),
            Some(vec![
                "version:1.0".to_string(),
                "hostname:test-host".to_string(),
            ]),
        )
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.machine_token, "machine_token_with_metadata");
}

#[tokio::test]
async fn test_authorize_gateway_failure_401_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/harmony/authorize"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client
        .authorize_gateway("invalid_token", "test-gateway", None, None)
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("401"));
}

#[tokio::test]
async fn test_authorize_gateway_failure_malformed_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/harmony/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client
        .authorize_gateway("test_token", "test-gateway", None, None)
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("parse"));
}

// ============================================================================
// Change Management API Tests (v1.2)
// ============================================================================

#[tokio::test]
async fn test_get_base_url_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "base_url": "https://api.runbeam.io"
    });

    Mock::given(method("GET"))
        .and(path("/api/harmony/base-url"))
        .and(header("Authorization", "Bearer machine_token_abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client.get_base_url("machine_token_abc").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.base_url, "https://api.runbeam.io");
}

#[tokio::test]
async fn test_list_changes_success_with_pending_changes() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [
            {
                "id": "change-001",
                "type": "change",
                "gateway_id": "gateway-123",
                "status": "pending",
                "toml_config": "[endpoint]\nname = \"api-endpoint\"",
                "metadata": {"operation": "create", "resourceType": "endpoint"},
                "created_at": "2024-10-31T00:00:00Z",
                "acknowledged_at": null,
                "applied_at": null,
                "failed_at": null,
                "error_message": null,
                "error_details": null
            },
            {
                "id": "change-002",
                "type": "change",
                "gateway_id": "gateway-123",
                "status": "pending",
                "toml_config": "[backend]\nurl = \"https://api.example.com\"",
                "metadata": {"operation": "update", "resourceType": "backend"},
                "created_at": "2024-10-31T00:01:00Z",
                "acknowledged_at": null,
                "applied_at": null,
                "failed_at": null,
                "error_message": null,
                "error_details": null
            }
        ],
        "links": {
            "first": "https://api.runbeam.io/api/changes?page=1",
            "last": "https://api.runbeam.io/api/changes?page=1",
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": 1,
            "last_page": 1,
            "path": "https://api.runbeam.io/api/changes",
            "per_page": 50,
            "to": 2,
            "total": 2
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/harmony/changes"))
        .and(header("Authorization", "Bearer machine_token_abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client.list_changes("machine_token_abc").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 2);
    assert_eq!(response.data[0].id, "change-001");
    assert_eq!(response.data[0].status, Some("pending".to_string()));
    assert_eq!(response.data[1].id, "change-002");
    assert_eq!(response.meta.total, 2);
}

#[tokio::test]
async fn test_list_changes_empty_results() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [],
        "links": {
            "first": null,
            "last": null,
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": null,
            "last_page": 1,
            "path": "https://api.runbeam.io/api/changes",
            "per_page": 50,
            "to": null,
            "total": 0
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/harmony/changes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client.list_changes("machine_token_abc").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 0);
    assert_eq!(response.meta.total, 0);
}

// OBSOLETE TEST - Removed duplicate test with wrong endpoint path (/api/changes/acknowledge instead of /api/harmony/changes/acknowledge)
// See corrected test further down in the file

// OBSOLETE TEST - Removed duplicate test with wrong endpoint path (/api/changes/... instead of /api/harmony/changes/...)
// See corrected test further down in the file

#[tokio::test]
async fn test_mark_change_failed_with_details() {
    let mock_server = MockServer::start().await;

    let expected_request = json!({
        "error": "Configuration parse error",
        "details": ["Invalid JSON at line 42", "Missing required field 'name'"]
    });

    let response_body = json!({
        "success": true,
        "message": "Change marked as failed"
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/changes/change-456/failed"))
        .and(header("Authorization", "Bearer machine_token_abc"))
        .and(header("Content-Type", "application/json"))
        .and(body_json(&expected_request))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client
        .mark_change_failed(
            "machine_token_abc",
            "change-456",
            "Configuration parse error".to_string(),
            Some(vec![
                "Invalid JSON at line 42".to_string(),
                "Missing required field 'name'".to_string(),
            ]),
        )
        .await;

    assert!(result.is_ok());
}

// ============================================================================
// Resource Listing Tests
// ============================================================================

#[tokio::test]
async fn test_list_gateways_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [
            {
                "type": "gateway",
                "id": "gateway-001",
                "code": "test-gateway-1",
                "name": "Test Gateway 1",
                "team_id": "team-123",
                "enabled": true,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        ],
        "links": {
            "first": "https://api.runbeam.io/api/gateways?page=1",
            "last": "https://api.runbeam.io/api/gateways?page=1",
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": 1,
            "last_page": 1,
            "path": "https://api.runbeam.io/api/gateways",
            "per_page": 50,
            "to": 1,
            "total": 1
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/gateways"))
        .and(header("Authorization", "Bearer test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client.list_gateways("test_token").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 1);
    assert_eq!(response.data[0].code, "test-gateway-1");
    assert_eq!(response.meta.total, 1);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_api_call_with_500_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/gateways"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client.list_gateways("test_token").await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("500"));
}

#[tokio::test]
async fn test_api_call_with_404_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/gateways/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());

    let result = client.get_gateway("test_token", "nonexistent").await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("404"));
}

// ============================================================================
// Change Management Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_list_changes_401_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/harmony/changes"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.list_changes("invalid_token").await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("401"));
}

#[tokio::test]
async fn test_get_change_404_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/harmony/changes/nonexistent-change"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Change not found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.get_change("machine_token", "nonexistent-change").await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("404"));
}

#[tokio::test]
async fn test_list_changes_for_gateway_403_forbidden() {
    let mock_server = MockServer::start().await;

    let error_body = json!({
        "error": "Forbidden",
        "message": "This gateway does not belong to your team"
    });

    Mock::given(method("GET"))
        .and(path("/api/harmony/changes/gateway-999"))
        .respond_with(ResponseTemplate::new(403).set_body_json(&error_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.list_changes_for_gateway("machine_token", "gateway-999").await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("403"));
}

#[tokio::test]
async fn test_acknowledge_changes_422_validation_error() {
    let mock_server = MockServer::start().await;

    let error_body = json!({
        "message": "The given data was invalid.",
        "errors": {
            "change_ids": ["The change_ids field is required."]
        }
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/changes/acknowledge"))
        .respond_with(ResponseTemplate::new(422).set_body_json(&error_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.acknowledge_changes("machine_token", vec![]).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("422"));
}

#[tokio::test]
async fn test_mark_change_applied_403_forbidden() {
    let mock_server = MockServer::start().await;

    let error_body = json!({
        "error": "Forbidden",
        "message": "This change does not belong to your gateway"
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/changes/change-777/applied"))
        .respond_with(ResponseTemplate::new(403).set_body_json(&error_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.mark_change_applied("machine_token", "change-777").await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("403"));
}

#[tokio::test]
async fn test_mark_change_failed_403_forbidden() {
    let mock_server = MockServer::start().await;

    let error_body = json!({
        "error": "Forbidden",
        "message": "This change does not belong to your gateway"
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/changes/change-888/failed"))
        .respond_with(ResponseTemplate::new(403).set_body_json(&error_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.mark_change_failed(
        "machine_token",
        "change-888",
        "Configuration error".to_string(),
        None
    ).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("403"));
}

#[tokio::test]
async fn test_mark_change_failed_422_validation_error() {
    let mock_server = MockServer::start().await;

    let error_body = json!({
        "message": "The given data was invalid.",
        "errors": {
            "error": ["The error field is required."]
        }
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/changes/change-555/failed"))
        .respond_with(ResponseTemplate::new(422).set_body_json(&error_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.mark_change_failed(
        "machine_token",
        "change-555",
        "".to_string(),  // Empty error message should trigger validation error
        None
    ).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("422"));
}

// ============================================================================
// Additional Resource Listing Tests
// ============================================================================

#[tokio::test]
async fn test_get_gateway_by_id() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": {
            "type": "gateway",
            "id": "gateway-123",
            "code": "my-gateway",
            "name": "My Gateway",
            "team_id": "team-456",
            "enabled": true,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/gateways/gateway-123"))
        .and(header("Authorization", "Bearer test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.get_gateway("test_token", "gateway-123").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.id, Some("gateway-123".to_string()));
    assert_eq!(response.data.code, "my-gateway");
}

#[tokio::test]
async fn test_list_services_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [
            {
                "type": "service",
                "id": "service-001",
                "code": "api-service",
                "name": "API Service",
                "team_id": "team-123",
                "gateway_id": "gateway-456",
                "description": "Main API service",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            },
            {
                "type": "service",
                "id": "service-002",
                "code": "auth-service",
                "name": "Auth Service",
                "team_id": "team-123",
                "gateway_id": "gateway-456",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        ],
        "links": {
            "first": "https://api.runbeam.io/api/services?page=1",
            "last": "https://api.runbeam.io/api/services?page=1",
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": 1,
            "last_page": 1,
            "path": "https://api.runbeam.io/api/services",
            "per_page": 50,
            "to": 2,
            "total": 2
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/services"))
        .and(header("Authorization", "Bearer test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.list_services("test_token").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 2);
    assert_eq!(response.data[0].code, "api-service");
    assert_eq!(response.data[1].code, "auth-service");
    assert_eq!(response.meta.total, 2);
}

#[tokio::test]
async fn test_get_service_by_id() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": {
            "type": "service",
            "id": "service-789",
            "code": "user-service",
            "name": "User Service",
            "team_id": "team-123",
            "gateway_id": "gateway-456",
            "description": "User management service",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/services/service-789"))
        .and(header("Authorization", "Bearer test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.get_service("test_token", "service-789").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.code, "user-service");
    assert_eq!(response.data.id, Some("service-789".to_string()));
}

#[tokio::test]
async fn test_list_endpoints_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [
            {
                "type": "endpoint",
                "id": "endpoint-001",
                "code": "users-list",
                "name": "List Users",
                "team_id": "team-123",
                "gateway_id": "gateway-456",
                "service_id": "service-789",
                "path": "/api/users",
                "methods": ["GET"],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        ],
        "links": {
            "first": "https://api.runbeam.io/api/endpoints?page=1",
            "last": "https://api.runbeam.io/api/endpoints?page=1",
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": 1,
            "last_page": 1,
            "path": "https://api.runbeam.io/api/endpoints",
            "per_page": 50,
            "to": 1,
            "total": 1
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/endpoints"))
        .and(header("Authorization", "Bearer test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.list_endpoints("test_token").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 1);
    assert_eq!(response.data[0].path, Some("/api/users".to_string()));
    assert_eq!(response.data[0].methods, Some(vec!["GET".to_string()]));
}

#[tokio::test]
async fn test_list_backends_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [
            {
                "type": "backend",
                "id": "backend-001",
                "code": "api-backend",
                "name": "API Backend",
                "team_id": "team-123",
                "gateway_id": "gateway-456",
                "service_id": "service-789",
                "url": "https://api.example.com",
                "timeout_seconds": 30,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        ],
        "links": {
            "first": "https://api.runbeam.io/api/backends?page=1",
            "last": "https://api.runbeam.io/api/backends?page=1",
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": 1,
            "last_page": 1,
            "path": "https://api.runbeam.io/api/backends",
            "per_page": 50,
            "to": 1,
            "total": 1
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/backends"))
        .and(header("Authorization", "Bearer test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.list_backends("test_token").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 1);
    assert_eq!(
        response.data[0].url,
        Some("https://api.example.com".to_string())
    );
    assert_eq!(response.data[0].timeout_seconds, Some(30));
}

#[tokio::test]
async fn test_list_pipelines_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [
            {
                "type": "pipeline",
                "id": "pipeline-001",
                "code": "main-pipeline",
                "name": "Main Pipeline",
                "description": "Main request pipeline",
                "team_id": "team-123",
                "gateway_id": "gateway-456",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        ],
        "links": {
            "first": "https://api.runbeam.io/api/pipelines?page=1",
            "last": "https://api.runbeam.io/api/pipelines?page=1",
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": 1,
            "last_page": 1,
            "path": "https://api.runbeam.io/api/pipelines",
            "per_page": 50,
            "to": 1,
            "total": 1
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/pipelines"))
        .and(header("Authorization", "Bearer test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.list_pipelines("test_token").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 1);
    assert_eq!(response.data[0].code, "main-pipeline");
}

// Test removed - using old Change structure with incorrect fields (operation, resourceType, payload, error)
// See TEST_UPDATE_NOTES.md for correct Change structure
// A corrected version of this test exists below as test_get_change_by_id()

// ============================================================================
// Legacy test removed - list_config_changes() method no longer exists
// Use list_changes() or list_changes_for_gateway() instead
// See updated tests below and TEST_UPDATE_NOTES.md
// ============================================================================

#[tokio::test]
async fn test_list_changes_for_gateway_empty() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [],
        "links": {
            "first": null,
            "last": null,
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": null,
            "last_page": 1,
            "links": [],
            "path": null,
            "per_page": 15,
            "to": null,
            "total": 0
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/harmony/changes/gateway-123"))
        .and(header("Authorization", "Bearer machine_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.list_changes_for_gateway("machine_token", "gateway-123").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 0);
}

#[tokio::test]
async fn test_list_changes_for_gateway_with_data() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": [
            {
                "id": "change-001",
                "type": "change",
                "gateway_id": "gateway-456",
                "status": "pending",
                "toml_config": "[endpoint]\npath = \"/api/v1\"",
                "metadata": {"operation": "create"},
                "created_at": "2024-10-31T10:00:00Z",
                "acknowledged_at": null,
                "applied_at": null,
                "failed_at": null,
                "error_message": null,
                "error_details": null
            },
            {
                "id": "change-002",
                "type": "change",
                "gateway_id": "gateway-456",
                "status": "acknowledged",
                "toml_config": "[backend]\nurl = \"https://example.com\"",
                "metadata": {"operation": "update"},
                "created_at": "2024-10-31T11:00:00Z",
                "acknowledged_at": "2024-10-31T11:05:00Z",
                "applied_at": null,
                "failed_at": null,
                "error_message": null,
                "error_details": null
            }
        ],
        "links": {
            "first": "https://api.runbeam.io/api/harmony/changes/gateway-456?page=1",
            "last": "https://api.runbeam.io/api/harmony/changes/gateway-456?page=1",
            "prev": null,
            "next": null
        },
        "meta": {
            "current_page": 1,
            "from": 1,
            "last_page": 1,
            "path": "https://api.runbeam.io/api/harmony/changes/gateway-456",
            "per_page": 15,
            "to": 2,
            "total": 2
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/harmony/changes/gateway-456"))
        .and(header("Authorization", "Bearer machine_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client.list_changes_for_gateway("machine_token", "gateway-456").await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.data.len(), 2);
    assert_eq!(response.data[0].id, "change-001");
    assert_eq!(response.data[0].gateway_id, "gateway-456");
    assert_eq!(response.data[0].status, Some("pending".to_string()));
    assert_eq!(response.data[1].id, "change-002");
    assert_eq!(response.data[1].status, Some("acknowledged".to_string()));
    assert!(response.data[1].acknowledged_at.is_some());
    assert_eq!(response.meta.total, 2);
}

#[tokio::test]
async fn test_get_change_by_id() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "data": {
            "id": "config-change-123",
            "status": "queued",
            "type": "gateway",
            "gateway_id": "gateway-123",
            "pipeline_id": null,
            "toml_config": "[proxy]\nid = \"test\"\n",
            "metadata": {
                "version": "1.0",
                "author": "admin"
            },
            "created_at": "2024-10-31T00:00:00Z",
            "acknowledged_at": null,
            "applied_at": null,
            "failed_at": null,
            "error_message": null,
            "error_details": null
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/harmony/changes/config-change-123"))
        .and(header("Authorization", "Bearer machine_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client
        .get_change("machine_token", "config-change-123")
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    let change = response.data;
    assert_eq!(change.id, "config-change-123");
    assert_eq!(change.status, Some("queued".to_string()));
    assert!(change.toml_config.unwrap().contains("proxy"));
    assert!(change.metadata.is_some());
}

#[tokio::test]
async fn test_acknowledge_changes_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "acknowledged": ["change-1", "change-2", "change-3"],
        "failed": []
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/changes/acknowledge"))
        .and(header("Authorization", "Bearer machine_token"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let change_ids = vec![
        "change-1".to_string(),
        "change-2".to_string(),
        "change-3".to_string(),
    ];
    let result = client
        .acknowledge_changes("machine_token", change_ids)
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.acknowledged.len(), 3);
    assert_eq!(response.failed.len(), 0);
}

#[tokio::test]
async fn test_mark_change_applied_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "success": true,
        "message": "Change marked as applied"
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/changes/config-change-789/applied"))
        .and(header("Authorization", "Bearer machine_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client
        .mark_change_applied("machine_token", "config-change-789")
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.message, "Change marked as applied");
}

#[tokio::test]
async fn test_mark_change_failed_success() {
    let mock_server = MockServer::start().await;

    let response_body = json!({
        "success": true,
        "message": "Change marked as failed"
    });

    Mock::given(method("POST"))
        .and(path("/api/harmony/changes/config-change-999/failed"))
        .and(header("Authorization", "Bearer machine_token"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(mock_server.uri());
    let result = client
        .mark_change_failed(
            "machine_token",
            "config-change-999",
            "Failed to apply configuration".to_string(),
            None,
        )
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.success);
    assert_eq!(response.message, "Change marked as failed");
}
