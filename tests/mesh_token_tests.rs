//! Mesh Token Tests
//!
//! Tests for mesh authentication token functionality including:
//! - Request/response serialization
//! - Client method with mock server
//! - Error handling

use runbeam_sdk::{MeshTokenRequest, MeshTokenResponse, RunbeamClient};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================================
// Mesh Token Request/Response Serialization Tests
// ============================================================================

#[test]
fn test_mesh_token_request_serialization() {
    let request = MeshTokenRequest {
        mesh_id: "01HXYZ123456789ABCDEF".to_string(),
        destination_url: "https://partner.example.com/fhir/r4/Patient".to_string(),
    };

    let json = serde_json::to_value(&request).unwrap();

    assert_eq!(json["mesh_id"], "01HXYZ123456789ABCDEF");
    assert_eq!(
        json["destination_url"],
        "https://partner.example.com/fhir/r4/Patient"
    );
}

#[test]
fn test_mesh_token_request_deserialization() {
    let json = json!({
        "mesh_id": "mesh-healthcare",
        "destination_url": "https://api.hospital.org/fhir"
    });

    let request: MeshTokenRequest = serde_json::from_value(json).unwrap();

    assert_eq!(request.mesh_id, "mesh-healthcare");
    assert_eq!(request.destination_url, "https://api.hospital.org/fhir");
}

#[test]
fn test_mesh_token_response_serialization() {
    let response = MeshTokenResponse {
        token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test".to_string(),
        expires_at: "2025-12-29T00:10:00+00:00".to_string(),
        mesh_id: "01HXYZ123456789ABCDEF".to_string(),
    };

    let json = serde_json::to_value(&response).unwrap();

    assert_eq!(json["token"], "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test");
    assert_eq!(json["expires_at"], "2025-12-29T00:10:00+00:00");
    assert_eq!(json["mesh_id"], "01HXYZ123456789ABCDEF");
}

#[test]
fn test_mesh_token_response_deserialization() {
    let json = json!({
        "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAxSFhZWjEyMzQ1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS5ydW5iZWFtLmlvIn0.signature",
        "expires_at": "2025-12-29T00:10:00+00:00",
        "mesh_id": "mesh-healthcare"
    });

    let response: MeshTokenResponse = serde_json::from_value(json).unwrap();

    assert!(response.token.starts_with("eyJhbGciOiJSUzI1NiI"));
    assert_eq!(response.expires_at, "2025-12-29T00:10:00+00:00");
    assert_eq!(response.mesh_id, "mesh-healthcare");
}

#[test]
fn test_mesh_token_response_roundtrip() {
    let original = MeshTokenResponse {
        token: "jwt.token.here".to_string(),
        expires_at: "2025-12-29T12:00:00Z".to_string(),
        mesh_id: "mesh-001".to_string(),
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: MeshTokenResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.token, original.token);
    assert_eq!(deserialized.expires_at, original.expires_at);
    assert_eq!(deserialized.mesh_id, original.mesh_id);
}

// ============================================================================
// Mesh Token Client Tests (with Mock Server)
// ============================================================================

#[tokio::test]
async fn test_request_mesh_token_success() {
    let mock_server = MockServer::start().await;

    let expected_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAxSFhZWjEyMzQ1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS5ydW5iZWFtLmlvIiwic3ViIjoiZ2F0ZXdheTowMWs4YWJjMTIzIiwiYXVkIjoibWVzaDptZXNoLWhlYWx0aGNhcmUiLCJqdGkiOiIwMWs4eHl6Nzg5IiwibWVzaF9pZCI6Im1lc2gtaGVhbHRoY2FyZSIsImRlc3RfdXJsIjoiaHR0cHM6Ly9wYXJ0bmVyLmV4YW1wbGUuY29tL2ZoaXIvcjQiLCJzb3VyY2VfdGVhbSI6IjAxazh0ZWFtMTIzIiwiaWF0IjoxNzM1Mzk0MTAwLCJleHAiOjE3MzUzOTQ0MDB9.signature";
    let mesh_id = "01HXYZ123456789ABCDEF";
    let destination_url = "https://partner.example.com/fhir/r4/Patient";

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .and(header("Authorization", "Bearer machine_token_abc123"))
        .and(header("Content-Type", "application/json"))
        .and(body_json(json!({
            "mesh_id": mesh_id,
            "destination_url": destination_url
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": expected_token,
            "expires_at": "2025-12-29T00:10:00+00:00",
            "mesh_id": mesh_id
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("machine_token_abc123", mesh_id, destination_url)
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.token, expected_token);
    assert_eq!(response.expires_at, "2025-12-29T00:10:00+00:00");
    assert_eq!(response.mesh_id, mesh_id);
}

#[tokio::test]
async fn test_request_mesh_token_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthenticated",
            "message": "This endpoint requires gateway authentication."
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("invalid_token", "mesh-123", "https://example.com")
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_str = error.to_string();
    assert!(
        error_str.contains("401") || error_str.contains("Unauthenticated"),
        "Expected 401 or Unauthenticated in error, got: {}",
        error_str
    );
}

#[tokio::test]
async fn test_request_mesh_token_mesh_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "Mesh not found",
            "message": "The specified mesh does not exist."
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("valid_token", "nonexistent-mesh", "https://example.com")
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_str = error.to_string();
    assert!(
        error_str.contains("404") || error_str.contains("not found"),
        "Expected 404 or 'not found' in error, got: {}",
        error_str
    );
}

#[tokio::test]
async fn test_request_mesh_token_no_egress_rights() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "Gateway does not have egress rights in this mesh"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("valid_token", "mesh-123", "https://example.com")
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_str = error.to_string();
    assert!(
        error_str.contains("403") || error_str.contains("egress"),
        "Expected 403 or 'egress' in error, got: {}",
        error_str
    );
}

#[tokio::test]
async fn test_request_mesh_token_no_matching_ingress() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "No ingress matches destination URL"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token(
            "valid_token",
            "mesh-123",
            "https://unauthorized-destination.com/api",
        )
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_str = error.to_string();
    assert!(
        error_str.contains("403") || error_str.contains("ingress"),
        "Expected 403 or 'ingress' in error, got: {}",
        error_str
    );
}

#[tokio::test]
async fn test_request_mesh_token_mesh_disabled() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "Mesh is disabled"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("valid_token", "disabled-mesh", "https://example.com")
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_str = error.to_string();
    assert!(
        error_str.contains("400") || error_str.contains("disabled"),
        "Expected 400 or 'disabled' in error, got: {}",
        error_str
    );
}

#[tokio::test]
async fn test_request_mesh_token_invalid_provider() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "Mesh provider must be 'runbeam' for API token requests"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("valid_token", "local-mesh", "https://example.com")
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_str = error.to_string();
    assert!(
        error_str.contains("400") || error_str.contains("provider"),
        "Expected 400 or 'provider' in error, got: {}",
        error_str
    );
}

#[tokio::test]
async fn test_request_mesh_token_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "Token signing failed",
            "message": "Internal error during JWT generation"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("valid_token", "mesh-123", "https://example.com")
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_str = error.to_string();
    assert!(
        error_str.contains("500") || error_str.contains("signing"),
        "Expected 500 or 'signing' in error, got: {}",
        error_str
    );
}

// ============================================================================
// Mesh Token with Different URL Patterns
// ============================================================================

#[tokio::test]
async fn test_request_mesh_token_with_path_params() {
    let mock_server = MockServer::start().await;

    let destination_url = "https://partner.example.com/fhir/r4/Patient/12345/_history/1";

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .and(body_json(json!({
            "mesh_id": "mesh-123",
            "destination_url": destination_url
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "jwt.token.here",
            "expires_at": "2025-12-29T00:10:00+00:00",
            "mesh_id": "mesh-123"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("machine_token", "mesh-123", destination_url)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_request_mesh_token_with_query_params() {
    let mock_server = MockServer::start().await;

    let destination_url = "https://partner.example.com/fhir/r4/Patient?name=Smith&birthdate=1990-01-01";

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .and(body_json(json!({
            "mesh_id": "mesh-123",
            "destination_url": destination_url
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "jwt.token.here",
            "expires_at": "2025-12-29T00:10:00+00:00",
            "mesh_id": "mesh-123"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("machine_token", "mesh-123", destination_url)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_request_mesh_token_with_port() {
    let mock_server = MockServer::start().await;

    let destination_url = "https://partner.example.com:8443/api/v1/data";

    Mock::given(method("POST"))
        .and(path("/harmony/mesh/token"))
        .and(body_json(json!({
            "mesh_id": "mesh-123",
            "destination_url": destination_url
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "jwt.token.here",
            "expires_at": "2025-12-29T00:10:00+00:00",
            "mesh_id": "mesh-123"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = RunbeamClient::new(&mock_server.uri());

    let result = client
        .request_mesh_token("machine_token", "mesh-123", destination_url)
        .await;

    assert!(result.is_ok());
}
