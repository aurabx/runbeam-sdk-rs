//! Resource Serialization Tests
//!
//! Comprehensive tests for API resource types serialization and deserialization.
//! These tests verify that all resource structs correctly handle JSON conversion,
//! optional fields, and API v1.2 schema compliance.
//!
//! # Status
//!
//! This file is currently SKIPPED (.skip extension) because it contains tests with outdated
//! API expectations from an earlier SDK version. See individual tests for details.
//!
//! ## Updated for v1.7.0
//!
//! The `test_policy_with_rules` test (lines 310+) has been updated to use the v1.7.0
//! policies format (rules as array of string IDs). This test will pass once the
//! broader test file compatibility issues are resolved and the file is re-enabled.

use runbeam_sdk::{
    AcknowledgeChangesRequest, Authentication, Backend, BaseUrlResponse, Change,
    ChangeFailedRequest, Endpoint, Gateway, GatewayConfiguration, Middleware, Network,
    PaginatedResponse, Pipeline, Policy, ResourceResponse, Service, Transform,
};
use serde_json::json;

// ============================================================================
// Gateway Resource Tests
// ============================================================================

#[test]
fn test_gateway_serialization_full() {
    let gateway_json = json!({
        "type": "gateway",
        "id": "gateway-123",
        "code": "my-gateway",
        "name": "My Gateway",
        "team_id": "team-456",
        "enabled": true,
        "pipelines_path": "/etc/harmony/pipelines",
        "transforms_path": "/etc/harmony/transforms",
        "jwks_cache_duration_hours": 24,
        "management_enabled": true,
        "management_base_path": "/manage",
        "management_network_id": "network-789",
        "dns": ["8.8.8.8", "1.1.1.1"],
        "settings": {"timeout": 30},
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let gateway: Gateway = serde_json::from_value(gateway_json).unwrap();

    assert_eq!(gateway.resource_type, "gateway");
    assert_eq!(gateway.id, Some("gateway-123".to_string()));
    assert_eq!(gateway.code, "my-gateway");
    assert_eq!(gateway.name, "My Gateway");
    assert_eq!(gateway.team_id, "team-456");
    assert_eq!(gateway.enabled, Some(true));
    assert_eq!(
        gateway.pipelines_path,
        Some("/etc/harmony/pipelines".to_string())
    );
    assert_eq!(gateway.jwks_cache_duration_hours, Some(24));
    assert_eq!(
        gateway.dns,
        Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()])
    );
}

#[test]
fn test_gateway_serialization_minimal() {
    let gateway_json = json!({
        "type": "gateway",
        "code": "minimal-gateway",
        "name": "Minimal Gateway",
        "team_id": "team-123"
    });

    let gateway: Gateway = serde_json::from_value(gateway_json).unwrap();

    assert_eq!(gateway.code, "minimal-gateway");
    assert_eq!(gateway.name, "Minimal Gateway");
    assert!(gateway.id.is_none());
    assert!(gateway.enabled.is_none());
    assert!(gateway.pipelines_path.is_none());
}

#[test]
fn test_gateway_roundtrip() {
    let gateway = Gateway {
        resource_type: "gateway".to_string(),
        id: Some("gw-001".to_string()),
        code: "test-gw".to_string(),
        name: "Test Gateway".to_string(),
        team_id: "team-001".to_string(),
        enabled: Some(true),
        pipelines_path: None,
        transforms_path: None,
        jwks_cache_duration_hours: Some(24),
        management_enabled: Some(false),
        management_base_path: None,
        management_network_id: None,
        dns: None,
        settings: None,
        created_at: Some("2024-01-01T00:00:00Z".to_string()),
        updated_at: Some("2024-01-01T00:00:00Z".to_string()),
    };

    let json = serde_json::to_value(&gateway).unwrap();
    let deserialized: Gateway = serde_json::from_value(json).unwrap();

    assert_eq!(deserialized.code, gateway.code);
    assert_eq!(deserialized.id, gateway.id);
}

// ============================================================================
// Service Resource Tests
// ============================================================================

#[test]
fn test_service_serialization() {
    let service_json = json!({
        "type": "service",
        "id": "service-123",
        "code": "api-service",
        "name": "API Service",
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "description": "Main API service",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let service: Service = serde_json::from_value(service_json).unwrap();

    assert_eq!(service.resource_type, "service");
    assert_eq!(service.code, "api-service");
    assert_eq!(service.description, Some("Main API service".to_string()));
}

#[test]
fn test_service_without_description() {
    let service_json = json!({
        "type": "service",
        "code": "minimal-service",
        "name": "Minimal Service",
        "team_id": "team-123",
        "gateway_id": "gateway-456"
    });

    let service: Service = serde_json::from_value(service_json).unwrap();

    assert!(service.description.is_none());
    assert!(service.id.is_none());
}

// ============================================================================
// Endpoint Resource Tests
// ============================================================================

#[test]
fn test_endpoint_with_methods() {
    let endpoint_json = json!({
        "type": "endpoint",
        "id": "endpoint-123",
        "code": "users-list",
        "name": "List Users",
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "service_id": "service-001",
        "path": "/api/users",
        "methods": ["GET", "POST"],
        "description": "User management endpoint",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let endpoint: Endpoint = serde_json::from_value(endpoint_json).unwrap();

    assert_eq!(endpoint.path, Some("/api/users".to_string()));
    assert_eq!(
        endpoint.methods,
        Some(vec!["GET".to_string(), "POST".to_string()])
    );
    assert_eq!(
        endpoint.description,
        Some("User management endpoint".to_string())
    );
}

#[test]
fn test_endpoint_minimal() {
    let endpoint_json = json!({
        "type": "endpoint",
        "code": "minimal-endpoint",
        "name": "Minimal Endpoint",
        "team_id": "team-123"
    });

    let endpoint: Endpoint = serde_json::from_value(endpoint_json).unwrap();

    assert!(endpoint.path.is_none());
    assert!(endpoint.methods.is_none());
    assert!(endpoint.gateway_id.is_none());
}

// ============================================================================
// Backend Resource Tests
// ============================================================================

#[test]
fn test_backend_with_timeout() {
    let backend_json = json!({
        "type": "backend",
        "id": "backend-123",
        "code": "api-backend",
        "name": "API Backend",
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "service_id": "service-001",
        "url": "https://api.example.com",
        "timeout_seconds": 30,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let backend: Backend = serde_json::from_value(backend_json).unwrap();

    assert_eq!(backend.url, Some("https://api.example.com".to_string()));
    assert_eq!(backend.timeout_seconds, Some(30));
}

// ============================================================================
// Pipeline Resource Tests
// ============================================================================

#[test]
fn test_pipeline_with_complex_data() {
    let pipeline_json = json!({
        "type": "pipeline",
        "id": "pipeline-123",
        "code": "main-pipeline",
        "name": "Main Pipeline",
        "description": "Primary request pipeline",
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "networks": ["network-1", "network-2"],
        "endpoints": {"list": ["endpoint-1", "endpoint-2"]},
        "backends": {"primary": "backend-1"},
        "middleware": {"auth": {"type": "jwt"}},
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let pipeline: Pipeline = serde_json::from_value(pipeline_json).unwrap();

    assert_eq!(pipeline.code, "main-pipeline");
    assert_eq!(pipeline.description, "Primary request pipeline");
    assert!(pipeline.networks.is_some());
    assert!(pipeline.endpoints.is_some());
    assert!(pipeline.backends.is_some());
    assert!(pipeline.middleware.is_some());
}

// ============================================================================
// Middleware Resource Tests
// ============================================================================

#[test]
fn test_middleware_with_options() {
    let middleware_json = json!({
        "type": "middleware",
        "id": "middleware-123",
        "code": "auth-middleware",
        "name": "Authentication Middleware",
        "team_id": "team-456",
        "middleware_type": "jwt",
        "options": {"issuer": "https://auth.example.com", "audience": "api"},
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let middleware: Middleware = serde_json::from_value(middleware_json).unwrap();

    assert_eq!(middleware.middleware_type, "jwt");
    assert!(middleware.options.is_some());

    let options = middleware.options.unwrap();
    assert_eq!(options["issuer"], "https://auth.example.com");
}

// ============================================================================
// Transform Resource Tests
// ============================================================================

#[test]
fn test_transform_with_instructions() {
    let transform_json = json!({
        "type": "transform",
        "id": "transform-123",
        "code": "user-transform",
        "name": "User Transform",
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "options": {
            "instructions": "Convert user format from v1 to v2"
        },
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let transform: Transform = serde_json::from_value(transform_json).unwrap();

    assert_eq!(transform.code, "user-transform");
    assert!(transform.options.is_some());
}

// ============================================================================
// Policy Resource Tests
// ============================================================================

#[test]
fn test_policy_with_rules() {
    // v1.7.0 format: rules is an array of rule IDs (strings)
    let policy_json = json!({
        "type": "policy",
        "id": "policy-123",
        "code": "rate-limit",
        "name": "Rate Limiting Policy",
        "enabled": 1,
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "rules": ["rate_limit_rule_1", "rate_limit_rule_2"],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let policy: Policy = serde_json::from_value(policy_json).unwrap();

    assert_eq!(policy.enabled, 1);
    assert!(policy.rules.is_some());

    let rules = policy.rules.unwrap();
    // v1.7.0: rules is a typed PolicyRules struct containing an array of rule IDs
    assert_eq!(rules.rules().len(), 2);
    assert_eq!(rules.rules()[0], "rate_limit_rule_1");
    assert_eq!(rules.rules()[1], "rate_limit_rule_2");
}

// ============================================================================
// Network Resource Tests
// ============================================================================

#[test]
fn test_network_with_tcp_config() {
    let network_json = json!({
        "type": "network",
        "id": "network-123",
        "code": "main-network",
        "name": "Main Network",
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "enable_wireguard": true,
        "interface": "wg0",
        "tcp_config": {
            "bind_address": "0.0.0.0",
            "bind_port": 8080
        },
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let network: Network = serde_json::from_value(network_json).unwrap();

    assert_eq!(network.enable_wireguard, true);
    assert_eq!(network.interface, Some("wg0".to_string()));
    assert!(network.tcp_config.is_some());

    let tcp_config = network.tcp_config.unwrap();
    assert_eq!(tcp_config.bind_address, Some("0.0.0.0".to_string()));
    assert_eq!(tcp_config.bind_port, Some(8080));
}

#[test]
fn test_network_with_http_backward_compatibility() {
    // Test that the old "http" field name still works via serde alias
    let network_json = json!({
        "type": "network",
        "id": "network-123",
        "code": "main-network",
        "name": "Main Network",
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "enable_wireguard": false,
        "http": {
            "bind_address": "127.0.0.1",
            "bind_port": 3000
        },
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let network: Network = serde_json::from_value(network_json).unwrap();

    // Old "http" field should be deserialized into tcp_config
    assert!(network.tcp_config.is_some());

    let tcp_config = network.tcp_config.unwrap();
    assert_eq!(tcp_config.bind_address, Some("127.0.0.1".to_string()));
    assert_eq!(tcp_config.bind_port, Some(3000));
}

// ============================================================================
// Authentication Resource Tests
// ============================================================================

#[test]
fn test_authentication_resource() {
    let auth_json = json!({
        "type": "authentication",
        "id": "auth-123",
        "code": "jwt-auth",
        "name": "JWT Authentication",
        "team_id": "team-456",
        "gateway_id": "gateway-789",
        "options": "{\"issuer\": \"https://auth.example.com\"}",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    });

    let auth: Authentication = serde_json::from_value(auth_json).unwrap();

    assert_eq!(auth.name, "JWT Authentication");
    assert!(auth.options.is_some());
}

// ============================================================================
// Response Wrapper Tests
// ============================================================================

#[test]
fn test_paginated_response() {
    let response_json = json!({
        "data": [
            {"type": "gateway", "code": "gw1", "name": "Gateway 1", "team_id": "team-1"},
            {"type": "gateway", "code": "gw2", "name": "Gateway 2", "team_id": "team-1"}
        ],
        "links": {
            "first": "https://api.example.com?page=1",
            "last": "https://api.example.com?page=5",
            "prev": null,
            "next": "https://api.example.com?page=2"
        },
        "meta": {
            "current_page": 1,
            "from": 1,
            "last_page": 5,
            "path": "https://api.example.com",
            "per_page": 50,
            "to": 2,
            "total": 250
        }
    });

    let response: PaginatedResponse<Gateway> = serde_json::from_value(response_json).unwrap();

    assert_eq!(response.data.len(), 2);
    let meta = response.meta.unwrap();
    assert_eq!(meta.total, 250);
    assert_eq!(meta.current_page, 1);
    let links = response.links.unwrap();
    assert_eq!(
        links.next,
        Some("https://api.example.com?page=2".to_string())
    );
}

#[test]
fn test_paginated_response_empty() {
    let response_json = json!({
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
            "path": "https://api.example.com",
            "per_page": 50,
            "to": null,
            "total": 0
        }
    });

    let response: PaginatedResponse<Gateway> = serde_json::from_value(response_json).unwrap();

    assert_eq!(response.data.len(), 0);
    let meta = response.meta.unwrap();
    assert_eq!(meta.total, 0);
    assert!(meta.from.is_none());
    assert!(meta.to.is_none());
}

#[test]
fn test_resource_response() {
    let response_json = json!({
        "data": {
            "type": "service",
            "code": "test-service",
            "name": "Test Service",
            "team_id": "team-123",
            "gateway_id": "gateway-456"
        }
    });

    let response: ResourceResponse<Service> = serde_json::from_value(response_json).unwrap();

    assert_eq!(response.data.code, "test-service");
    assert_eq!(response.data.name, "Test Service");
}

// ============================================================================
// Change Resource Tests
// ============================================================================

#[test]
fn test_change_with_all_fields() {
    let change_json = json!({
        "id": "change-123",
        "type": "change",
        "gateway_id": "gateway-456",
        "status": "pending",
        "pipeline_id": "pipeline-789",
        "created_at": "2024-10-31T00:00:00Z"
    });

    let change: Change = serde_json::from_value(change_json).unwrap();

    assert_eq!(change.id, "change-123");
    assert_eq!(change.status, Some("pending".to_string()));
    assert_eq!(change.gateway_id, "gateway-456");
    assert_eq!(change.pipeline_id, Some("pipeline-789".to_string()));
    assert_eq!(change.resource_type, "change");
}

#[test]
fn test_change_with_error() {
    let change_json = json!({
        "id": "change-456",
        "type": "change",
        "gateway_id": "gateway-789",
        "status": "failed",
        "pipeline_id": "pipeline-001",
        "error_message": "Connection timeout after 30 seconds",
        "created_at": "2024-10-31T00:00:00Z"
    });

    let change: Change = serde_json::from_value(change_json).unwrap();

    assert_eq!(change.status, Some("failed".to_string()));
    assert_eq!(
        change.error_message,
        Some("Connection timeout after 30 seconds".to_string())
    );
}

#[test]
fn test_change_basic_structure() {
    let change_json = json!({
        "id": "change-001",
        "type": "change",
        "gateway_id": "gateway-123",
        "status": "pending",
        "created_at": "2024-10-31T00:00:00Z"
    });

    let change: Change = serde_json::from_value(change_json).unwrap();
    assert_eq!(change.id, "change-001");
    assert_eq!(change.gateway_id, "gateway-123");
    assert_eq!(change.status, Some("pending".to_string()));
    assert_eq!(change.resource_type, "change");
}

// ============================================================================
// Gateway Configuration Tests
// ============================================================================

#[test]
fn test_gateway_configuration_full() {
    let config_json = json!({
        "gateway": {
            "type": "gateway",
            "code": "main-gw",
            "name": "Main Gateway",
            "team_id": "team-123"
        },
        "services": [
            {"type": "service", "code": "svc1", "name": "Service 1", "team_id": "team-123", "gateway_id": "gw1"}
        ],
        "endpoints": [
            {"type": "endpoint", "code": "ep1", "name": "Endpoint 1", "team_id": "team-123"}
        ],
        "backends": [],
        "pipelines": [],
        "middlewares": [],
        "transforms": [],
        "policies": [],
        "networks": []
    });

    let config: GatewayConfiguration = serde_json::from_value(config_json).unwrap();

    assert_eq!(config.gateway.code, "main-gw");
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.endpoints.len(), 1);
    assert_eq!(config.backends.len(), 0);
}

// ============================================================================
// Helper Struct Tests
// ============================================================================

#[test]
fn test_base_url_response() {
    let response_json = json!({
        "base_url": "https://api.runbeam.io"
    });

    let response: BaseUrlResponse = serde_json::from_value(response_json).unwrap();
    assert_eq!(response.base_url, "https://api.runbeam.io");
}

#[test]
fn test_acknowledge_changes_request() {
    let request = AcknowledgeChangesRequest {
        change_ids: vec!["change-1".to_string(), "change-2".to_string()],
    };

    let json = serde_json::to_value(&request).unwrap();
    assert!(json["change_ids"].is_array());
    assert_eq!(json["change_ids"].as_array().unwrap().len(), 2);
}

#[test]
fn test_change_failed_request_with_details() {
    let request = ChangeFailedRequest {
        error: "Configuration error".to_string(),
        details: Some(vec!["Invalid field".to_string()]),
    };

    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["error"], "Configuration error");
    assert!(json["details"].is_array());
}

#[test]
fn test_change_failed_request_without_details() {
    let request = ChangeFailedRequest {
        error: "Unknown error".to_string(),
        details: None,
    };

    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["error"], "Unknown error");
    // details should be omitted when None
    assert!(json.get("details").is_none());
}
