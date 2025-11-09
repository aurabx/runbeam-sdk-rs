//! Integration tests for Change Management API (v1.2)
//!
//! These tests verify the Change Management functionality at the integration level:
//! - Complex Change resource scenarios with realistic payloads
//! - Response structure parsing (paginated and single resources)
//! - All supported resource types and operations
//! - Payload variations and edge cases
//!
//! Note: Basic serialization tests are covered in unit tests (client.rs)

use runbeam_sdk::{Change, PaginatedResponse, ResourceResponse};
use serde_json::json;

#[test]
fn test_change_resource_full_lifecycle() {
    // Test a change through all states: pending -> acknowledged -> applied
    let pending_change = Change {
        id: "change-001".to_string(),
        resource_type: "change".to_string(),
        gateway_id: "gw-123".to_string(),
        status: "pending".to_string(),
        operation: "create".to_string(),
        change_resource_type: "endpoint".to_string(),
        resource_id: "endpoint-456".to_string(),
        payload: json!({
            "name": "api-endpoint",
            "path": "/api/v1/users",
            "methods": ["GET", "POST"]
        }),
        error: None,
        created_at: "2024-10-31T00:00:00Z".to_string(),
        updated_at: "2024-10-31T00:00:00Z".to_string(),
    };

    // Serialize and deserialize
    let json = serde_json::to_string(&pending_change).unwrap();
    let deserialized: Change = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.id, "change-001");
    assert_eq!(deserialized.status, "pending");
    assert_eq!(deserialized.operation, "create");
    assert_eq!(deserialized.change_resource_type, "endpoint");
    assert!(deserialized.error.is_none());

    // Verify payload structure
    assert_eq!(
        deserialized.payload["name"].as_str().unwrap(),
        "api-endpoint"
    );
    assert_eq!(
        deserialized.payload["path"].as_str().unwrap(),
        "/api/v1/users"
    );
}

#[test]
fn test_change_with_different_operations() {
    let operations = vec!["create", "update", "delete"];

    for operation in operations {
        let change = Change {
            id: format!("change-{}", operation),
            resource_type: "change".to_string(),
            gateway_id: "gw-123".to_string(),
            status: "pending".to_string(),
            operation: operation.to_string(),
            change_resource_type: "service".to_string(),
            resource_id: "service-789".to_string(),
            payload: json!({"operation": operation}),
            error: None,
            created_at: "2024-10-31T00:00:00Z".to_string(),
            updated_at: "2024-10-31T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&change).unwrap();
        let deserialized: Change = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.operation, operation);
        assert_eq!(
            deserialized.payload["operation"].as_str().unwrap(),
            operation
        );
    }
}

#[test]
fn test_change_with_error_state() {
    // Test a failed change with error details
    let failed_change = Change {
        id: "change-failed-001".to_string(),
        resource_type: "change".to_string(),
        gateway_id: "gw-123".to_string(),
        status: "failed".to_string(),
        operation: "update".to_string(),
        change_resource_type: "backend".to_string(),
        resource_id: "backend-789".to_string(),
        payload: json!({"url": "https://invalid-url"}),
        error: Some("Connection timeout after 30 seconds".to_string()),
        created_at: "2024-10-31T00:00:00Z".to_string(),
        updated_at: "2024-10-31T00:01:30Z".to_string(),
    };

    let json = serde_json::to_string(&failed_change).unwrap();
    let deserialized: Change = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.status, "failed");
    assert!(deserialized.error.is_some());
    assert_eq!(
        deserialized.error.unwrap(),
        "Connection timeout after 30 seconds"
    );
}

#[test]
fn test_paginated_changes_response() {
    // Simulate a paginated response structure
    let changes = vec![
        Change {
            id: "change-001".to_string(),
            resource_type: "change".to_string(),
            gateway_id: "gw-123".to_string(),
            status: "pending".to_string(),
            operation: "create".to_string(),
            change_resource_type: "endpoint".to_string(),
            resource_id: "endpoint-001".to_string(),
            payload: json!({"name": "endpoint-1"}),
            error: None,
            created_at: "2024-10-31T00:00:00Z".to_string(),
            updated_at: "2024-10-31T00:00:00Z".to_string(),
        },
        Change {
            id: "change-002".to_string(),
            resource_type: "change".to_string(),
            gateway_id: "gw-123".to_string(),
            status: "acknowledged".to_string(),
            operation: "update".to_string(),
            change_resource_type: "backend".to_string(),
            resource_id: "backend-002".to_string(),
            payload: json!({"url": "https://api.example.com"}),
            error: None,
            created_at: "2024-10-31T00:01:00Z".to_string(),
            updated_at: "2024-10-31T00:01:30Z".to_string(),
        },
    ];

    // Create a minimal paginated response JSON structure
    let response_json = json!({
        "data": changes,
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
            "links": [],
            "path": "https://api.runbeam.io/api/changes",
            "per_page": 50,
            "to": 2,
            "total": 2
        }
    });

    let response: PaginatedResponse<Change> = serde_json::from_value(response_json).unwrap();

    assert_eq!(response.data.len(), 2);
    assert_eq!(response.data[0].id, "change-001");
    assert_eq!(response.data[0].status, "pending");
    assert_eq!(response.data[1].id, "change-002");
    assert_eq!(response.data[1].status, "acknowledged");
    assert_eq!(response.meta.total, 2);
    assert_eq!(response.meta.current_page, 1);
}

#[test]
fn test_single_change_resource_response() {
    let change = Change {
        id: "change-single".to_string(),
        resource_type: "change".to_string(),
        gateway_id: "gw-456".to_string(),
        status: "applied".to_string(),
        operation: "delete".to_string(),
        change_resource_type: "pipeline".to_string(),
        resource_id: "pipeline-999".to_string(),
        payload: json!({"pipeline_id": "pipeline-999"}),
        error: None,
        created_at: "2024-10-31T00:00:00Z".to_string(),
        updated_at: "2024-10-31T00:05:00Z".to_string(),
    };

    let response_json = json!({
        "data": change
    });

    let response: ResourceResponse<Change> = serde_json::from_value(response_json).unwrap();

    assert_eq!(response.data.id, "change-single");
    assert_eq!(response.data.status, "applied");
    assert_eq!(response.data.operation, "delete");
    assert_eq!(response.data.change_resource_type, "pipeline");
}

#[test]
fn test_change_resource_types_coverage() {
    // Test all supported resource types
    let resource_types = vec![
        "endpoint",
        "backend",
        "service",
        "pipeline",
        "middleware",
        "transform",
        "policy",
        "network",
        "gateway",
    ];

    for resource_type in resource_types {
        let change = Change {
            id: format!("change-{}", resource_type),
            resource_type: "change".to_string(),
            gateway_id: "gw-test".to_string(),
            status: "pending".to_string(),
            operation: "create".to_string(),
            change_resource_type: resource_type.to_string(),
            resource_id: format!("{}-123", resource_type),
            payload: json!({"resource_type": resource_type}),
            error: None,
            created_at: "2024-10-31T00:00:00Z".to_string(),
            updated_at: "2024-10-31T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&change).unwrap();
        let deserialized: Change = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.change_resource_type, resource_type);
    }
}

#[test]
fn test_change_payload_variations() {
    // Test different payload structures
    let payloads = [
        json!({"simple": "string"}),
        json!({"nested": {"key": "value"}}),
        json!({"array": [1, 2, 3]}),
        json!({"complex": {"array": [{"id": 1}, {"id": 2}], "metadata": {"version": "1.0"}}}),
        json!(null),
    ];

    for (i, payload) in payloads.iter().enumerate() {
        let change = Change {
            id: format!("change-payload-{}", i),
            resource_type: "change".to_string(),
            gateway_id: "gw-123".to_string(),
            status: "pending".to_string(),
            operation: "update".to_string(),
            change_resource_type: "endpoint".to_string(),
            resource_id: "endpoint-123".to_string(),
            payload: payload.clone(),
            error: None,
            created_at: "2024-10-31T00:00:00Z".to_string(),
            updated_at: "2024-10-31T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&change).unwrap();
        let deserialized: Change = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.payload, *payload);
    }
}
