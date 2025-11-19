//! Integration tests for pipeline.toml validation against PIPELINE_SCHEMA

use runbeam_sdk::validate_pipeline_toml;

const FIXTURES_DIR: &str = "tests/fixtures";

/// Helper to load a fixture file
fn load_fixture(filename: &str) -> String {
    std::fs::read_to_string(format!("{}/{}", FIXTURES_DIR, filename))
        .unwrap_or_else(|_| panic!("Failed to load fixture: {}", filename))
}

#[test]
fn test_valid_pipeline_passes() {
    let content = load_fixture("valid_pipeline.toml");
    let result = validate_pipeline_toml(&content);

    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }

    assert!(result.is_ok(), "Valid pipeline should pass validation");
}

#[test]
fn test_invalid_array_length() {
    let content = load_fixture("invalid_array_length.toml");
    let result = validate_pipeline_toml(&content);

    assert!(
        result.is_err(),
        "Pipeline with empty networks array should fail"
    );

    let error = result.unwrap_err();
    let error_message = error.to_string();

    assert!(
        error_message.contains("networks") || error_message.contains("array"),
        "Error should mention networks array issue, got: {}",
        error_message
    );
}

#[test]
fn test_minimal_valid_pipeline() {
    let content = r#"
[pipelines.minimal]
networks = ["default"]
endpoints = ["ep1"]
backends = ["be1"]

[endpoints.ep1]
service = "http"

[backends.be1]
service = "http"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Minimal pipeline should be valid");
}

#[test]
fn test_multiple_pipelines() {
    let content = r#"
[pipelines.http_api]
networks = ["default"]
endpoints = ["http_ep"]
backends = ["http_be"]

[pipelines.dicom_scp]
networks = ["dicom"]
endpoints = ["dicom_ep"]
backends = ["dicom_be"]

[endpoints.http_ep]
service = "http"

[endpoints.dicom_ep]
service = "dicom"

[backends.http_be]
service = "http"

[backends.dicom_be]
service = "dicom"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Multiple pipelines should be valid");
}

#[test]
fn test_pipeline_with_middleware() {
    let content = r#"
[pipelines.api]
networks = ["default"]
endpoints = ["ep"]
middleware = ["auth", "transform"]
backends = ["be"]

[endpoints.ep]
service = "http"

[middleware.auth]
type = "jwt_auth"

[middleware.transform]
type = "jolt_transform"

[backends.be]
service = "http"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Pipeline with middleware should be valid");
}

#[test]
fn test_endpoint_with_options() {
    let content = r#"
[pipelines.http]
networks = ["default"]
endpoints = ["http_ep"]
backends = ["http_be"]

[endpoints.http_ep]
service = "http"

[endpoints.http_ep.options]
path_prefix = "/api/v1"

[backends.http_be]
service = "http"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Endpoint with options should be valid");
}

#[test]
fn test_backend_with_options() {
    let content = r#"
[pipelines.http]
networks = ["default"]
endpoints = ["http_ep"]
backends = ["http_be"]

[endpoints.http_ep]
service = "http"

[backends.http_be]
service = "http"

[backends.http_be.options]
base_url = "http://localhost:3000"
path_prefix = "/v1"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Backend with options should be valid");
}

#[test]
fn test_missing_required_pipeline_field() {
    let content = r#"
[pipelines.incomplete]
networks = ["default"]
endpoints = ["ep"]
# Missing required field: backends

[endpoints.ep]
service = "http"
"#;

    let result = validate_pipeline_toml(content);
    assert!(
        result.is_err(),
        "Pipeline missing required field should fail"
    );

    let error = result.unwrap_err();
    let error_message = error.to_string();
    assert!(
        error_message.contains("backends") || error_message.contains("required"),
        "Error should mention missing backends field"
    );
}

#[test]
fn test_missing_endpoint_service() {
    let content = r#"
[pipelines.test]
networks = ["default"]
endpoints = ["ep"]
backends = ["be"]

[endpoints.ep]
# Missing required field: service

[backends.be]
service = "http"
"#;

    let result = validate_pipeline_toml(content);
    assert!(result.is_err(), "Endpoint missing service should fail");
}

#[test]
fn test_missing_backend_service() {
    let content = r#"
[pipelines.test]
networks = ["default"]
endpoints = ["ep"]
backends = ["be"]

[endpoints.ep]
service = "http"

[backends.be]
# Missing required field: service
"#;

    let result = validate_pipeline_toml(content);
    assert!(result.is_err(), "Backend missing service should fail");
}

#[test]
fn test_pipeline_pattern_matching() {
    // Test that pattern matching works for pipelines.*, endpoints.*, backends.*, middleware.*
    let content = r#"
[pipelines.custom_pipeline_name]
networks = ["net1", "net2"]
endpoints = ["custom_endpoint"]
backends = ["custom_backend"]
middleware = ["custom_middleware"]

[endpoints.custom_endpoint]
service = "http"

[backends.custom_backend]
service = "http"

[middleware.custom_middleware]
type = "transform"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Custom named tables should match patterns");
}

#[test]
fn test_dicom_endpoint_with_options() {
    let content = r#"
[pipelines.dicom]
networks = ["dicom_net"]
endpoints = ["dicom_ep"]
backends = ["dicom_be"]

[endpoints.dicom_ep]
service = "dicom"

[endpoints.dicom_ep.options]
aet = "DICOM_SCP"
port = 11112

[backends.dicom_be]
service = "dicom"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(
        result.is_ok(),
        "DICOM endpoint with options should be valid"
    );
}

#[test]
fn test_dicom_backend_with_options() {
    let content = r#"
[pipelines.dicom]
networks = ["dicom_net"]
endpoints = ["dicom_ep"]
backends = ["dicom_be"]

[endpoints.dicom_ep]
service = "dicom"

[backends.dicom_be]
service = "dicom"

[backends.dicom_be.options]
aet = "REMOTE_SCP"
host = "pacs.example.com"
port = 11112
local_aet = "LOCAL_SCU"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "DICOM backend with options should be valid");
}

#[test]
fn test_middleware_with_options() {
    let content = r#"
[pipelines.api]
networks = ["default"]
endpoints = ["ep"]
middleware = ["auth"]
backends = ["be"]

[endpoints.ep]
service = "http"

[middleware.auth]
type = "jwt_auth"

[middleware.auth.options]
issuer = "https://auth.example.com"
audience = "api.example.com"

[backends.be]
service = "http"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Middleware with options should be valid");
}

#[test]
fn test_array_field_validation() {
    // Test that array fields with correct item types are accepted
    let content = r#"
[pipelines.multi]
networks = ["net1", "net2", "net3"]
endpoints = ["ep1", "ep2"]
backends = ["be1", "be2", "be3"]
middleware = ["mw1"]

[endpoints.ep1]
service = "http"

[endpoints.ep2]
service = "http"

[backends.be1]
service = "http"

[backends.be2]
service = "http"

[backends.be3]
service = "http"

[middleware.mw1]
type = "transform"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Multiple items in arrays should be valid");
}

#[test]
fn test_pipeline_description() {
    let content = r#"
[pipelines.documented]
description = "This is a well-documented pipeline"
networks = ["default"]
endpoints = ["ep"]
backends = ["be"]

[endpoints.ep]
service = "http"

[backends.be]
service = "http"
"#;

    let result = validate_pipeline_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(result.is_ok(), "Pipeline with description should be valid");
}
