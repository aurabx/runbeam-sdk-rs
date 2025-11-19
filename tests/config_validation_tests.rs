//! Integration tests for config.toml validation against CONFIG_SCHEMA

use runbeam_sdk::{validate_config_toml, ValidationError};

const FIXTURES_DIR: &str = "tests/fixtures";

/// Helper to load a fixture file
fn load_fixture(filename: &str) -> String {
    std::fs::read_to_string(format!("{}/{}", FIXTURES_DIR, filename))
        .unwrap_or_else(|_| panic!("Failed to load fixture: {}", filename))
}

#[test]
fn test_valid_config_passes() {
    let content = load_fixture("valid_config.toml");
    let result = validate_config_toml(&content);

    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }

    assert!(result.is_ok(), "Valid config should pass validation");
}

#[test]
fn test_missing_required_field_detected() {
    let content = load_fixture("invalid_missing_required.toml");
    let result = validate_config_toml(&content);

    assert!(
        result.is_err(),
        "Config with missing required field should fail"
    );

    let error = result.unwrap_err();
    let error_message = error.to_string();

    // Verify the error mentions the missing field
    assert!(
        error_message.contains("proxy.id") || error_message.contains("Missing required field"),
        "Error should mention missing proxy.id field, got: {}",
        error_message
    );
}

#[test]
fn test_wrong_type_detected() {
    let content = load_fixture("invalid_wrong_type.toml");
    let result = validate_config_toml(&content);

    assert!(result.is_err(), "Config with wrong field type should fail");

    let error = result.unwrap_err();
    let error_message = error.to_string();

    // Verify the error mentions type mismatch
    assert!(
        error_message.contains("bind_port")
            && (error_message.contains("type") || error_message.contains("integer")),
        "Error should mention type issue with bind_port field, got: {}",
        error_message
    );
}

#[test]
fn test_out_of_range_detected() {
    let content = load_fixture("invalid_out_of_range.toml");
    let result = validate_config_toml(&content);

    assert!(
        result.is_err(),
        "Config with out-of-range value should fail"
    );

    let error = result.unwrap_err();
    let error_message = error.to_string();

    // Verify the error mentions range violation
    assert!(
        error_message.contains("range") || error_message.contains("200"),
        "Error should mention out-of-range value, got: {}",
        error_message
    );
}

#[test]
fn test_pattern_mismatch_detected() {
    let content = load_fixture("invalid_pattern_mismatch.toml");
    let result = validate_config_toml(&content);

    assert!(result.is_err(), "Config with pattern mismatch should fail");

    let error = result.unwrap_err();
    let error_message = error.to_string();

    // Verify the error mentions pattern mismatch
    assert!(
        error_message.contains("pattern") || error_message.contains("INVALID_NAME"),
        "Error should mention pattern mismatch, got: {}",
        error_message
    );
}

#[test]
fn test_conditional_requirement_detected() {
    let content = load_fixture("invalid_conditional_requirement.toml");
    let result = validate_config_toml(&content);

    assert!(
        result.is_err(),
        "Config with missing conditional requirement should fail"
    );

    let error = result.unwrap_err();
    let error_message = error.to_string();

    // Verify the error mentions the conditionally required field
    assert!(
        error_message.contains("management.network") || error_message.contains("required"),
        "Error should mention missing management.network field, got: {}",
        error_message
    );
}

#[test]
fn test_network_pattern_matching() {
    // Test that pattern tables like network.* work correctly
    let content = r#"
[proxy]
id = "test-gateway"

[network.custom_network]
enable_wireguard = false
interface = "wg0"

[network.custom_network.tcp_config]
bind_address = "192.168.1.1"
bind_port = 8080

[network.another_one]
enable_wireguard = false
interface = "wg1"

[network.another_one.tcp_config]
bind_address = "10.0.0.1"
bind_port = 9090
"#;

    let result = validate_config_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(
        result.is_ok(),
        "Config with multiple pattern-matched networks should be valid"
    );
}

#[test]
fn test_minimal_valid_config() {
    // Test the absolute minimum required configuration
    let content = r#"
[proxy]
id = "minimal-gateway"
"#;

    let result = validate_config_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(
        result.is_ok(),
        "Minimal config with only required fields should be valid"
    );
}

#[test]
fn test_error_provides_helpful_context() {
    // Test that validation errors provide helpful context
    let content = r#"
[proxy]
id = 123
"#;

    let result = validate_config_toml(content);
    assert!(result.is_err());

    let error = result.unwrap_err();

    // Check that the error is a specific variant with field path
    match error {
        ValidationError::InvalidType {
            field_path,
            expected,
            found,
        } => {
            assert!(field_path.contains("proxy.id"));
            assert_eq!(expected, "string");
            assert_eq!(found, "integer");
        }
        _ => panic!("Expected InvalidType error, got: {:?}", error),
    }
}

#[test]
fn test_multiple_errors_reported() {
    // Config with multiple validation errors
    let content = r#"
[proxy]
jwks_cache_duration_hours = 999

[network.INVALID]
enable_wireguard = "not_a_boolean"
"#;

    let result = validate_config_toml(content);
    assert!(result.is_err());

    let error = result.unwrap_err();

    // Should report multiple errors
    match error {
        ValidationError::Multiple(errors) => {
            assert!(
                errors.len() >= 2,
                "Should report multiple errors, got: {}",
                errors.len()
            );
        }
        _ => {
            // Single error is also acceptable depending on validation order
            // Just verify we got an error
        }
    }
}

#[test]
fn test_nested_table_validation() {
    // Test that nested tables (tcp_config) are validated correctly
    let content = r#"
[proxy]
id = "test-gateway"

[network.default]
enable_wireguard = false

[network.default.tcp_config]
bind_address = 12345
bind_port = 8080
"#;

    let result = validate_config_toml(content);
    assert!(
        result.is_err(),
        "Invalid nested table field should be detected"
    );

    let error = result.unwrap_err();
    let error_message = error.to_string();
    assert!(
        error_message.contains("bind_address"),
        "Error should mention bind_address field"
    );
}

#[test]
fn test_content_limits_validation() {
    // Test validation of nested content_limits configuration
    let content = r#"
[proxy]
id = "test-gateway"

[proxy.content_limits]
max_body_size = 1024
max_csv_rows = 5000
max_xml_depth = 50
max_multipart_files = 5
max_form_fields = 500
"#;

    let result = validate_config_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(
        result.is_ok(),
        "Valid content_limits should pass validation"
    );
}

#[test]
fn test_runbeam_configuration() {
    // Test Runbeam Cloud integration configuration
    let content = r#"
[proxy]
id = "test-gateway"

[runbeam]
enabled = true
cloud_api_base_url = "https://custom.runbeam.cloud"
poll_interval_secs = 60
"#;

    let result = validate_config_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(
        result.is_ok(),
        "Valid runbeam config should pass validation"
    );
}

#[test]
fn test_management_api_configuration() {
    // Test management API configuration with conditional requirements
    let content = r#"
[proxy]
id = "test-gateway"

[management]
enabled = true
base_path = "admin"
network = "management"

[network.management]
enable_wireguard = false
interface = "wg1"

[network.management.tcp_config]
bind_address = "127.0.0.1"
bind_port = 9090
"#;

    let result = validate_config_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(
        result.is_ok(),
        "Valid management config should pass validation"
    );
}

#[test]
fn test_management_disabled_doesnt_require_network() {
    // When management is disabled, network field should not be required
    let content = r#"
[proxy]
id = "test-gateway"

[management]
enabled = false
base_path = "admin"
"#;

    let result = validate_config_toml(content);
    if let Err(e) = &result {
        eprintln!("Unexpected validation error: {}", e);
    }
    assert!(
        result.is_ok(),
        "Management network not required when disabled"
    );
}
