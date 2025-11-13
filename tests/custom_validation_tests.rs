//! Integration tests for custom schema validation using validate_toml()

use runbeam_sdk::{validate_toml, ValidationError};

#[test]
fn test_simple_custom_schema() {
    let schema = r#"
[schema]
version = "1.0"
description = "Simple application config"

[[table]]
name = "app"
required = true

[[table.field]]
name = "name"
type = "string"
required = true

[[table.field]]
name = "port"
type = "integer"
required = true
min = 1
max = 65535
"#;

    let content = r#"
[app]
name = "my-app"
port = 8080
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_ok(), "Valid content should pass validation");
}

#[test]
fn test_custom_schema_with_enums() {
    let schema = r#"
[schema]
version = "1.0"
description = "Config with enum"

[[table]]
name = "config"
required = true

[[table.field]]
name = "environment"
type = "string"
required = true
enum = ["development", "staging", "production"]

[[table.field]]
name = "log_level"
type = "string"
required = false
default = "info"
enum = ["debug", "info", "warn", "error"]
"#;

    let content = r#"
[config]
environment = "production"
log_level = "warn"
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_ok(), "Valid enum values should pass");
}

#[test]
fn test_custom_schema_invalid_enum() {
    let schema = r#"
[schema]
version = "1.0"
description = "Config with enum"

[[table]]
name = "config"
required = true

[[table.field]]
name = "environment"
type = "string"
required = true
enum = ["development", "staging", "production"]
"#;

    let content = r#"
[config]
environment = "invalid"
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_err(), "Invalid enum value should fail");
}

#[test]
fn test_custom_schema_with_arrays() {
    let schema = r#"
[schema]
version = "1.0"
description = "Config with arrays"

[[table]]
name = "service"
required = true

[[table.field]]
name = "hosts"
type = "array"
array_item_type = "string"
min_items = 1
max_items = 10
"#;

    let content = r#"
[service]
hosts = ["host1.example.com", "host2.example.com", "host3.example.com"]
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_ok(), "Valid array should pass");
}

#[test]
fn test_custom_schema_array_too_long() {
    let schema = r#"
[schema]
version = "1.0"
description = "Config with max array size"

[[table]]
name = "config"
required = true

[[table.field]]
name = "items"
type = "array"
array_item_type = "string"
max_items = 3
"#;

    let content = r#"
[config]
items = ["one", "two", "three", "four", "five"]
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_err(), "Array exceeding max_items should fail");
}

#[test]
fn test_custom_schema_with_pattern_tables() {
    let schema = r#"
[schema]
version = "1.0"
description = "Dynamic table names"

[[table]]
name = "database.*"
pattern = true
pattern_constraint = "^[a-z_]+$"

[[table.field]]
name = "host"
type = "string"
required = true

[[table.field]]
name = "port"
type = "integer"
required = true
"#;

    let content = r#"
[database.primary]
host = "db1.example.com"
port = 5432

[database.replica]
host = "db2.example.com"
port = 5432
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_ok(), "Pattern-matched tables should pass");
}

#[test]
fn test_custom_schema_pattern_constraint_violation() {
    let schema = r#"
[schema]
version = "1.0"
description = "Pattern constraint test"

[[table]]
name = "env.*"
pattern = true
pattern_constraint = "^[a-z]+$"

[[table.field]]
name = "value"
type = "string"
required = true
"#;

    let content = r#"
[env.INVALID_NAME]
value = "test"
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_err(), "Pattern constraint violation should fail");
}

#[test]
fn test_custom_schema_with_conditionals() {
    let schema = r#"
[schema]
version = "1.0"
description = "Conditional requirements"

[[table]]
name = "server"
required = true

[[table.field]]
name = "ssl_enabled"
type = "boolean"
required = false

[[table.field]]
name = "ssl_cert_path"
type = "string"
required = false
required_if = "ssl_enabled == true"

[[table.field]]
name = "ssl_key_path"
type = "string"
required = false
required_if = "ssl_enabled == true"
"#;

    // Valid: SSL disabled, no cert/key needed
    let content1 = r#"
[server]
ssl_enabled = false
"#;
    assert!(validate_toml(content1, schema).is_ok());

    // Valid: SSL enabled with cert and key
    let content2 = r#"
[server]
ssl_enabled = true
ssl_cert_path = "/etc/ssl/cert.pem"
ssl_key_path = "/etc/ssl/key.pem"
"#;
    assert!(validate_toml(content2, schema).is_ok());

    // Invalid: SSL enabled without cert/key
    let content3 = r#"
[server]
ssl_enabled = true
"#;
    assert!(validate_toml(content3, schema).is_err());
}

#[test]
fn test_custom_schema_nested_tables() {
    let schema = r#"
[schema]
version = "1.0"
description = "Nested configuration"

[[table]]
name = "app"
required = true

[[table.field]]
name = "database.host"
type = "string"
required = true

[[table.field]]
name = "database.port"
type = "integer"
required = true

[[table.field]]
name = "cache.enabled"
type = "boolean"
required = false
"#;

    let content = r#"
[app.database]
host = "localhost"
port = 5432

[app.cache]
enabled = true
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_ok(), "Nested fields should validate correctly");
}

#[test]
fn test_custom_schema_numeric_ranges() {
    let schema = r#"
[schema]
version = "1.0"
description = "Numeric validation"

[[table]]
name = "limits"
required = true

[[table.field]]
name = "max_connections"
type = "integer"
min = 1
max = 1000

[[table.field]]
name = "timeout_seconds"
type = "integer"
min = 0
"#;

    // Valid values
    let content = r#"
[limits]
max_connections = 500
timeout_seconds = 30
"#;
    assert!(validate_toml(content, schema).is_ok());

    // Out of range
    let invalid = r#"
[limits]
max_connections = 2000
timeout_seconds = 30
"#;
    assert!(validate_toml(invalid, schema).is_err());
}

#[test]
fn test_custom_schema_all_field_types() {
    let schema = r#"
[schema]
version = "1.0"
description = "All field types"

[[table]]
name = "types"
required = true

[[table.field]]
name = "str_field"
type = "string"

[[table.field]]
name = "int_field"
type = "integer"

[[table.field]]
name = "bool_field"
type = "boolean"

[[table.field]]
name = "float_field"
type = "float"

[[table.field]]
name = "array_field"
type = "array"

[[table.field]]
name = "table_field"
type = "table"
"#;

    let content = r#"
[types]
str_field = "hello"
int_field = 42
bool_field = true
float_field = 3.14
array_field = [1, 2, 3]

[types.table_field]
nested = "value"
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_ok(), "All field types should validate");
}

#[test]
fn test_invalid_schema() {
    // Schema without required metadata
    let invalid_schema = r#"
[[table]]
name = "app"
"#;

    let content = r#"
[app]
name = "test"
"#;

    let result = validate_toml(content, invalid_schema);
    assert!(result.is_err(), "Invalid schema should cause error");
    
    match result.unwrap_err() {
        ValidationError::SchemaParseError(_) => {
            // Expected error type
        }
        _ => panic!("Expected SchemaParseError"),
    }
}

#[test]
fn test_multiple_validation_errors() {
    let schema = r#"
[schema]
version = "1.0"
description = "Test multiple errors"

[[table]]
name = "config"
required = true

[[table.field]]
name = "name"
type = "string"
required = true

[[table.field]]
name = "port"
type = "integer"
required = true
min = 1
max = 100
"#;

    // Content with multiple errors
    let content = r#"
[config]
port = 999
"#;

    let result = validate_toml(content, schema);
    assert!(result.is_err(), "Multiple errors should be caught");
}

#[test]
fn test_pattern_field_validation() {
    let schema = r#"
[schema]
version = "1.0"
description = "Field pattern validation"

[[table]]
name = "user"
required = true

[[table.field]]
name = "email"
type = "string"
required = true
pattern_constraint = "^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$"
"#;

    // Valid email
    let valid_content = r#"
[user]
email = "test@example.com"
"#;
    assert!(validate_toml(valid_content, schema).is_ok());

    // Invalid email
    let invalid_content = r#"
[user]
email = "not-an-email"
"#;
    assert!(validate_toml(invalid_content, schema).is_err());
}
