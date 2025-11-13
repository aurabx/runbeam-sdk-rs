//! TOML configuration validation for Harmony Proxy.
//!
//! This module provides validation functionality for TOML configuration files
//! using the Harmony DSL schema definitions.
//!
//! # Examples
//!
//! ## Validating a config.toml file
//!
//! ```no_run
//! use runbeam_sdk::validation::validate_config_toml;
//!
//! let content = std::fs::read_to_string("config.toml").unwrap();
//! match validate_config_toml(&content) {
//!     Ok(()) => println!("Configuration is valid!"),
//!     Err(e) => eprintln!("Validation failed: {}", e),
//! }
//! ```
//!
//! ## Validating a pipeline.toml file
//!
//! ```no_run
//! use runbeam_sdk::validation::validate_pipeline_toml;
//!
//! let content = std::fs::read_to_string("pipelines/http.toml").unwrap();
//! match validate_pipeline_toml(&content) {
//!     Ok(()) => println!("Pipeline configuration is valid!"),
//!     Err(e) => eprintln!("Validation failed: {}", e),
//! }
//! ```
//!
//! ## Validating with a custom schema
//!
//! ```no_run
//! use runbeam_sdk::validation::validate_toml;
//!
//! let schema = r#"
//! [schema]
//! version = "1.0"
//! description = "Custom schema"
//!
//! [[table]]
//! name = "app"
//! required = true
//!
//! [[table.field]]
//! name = "name"
//! type = "string"
//! required = true
//! "#;
//!
//! let content = r#"
//! [app]
//! name = "my-app"
//! "#;
//!
//! validate_toml(content, schema).unwrap();
//! ```

pub mod error;
pub mod schema;
pub mod validator;

pub use error::ValidationError;
pub use schema::{FieldDefinition, Schema, TableDefinition};

use harmony_dsl::{CONFIG_SCHEMA, PIPELINE_SCHEMA};

/// Validate a Harmony Proxy config.toml file.
///
/// This function validates the content against the CONFIG_SCHEMA from harmony-dsl,
/// which defines the structure for main gateway configuration files.
///
/// # Example
///
/// ```no_run
/// use runbeam_sdk::validation::validate_config_toml;
///
/// let content = r#"
/// [proxy]
/// id = "gateway-1"
///
/// [network.default]
/// bind_address = "0.0.0.0"
/// port = 8080
/// "#;
///
/// validate_config_toml(content).unwrap();
/// ```
///
/// # Errors
///
/// Returns a `ValidationError` if the configuration is invalid. The error will
/// contain detailed information about what validation rule failed and where.
pub fn validate_config_toml(content: &str) -> Result<(), ValidationError> {
    validator::validate(content, CONFIG_SCHEMA)
}

/// Validate a Harmony Proxy pipeline.toml file.
///
/// This function validates the content against the PIPELINE_SCHEMA from harmony-dsl,
/// which defines the structure for pipeline configuration files.
///
/// # Example
///
/// ```no_run
/// use runbeam_sdk::validation::validate_pipeline_toml;
///
/// let content = r#"
/// [pipelines.http_api]
/// networks = ["default"]
/// endpoints = ["http_endpoint"]
/// backends = ["api_backend"]
///
/// [endpoints.http_endpoint]
/// service = "http"
///
/// [backends.api_backend]
/// service = "http"
/// "#;
///
/// validate_pipeline_toml(content).unwrap();
/// ```
///
/// # Errors
///
/// Returns a `ValidationError` if the pipeline configuration is invalid.
pub fn validate_pipeline_toml(content: &str) -> Result<(), ValidationError> {
    validator::validate(content, PIPELINE_SCHEMA)
}

/// Validate TOML content against a custom schema.
///
/// This is a generic validation function that allows you to validate any TOML
/// content against any schema written in the Harmony DSL format.
///
/// # Example
///
/// ```
/// use runbeam_sdk::validation::validate_toml;
///
/// let schema = r#"
/// [schema]
/// version = "1.0"
/// description = "Application config"
///
/// [[table]]
/// name = "app"
/// required = true
///
/// [[table.field]]
/// name = "name"
/// type = "string"
/// required = true
///
/// [[table.field]]
/// name = "port"
/// type = "integer"
/// required = true
/// min = 1
/// max = 65535
/// "#;
///
/// let content = r#"
/// [app]
/// name = "my-application"
/// port = 8080
/// "#;
///
/// assert!(validate_toml(content, schema).is_ok());
/// ```
///
/// # Errors
///
/// Returns a `ValidationError` if:
/// - The schema TOML is invalid
/// - The content TOML is invalid
/// - The content doesn't match the schema validation rules
pub fn validate_toml(content: &str, schema: &str) -> Result<(), ValidationError> {
    validator::validate(content, schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_simple_config() {
        let schema = r#"
[schema]
version = "1.0"
description = "Simple config"

[[table]]
name = "app"
required = true

[[table.field]]
name = "name"
type = "string"
required = true
"#;

        let content = r#"
[app]
name = "test"
"#;

        assert!(validate_toml(content, schema).is_ok());
    }

    #[test]
    fn test_validate_missing_required() {
        let schema = r#"
[schema]
version = "1.0"
description = "Simple config"

[[table]]
name = "app"
required = true

[[table.field]]
name = "name"
type = "string"
required = true
"#;

        let content = r#"
[app]
"#;

        assert!(validate_toml(content, schema).is_err());
    }

    #[test]
    fn test_config_schema_available() {
        // Verify that CONFIG_SCHEMA from harmony-dsl is accessible
        assert!(!CONFIG_SCHEMA.is_empty());
        assert!(CONFIG_SCHEMA.contains("[schema]"));
    }

    #[test]
    fn test_pipeline_schema_available() {
        // Verify that PIPELINE_SCHEMA from harmony-dsl is accessible
        assert!(!PIPELINE_SCHEMA.is_empty());
        assert!(PIPELINE_SCHEMA.contains("[schema]"));
    }
}
