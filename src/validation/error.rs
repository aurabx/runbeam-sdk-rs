//! Validation error types for TOML configuration validation.
//!
//! This module defines error types used when validating TOML configurations
//! against schema definitions.

use std::fmt;

/// Errors that can occur during TOML validation.
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// A required field is missing from the configuration.
    MissingRequiredField {
        /// The path to the missing field (e.g., "proxy.id" or "network.default.bind_address").
        field_path: String,
    },

    /// A field has an invalid type.
    InvalidType {
        /// The path to the field with the wrong type.
        field_path: String,
        /// The expected type according to the schema.
        expected: String,
        /// The actual type found in the TOML.
        found: String,
    },

    /// A field value is not one of the allowed enum values.
    InvalidEnumValue {
        /// The path to the field with the invalid value.
        field_path: String,
        /// The value that was found.
        value: String,
        /// The list of allowed values.
        allowed: Vec<String>,
    },

    /// A numeric value is outside the allowed range.
    OutOfRange {
        /// The path to the field that is out of range.
        field_path: String,
        /// The value that was found.
        value: String,
        /// The minimum allowed value, if specified.
        min: Option<String>,
        /// The maximum allowed value, if specified.
        max: Option<String>,
    },

    /// An array has an invalid number of items.
    InvalidArrayLength {
        /// The path to the array field.
        field_path: String,
        /// The actual length of the array.
        length: usize,
        /// The minimum required length, if specified.
        min: Option<usize>,
        /// The maximum allowed length, if specified.
        max: Option<usize>,
    },

    /// A field value does not match the required pattern.
    PatternMismatch {
        /// The path to the field with the pattern mismatch.
        field_path: String,
        /// The pattern that should have been matched.
        pattern: String,
    },

    /// A conditionally required field is missing.
    ConditionalRequirementFailed {
        /// The path to the missing field.
        field_path: String,
        /// The condition that triggered the requirement.
        condition: String,
    },

    /// Failed to parse the schema TOML.
    SchemaParseError(String),

    /// Failed to parse the content TOML.
    TomlParseError(String),

    /// Multiple validation errors occurred.
    Multiple(Vec<ValidationError>),

    /// An unexpected table was found.
    UnexpectedTable {
        /// The path to the unexpected table.
        table_path: String,
    },

    /// An unexpected field was found.
    UnexpectedField {
        /// The path to the unexpected field.
        field_path: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::MissingRequiredField { field_path } => {
                write!(f, "Missing required field: {}", field_path)
            }
            ValidationError::InvalidType {
                field_path,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Invalid type for field '{}': expected {}, found {}",
                    field_path, expected, found
                )
            }
            ValidationError::InvalidEnumValue {
                field_path,
                value,
                allowed,
            } => {
                write!(
                    f,
                    "Invalid value '{}' for field '{}': must be one of [{}]",
                    value,
                    field_path,
                    allowed.join(", ")
                )
            }
            ValidationError::OutOfRange {
                field_path,
                value,
                min,
                max,
            } => {
                let range = match (min, max) {
                    (Some(min), Some(max)) => format!("between {} and {}", min, max),
                    (Some(min), None) => format!("at least {}", min),
                    (None, Some(max)) => format!("at most {}", max),
                    (None, None) => "within valid range".to_string(),
                };
                write!(
                    f,
                    "Value '{}' for field '{}' is out of range: must be {}",
                    value, field_path, range
                )
            }
            ValidationError::InvalidArrayLength {
                field_path,
                length,
                min,
                max,
            } => {
                let constraint = match (min, max) {
                    (Some(min), Some(max)) => format!("between {} and {} items", min, max),
                    (Some(min), None) => format!("at least {} items", min),
                    (None, Some(max)) => format!("at most {} items", max),
                    (None, None) => "valid length".to_string(),
                };
                write!(
                    f,
                    "Array '{}' has {} items, but must have {}",
                    field_path, length, constraint
                )
            }
            ValidationError::PatternMismatch {
                field_path,
                pattern,
            } => {
                write!(
                    f,
                    "Field '{}' does not match required pattern: {}",
                    field_path, pattern
                )
            }
            ValidationError::ConditionalRequirementFailed {
                field_path,
                condition,
            } => {
                write!(
                    f,
                    "Field '{}' is required when condition '{}' is met",
                    field_path, condition
                )
            }
            ValidationError::SchemaParseError(msg) => {
                write!(f, "Failed to parse schema: {}", msg)
            }
            ValidationError::TomlParseError(msg) => {
                write!(f, "Failed to parse TOML: {}", msg)
            }
            ValidationError::Multiple(errors) => {
                writeln!(f, "Multiple validation errors occurred:")?;
                for (i, error) in errors.iter().enumerate() {
                    writeln!(f, "  {}. {}", i + 1, error)?;
                }
                Ok(())
            }
            ValidationError::UnexpectedTable { table_path } => {
                write!(f, "Unexpected table: {}", table_path)
            }
            ValidationError::UnexpectedField { field_path } => {
                write!(f, "Unexpected field: {}", field_path)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_required_field_display() {
        let error = ValidationError::MissingRequiredField {
            field_path: "proxy.id".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("proxy.id"));
        assert!(message.contains("Missing required field"));
    }

    #[test]
    fn test_invalid_type_display() {
        let error = ValidationError::InvalidType {
            field_path: "network.default.bind_address".to_string(),
            expected: "string".to_string(),
            found: "integer".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("network.default.bind_address"));
        assert!(message.contains("string"));
        assert!(message.contains("integer"));
    }

    #[test]
    fn test_invalid_enum_value_display() {
        let error = ValidationError::InvalidEnumValue {
            field_path: "proxy.log_level".to_string(),
            value: "invalid".to_string(),
            allowed: vec!["trace".to_string(), "debug".to_string(), "info".to_string()],
        };
        let message = error.to_string();
        assert!(message.contains("proxy.log_level"));
        assert!(message.contains("invalid"));
        assert!(message.contains("trace"));
        assert!(message.contains("debug"));
        assert!(message.contains("info"));
    }

    #[test]
    fn test_out_of_range_display() {
        let error = ValidationError::OutOfRange {
            field_path: "proxy.jwks_cache_duration_hours".to_string(),
            value: "200".to_string(),
            min: Some("1".to_string()),
            max: Some("168".to_string()),
        };
        let message = error.to_string();
        assert!(message.contains("proxy.jwks_cache_duration_hours"));
        assert!(message.contains("200"));
        assert!(message.contains("1"));
        assert!(message.contains("168"));
    }

    #[test]
    fn test_invalid_array_length_display() {
        let error = ValidationError::InvalidArrayLength {
            field_path: "pipelines.example.endpoints".to_string(),
            length: 0,
            min: Some(1),
            max: None,
        };
        let message = error.to_string();
        assert!(message.contains("pipelines.example.endpoints"));
        assert!(message.contains("0 items"));
        assert!(message.contains("at least 1"));
    }

    #[test]
    fn test_pattern_mismatch_display() {
        let error = ValidationError::PatternMismatch {
            field_path: "network.invalid-name".to_string(),
            pattern: "^[a-z0-9_-]+$".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("network.invalid-name"));
        assert!(message.contains("^[a-z0-9_-]+$"));
    }

    #[test]
    fn test_conditional_requirement_failed_display() {
        let error = ValidationError::ConditionalRequirementFailed {
            field_path: "management.network".to_string(),
            condition: "management.enabled == true".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("management.network"));
        assert!(message.contains("management.enabled == true"));
    }

    #[test]
    fn test_multiple_errors_display() {
        let errors = vec![
            ValidationError::MissingRequiredField {
                field_path: "proxy.id".to_string(),
            },
            ValidationError::InvalidType {
                field_path: "proxy.port".to_string(),
                expected: "integer".to_string(),
                found: "string".to_string(),
            },
        ];
        let error = ValidationError::Multiple(errors);
        let message = error.to_string();
        assert!(message.contains("Multiple validation errors"));
        assert!(message.contains("proxy.id"));
        assert!(message.contains("proxy.port"));
    }
}
