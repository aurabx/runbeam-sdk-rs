//! Core validation logic for TOML configurations against schema definitions.
//!
//! This module implements the actual validation that checks TOML content
//! against parsed schema definitions.

use crate::validation::error::ValidationError;
use crate::validation::schema::{FieldDefinition, Schema, TableDefinition};

/// Validate TOML content against a schema
pub fn validate(content_toml: &str, schema_toml: &str) -> Result<(), ValidationError> {
    // Parse schema
    let schema = Schema::from_str(schema_toml)?;

    // Parse content
    let content: toml::Value =
        toml::from_str(content_toml).map_err(|e| ValidationError::TomlParseError(e.to_string()))?;

    // Validate
    let mut errors = Vec::new();
    validate_document(&content, &schema, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else if errors.len() == 1 {
        Err(errors.into_iter().next().unwrap())
    } else {
        Err(ValidationError::Multiple(errors))
    }
}

/// Recursively validate tables, building full paths for nested tables
fn validate_tables_recursive(
    table: &toml::map::Map<String, toml::Value>,
    parent_path: &str,
    schema: &Schema,
    errors: &mut Vec<ValidationError>,
) {
    for (key, value) in table.iter() {
        let table_path = if parent_path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{}", parent_path, key)
        };

        // Check if this table path matches a schema definition
        if let Some(table_def) = schema.find_table(&table_path) {
            validate_table(value, table_def, &table_path, schema, errors);
        } else if value.is_table() {
            // No direct match, check if we need to recurse deeper for dotted table names
            // like [network.default] which becomes {network: {default: {...}}}
            if let Some(nested_table) = value.as_table() {
                // Try to find a pattern that might match this nested structure
                let has_pattern_match = schema
                    .tables
                    .values()
                    .any(|t| t.is_pattern && schema.matches_pattern(&table_path, &t.name));

                if has_pattern_match {
                    // This table itself doesn't match, but its children might match a pattern
                    validate_tables_recursive(nested_table, &table_path, schema, errors);
                } else {
                    // Check if any nested tables might match
                    validate_tables_recursive(nested_table, &table_path, schema, errors);
                }
            } else {
                // Not a table, and doesn't match - this is unexpected
                errors.push(ValidationError::UnexpectedTable {
                    table_path: table_path.clone(),
                });
            }
        }
    }
}

/// Validate the entire TOML document
fn validate_document(content: &toml::Value, schema: &Schema, errors: &mut Vec<ValidationError>) {
    let Some(root_table) = content.as_table() else {
        errors.push(ValidationError::TomlParseError(
            "Root of TOML must be a table".to_string(),
        ));
        return;
    };

    // Validate each table in the content
    // Handle both direct tables and nested/dotted tables
    validate_tables_recursive(root_table, "", schema, errors);

    // Check for missing required tables
    for table_def in schema.get_concrete_tables() {
        if table_def.required && !root_table.contains_key(&table_def.name) {
            errors.push(ValidationError::MissingRequiredField {
                field_path: table_def.name.clone(),
            });
        }
    }
}

/// Validate a table against its schema definition
fn validate_table(
    table_value: &toml::Value,
    table_def: &TableDefinition,
    table_path: &str,
    schema: &Schema,
    errors: &mut Vec<ValidationError>,
) {
    let Some(table) = table_value.as_table() else {
        errors.push(ValidationError::InvalidType {
            field_path: table_path.to_string(),
            expected: "table".to_string(),
            found: get_type_name(table_value),
        });
        return;
    };

    // Validate pattern constraint if this is a pattern table
    if table_def.is_pattern {
        if let Some(pattern_constraint) = &table_def.pattern_constraint {
            // Extract the dynamic part of the table name
            // e.g., for "network.default" with pattern "network.*", extract "default"
            if let Some(dynamic_part) = extract_dynamic_part(table_path, &table_def.name) {
                if !pattern_constraint.is_match(&dynamic_part) {
                    errors.push(ValidationError::PatternMismatch {
                        field_path: table_path.to_string(),
                        pattern: pattern_constraint.as_str().to_string(),
                    });
                }
            }
        }
    }

    // Validate each field in the schema
    for field_def in table_def.get_fields() {
        let field_path = format!("{}.{}", table_path, field_def.name);

        // Handle nested field paths (e.g., "tcp_config.bind_address")
        let field_value = get_nested_field(table, &field_def.name);

        // Check required fields
        // If required_if is specified, it takes precedence over the base required flag
        let is_required = if field_def.required_if.is_some() {
            field_def.is_conditionally_required(&toml::Value::Table(table.clone()))
        } else {
            field_def.required
        };

        if is_required && field_value.is_none() {
            if field_def.required_if.is_some() {
                errors.push(ValidationError::ConditionalRequirementFailed {
                    field_path: field_path.clone(),
                    condition: field_def.required_if.as_ref().unwrap().clone(),
                });
            } else {
                errors.push(ValidationError::MissingRequiredField {
                    field_path: field_path.clone(),
                });
            }
            continue;
        }

        // Validate field value if present
        if let Some(value) = field_value {
            validate_field(value, field_def, &field_path, schema, errors);
        }
    }

    // Check for unexpected fields (optional strict mode - currently lenient)
    // This could be enabled with a flag in the future
}

/// Validate a field value against its definition
fn validate_field(
    value: &toml::Value,
    field_def: &FieldDefinition,
    field_path: &str,
    schema: &Schema,
    errors: &mut Vec<ValidationError>,
) {
    // Validate type
    if !validate_type(value, &field_def.field_type) {
        errors.push(ValidationError::InvalidType {
            field_path: field_path.to_string(),
            expected: field_def.field_type.clone(),
            found: get_type_name(value),
        });
        return;
    }

    // Validate enum values
    if let Some(enum_values) = &field_def.enum_values {
        if let Some(str_value) = value.as_str() {
            if !enum_values.contains(&str_value.to_string()) {
                errors.push(ValidationError::InvalidEnumValue {
                    field_path: field_path.to_string(),
                    value: str_value.to_string(),
                    allowed: enum_values.clone(),
                });
            }
        }
    }

    // Validate numeric ranges
    if let Some(int_value) = value.as_integer() {
        if let Some(min) = field_def.min {
            if int_value < min {
                errors.push(ValidationError::OutOfRange {
                    field_path: field_path.to_string(),
                    value: int_value.to_string(),
                    min: Some(min.to_string()),
                    max: field_def.max.map(|m| m.to_string()),
                });
            }
        }
        if let Some(max) = field_def.max {
            if int_value > max {
                errors.push(ValidationError::OutOfRange {
                    field_path: field_path.to_string(),
                    value: int_value.to_string(),
                    min: field_def.min.map(|m| m.to_string()),
                    max: Some(max.to_string()),
                });
            }
        }
    }

    // Validate pattern for string values
    if let Some(pattern) = &field_def.pattern {
        if let Some(str_value) = value.as_str() {
            if !pattern.is_match(str_value) {
                errors.push(ValidationError::PatternMismatch {
                    field_path: field_path.to_string(),
                    pattern: pattern.as_str().to_string(),
                });
            }
        }
    }

    // Validate arrays
    if let Some(array) = value.as_array() {
        // Validate array length
        if let Some(min_items) = field_def.min_items {
            if array.len() < min_items {
                errors.push(ValidationError::InvalidArrayLength {
                    field_path: field_path.to_string(),
                    length: array.len(),
                    min: Some(min_items),
                    max: field_def.max_items,
                });
            }
        }
        if let Some(max_items) = field_def.max_items {
            if array.len() > max_items {
                errors.push(ValidationError::InvalidArrayLength {
                    field_path: field_path.to_string(),
                    length: array.len(),
                    min: field_def.min_items,
                    max: Some(max_items),
                });
            }
        }

        // Validate array item types
        if let Some(expected_item_type) = &field_def.array_item_type {
            for (i, item) in array.iter().enumerate() {
                if !validate_type(item, expected_item_type) {
                    errors.push(ValidationError::InvalidType {
                        field_path: format!("{}[{}]", field_path, i),
                        expected: expected_item_type.clone(),
                        found: get_type_name(item),
                    });
                }
            }
        }
    }

    // Validate nested tables recursively
    if field_def.field_type == "table" {
        if let Some(table_value) = value.as_table() {
            // For nested tables, we need to find the corresponding table definition
            // This is simplified - in a full implementation, we'd need to handle
            // nested table schemas more comprehensively
            for (nested_key, nested_value) in table_value.iter() {
                let nested_path = format!("{}.{}", field_path, nested_key);
                if let Some(nested_table_def) = schema.find_table(&nested_path) {
                    validate_table(nested_value, nested_table_def, &nested_path, schema, errors);
                }
            }
        }
    }
}

/// Check if a value matches the expected type
fn validate_type(value: &toml::Value, expected_type: &str) -> bool {
    match expected_type {
        "string" => value.is_str(),
        "integer" => value.is_integer(),
        "boolean" => value.is_bool(),
        "float" => value.is_float() || value.is_integer(), // Allow integers as floats
        "array" => value.is_array(),
        "table" => value.is_table(),
        _ => false,
    }
}

/// Get a human-readable type name for a TOML value
fn get_type_name(value: &toml::Value) -> String {
    match value {
        toml::Value::String(_) => "string".to_string(),
        toml::Value::Integer(_) => "integer".to_string(),
        toml::Value::Float(_) => "float".to_string(),
        toml::Value::Boolean(_) => "boolean".to_string(),
        toml::Value::Array(_) => "array".to_string(),
        toml::Value::Table(_) => "table".to_string(),
        toml::Value::Datetime(_) => "datetime".to_string(),
    }
}

/// Extract nested field value from a table using dot notation
///
/// Supports paths like "tcp_config.bind_address"
fn get_nested_field<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    path: &str,
) -> Option<&'a toml::Value> {
    let parts: Vec<&str> = path.split('.').collect();

    if parts.len() == 1 {
        return table.get(path);
    }

    let mut current = table.get(parts[0])?;

    for part in &parts[1..] {
        current = current.as_table()?.get(*part)?;
    }

    Some(current)
}

/// Extract the dynamic part from a table path given a pattern
///
/// For example: extract_dynamic_part("network.default", "network.*") returns Some("default")
fn extract_dynamic_part(table_path: &str, pattern: &str) -> Option<String> {
    if !pattern.contains('*') {
        return None;
    }

    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    let path_parts: Vec<&str> = table_path.split('.').collect();

    if pattern_parts.len() != path_parts.len() {
        return None;
    }

    for (i, pattern_part) in pattern_parts.iter().enumerate() {
        if *pattern_part == "*" {
            return Some(path_parts[i].to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_schema() -> &'static str {
        r#"
[schema]
version = "1.0"
description = "Simple test schema"

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
required = false
min = 1
max = 65535

[[table.field]]
name = "enabled"
type = "boolean"
required = false

[[table.field]]
name = "log_level"
type = "string"
required = false
enum = ["debug", "info", "warn", "error"]

[[table.field]]
name = "tags"
type = "array"
array_item_type = "string"
min_items = 1
"#
    }

    #[test]
    fn test_valid_toml() {
        let schema = simple_schema();
        let content = r#"
[config]
name = "test"
port = 8080
enabled = true
log_level = "info"
tags = ["api", "production"]
"#;

        assert!(validate(content, schema).is_ok());
    }

    #[test]
    fn test_missing_required_field() {
        let schema = simple_schema();
        let content = r#"
[config]
port = 8080
"#;

        let result = validate(content, schema);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            ValidationError::MissingRequiredField { .. }
        ));
    }

    #[test]
    fn test_invalid_type() {
        let schema = simple_schema();
        let content = r#"
[config]
name = "test"
port = "not a number"
"#;

        let result = validate(content, schema);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, ValidationError::InvalidType { .. }));
    }

    #[test]
    fn test_invalid_enum_value() {
        let schema = simple_schema();
        let content = r#"
[config]
name = "test"
log_level = "invalid"
"#;

        let result = validate(content, schema);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, ValidationError::InvalidEnumValue { .. }));
    }

    #[test]
    fn test_out_of_range() {
        let schema = simple_schema();
        let content = r#"
[config]
name = "test"
port = 999999
"#;

        let result = validate(content, schema);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, ValidationError::OutOfRange { .. }));
    }

    #[test]
    fn test_invalid_array_length() {
        let schema = simple_schema();
        let content = r#"
[config]
name = "test"
tags = []
"#;

        let result = validate(content, schema);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, ValidationError::InvalidArrayLength { .. }));
    }

    #[test]
    fn test_invalid_array_item_type() {
        let schema = simple_schema();
        let content = r#"
[config]
name = "test"
tags = [1, 2, 3]
"#;

        let result = validate(content, schema);
        assert!(result.is_err());
        let error = result.unwrap_err();
        // Should be Multiple errors or InvalidType
        match error {
            ValidationError::Multiple(errors) => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, ValidationError::InvalidType { .. })));
            }
            ValidationError::InvalidType { .. } => {}
            _ => panic!("Expected InvalidType or Multiple errors"),
        }
    }

    #[test]
    fn test_pattern_tables() {
        let schema = r#"
[schema]
version = "1.0"
description = "Pattern table test"

[[table]]
name = "network.*"
pattern = true
pattern_constraint = "^[a-z0-9_-]+$"

[[table.field]]
name = "bind_address"
type = "string"
required = true
"#;

        let content = r#"
[network.default]
bind_address = "0.0.0.0"

[network.management]
bind_address = "127.0.0.1"
"#;

        let result = validate(content, schema);
        if let Err(e) = &result {
            eprintln!("Validation error: {}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_pattern_constraint_violation() {
        let schema = r#"
[schema]
version = "1.0"
description = "Pattern constraint test"

[[table]]
name = "network.*"
pattern = true
pattern_constraint = "^[a-z0-9_-]+$"

[[table.field]]
name = "bind_address"
type = "string"
required = true
"#;

        let content = r#"
[network.INVALID_NAME]
bind_address = "0.0.0.0"
"#;

        let result = validate(content, schema);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, ValidationError::PatternMismatch { .. }));
    }

    #[test]
    fn test_nested_fields() {
        let schema = r#"
[schema]
version = "1.0"
description = "Nested fields test"

[[table]]
name = "network"
required = true

[[table.field]]
name = "tcp_config.bind_address"
type = "string"
required = true

[[table.field]]
name = "tcp_config.port"
type = "integer"
required = true
"#;

        let content = r#"
[network.tcp_config]
bind_address = "0.0.0.0"
port = 8080
"#;

        assert!(validate(content, schema).is_ok());
    }

    #[test]
    fn test_get_nested_field() {
        let mut table = toml::map::Map::new();
        let mut tcp_config = toml::map::Map::new();
        tcp_config.insert(
            "bind_address".to_string(),
            toml::Value::String("0.0.0.0".to_string()),
        );
        table.insert("tcp_config".to_string(), toml::Value::Table(tcp_config));

        let value = get_nested_field(&table, "tcp_config.bind_address");
        assert!(value.is_some());
        assert_eq!(value.unwrap().as_str(), Some("0.0.0.0"));
    }

    #[test]
    fn test_extract_dynamic_part() {
        assert_eq!(
            extract_dynamic_part("network.default", "network.*"),
            Some("default".to_string())
        );
        assert_eq!(
            extract_dynamic_part("network.management", "network.*"),
            Some("management".to_string())
        );
        assert_eq!(extract_dynamic_part("network", "network.*"), None);
    }
}
