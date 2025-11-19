//! Schema DSL parser for TOML configuration validation.
//!
//! This module parses schema definition files written in the Harmony DSL format
//! and converts them into structured data that can be used for validation.

use crate::validation::error::ValidationError;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

/// A parsed schema containing table and field definitions.
#[derive(Debug, Clone)]
pub struct Schema {
    /// Schema version
    pub version: String,
    /// Schema description
    pub description: String,
    /// Table definitions indexed by name
    pub tables: HashMap<String, TableDefinition>,
}

/// A table definition in the schema.
#[derive(Debug, Clone)]
pub struct TableDefinition {
    /// Table name (may include wildcards like "network.*")
    pub name: String,
    /// Whether this table name is a pattern (contains wildcards)
    pub is_pattern: bool,
    /// Pattern constraint regex if this is a pattern table
    pub pattern_constraint: Option<Regex>,
    /// Whether this table is required
    pub required: bool,
    /// Table description
    pub description: Option<String>,
    /// Field definitions for this table
    pub fields: Vec<FieldDefinition>,
}

/// A field definition within a table.
#[derive(Debug, Clone)]
pub struct FieldDefinition {
    /// Field name (may be a path like "tcp_config.bind_address")
    pub name: String,
    /// Field type (string, integer, boolean, float, array, table)
    pub field_type: String,
    /// Whether this field is required
    pub required: bool,
    /// Conditional requirement expression
    pub required_if: Option<String>,
    /// Default value
    pub default: Option<toml::Value>,
    /// Allowed enum values
    pub enum_values: Option<Vec<String>>,
    /// Minimum value (for numeric types)
    pub min: Option<i64>,
    /// Maximum value (for numeric types)
    pub max: Option<i64>,
    /// Minimum number of array items
    pub min_items: Option<usize>,
    /// Maximum number of array items
    pub max_items: Option<usize>,
    /// Expected type of array items
    pub array_item_type: Option<String>,
    /// Pattern constraint for string values
    pub pattern: Option<Regex>,
    /// Field description
    pub description: Option<String>,
}

/// Raw schema format as parsed from TOML
#[derive(Debug, Deserialize)]
struct RawSchema {
    schema: SchemaMetadata,
    table: Vec<RawTable>,
}

#[derive(Debug, Deserialize)]
struct SchemaMetadata {
    version: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct RawTable {
    name: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    pattern: bool,
    pattern_constraint: Option<String>,
    description: Option<String>,
    #[serde(default)]
    field: Vec<RawField>,
}

#[derive(Debug, Deserialize)]
struct RawField {
    name: String,
    #[serde(rename = "type")]
    field_type: String,
    #[serde(default)]
    required: bool,
    required_if: Option<String>,
    default: Option<toml::Value>,
    #[serde(rename = "enum")]
    enum_values: Option<Vec<String>>,
    min: Option<i64>,
    max: Option<i64>,
    min_items: Option<usize>,
    max_items: Option<usize>,
    array_item_type: Option<String>,
    pattern_constraint: Option<String>,
    description: Option<String>,
}

impl Schema {
    /// Parse a schema from TOML string
    ///
    /// Note: This is similar to `FromStr::from_str` but returns our custom error type
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(schema_toml: &str) -> Result<Self, ValidationError> {
        let raw: RawSchema = toml::from_str(schema_toml).map_err(|e| {
            ValidationError::SchemaParseError(format!("Failed to parse schema TOML: {}", e))
        })?;

        let mut tables = HashMap::new();

        for raw_table in raw.table {
            let pattern_constraint = if let Some(pattern_str) = &raw_table.pattern_constraint {
                Some(Regex::new(pattern_str).map_err(|e| {
                    ValidationError::SchemaParseError(format!(
                        "Invalid pattern constraint '{}': {}",
                        pattern_str, e
                    ))
                })?)
            } else {
                None
            };

            let mut fields = Vec::new();
            for raw_field in raw_table.field {
                let pattern = if let Some(pattern_str) = &raw_field.pattern_constraint {
                    Some(Regex::new(pattern_str).map_err(|e| {
                        ValidationError::SchemaParseError(format!(
                            "Invalid pattern for field '{}': {}",
                            raw_field.name, e
                        ))
                    })?)
                } else {
                    None
                };

                fields.push(FieldDefinition {
                    name: raw_field.name,
                    field_type: raw_field.field_type,
                    required: raw_field.required,
                    required_if: raw_field.required_if,
                    default: raw_field.default,
                    enum_values: raw_field.enum_values,
                    min: raw_field.min,
                    max: raw_field.max,
                    min_items: raw_field.min_items,
                    max_items: raw_field.max_items,
                    array_item_type: raw_field.array_item_type,
                    pattern,
                    description: raw_field.description,
                });
            }

            let table_def = TableDefinition {
                name: raw_table.name.clone(),
                is_pattern: raw_table.pattern,
                pattern_constraint,
                required: raw_table.required,
                description: raw_table.description,
                fields,
            };

            tables.insert(raw_table.name, table_def);
        }

        Ok(Schema {
            version: raw.schema.version,
            description: raw.schema.description,
            tables,
        })
    }

    /// Find a table definition that matches the given table path.
    ///
    /// This handles both exact matches and pattern matches (e.g., "network.*" matches "network.default").
    pub fn find_table(&self, table_path: &str) -> Option<&TableDefinition> {
        // Try exact match first
        if let Some(table_def) = self.tables.get(table_path) {
            return Some(table_def);
        }

        // Try pattern matches
        self.tables.values().find(|&table_def| {
            table_def.is_pattern && self.matches_pattern(table_path, &table_def.name)
        })
    }

    /// Check if a table path matches a pattern table name.
    ///
    /// For example, "network.default" matches pattern "network.*"
    pub fn matches_pattern(&self, table_path: &str, pattern: &str) -> bool {
        if !pattern.contains('*') {
            return table_path == pattern;
        }

        // Convert pattern to regex
        // "network.*" becomes "^network\.[^.]+$"
        let pattern_regex = pattern.replace(".", r"\.").replace("*", "[^.]+");
        let pattern_regex = format!("^{}$", pattern_regex);

        if let Ok(re) = Regex::new(&pattern_regex) {
            re.is_match(table_path)
        } else {
            false
        }
    }

    /// Get all tables that should be validated
    pub fn get_concrete_tables(&self) -> impl Iterator<Item = &TableDefinition> {
        self.tables.values().filter(|t| !t.is_pattern)
    }
}

impl TableDefinition {
    /// Find a field definition by name (supports nested paths like "tcp_config.bind_address")
    pub fn find_field(&self, field_name: &str) -> Option<&FieldDefinition> {
        self.fields.iter().find(|f| f.name == field_name)
    }

    /// Get all fields for this table
    pub fn get_fields(&self) -> &[FieldDefinition] {
        &self.fields
    }
}

impl FieldDefinition {
    /// Check if this field is conditionally required based on the given table data
    pub fn is_conditionally_required(&self, table_data: &toml::Value) -> bool {
        if let Some(condition) = &self.required_if {
            evaluate_condition(condition, table_data)
        } else {
            false
        }
    }
}

/// Evaluate a required_if condition expression
///
/// Supports:
/// - `field == "value"` - Field equals value
/// - `field != "value"` - Field doesn't equal value  
/// - `field == true` - Boolean field is true
/// - `field == false` - Boolean field is false
/// - `field exists` or just `field` - Field exists
fn evaluate_condition(condition: &str, table_data: &toml::Value) -> bool {
    let condition = condition.trim();

    // Handle "field exists" or just "field"
    if !condition.contains("==") && !condition.contains("!=") {
        let field_name = condition.replace(" exists", "").trim().to_string();
        return table_data.get(&field_name).is_some();
    }

    // Handle == and != operators
    if let Some((left, right)) = condition.split_once("==") {
        let field_name = left.trim();
        let expected_value = right.trim().trim_matches('"').trim_matches('\'');

        if let Some(field_value) = table_data.get(field_name) {
            match field_value {
                toml::Value::String(s) => return s == expected_value,
                toml::Value::Boolean(b) => {
                    return expected_value == "true" && *b || expected_value == "false" && !*b
                }
                toml::Value::Integer(i) => {
                    if let Ok(expected_int) = expected_value.parse::<i64>() {
                        return *i == expected_int;
                    }
                }
                _ => {}
            }
        }
        return false;
    }

    if let Some((left, right)) = condition.split_once("!=") {
        let field_name = left.trim();
        let expected_value = right.trim().trim_matches('"').trim_matches('\'');

        if let Some(field_value) = table_data.get(field_name) {
            match field_value {
                toml::Value::String(s) => return s != expected_value,
                toml::Value::Boolean(b) => {
                    return !(expected_value == "true" && *b || expected_value == "false" && !*b)
                }
                toml::Value::Integer(i) => {
                    if let Ok(expected_int) = expected_value.parse::<i64>() {
                        return *i != expected_int;
                    }
                }
                _ => {}
            }
        }
        return true; // Field doesn't exist or doesn't match, so != is satisfied
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_schema() -> &'static str {
        r#"
[schema]
version = "1.0"
description = "Test schema"

[[table]]
name = "proxy"
required = true
description = "Core proxy configuration"

[[table.field]]
name = "id"
type = "string"
required = true
description = "Proxy ID"

[[table.field]]
name = "log_level"
type = "string"
required = false
default = "error"
enum = ["trace", "debug", "info", "warn", "error"]

[[table.field]]
name = "port"
type = "integer"
required = false
min = 1
max = 65535

[[table]]
name = "network.*"
pattern = true
pattern_constraint = "^[a-z0-9_-]+$"
required = false

[[table.field]]
name = "bind_address"
type = "string"
required = true
"#
    }

    #[test]
    fn test_parse_schema() {
        let schema = Schema::from_str(sample_schema()).unwrap();
        assert_eq!(schema.version, "1.0");
        assert_eq!(schema.description, "Test schema");
        assert_eq!(schema.tables.len(), 2);
    }

    #[test]
    fn test_find_table_exact() {
        let schema = Schema::from_str(sample_schema()).unwrap();
        let table = schema.find_table("proxy");
        assert!(table.is_some());
        assert_eq!(table.unwrap().name, "proxy");
    }

    #[test]
    fn test_find_table_pattern() {
        let schema = Schema::from_str(sample_schema()).unwrap();
        let table = schema.find_table("network.default");
        assert!(table.is_some());
        assert_eq!(table.unwrap().name, "network.*");
    }

    #[test]
    fn test_find_field() {
        let schema = Schema::from_str(sample_schema()).unwrap();
        let table = schema.find_table("proxy").unwrap();
        let field = table.find_field("id");
        assert!(field.is_some());
        assert_eq!(field.unwrap().field_type, "string");
        assert!(field.unwrap().required);
    }

    #[test]
    fn test_enum_values() {
        let schema = Schema::from_str(sample_schema()).unwrap();
        let table = schema.find_table("proxy").unwrap();
        let field = table.find_field("log_level").unwrap();
        assert!(field.enum_values.is_some());
        let enums = field.enum_values.as_ref().unwrap();
        assert_eq!(enums.len(), 5);
        assert!(enums.contains(&"error".to_string()));
    }

    #[test]
    fn test_numeric_range() {
        let schema = Schema::from_str(sample_schema()).unwrap();
        let table = schema.find_table("proxy").unwrap();
        let field = table.find_field("port").unwrap();
        assert_eq!(field.min, Some(1));
        assert_eq!(field.max, Some(65535));
    }

    #[test]
    fn test_evaluate_condition_equals() {
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        let table_value = toml::Value::Table(table);

        assert!(evaluate_condition("enabled == true", &table_value));
        assert!(!evaluate_condition("enabled == false", &table_value));
    }

    #[test]
    fn test_evaluate_condition_string() {
        let mut table = toml::map::Map::new();
        table.insert("type".to_string(), toml::Value::String("http".to_string()));
        let table_value = toml::Value::Table(table);

        assert!(evaluate_condition("type == \"http\"", &table_value));
        assert!(!evaluate_condition("type == \"tcp\"", &table_value));
    }

    #[test]
    fn test_evaluate_condition_exists() {
        let mut table = toml::map::Map::new();
        table.insert(
            "field".to_string(),
            toml::Value::String("value".to_string()),
        );
        let table_value = toml::Value::Table(table);

        assert!(evaluate_condition("field exists", &table_value));
        assert!(evaluate_condition("field", &table_value));
        assert!(!evaluate_condition("missing", &table_value));
    }

    #[test]
    fn test_pattern_matching() {
        let schema = Schema::from_str(sample_schema()).unwrap();

        // Should match
        assert!(schema.matches_pattern("network.default", "network.*"));
        assert!(schema.matches_pattern("network.management", "network.*"));

        // Should not match
        assert!(!schema.matches_pattern("network.sub.deep", "network.*"));
        assert!(!schema.matches_pattern("other.default", "network.*"));
        assert!(!schema.matches_pattern("network", "network.*"));
    }
}
