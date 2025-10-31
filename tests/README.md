# Integration Tests

This directory contains integration tests for the runbeam-sdk library.

## Test Files

### `change_management.rs`

Comprehensive integration tests for the Change Management API (v1.2) functionality.

#### Test Coverage

**Change Resource Tests:**
- `test_change_resource_full_lifecycle` - Validates Change resource through complete workflow with realistic payload
- `test_change_with_different_operations` - Tests all CRUD operations (create, update, delete)
- `test_change_with_error_state` - Tests failed changes with error details
- `test_change_resource_types_coverage` - Validates all 9 supported resource types

**Response Structure Tests:**
- `test_paginated_changes_response` - Tests paginated API response with multiple changes
- `test_single_change_resource_response` - Tests single resource response wrapper
- `test_change_payload_variations` - Tests various JSON payload structures (simple, nested, arrays, complex, null)

**Note:** Basic serialization/deserialization tests for request types (BaseUrlResponse, AcknowledgeChangesRequest, ChangeFailedRequest) are covered in unit tests (src/runbeam_api/client.rs).

#### Running Tests

```bash
# Run all integration tests
cargo test --test change_management

# Run specific test
cargo test --test change_management test_change_resource_full_lifecycle

# Run with output
cargo test --test change_management -- --nocapture

# Run with verbose output
cargo test --test change_management -- --nocapture --test-threads=1
```

## Test Statistics

- **Total Integration Tests**: 7
- **Test Categories**:
  - Change resource scenarios: 4 tests
  - Response structures: 2 tests
  - Payload variations: 1 test
- **Coverage**: Complex integration scenarios; basic serialization covered in unit tests

## Test Data

All tests use deterministic, hardcoded test data for reproducibility:
- Gateway IDs: `gw-123`, `gw-456`, `gw-test`
- Change IDs: Sequential format `change-001`, `change-002`, etc.
- Timestamps: ISO 8601 format `2024-10-31T00:00:00Z`
- Resource types: All 9 supported types
- Operations: `create`, `update`, `delete`
- States: `pending`, `acknowledged`, `applied`, `failed`

## Adding New Tests

When adding new tests:

1. Follow the existing naming convention: `test_<feature>_<scenario>`
2. Include doc comments explaining what the test validates
3. Use deterministic test data for reproducibility
4. Test both success and failure paths
5. Verify serialization and deserialization roundtrips
6. Update this README with new test descriptions

## Related Documentation

- [CHANGELOG.md](../CHANGELOG.md) - Version history and changes
- [WARP.md](../WARP.md) - Development guide and API documentation
- [API Specification](../docs/v1-2.json) - OpenAPI 3.1.0 specification
