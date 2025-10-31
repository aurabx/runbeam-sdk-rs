# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2024-10-31

### Added

- **Change Management API Support (API v1.2)**
  - Added `Change` resource type for configuration change tracking
  - Added `BaseUrlResponse` for service discovery
  - Added `AcknowledgeChangesRequest` for bulk change acknowledgment
  - Added `ChangeFailedRequest` for failure reporting with error details

- **New Client Methods**
  - `get_base_url()` - Service discovery endpoint for the changes API
  - `list_changes()` - Retrieve queued configuration changes
  - `get_change()` - Get details of a specific change
  - `acknowledge_changes()` - Bulk acknowledge receipt of changes
  - `mark_change_applied()` - Report successful change application
  - `mark_change_failed()` - Report change application failures with error details

- **Documentation**
  - Added comprehensive Change Management Flow documentation in WARP.md
  - Added three usage examples for change management workflows
  - Added complete API reference for all new endpoints

### Changed

- Updated API compatibility from v1.1 to v1.2
- Updated OpenAPI specification reference from `docs/v1-1.json` to `docs/v1-2.json`
- Expanded public API exports to include all Change Management types

### Technical Details

- All new endpoints support JWT tokens, Sanctum API tokens, and machine tokens
- Change states: `pending` → `acknowledged` → `applied`/`failed`
- Gateways can poll for changes (typically every 30 seconds)
- Full error reporting with optional detailed stack traces
- Thread-safe implementation with async/await patterns

## [0.2.0] - 2024-10-28

### Added

- Laravel Sanctum API token support alongside JWT tokens
- All API client methods now accept both JWT and Sanctum tokens interchangeably
- Enhanced documentation for choosing between authentication methods

### Changed

- Authentication flow now supports server-side token validation
- Improved error handling for different token types

## [0.1.0] - 2024-10-26

### Added

- Initial release of runbeam-sdk
- JWT token validation with RS256 and JWKS caching
- Runbeam Cloud API client for gateway authorization
- Machine token storage and lifecycle management
- Support for OS-native credential stores (Keychain, Secret Service, Credential Manager)
- Basic CRUD operations for gateways, services, endpoints, backends, and pipelines
- Comprehensive type definitions for API requests/responses
- Error handling with `RunbeamError` and `ApiError` types
- Storage abstraction with `KeyringStorage` and `FilesystemStorage` implementations

[0.3.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/aurabx/runbeam-sdk-rs/releases/tag/v0.1.0
