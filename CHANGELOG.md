# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2025-11-23

### Added

- **Harmony DSL v1.8.0 Support**
  - Added `Peer` resource type for external systems that send requests to Harmony
  - Added `Target` resource type for external systems that receive requests from Harmony
  - Added `Rule` resource type for policy rule definitions
  - Added shared configuration structures:
    - `ConnectionConfig` - normalized connection settings (host, port, protocol, base_path)
    - `AuthenticationConfig` - authentication settings (method, credentials_path)

- **Endpoint Enhancements**
  - Added `peer_ref` field - reference to peer configuration for inheritance
  - Added `connection` field - normalized connection overrides
  - Added `authentication` field - authentication configuration overrides
  - Added `options` field - service-specific options (highest precedence)

- **Backend Enhancements**
  - Added `target_ref` field - reference to target configuration for inheritance
  - Added `connection` field - normalized connection overrides
  - Added `authentication` field - authentication configuration overrides
  - Added `max_retries` field - retry configuration
  - Added `options` field - service-specific options (highest precedence)

- **GatewayConfiguration Updates**
  - Added `peers` collection for peer system configurations
  - Added `targets` collection for target system configurations
  - Added `rules` collection for rule definitions

### Changed

- Resource types now support normalized connection settings across all components
- Endpoints and backends now support configuration inheritance through references
- All new fields are optional to maintain backward compatibility

### Technical Details

- Aligns with harmony-dsl config schema v1.8.0 and pipeline schema v1.7.0
- Supports peer_ref/target_ref configuration reuse pattern
- Three-tier precedence: base (peer/target) → overrides (connection/auth) → options (service-specific)
- All existing API responses remain compatible (new fields are optional)

## [0.7.2] - 2025-11-19

- Fixed: Runbeam configuration synchronisation

## [0.7.0] - 2025-11-19

### Breaking Changes

- **Removed keyring dependency**: The SDK no longer uses OS keyring/credential stores (macOS Keychain, Linux Secret Service, Windows Credential Manager) for token storage. All tokens are now stored using encrypted filesystem storage at `~/.runbeam/<instance_id>/auth.json`.
  - **Impact**: Existing tokens stored in OS keyring will NOT be automatically migrated
  - **Migration**: Users must re-authenticate to generate new tokens in encrypted filesystem storage
  - **Benefits**: 
    - No system dependencies (dbus, libdbus-sys, openssl, openssl-sys) required
    - Eliminates build-time dependencies on system libraries
    - Simplified cross-compilation and containerized deployments
    - Better support for headless systems, CI/CD pipelines, Docker, Kubernetes, and cloud VMs
    - Smaller binary size and faster compilation
    - Pure Rust implementation with no platform-specific FFI
  - **Note**: Since machine tokens expire after 30 days anyway, losing keyring-stored tokens has minimal impact

### Changed

- Token storage now uses only `EncryptedFilesystemStorage` with age encryption
- Encryption keys sourced from `RUNBEAM_ENCRYPTION_KEY` environment variable or auto-generated at `~/.runbeam/<instance_id>/encryption.key`
- Removed `RUNBEAM_DISABLE_KEYRING` environment variable (no longer needed)
- All storage functions (`save_token`, `load_token`, `clear_token`) now directly use encrypted filesystem storage

### Removed

- Removed `keyring` crate dependency (version 3.6.3)
- Removed `KeyringStorage` implementation from storage module
- Removed `StorageError::Keyring` error variant
- Removed automatic storage backend selection (keyring fallback logic)

## [0.6.2] - 2025-11-16

### Added

- PolicyRule struct

## [0.6.1] - 2025-11-16

### Fixed

- Fixed applying changes through correct routes
  - `/gateway/changes/{id}/applied` → `/api/change/{id}/applied`
  - `/gateway/changes/{id}/failed` → `/api/change/{id}/failed`

## [0.6.0] - 2025-11-14

### Added

- Added the DSL Validation API

## [0.5.0] - 2025-11-10

### Changed

- **⚠️ BREAKING CHANGE: Change Management API Endpoints**
  - Updated all Change Management API endpoints from `/gateway/*` to `/api/changes/*`
  - Affected endpoints:
    - `/gateway/base-url` → `/api/changes/base-url`
    - `/gateway/changes` → `/api/changes`
    - `/gateway/changes/{id}` → `/api/changes/{id}`
    - `/gateway/changes/acknowledge` → `/api/changes/acknowledge`
    - `/gateway/changes/{id}/applied` → `/api/changes/{id}/applied`
    - `/gateway/changes/{id}/failed` → `/api/changes/{id}/failed`
  - **Migration required**: Applications using Change Management API must update to use new endpoints
  - Requires Runbeam API v1.2 or later
  - No backwards compatibility - old endpoints are no longer supported

### Added

- Support for pushing configuration to Runbeam Cloud via `harmony.update` endpoint
- Transform resource retrieval functionality
- Updated API client to match current Runbeam API specification

### Fixed

- Keyring storage compatibility on macOS
- Various configuration synchronization issues
- Test compilation errors with updated API structures

## [0.4.0] - 2025-11-03

### Added

- **Generic Secure Token Storage**
  - Generic functions: `save_token_generic()`, `load_token_generic()`, `clear_token_generic()`
  - Support for any serializable token type (machine tokens, user tokens, custom types)
  - Token isolation by name (e.g., `user_token`, `machine_token`)
  - `UserToken` type for storing user authentication tokens with expiry validation
  - `UserInfo` struct containing user details (id, name, email)

- **Encrypted Filesystem Storage**
  - ChaCha20-Poly1305 AEAD encryption for filesystem token storage
  - Argon2id key derivation with random salt (prevents rainbow table attacks)
  - Automatic encryption key generation and secure storage in OS keyring
  - Encryption key stored at `runbeam/encryption_key` identifier
  - Transparent encryption/decryption (no user configuration needed)

- **Tests**
  - Generic token storage tests with `UserToken` type
  - Token type isolation tests (user vs machine tokens)
  - Encryption verification tests
  - Comprehensive test coverage for generic storage operations

### Changed

- **Token Storage Refactoring**
  - Refactored storage to use generic functions internally
  - Legacy functions (`save_machine_token`, `load_machine_token`) now call generic storage
  - FilesystemStorage now encrypts all tokens by default
  - Storage backends automatically handle encryption transparently

- **Security Improvements**
  - All tokens encrypted at rest (except in OS keyring)
  - Automatic fallback from keyring to encrypted filesystem
  - Encryption keys never stored on disk in plaintext
  - Per-token-type storage isolation

- **Documentation**
  - Comprehensive documentation updates in WARP.md
  - Migration guide from v0.2.x to v0.3.x
  - Security features documentation
  - Custom token type examples
  - Generic storage API examples

### Backwards Compatibility

- All existing code using machine token functions continues to work without changes
- Legacy function names preserved as wrappers
- No breaking changes to public API
- Automatic storage format compatibility

## [0.3.1] - 2024-10-31

### Added

- **Tests**
  - Added 7 integration tests for Change Management complex scenarios
  - Tests cover realistic change workflows with all resource types and operations
  - Tests verify paginated and single resource response structures
  - Tests cover various payload structures and edge cases
  - Added `tests/README.md` with detailed test documentation
  - All 43 tests passing (25 unit + 7 integration + 11 doc tests)

### Changed

- Fixed clippy warning in test code (useless vec! allocation)

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

[0.8.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.7.0...v0.7.2
[0.7.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/aurabx/runbeam-sdk-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/aurabx/runbeam-sdk-rs/releases/tag/v0.1.0
