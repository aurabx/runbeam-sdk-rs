# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Overview

`runbeam-sdk` is a Rust library that provides SDK functionality for integrating with the Runbeam Cloud API. It is part of the larger Runbeam ecosystem alongside `harmony-proxy`, `runbeam-cli`, and other components.

The SDK handles:
- JWT token validation using RS256 with JWKS endpoint discovery
- Laravel Sanctum API token support
- Runbeam Cloud API client for gateway authorization
- Generic secure token storage with automatic encryption and OS keyring integration
- Machine token and user token storage and lifecycle management
- Type definitions for API requests/responses and error handling

## Architecture

### Module Structure

The codebase is organized as a library crate (`src/lib.rs`) with the main implementation in `src/runbeam_api/`:

- **`mod.rs`** - Module exports and authorization flow documentation
- **`client.rs`** - `RunbeamClient` HTTP client for Runbeam Cloud API operations
- **`jwt.rs`** - JWT validation with RS256 algorithm and JWKS caching
- **`token_storage.rs`** - Generic secure token persistence with keyring and encrypted filesystem support
- **`types.rs`** - Error types (`RunbeamError`, `ApiError`), token types (`MachineToken`, `UserToken`), and API response structures
- **`resources.rs`** - Resource structs matching API v1.2 schemas (Gateway, Service, Endpoint, Backend, Pipeline, Change, etc.)

### Authorization Flow

The SDK supports two authentication methods for authorization:

#### JWT Token Authorization (Legacy)

1. CLI sends user JWT token to Harmony Management API
2. Harmony validates JWT locally (signature verification via JWKS)
3. Harmony exchanges user JWT for machine token from Runbeam Cloud
4. Runbeam Cloud issues machine-scoped token (30-day expiry)
5. Machine token is stored locally for autonomous API access

#### Sanctum Token Authorization

1. CLI sends user Sanctum API token to Harmony Management API
2. Harmony passes token directly to Runbeam Cloud (no local validation)
3. Runbeam Cloud validates token server-side and issues machine-scoped token (30-day expiry)
4. Machine token is stored locally for autonomous API access

All API methods accept both JWT and Sanctum tokens interchangeably.

### Change Management Flow

The Change Management API (introduced in API v1.2) enables Harmony Proxy gateways to poll for and apply configuration updates:

1. Gateway polls `/api/changes/base-url` to discover the changes API base URL
2. Gateway polls `/api/changes` to retrieve queued configuration changes (typically every 30 seconds)
3. Gateway acknowledges receipt via `/api/changes/acknowledge` (bulk operation)
4. Gateway attempts to apply each change to its configuration
5. Gateway reports success via `/api/changes/{id}/applied` OR
6. Gateway reports failure via `/api/changes/{id}/failed` with error details

**Change States:**
- `pending` - Change is queued and awaiting acknowledgment
- `acknowledged` - Gateway has received the change
- `applied` - Change was successfully applied to gateway configuration
- `failed` - Change application failed (includes error details)

All endpoints accept JWT tokens, Sanctum API tokens, or machine tokens for authentication.

### Key Patterns

**JWT Validation with JWKS Caching:**
- Fetches public keys from `{issuer}/api/.well-known/jwks.json`
- Implements per-issuer JWKS caching with configurable duration
- Automatic cache refresh on validation failures
- Thread-safe using `RwLock` and double-checked locking

**Error Handling:**
- `RunbeamError` enum consolidates JWT, API, Storage, and Config errors
- `ApiError` differentiates Network, HTTP, Parse, and Request errors
- Error conversions via `From` implementations for common error types

**Async/Await:**
- All I/O operations are async (HTTP requests, token storage)
- Tests use `#[tokio::test]` for async test execution
- Requires tokio runtime in consumer applications

**Storage Abstraction:**
- `StorageBackend` trait defines async storage operations (write, read, exists, remove)
- Two implementations: `KeyringStorage` (secure) and `FilesystemStorage` (encrypted fallback)
- Generic token storage: `save_token_generic`, `load_token_generic`, `clear_token_generic` accept any serializable token type
- Multiple token types supported: machine tokens (`runbeam/machine_token.json`), user tokens (`runbeam/user_token.json`)
- `KeyringStorage` uses OS-native credential stores (Keychain, Secret Service, Credential Manager)
- `FilesystemStorage` provides encrypted storage with ChaCha20-Poly1305 and argon2 key derivation
- Automatic encryption key generation and secure storage in OS keyring
- `MachineToken` and `UserToken` structs include expiry validation methods
- Uses boxed futures (`Pin<Box<dyn Future>>`) for trait object safety
- Backwards-compatible wrappers: `save_machine_token`, `load_machine_token`, `clear_machine_token`

## Development Commands

### Building
```bash
cargo build          # Debug build
cargo build --release # Optimized release build
cargo check          # Fast syntax/type check without codegen
```

### Testing
```bash
cargo test                    # Run all tests
cargo test --lib              # Run only library tests
cargo test jwt                # Run tests matching "jwt"
cargo test -- --nocapture     # Show println! output from tests
cargo test --test <test_name> # Run specific integration test
```

### Code Quality
```bash
cargo clippy                  # Run linter
cargo clippy -- -D warnings   # Fail on warnings
cargo fmt                     # Format code
cargo fmt -- --check          # Check formatting without modifying
```

### Documentation
```bash
cargo doc                     # Generate documentation
cargo doc --open              # Generate and open in browser
cargo doc --no-deps           # Document only this crate, not dependencies
```

### Running Single Tests
```bash
cargo test test_client_creation          # Run specific test function
cargo test runbeam_api::jwt::tests::     # Run all tests in jwt module
```

## Important Implementation Notes

### Secure Storage

The SDK provides **generic secure token storage** that works with any serializable token type. Storage automatically selects the best available backend and handles encryption transparently.

#### Storage Backends

Two storage backends are provided, both implementing the `StorageBackend` trait:

**1. KeyringStorage (Primary)**
- Uses OS-native credential stores via the `keyring` crate:
  - **macOS**: Keychain
  - **Linux**: Secret Service API (freedesktop.org)
  - **Windows**: Credential Manager
- Tokens stored as JSON at identifier: `runbeam/{token_type}.json`
- No encryption needed (OS handles security)
- Production-ready and recommended for all deployments

**2. FilesystemStorage (Automatic Fallback)**
- Encrypted JSON storage using ChaCha20-Poly1305 AEAD
- Encryption key derived using Argon2id with random salt
- Key stored securely in OS keyring at `runbeam/encryption_key`
- Automatic fallback when keyring unavailable (e.g., headless systems, CI/CD)
- Tokens stored at: `~/.runbeam/{token_type}.json` (encrypted)

#### Generic Token Storage API

The SDK provides generic functions that work with any token type:

```rust
use runbeam_sdk::{
    save_token_generic,
    load_token_generic,
    clear_token_generic,
    storage::KeyringStorage,
    UserToken,
};

// Save any token type
let storage = KeyringStorage::new("runbeam");
let user_token = UserToken::new("eyJhbGci...".to_string(), 3600, user_info);
save_token_generic(&storage, &user_token, "user_token").await?;

// Load token with automatic type inference
let loaded: Option<UserToken> = load_token_generic(&storage, "user_token").await?;

// Clear token
clear_token_generic::<UserToken>(&storage, "user_token").await?;
```

#### Backwards Compatibility

Legacy machine token functions are preserved for backwards compatibility:

```rust
use runbeam_sdk::{save_machine_token, load_machine_token, MachineToken};

// Old API still works (calls generic storage internally)
let token = MachineToken::new(...);
save_machine_token(&storage, &token).await?;
let loaded = load_machine_token(&storage).await?;
```

#### Security Features

- **Automatic backend selection**: Tries keyring first, falls back to encrypted filesystem
- **Transparent encryption**: Filesystem storage automatically encrypts/decrypts tokens
- **Key derivation**: Argon2id with random salt prevents rainbow table attacks
- **AEAD encryption**: ChaCha20-Poly1305 provides authenticated encryption
- **Secure key storage**: Encryption keys stored in OS keyring, never on disk in plaintext
- **Token isolation**: Different token types stored separately by name
- **No plaintext**: Tokens never written to disk without encryption (except in OS keyring)

Both backends implement the `StorageBackend` trait with boxed futures for trait object compatibility.

### API Documentation
The OpenAPI 3.1.0 specification for the Runbeam API v1.2 is available in `docs/v1-2.json` and includes detailed endpoint documentation, authentication methods, and data schemas. This SDK is compatible with API version 1.2.

### Logging
The codebase uses `tracing` for structured logging with debug, info, warn, and error levels. Consumers should initialize a tracing subscriber to capture logs.

### Edition 2024
The project uses Rust edition 2024, which may require a recent nightly or future stable Rust toolchain depending on when you're reading this.

## Usage Examples

### User Token Storage

The SDK provides secure storage for user authentication tokens (JWT or Sanctum). User tokens are stored separately from machine tokens and can be saved/loaded independently.

```rust
use runbeam_sdk::{
    save_token_generic,
    load_token_generic,
    clear_token_generic,
    storage::KeyringStorage,
    UserToken,
    UserInfo,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = KeyringStorage::new("runbeam");
    
    // Create user info from authentication
    let user_info = UserInfo {
        id: "user-123".to_string(),
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
    };
    
    // Save user token securely
    let user_token = UserToken::new(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...".to_string(),
        3600,  // expires_in seconds
        user_info,
    );
    save_token_generic(&storage, &user_token, "user_token").await?;
    println!("User token saved securely");
    
    // Load user token later
    if let Some(token) = load_token_generic::<UserToken>(&storage, "user_token").await? {
        if token.is_valid() {
            println!("User: {} ({})", token.user.name, token.user.email);
            println!("Token expires at: {}", token.expires_at);
            
            // Use token for API calls
            // let response = client.some_api_call(&token.token).await?;
        } else {
            println!("Token expired, re-authentication required");
            clear_token_generic::<UserToken>(&storage, "user_token").await?;
        }
    }
    
    Ok(())
}
```

### JWT Token Authentication with Security Validation

```rust
use runbeam_sdk::{
    RunbeamClient,
    validate_jwt_token,
    JwtValidationOptions,
    save_machine_token,  // Backwards-compatible wrapper
    load_machine_token,  // Backwards-compatible wrapper
    MachineToken,
    storage::KeyringStorage,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Validate user JWT token with security options
    let user_token = "eyJhbGci...";
    
    // Configure validation with trusted issuers (IMPORTANT for security)
    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![
            "https://api.runbeam.io".to_string(),
            "https://staging.runbeam.io".to_string(),
        ])
        .with_jwks_cache_duration_hours(24);
    
    let claims = validate_jwt_token(user_token, &options).await?;
    
    // 2. Create API client from JWT issuer
    let client = RunbeamClient::new(claims.api_base_url());
    
    // 3. Authorize gateway and get machine token
    let response = client.authorize_gateway(
        user_token,
        "gateway-123",
        None,
        None
    ).await?;
    
    // 4. Save machine token securely (automatically uses keyring or encrypted filesystem)
    let storage = KeyringStorage::new("runbeam");
    let machine_token = MachineToken::new(
        response.machine_token,
        response.expires_at,
        response.gateway.id,
        response.gateway.code,
        response.abilities,
    );
    save_machine_token(&storage, &machine_token).await?;
    
    // 5. Later, load the token from secure storage
    if let Some(token) = load_machine_token(&storage).await? {
        if token.is_valid() {
            println!("Token is valid, expires at: {}", token.expires_at);
        } else {
            println!("Token has expired");
        }
    }
    
    Ok(())
}
```

### Laravel Sanctum API Token Authentication

```rust
use runbeam_sdk::{
    RunbeamClient,
    save_machine_token,  // Backwards-compatible wrapper
    load_machine_token,  // Backwards-compatible wrapper
    MachineToken,
    storage::KeyringStorage,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create API client with base URL (no JWT validation needed)
    let client = RunbeamClient::new("https://api.runbeam.io");
    
    // 2. Authorize gateway with Sanctum token
    // Sanctum tokens typically have the format: {id}|{plaintext_token}
    let sanctum_token = "1|abc123def456...";
    let response = client.authorize_gateway(
        sanctum_token,
        "gateway-123",
        None,
        None
    ).await?;
    
    // 3. Save machine token securely (automatically uses keyring or encrypted filesystem)
    let storage = KeyringStorage::new("runbeam");
    let machine_token = MachineToken::new(
        response.machine_token,
        response.expires_at,
        response.gateway.id,
        response.gateway.code,
        response.abilities,
    );
    save_machine_token(&storage, &machine_token).await?;
    
    // 4. Use the machine token for subsequent API calls
    if let Some(token) = load_machine_token(&storage).await? {
        if token.is_valid() {
            // Use machine token with any API method
            let gateways = client.list_gateways(&token.machine_token).await?;
            println!("Found {} gateways", gateways.data.len());
        }
    }
    
    Ok(())
}
```

### Advanced JWT Validation Configuration

The SDK provides comprehensive JWT validation options aligned with the harmony-dsl JWT authentication middleware schema. All options support security best practices.

```rust
use runbeam_sdk::{validate_jwt_token, JwtValidationOptions};
use jsonwebtoken::Algorithm;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user_token = "eyJhbGci...";
    
    // Full configuration example with all security options
    let options = JwtValidationOptions::new()
        .with_trusted_issuers(vec![
            "https://api.runbeam.io".to_string(),
            "https://staging.runbeam.io".to_string(),
        ])
        // Optional: Override JWKS endpoint (instead of auto-discovery)
        .with_jwks_uri("https://api.runbeam.io/.well-known/jwks.json".to_string())
        // Optional: Restrict allowed signing algorithms
        .with_algorithms(vec![Algorithm::RS256, Algorithm::ES256])
        // Optional: Require additional custom claims
        .with_required_claims(vec!["email".to_string(), "scope".to_string()])
        // Optional: Clock skew tolerance (0-300 seconds)
        .with_leeway_seconds(60)
        // Optional: Disable expiration validation (not recommended)
        .with_validate_expiry(true)
        // JWKS caching duration
        .with_jwks_cache_duration_hours(24);
    
    let claims = validate_jwt_token(user_token, &options).await?;
    println!("Token valid for user: {}", claims.sub);
    
    Ok(())
}
```

#### Security Best Practices

**CRITICAL: Always configure `trusted_issuers` in production!**

Without issuer validation, an attacker can:
1. Stand up their own authorization server with a JWKS endpoint
2. Issue tokens with any claims they want (elevated permissions, fake user IDs, etc.)
3. Sign tokens with their own private key
4. These malicious tokens will pass signature validation

Example secure configuration:

```rust
let options = JwtValidationOptions::new()
    .with_trusted_issuers(vec!["https://api.runbeam.io".to_string()]);
```

**Other security recommendations:**
- Use `with_algorithms()` to restrict allowed signing algorithms (prevents algorithm confusion attacks)
- Use `with_required_claims()` to enforce presence of critical claims
- Keep `validate_expiry` enabled (default: true) to reject expired tokens
- Use reasonable `leeway_seconds` (30-60s) only if experiencing clock skew issues
- Monitor JWT validation failures in logs for security incidents

### Choosing Between Authentication Methods

**Use JWT tokens when:**
- You need local token validation before making API calls
- You need to extract claims (user info, team info) from the token locally
- You're working with existing JWT-based infrastructure
- You want to verify token authenticity without server roundtrips

**Use Sanctum API tokens when:**
- You want simpler authentication without local validation complexity
- Your application doesn't need to inspect token claims locally
- You're integrating with Laravel-based authentication systems
- You prefer server-side token validation

### Using All API Methods with Both Token Types

All API client methods accept both JWT and Sanctum tokens:

```rust
use runbeam_sdk::RunbeamClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://api.runbeam.io");
    
    // Works with JWT tokens
    let jwt_token = "eyJhbGci...";
    let gateways = client.list_gateways(jwt_token).await?;
    
    // Also works with Sanctum tokens
    let sanctum_token = "1|abc123def456...";
    let services = client.list_services(sanctum_token).await?;
    
    // Also works with machine tokens
    let machine_token = "machine_token_string";
    let endpoints = client.list_endpoints(machine_token).await?;
    
    Ok(())
}
```

### Migration and Upgrade Guide

#### Upgrading from SDK v0.2.x to v0.3.x

SDK v0.3.0 introduced **generic secure token storage** with automatic encryption and backwards compatibility. Existing applications using machine token storage will continue to work without changes.

**What Changed:**
- Token storage is now generic and supports multiple token types (machine tokens, user tokens, custom types)
- FilesystemStorage now encrypts tokens automatically using ChaCha20-Poly1305 AEAD
- Encryption keys are stored securely in OS keyring
- Legacy function names (`save_token`, `load_token`) are now wrappers calling generic storage

**No Breaking Changes:**
All existing code continues to work:
```rust
// This still works exactly as before
use runbeam_sdk::{save_machine_token, load_machine_token};

save_machine_token(&storage, &token).await?;
let token = load_machine_token(&storage).await?;
```

**New Capabilities:**
You can now store user tokens and other token types securely:
```rust
// New in v0.3.0: User token storage
use runbeam_sdk::{save_token_generic, load_token_generic, UserToken};

save_token_generic(&storage, &user_token, "user_token").await?;
let token: Option<UserToken> = load_token_generic(&storage, "user_token").await?;
```

#### Migration for CLI Applications

The `runbeam-cli` automatically migrates legacy plaintext token files to secure storage:

1. **First run after upgrade**: CLI detects `~/.runbeam/auth.json` (plaintext)
2. **Automatic migration**: Token is loaded and saved to secure storage (keyring or encrypted filesystem)
3. **Cleanup**: Legacy plaintext file is removed
4. **Subsequent runs**: CLI loads tokens from secure storage only

**No user action required** - migration happens automatically on first run.

#### Custom Token Types

You can now store any serializable token type:

```rust
use serde::{Deserialize, Serialize};
use runbeam_sdk::{save_token_generic, load_token_generic};

#[derive(Serialize, Deserialize)]
struct CustomToken {
    access_token: String,
    refresh_token: String,
    expires_at: i64,
}

// Save custom token
let custom = CustomToken { /* ... */ };
save_token_generic(&storage, &custom, "custom_token").await?;

// Load custom token
let loaded: Option<CustomToken> = load_token_generic(&storage, "custom_token").await?;
```

### Using with Harmony Proxy

When integrating back into `harmony-proxy`, import the SDK:

```rust
// In harmony-proxy's Cargo.toml
[dependencies]
runbeam-sdk = { path = "../runbeam-sdk" }

// In harmony code
use runbeam_sdk::{
    RunbeamClient,
    validate_jwt_token,
    storage::KeyringStorage,
    save_machine_token,
    load_machine_token,
};
```

### Change Management Examples

The SDK provides comprehensive support for the Change Management API (v1.2):

#### Polling for Configuration Changes

```rust
use runbeam_sdk::{RunbeamClient, load_machine_token, storage::KeyringStorage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://api.runbeam.io");
    let storage = KeyringStorage::new("runbeam");
    
    // Load machine token
    let token = load_machine_token(&storage).await?
        .expect("Machine token not found");
    
    // Get the base URL for changes API (service discovery)
    let base_url_response = client.get_base_url(&token.machine_token).await?;
    println!("Changes API base URL: {}", base_url_response.base_url);
    
    // Poll for pending changes
    let changes = client.list_changes(&token.machine_token).await?;
    println!("Found {} pending changes", changes.data.len());
    
    // Acknowledge all changes
    if !changes.data.is_empty() {
        let change_ids: Vec<String> = changes.data.iter()
            .map(|c| c.id.clone())
            .collect();
        client.acknowledge_changes(&token.machine_token, change_ids).await?;
        println!("Acknowledged all changes");
    }
    
    Ok(())
}
```

#### Applying Configuration Changes

```rust
use runbeam_sdk::{RunbeamClient, Change};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://api.runbeam.io");
    let machine_token = "machine_token_abc123";
    
    // Get a specific change
    let change_response = client.get_change(machine_token, "change-123").await?;
    let change = change_response.data;
    
    // Attempt to apply the change
    match apply_change_to_gateway(&change) {
        Ok(_) => {
            // Report success
            client.mark_change_applied(machine_token, &change.id).await?;
            println!("Change {} applied successfully", change.id);
        }
        Err(e) => {
            // Report failure with error details
            client.mark_change_failed(
                machine_token,
                &change.id,
                e.to_string(),
                Some(vec!["Stack trace or additional context".to_string()])
            ).await?;
            println!("Change {} failed: {}", change.id, e);
        }
    }
    
    Ok(())
}

fn apply_change_to_gateway(change: &Change) -> Result<(), Box<dyn std::error::Error>> {
    // Implementation would parse change.payload and update gateway configuration
    // This is a placeholder
    Ok(())
}
```

#### Continuous Change Polling Loop

```rust
use runbeam_sdk::{RunbeamClient, load_machine_token, storage::KeyringStorage};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://api.runbeam.io");
    let storage = KeyringStorage::new("runbeam");
    
    loop {
        // Load machine token (checks expiry)
        let Some(token) = load_machine_token(&storage).await? else {
            eprintln!("No machine token found, sleeping...");
            sleep(Duration::from_secs(60)).await;
            continue;
        };
        
        if !token.is_valid() {
            eprintln!("Machine token expired, re-authorization needed");
            break;
        }
        
        // Poll for changes
        match client.list_changes(&token.machine_token).await {
            Ok(changes) => {
                if !changes.data.is_empty() {
                    println!("Processing {} changes", changes.data.len());
                    
                    // Acknowledge all changes immediately
                    let change_ids: Vec<String> = changes.data.iter()
                        .map(|c| c.id.clone())
                        .collect();
                    client.acknowledge_changes(&token.machine_token, change_ids).await?;
                    
                    // Process each change
                    for change in changes.data {
                        println!("Applying change {}: {} on {}",
                            change.id, change.operation, change.change_resource_type);
                        
                        // Apply change logic here...
                        // Report success/failure using mark_change_applied or mark_change_failed
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to poll changes: {}", e);
            }
        }
        
        // Poll every 30 seconds
        sleep(Duration::from_secs(30)).await;
    }
    
    Ok(())
}
```
