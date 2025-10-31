# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Overview

`runbeam-sdk` is a Rust library that provides SDK functionality for integrating with the Runbeam Cloud API. It is part of the larger Runbeam ecosystem alongside `harmony-proxy`, `runbeam-cli`, and other components.

The SDK handles:
- JWT token validation using RS256 with JWKS endpoint discovery
- Laravel Sanctum API token support
- Runbeam Cloud API client for gateway authorization
- Machine token storage and lifecycle management
- Type definitions for API requests/responses and error handling

## Architecture

### Module Structure

The codebase is organized as a library crate (`src/lib.rs`) with the main implementation in `src/runbeam_api/`:

- **`mod.rs`** - Module exports and authorization flow documentation
- **`client.rs`** - `RunbeamClient` HTTP client for Runbeam Cloud API operations
- **`jwt.rs`** - JWT validation with RS256 algorithm and JWKS caching
- **`token_storage.rs`** - Machine token persistence operations
- **`types.rs`** - Error types (`RunbeamError`, `ApiError`) and API response structures
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

1. Gateway polls `/gateway/base-url` to discover the changes API base URL
2. Gateway polls `/gateway/changes` to retrieve queued configuration changes (typically every 30 seconds)
3. Gateway acknowledges receipt via `/gateway/changes/acknowledge` (bulk operation)
4. Gateway attempts to apply each change to its configuration
5. Gateway reports success via `/gateway/changes/{id}/applied` OR
6. Gateway reports failure via `/gateway/changes/{id}/failed` with error details

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
- Two implementations: `KeyringStorage` (secure) and `FilesystemStorage` (fallback)
- Tokens stored at `runbeam/auth.json` identifier (keyring) or relative path (filesystem)
- `MachineToken` struct includes expiry validation methods
- Uses boxed futures (`Pin<Box<dyn Future>>`) for trait object safety

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
The SDK uses OS-native credential stores for secure token storage via the `keyring` crate:
- **macOS**: Keychain
- **Linux**: Secret Service API (freedesktop.org)
- **Windows**: Credential Manager

Two storage backends are provided:
- `KeyringStorage` - For production use with secure credential storage
- `FilesystemStorage` - For development/testing or when keyring is unavailable

Both implement the `StorageBackend` trait with boxed futures for trait object compatibility.

### API Documentation
The OpenAPI 3.1.0 specification for the Runbeam API v1.2 is available in `docs/v1-2.json` and includes detailed endpoint documentation, authentication methods, and data schemas. This SDK is compatible with API version 1.2.

### Logging
The codebase uses `tracing` for structured logging with debug, info, warn, and error levels. Consumers should initialize a tracing subscriber to capture logs.

### Edition 2024
The project uses Rust edition 2024, which may require a recent nightly or future stable Rust toolchain depending on when you're reading this.

## Usage Examples

### JWT Token Authentication (Legacy)

```rust
use runbeam_sdk::{
    RunbeamClient,
    validate_jwt_token,
    save_token,
    load_token,
    MachineToken,
    storage::KeyringStorage,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Validate user JWT token
    let user_token = "eyJhbGci...";
    let claims = validate_jwt_token(user_token, 24).await?;
    
    // 2. Create API client from JWT issuer
    let client = RunbeamClient::new(claims.api_base_url());
    
    // 3. Authorize gateway and get machine token
    let response = client.authorize_gateway(
        user_token,
        "gateway-123",
        None,
        None
    ).await?;
    
    // 4. Save machine token securely in OS keyring
    let storage = KeyringStorage::new("runbeam");
    let machine_token = MachineToken::new(
        response.machine_token,
        response.expires_at,
        response.gateway.id,
        response.gateway.code,
        response.abilities,
    );
    save_token(&storage, &machine_token).await?;
    
    // 5. Later, load the token from storage
    if let Some(token) = load_token(&storage).await? {
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
    save_token,
    load_token,
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
    
    // 3. Save machine token securely in OS keyring
    let storage = KeyringStorage::new("runbeam");
    let machine_token = MachineToken::new(
        response.machine_token,
        response.expires_at,
        response.gateway.id,
        response.gateway.code,
        response.abilities,
    );
    save_token(&storage, &machine_token).await?;
    
    // 4. Use the machine token for subsequent API calls
    if let Some(token) = load_token(&storage).await? {
        if token.is_valid() {
            // Use machine token with any API method
            let gateways = client.list_gateways(&token.machine_token).await?;
            println!("Found {} gateways", gateways.data.len());
        }
    }
    
    Ok(())
}
```

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
};
```

### Change Management Examples

The SDK provides comprehensive support for the Change Management API (v1.2):

#### Polling for Configuration Changes

```rust
use runbeam_sdk::{RunbeamClient, load_token, storage::KeyringStorage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://api.runbeam.io");
    let storage = KeyringStorage::new("runbeam");
    
    // Load machine token
    let token = load_token(&storage).await?
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
use runbeam_sdk::{RunbeamClient, load_token, storage::KeyringStorage};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://api.runbeam.io");
    let storage = KeyringStorage::new("runbeam");
    
    loop {
        // Load machine token (checks expiry)
        let Some(token) = load_token(&storage).await? else {
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
