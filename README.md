# Runbeam SDK

A Rust library for integrating with the Runbeam Cloud API.

## Features

- **JWT Token Validation** - RS256 signature verification with automatic JWKS caching
- **API Client** - HTTP client for Runbeam Cloud gateway authorization
- **Secure Storage** - OS-native credential storage (Keychain/Secret Service/Credential Manager)
- **Machine Tokens** - Autonomous gateway authentication with 30-day expiry
- **Cross-Platform** - Works on macOS, Linux, and Windows

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
runbeam-sdk = { path = "../runbeam-sdk" }
```

## Quick Start

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
    // Validate user JWT token
    let user_token = "eyJhbGci...";
    let claims = validate_jwt_token(user_token, 24).await?;
    
    // Create API client
    let client = RunbeamClient::new(claims.api_base_url());
    
    // Authorize gateway and get machine token
    let response = client.authorize_gateway(
        user_token,
        "gateway-123",
        None,
        None
    ).await?;
    
    // Save machine token securely
    let storage = KeyringStorage::new("runbeam");
    let machine_token = MachineToken::new(
        response.machine_token,
        response.expires_at,
        response.gateway.id,
        response.gateway.code,
        response.abilities,
    );
    save_token(&storage, &machine_token).await?;
    
    Ok(())
}
```

## Authorization Flow

1. CLI sends user JWT token to Harmony Management API
2. Harmony validates JWT locally (signature verification via JWKS)
3. Harmony exchanges user JWT for machine token from Runbeam Cloud
4. Runbeam Cloud issues machine-scoped token (30-day expiry)
5. Machine token is stored securely for autonomous API access

## Storage Options

### KeyringStorage (Recommended)

Uses OS-native secure credential storage:
- **macOS**: Keychain
- **Linux**: Secret Service API
- **Windows**: Credential Manager

```rust
use runbeam_sdk::storage::KeyringStorage;

let storage = KeyringStorage::new("runbeam");
```

### FilesystemStorage (Development/Testing)

Stores tokens in the filesystem:

```rust
use runbeam_sdk::storage::FilesystemStorage;

let storage = FilesystemStorage::new("/path/to/storage")?;
```

## Development

### Build

```bash
cargo build
cargo build --release
```

### Test

```bash
cargo test           # Run all tests
cargo test --lib     # Run only library tests
```

### Lint

```bash
cargo clippy
cargo clippy -- -D warnings
```

### Documentation

```bash
cargo doc --open
```

## Architecture

- **`runbeam_api/client.rs`** - HTTP client for Runbeam Cloud API
- **`runbeam_api/jwt.rs`** - JWT validation with JWKS caching
- **`runbeam_api/token_storage.rs`** - Token persistence operations
- **`runbeam_api/types.rs`** - Error types and API structures
- **`storage/mod.rs`** - Storage backend trait and implementations

## License

Part of the Runbeam project.
