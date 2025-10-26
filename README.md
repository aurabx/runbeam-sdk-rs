# Runbeam SDK

A Rust library for integrating with the Runbeam Cloud API.

## Features

- **JWT Token Validation** - RS256 signature verification with automatic JWKS caching
- **API Client** - Comprehensive HTTP client for Runbeam Cloud API
  - Gateway management (list, get, create, update, delete)
  - Service management (list, get, create, update, delete)
  - Endpoint, Backend, and Pipeline management
  - Gateway authorization and token management
- **Secure Storage** - OS-native credential storage (Keychain/Secret Service/Credential Manager)
- **Machine Tokens** - Autonomous gateway authentication with 30-day expiry
- **Cross-Platform** - Works on macOS, Linux, and Windows

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
runbeam-sdk = "0.1.0"
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

## API Usage

### List Gateways

```rust
use runbeam_sdk::RunbeamClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://runbeam.example.com");
    let machine_token = "your_machine_token";
    
    // List all gateways
    let gateways = client.list_gateways(machine_token).await?;
    for gateway in gateways.data {
        println!("Gateway: {} ({})", gateway.name, gateway.code);
    }
    
    // Get specific gateway
    let gateway = client.get_gateway(machine_token, "gateway-123").await?;
    println!("Gateway enabled: {}", gateway.data.enabled);
    
    Ok(())
}
```

### Manage Services

```rust
use runbeam_sdk::RunbeamClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://runbeam.example.com");
    let machine_token = "your_machine_token";
    
    // List all services
    let services = client.list_services(machine_token).await?;
    for service in services.data {
        println!("Service: {} on gateway {}", service.name, service.gateway_id);
    }
    
    // Get specific service
    let service = client.get_service(machine_token, "service-456").await?;
    println!("Service type: {}", service.data.service_type);
    
    Ok(())
}
```

### Download Full Configuration

```rust
use runbeam_sdk::RunbeamClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RunbeamClient::new("https://runbeam.example.com");
    let machine_token = "your_machine_token";
    
    // Fetch all configuration resources
    let endpoints = client.list_endpoints(machine_token).await?;
    let backends = client.list_backends(machine_token).await?;
    let pipelines = client.list_pipelines(machine_token).await?;
    
    // Use the data to configure harmony-proxy
    println!("Endpoints: {}", endpoints.data.len());
    println!("Backends: {}", backends.data.len());
    println!("Pipelines: {}", pipelines.data.len());
    
    Ok(())
}
```

## Architecture

- **`runbeam_api/client.rs`** - HTTP client for Runbeam Cloud API
- **`runbeam_api/jwt.rs`** - JWT validation with JWKS caching
- **`runbeam_api/resources.rs`** - API resource types (Gateway, Service, etc.)
- **`runbeam_api/token_storage.rs`** - Token persistence operations
- **`runbeam_api/types.rs`** - Error types and API structures
- **`storage/mod.rs`** - Storage backend trait and implementations

## License

Part of the Runbeam project.
