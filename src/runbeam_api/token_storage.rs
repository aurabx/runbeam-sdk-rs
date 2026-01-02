use crate::storage::{EncryptedFilesystemStorage, StorageBackend, StorageError};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Machine-scoped token for Runbeam Cloud API authentication
///
/// This token is issued by Runbeam Cloud and allows the gateway to make
/// autonomous API calls without user intervention. It has a 30-day expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineToken {
    /// The machine token string
    pub machine_token: String,
    /// When the token expires (ISO 8601 format)
    pub expires_at: String,
    /// Gateway ID
    pub gateway_id: String,
    /// Token abilities/permissions
    #[serde(default)]
    pub abilities: Vec<String>,
    /// When this token was issued/stored (ISO 8601 format)
    pub issued_at: String,
}

impl MachineToken {
    /// Create a new machine token
    pub fn new(
        machine_token: String,
        expires_at: String,
        gateway_id: String,
        abilities: Vec<String>,
    ) -> Self {
        let issued_at = Utc::now().to_rfc3339();

        Self {
            machine_token,
            expires_at,
            gateway_id,
            abilities,
            issued_at,
        }
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        // Parse the expiry timestamp
        match DateTime::parse_from_rfc3339(&self.expires_at) {
            Ok(expiry) => {
                let now = Utc::now();
                expiry.with_timezone(&Utc) < now
            }
            Err(e) => {
                tracing::warn!("Failed to parse token expiry date: {}", e);
                // If we can't parse the date, consider it expired for safety
                true
            }
        }
    }

    /// Check if the token is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }
}

// ============================================================================
// Generic Token Storage Functions
// ============================================================================

/// Save any token using encrypted filesystem storage
///
/// Tokens are stored encrypted at `~/.runbeam/<instance_id>/<token_type>.json`
/// using age encryption. The encryption key is sourced from:
/// 1. **RUNBEAM_ENCRYPTION_KEY** environment variable (production/containers)
/// 2. Auto-generated at `~/.runbeam/<instance_id>/encryption.key` (local development)
///
/// # Type Parameters
///
/// * `T` - Any type that implements `Serialize`
///
/// # Arguments
///
/// * `instance_id` - Unique identifier for this application instance (e.g., "harmony", "runbeam-cli")
/// * `token_type` - Token type identifier (e.g., "auth", "user_auth", "custom")
/// * `token` - The token to save
///
/// # Returns
///
/// Returns `Ok(())` if the token was saved successfully, or `Err(StorageError)`
/// if the operation failed.
///
/// # Examples
///
/// ```no_run
/// use runbeam_sdk::{save_token, MachineToken, UserToken, UserInfo};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Save machine token
/// let machine_token = MachineToken::new(
///     "token123".to_string(),
///     "2024-12-01T00:00:00Z".to_string(),
///     "gateway-1".to_string(),
///     vec!["read".to_string()],
/// );
/// save_token("harmony", "auth", &machine_token).await?;
///
/// // Save user token
/// let user_info = UserInfo {
///     id: "user-1".to_string(),
///     name: "User".to_string(),
///     email: "user@example.com".to_string(),
/// };
/// let user_token = UserToken::new("jwt123".to_string(), Some(3600), Some(user_info));
/// save_token("runbeam-cli", "user_auth", &user_token).await?;
/// # Ok(())
/// # }
/// ```
pub async fn save_token<T>(
    instance_id: &str,
    token_type: &str,
    token: &T,
) -> Result<(), StorageError>
where
    T: Serialize,
{
    let token_path = format!("runbeam/{}.json", token_type);
    tracing::debug!(
        "Saving token: type={}, instance={}, path={}",
        token_type,
        instance_id,
        token_path
    );

    // Initialize encrypted storage
    let storage = EncryptedFilesystemStorage::new_with_instance(instance_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initialize encrypted storage: {}", e);
            e
        })?;

    // Serialize token to JSON
    let json = serde_json::to_vec_pretty(&token).map_err(|e| {
        tracing::error!("Failed to serialize token: {}", e);
        StorageError::Config(format!("JSON serialization failed: {}", e))
    })?;

    // Write to encrypted storage
    storage.write_file_str(&token_path, &json).await?;

    tracing::info!(
        "Token saved successfully to encrypted storage: type={}, instance={}",
        token_type,
        instance_id
    );

    Ok(())
}

/// Load any token from encrypted filesystem storage
///
/// Tokens are loaded from `~/.runbeam/<instance_id>/<token_type>.json`
/// and automatically decrypted using the age encryption key.
///
/// # Type Parameters
///
/// * `T` - Any type that implements `DeserializeOwned`
///
/// # Arguments
///
/// * `instance_id` - Unique identifier for this application instance
/// * `token_type` - Token type identifier (e.g., "auth", "user_auth", "custom")
///
/// # Returns
///
/// Returns `Ok(Some(token))` if a token was found and loaded successfully,
/// `Ok(None)` if no token file exists, or `Err(StorageError)` if loading failed.
///
/// # Examples
///
/// ```no_run
/// use runbeam_sdk::{load_token, MachineToken, UserToken};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Load machine token
/// let machine_token: Option<MachineToken> = load_token("harmony", "auth").await?;
///
/// // Load user token
/// let user_token: Option<UserToken> = load_token("runbeam-cli", "user_auth").await?;
/// # Ok(())
/// # }
/// ```
pub async fn load_token<T>(instance_id: &str, token_type: &str) -> Result<Option<T>, StorageError>
where
    T: DeserializeOwned,
{
    let token_path = format!("runbeam/{}.json", token_type);
    tracing::debug!(
        "Loading token: type={}, instance={}, path={}",
        token_type,
        instance_id,
        token_path
    );

    // Initialize encrypted storage
    let storage = EncryptedFilesystemStorage::new_with_instance(instance_id)
        .await
        .map_err(|e| {
            tracing::debug!("Failed to initialize encrypted storage: {}", e);
            e
        })?;

    // Check if token exists
    if !storage.exists_str(&token_path) {
        tracing::debug!("No token file found: type={}", token_type);
        return Ok(None);
    }

    // Read and decrypt token
    tracing::debug!("Token found in encrypted filesystem, loading...");
    let json = storage.read_file_str(&token_path).await?;

    // Deserialize token
    let token: T = serde_json::from_slice(&json).map_err(|e| {
        tracing::error!("Failed to deserialize token: {}", e);
        StorageError::Config(format!("JSON deserialization failed: {}", e))
    })?;

    tracing::debug!(
        "Token loaded successfully from encrypted filesystem: type={}",
        token_type
    );
    Ok(Some(token))
}

/// Clear any token from encrypted filesystem storage
///
/// Removes the token file from `~/.runbeam/<instance_id>/<token_type>.json`.
///
/// # Arguments
///
/// * `instance_id` - Unique identifier for this application instance
/// * `token_type` - Token type identifier (e.g., "auth", "user_auth", "custom")
///
/// # Returns
///
/// Returns `Ok(())` if the token was cleared successfully or didn't exist,
/// or `Err(StorageError)` if the operation failed.
///
/// # Examples
///
/// ```no_run
/// use runbeam_sdk::clear_token;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Clear machine token
/// clear_token("harmony", "auth").await?;
///
/// // Clear user token
/// clear_token("runbeam-cli", "user_auth").await?;
/// # Ok(())
/// # }
/// ```
pub async fn clear_token(instance_id: &str, token_type: &str) -> Result<(), StorageError> {
    let token_path = format!("runbeam/{}.json", token_type);
    tracing::debug!(
        "Clearing token: type={}, instance={}, path={}",
        token_type,
        instance_id,
        token_path
    );

    // Initialize encrypted storage
    let storage = EncryptedFilesystemStorage::new_with_instance(instance_id)
        .await
        .map_err(|e| {
            tracing::debug!("Failed to initialize encrypted storage: {}", e);
            e
        })?;

    // Check if token exists
    if !storage.exists_str(&token_path) {
        tracing::debug!("No token file to clear: type={}", token_type);
        return Ok(());
    }

    // Remove token
    tracing::debug!("Clearing token from encrypted filesystem storage");
    storage.remove_str(&token_path).await.map_err(|e| {
        tracing::error!("Failed to clear token: {}", e);
        e
    })?;

    tracing::info!("Token cleared successfully: type={}", token_type);
    Ok(())
}

// ============================================================================
// Backwards-Compatible Machine Token Functions
// ============================================================================

/// Save a machine token with an explicit encryption key
///
/// This function uses the provided encryption key for token storage.
///
/// # Arguments
///
/// * `instance_id` - Unique identifier for this application instance (e.g., "harmony", "runbeam-cli", "test-123")
/// * `token` - The machine token to save
/// * `encryption_key` - Base64-encoded age X25519 encryption key for filesystem storage
///
/// # Returns
///
/// Returns `Ok(())` if the token was saved successfully, or `Err(StorageError)`
/// if the operation failed.
pub async fn save_token_with_key(
    instance_id: &str,
    token: &MachineToken,
    encryption_key: &str,
) -> Result<(), StorageError> {
    let token_path = "runbeam/auth.json";
    tracing::debug!(
        "Saving machine token with explicit encryption key: gateway={}, instance={}",
        token.gateway_id,
        instance_id
    );

    // Use encrypted filesystem with the provided key
    let storage =
        EncryptedFilesystemStorage::new_with_instance_and_key(instance_id, encryption_key).await?;

    // Serialize token to JSON
    let json = serde_json::to_vec_pretty(&token).map_err(|e| {
        tracing::error!("Failed to serialize machine token: {}", e);
        StorageError::Config(format!("JSON serialization failed: {}", e))
    })?;

    // Write to encrypted storage
    storage.write_file_str(token_path, &json).await?;

    tracing::info!(
        "Machine token saved successfully with explicit key: gateway_id={}, expires_at={}",
        token.gateway_id,
        token.expires_at
    );

    Ok(())
}

/// Save a machine token using encrypted filesystem storage
///
/// **Backwards-compatible wrapper** for `save_token(instance_id, "auth", token)`.
///
/// Tokens are stored encrypted at `~/.runbeam/<instance_id>/auth.json`.
///
/// # Encryption
///
/// The encryption key is sourced from:
/// 1. `RUNBEAM_ENCRYPTION_KEY` environment variable (base64-encoded)
/// 2. Auto-generated key stored at `~/.runbeam/<instance_id>/encryption.key` (0600 permissions)
///
/// # Arguments
///
/// * `instance_id` - Unique identifier for this application instance (e.g., "harmony", "runbeam-cli", "test-123")
/// * `token` - The machine token to save
///
/// # Returns
///
/// Returns `Ok(())` if the token was saved successfully, or `Err(StorageError)`
/// if the operation failed.
pub async fn save_machine_token(
    instance_id: &str,
    token: &MachineToken,
) -> Result<(), StorageError> {
    save_token(instance_id, "auth", token).await
}

/// Load a machine token from encrypted filesystem storage
///
/// **Backwards-compatible wrapper** for `load_token(instance_id, "auth")`.
///
/// Attempts to load the token from `~/.runbeam/<instance_id>/auth.json`. Returns `None` if the
/// file doesn't exist.
///
/// # Arguments
///
/// * `instance_id` - Unique identifier for this application instance (e.g., "harmony", "runbeam-cli")
///
/// # Returns
///
/// Returns `Ok(Some(token))` if a token was found and loaded successfully,
/// `Ok(None)` if no token file exists, or `Err(StorageError)` if loading failed.
pub async fn load_machine_token(instance_id: &str) -> Result<Option<MachineToken>, StorageError> {
    load_token(instance_id, "auth").await
}

/// Clear the machine token from encrypted filesystem storage
///
/// **Backwards-compatible wrapper** for `clear_token(instance_id, "auth")`.
///
/// Removes the token file at `~/.runbeam/<instance_id>/auth.json` if it exists.
///
/// # Arguments
///
/// * `instance_id` - Unique identifier for this application instance (e.g., "harmony", "runbeam-cli")
///
/// # Returns
///
/// Returns `Ok(())` if the token was cleared successfully or didn't exist,
/// or `Err(StorageError)` if the operation failed.
pub async fn clear_machine_token(instance_id: &str) -> Result<(), StorageError> {
    clear_token(instance_id, "auth").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Setup test encryption key and return cleanup function
    fn setup_test_encryption() -> impl Drop {
        use base64::Engine;
        use secrecy::ExposeSecret;
        use std::env;

        let identity = age::x25519::Identity::generate();
        let key_base64 = base64::engine::general_purpose::STANDARD
            .encode(identity.to_string().expose_secret().as_bytes());
        env::set_var("RUNBEAM_ENCRYPTION_KEY", &key_base64);

        // Return a guard that will clean up on drop
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                std::env::remove_var("RUNBEAM_ENCRYPTION_KEY");
            }
        }
        Guard
    }

    #[test]
    fn test_machine_token_creation() {
        let token = MachineToken::new(
            "test_token".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
            "gw123".to_string(),
            vec!["harmony:send".to_string(), "harmony:receive".to_string()],
        );

        assert_eq!(token.machine_token, "test_token");
        assert_eq!(token.gateway_id, "gw123");
        assert_eq!(token.abilities.len(), 2);
        assert!(!token.issued_at.is_empty());
    }

    #[test]
    fn test_machine_token_is_expired() {
        // Expired token (year 2020)
        let expired_token = MachineToken::new(
            "test_token".to_string(),
            "2020-01-01T00:00:00Z".to_string(),
            "gw123".to_string(),
            vec![],
        );
        assert!(expired_token.is_expired());
        assert!(!expired_token.is_valid());

        // Valid token (far future)
        let valid_token = MachineToken::new(
            "test_token".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw123".to_string(),
            vec![],
        );
        assert!(!valid_token.is_expired());
        assert!(valid_token.is_valid());
    }

    #[test]
    fn test_machine_token_serialization() {
        let token = MachineToken::new(
            "test_token".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
            "gw123".to_string(),
            vec!["harmony:send".to_string()],
        );

        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains("\"machine_token\":\"test_token\""));
        assert!(json.contains("\"gateway_id\":\"gw123\""));

        // Deserialize and verify
        let deserialized: MachineToken = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.machine_token, token.machine_token);
        assert_eq!(deserialized.gateway_id, token.gateway_id);
    }

    #[tokio::test]
    #[serial]
    async fn test_save_and_load_token_secure() {
        let _guard = setup_test_encryption();
        let instance_id = "test-save-load";
        // Clear any existing token first
        let _ = clear_machine_token(instance_id).await;

        let token = MachineToken::new(
            "test_token_secure".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_test".to_string(),
            vec!["harmony:send".to_string()],
        );

        // Save token using automatic secure storage (wrapper)
        save_machine_token(instance_id, &token).await.unwrap();

        // Load token using automatic secure storage (wrapper)
        let loaded = load_machine_token(instance_id).await.unwrap();
        assert!(loaded.is_some());

        let loaded_token = loaded.unwrap();
        assert_eq!(loaded_token.machine_token, token.machine_token);
        assert_eq!(loaded_token.gateway_id, token.gateway_id);
        assert!(loaded_token.is_valid());

        // Cleanup
        clear_machine_token(instance_id).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_load_nonexistent_token_secure() {
        let _guard = setup_test_encryption();
        let instance_id = "test-nonexistent";
        // Clear any existing token
        let _ = clear_machine_token(instance_id).await;

        // Load from empty storage should return None
        let result = load_machine_token(instance_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_clear_token_secure() {
        let _guard = setup_test_encryption();
        let instance_id = "test-clear";
        // Clear any existing token first
        let _ = clear_machine_token(instance_id).await;

        let token = MachineToken::new(
            "test_clear".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_clear".to_string(),
            vec![],
        );

        // Save token
        save_machine_token(instance_id, &token).await.unwrap();

        // Verify it exists
        assert!(load_machine_token(instance_id).await.unwrap().is_some());

        // Clear token
        clear_machine_token(instance_id).await.unwrap();

        // Verify it's gone
        assert!(load_machine_token(instance_id).await.unwrap().is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_clear_nonexistent_token_secure() {
        let _guard = setup_test_encryption();
        let instance_id = "test-clear-nonexistent";
        // Clear token that doesn't exist should not error
        clear_machine_token(instance_id).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_token_expiry_detection() {
        let _guard = setup_test_encryption();
        let instance_id = "test-expiry";
        let _ = clear_machine_token(instance_id).await;

        // Create expired token
        let expired_token = MachineToken::new(
            "expired_token".to_string(),
            "2020-01-01T00:00:00Z".to_string(),
            "gw_expired".to_string(),
            vec![],
        );

        save_machine_token(instance_id, &expired_token)
            .await
            .unwrap();

        // Load and verify it's marked as expired
        let loaded = load_machine_token(instance_id).await.unwrap();
        assert!(loaded.is_some());
        let loaded_token = loaded.unwrap();
        assert!(loaded_token.is_expired());
        assert!(!loaded_token.is_valid());

        // Cleanup
        clear_machine_token(instance_id).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_token_with_abilities() {
        let _guard = setup_test_encryption();
        let instance_id = "test-abilities";
        let _ = clear_machine_token(instance_id).await;

        let token = MachineToken::new(
            "token_with_abilities".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_abilities".to_string(),
            vec![
                "harmony:send".to_string(),
                "harmony:receive".to_string(),
                "harmony:config".to_string(),
            ],
        );

        save_machine_token(instance_id, &token).await.unwrap();

        let loaded = load_machine_token(instance_id).await.unwrap().unwrap();
        assert_eq!(loaded.abilities.len(), 3);
        assert!(loaded.abilities.contains(&"harmony:send".to_string()));
        assert!(loaded.abilities.contains(&"harmony:receive".to_string()));
        assert!(loaded.abilities.contains(&"harmony:config".to_string()));

        // Cleanup
        clear_machine_token(instance_id).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_token_overwrites_existing() {
        let _guard = setup_test_encryption();
        let instance_id = "test-overwrite";
        let _ = clear_machine_token(instance_id).await;

        // Save first token
        let token1 = MachineToken::new(
            "first_token".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_first".to_string(),
            vec![],
        );
        save_machine_token(instance_id, &token1).await.unwrap();

        // Save second token (should overwrite)
        let token2 = MachineToken::new(
            "second_token".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_second".to_string(),
            vec![],
        );
        save_machine_token(instance_id, &token2).await.unwrap();

        // Should load second token
        let loaded = load_machine_token(instance_id).await.unwrap().unwrap();
        assert_eq!(loaded.machine_token, "second_token");
        assert_eq!(loaded.gateway_id, "gw_second");

        // Cleanup
        clear_machine_token(instance_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_token_encrypted_on_disk() {
        use crate::storage::EncryptedFilesystemStorage;
        use tempfile::TempDir;

        let instance_id = "test-encryption-verify";
        let temp_dir = TempDir::new().unwrap();

        // Create token with sensitive data
        let token = MachineToken::new(
            "super_secret_token_12345".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_secret".to_string(),
            vec!["harmony:admin".to_string()],
        );

        // Use encrypted storage directly for testing
        let storage_path = temp_dir.path().join(instance_id);
        let storage = EncryptedFilesystemStorage::new(&storage_path)
            .await
            .unwrap();

        // Save token
        let token_json = serde_json::to_vec(&token).unwrap();
        storage
            .write_file_str("auth.json", &token_json)
            .await
            .unwrap();

        // Find the stored token file
        let token_path = storage_path.join("auth.json");

        // Verify file exists
        assert!(
            token_path.exists(),
            "Token file should exist at {:?}",
            token_path
        );

        // Read raw file contents
        let raw_contents = std::fs::read(&token_path).unwrap();
        let raw_string = String::from_utf8_lossy(&raw_contents);

        // Verify the file does NOT contain plaintext sensitive data
        assert!(
            !raw_string.contains("super_secret_token_12345"),
            "Token file should NOT contain plaintext token: {}",
            raw_string
        );
        assert!(
            !raw_string.contains("gw_secret"),
            "Token file should NOT contain plaintext gateway_id: {}",
            raw_string
        );
        assert!(
            !raw_string.contains("harmony:admin"),
            "Token file should NOT contain plaintext abilities: {}",
            raw_string
        );

        // Verify it contains age encryption markers
        if raw_contents.len() > 50 {
            // age encryption typically starts with "age-encryption.org/v1"
            let has_age_header = raw_string.starts_with("age-encryption.org/v1");
            assert!(
                has_age_header || raw_contents.starts_with(b"age-encryption.org/v1"),
                "File should contain age encryption header. Raw contents (first 100 bytes): {:?}",
                &raw_contents[..std::cmp::min(100, raw_contents.len())]
            );
        }

        // Verify we can still decrypt and load the token correctly
        let decrypted_data = storage.read_file_str("auth.json").await.unwrap();
        let loaded_token: MachineToken = serde_json::from_slice(&decrypted_data).unwrap();
        assert_eq!(loaded_token.machine_token, "super_secret_token_12345");
        assert_eq!(loaded_token.gateway_id, "gw_secret");
    }

    #[tokio::test]
    async fn test_token_file_cannot_be_read_as_json() {
        use crate::storage::EncryptedFilesystemStorage;
        use tempfile::TempDir;

        let instance_id = "test-raw-json-read";
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().join(instance_id);

        let token = MachineToken::new(
            "test_token_json".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_json".to_string(),
            vec![],
        );

        // Use encrypted storage directly
        let storage = EncryptedFilesystemStorage::new(&storage_path)
            .await
            .unwrap();
        let token_json = serde_json::to_vec(&token).unwrap();
        storage
            .write_file_str("auth.json", &token_json)
            .await
            .unwrap();

        // Try to read the file as JSON
        let token_path = storage_path.join("auth.json");

        // Read as bytes first (encrypted data may not be valid UTF-8)
        let raw_contents = std::fs::read(&token_path).unwrap();

        // Try to parse as JSON - should fail because it's encrypted
        let json_parse_result: Result<serde_json::Value, _> = serde_json::from_slice(&raw_contents);
        assert!(
            json_parse_result.is_err(),
            "Raw token file should NOT be parseable as JSON (it should be encrypted)"
        );
    }

    #[tokio::test]
    async fn test_token_different_from_plaintext() {
        use crate::storage::EncryptedFilesystemStorage;
        use tempfile::TempDir;

        let instance_id = "test-plaintext-compare";
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().join(instance_id);

        let token = MachineToken::new(
            "comparison_token".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_compare".to_string(),
            vec!["test:ability".to_string()],
        );

        // Get plaintext JSON representation
        let plaintext_json = serde_json::to_vec(&token).unwrap();

        // Use encrypted storage directly
        let storage = EncryptedFilesystemStorage::new(&storage_path)
            .await
            .unwrap();
        storage
            .write_file_str("auth.json", &plaintext_json)
            .await
            .unwrap();

        // Read encrypted file
        let token_path = storage_path.join("auth.json");
        let encrypted_contents = std::fs::read(&token_path).unwrap();

        // Encrypted contents should be different from plaintext
        assert_ne!(
            encrypted_contents, plaintext_json,
            "Encrypted file contents should differ from plaintext JSON"
        );

        // Encrypted contents should be longer (encryption overhead)
        assert!(
            encrypted_contents.len() > plaintext_json.len(),
            "Encrypted file should be larger due to encryption overhead. Encrypted: {}, Plaintext: {}",
            encrypted_contents.len(),
            plaintext_json.len()
        );
    }

    #[tokio::test]
    async fn test_multiple_instances_isolated() {
        use crate::storage::EncryptedFilesystemStorage;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create tokens for different instances
        let token1 = MachineToken::new(
            "token_instance_1".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_1".to_string(),
            vec![],
        );

        let token2 = MachineToken::new(
            "token_instance_2".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_2".to_string(),
            vec![],
        );

        // Create separate storage instances
        let storage1_path = temp_dir.path().join("instance-1");
        let storage2_path = temp_dir.path().join("instance-2");

        let storage1 = EncryptedFilesystemStorage::new(&storage1_path)
            .await
            .unwrap();
        let storage2 = EncryptedFilesystemStorage::new(&storage2_path)
            .await
            .unwrap();

        // Save tokens
        let token1_json = serde_json::to_vec(&token1).unwrap();
        let token2_json = serde_json::to_vec(&token2).unwrap();
        storage1
            .write_file_str("auth.json", &token1_json)
            .await
            .unwrap();
        storage2
            .write_file_str("auth.json", &token2_json)
            .await
            .unwrap();

        // Verify files are in separate directories
        let path1 = storage1_path.join("auth.json");
        let path2 = storage2_path.join("auth.json");

        assert!(path1.exists(), "Instance 1 token file should exist");
        assert!(path2.exists(), "Instance 2 token file should exist");
        assert_ne!(path1, path2, "Token files should be in different locations");

        // Verify encryption keys are separate (if not using env var)
        let key1_path = storage1_path.join("encryption.key");
        let key2_path = storage2_path.join("encryption.key");

        if key1_path.exists() && key2_path.exists() {
            let key1_contents = std::fs::read(&key1_path).unwrap();
            let key2_contents = std::fs::read(&key2_path).unwrap();
            assert_ne!(
                key1_contents, key2_contents,
                "Encryption keys should be different for each instance"
            );
        }

        // Verify tokens are isolated by decrypting them
        let decrypted1 = storage1.read_file_str("auth.json").await.unwrap();
        let decrypted2 = storage2.read_file_str("auth.json").await.unwrap();

        let loaded1: MachineToken = serde_json::from_slice(&decrypted1).unwrap();
        let loaded2: MachineToken = serde_json::from_slice(&decrypted2).unwrap();

        assert_eq!(loaded1.machine_token, "token_instance_1");
        assert_eq!(loaded1.gateway_id, "gw_1");
        assert_eq!(loaded2.machine_token, "token_instance_2");
        assert_eq!(loaded2.gateway_id, "gw_2");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_encryption_key_file_permissions() {
        use crate::storage::EncryptedFilesystemStorage;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::TempDir;

        let instance_id = "test-key-permissions";
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().join(instance_id);

        // Create storage which will generate encryption key
        let _storage = EncryptedFilesystemStorage::new(&storage_path)
            .await
            .unwrap();

        // Check encryption key file permissions
        let key_path = storage_path.join("encryption.key");

        // Key may be in storage path or env var - check if file was created
        if !key_path.exists() {
            // If using RUNBEAM_ENCRYPTION_KEY env var, skip this test
            return;
        }

        let metadata = std::fs::metadata(&key_path).unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Check that only owner has read/write (0600)
        let permission_bits = mode & 0o777;
        assert_eq!(
            permission_bits, 0o600,
            "Encryption key file should have 0600 permissions (owner read/write only), got {:o}",
            permission_bits
        );
    }

    #[tokio::test]
    async fn test_tampered_token_file_fails_to_load() {
        use crate::storage::EncryptedFilesystemStorage;
        use tempfile::TempDir;

        let instance_id = "test-tamper";
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().join(instance_id);

        let token = MachineToken::new(
            "original_token".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_tamper".to_string(),
            vec![],
        );

        // Use encrypted storage directly
        let storage = EncryptedFilesystemStorage::new(&storage_path)
            .await
            .unwrap();
        let token_json = serde_json::to_vec(&token).unwrap();
        storage
            .write_file_str("auth.json", &token_json)
            .await
            .unwrap();

        // Tamper with the encrypted file
        let token_path = storage_path.join("auth.json");
        let mut contents = std::fs::read(&token_path).unwrap();

        // Flip some bytes in the middle of the file
        if contents.len() > 50 {
            contents[25] = contents[25].wrapping_add(1);
            contents[30] = contents[30].wrapping_sub(1);
            std::fs::write(&token_path, contents).unwrap();
        }

        // Attempting to decrypt should fail
        let result = storage.read_file_str("auth.json").await;
        assert!(
            result.is_err(),
            "Loading tampered encrypted file should fail"
        );
    }

    // ========================================================================
    // Generic Token Storage Tests
    // ========================================================================

    #[tokio::test]
    #[serial]
    async fn test_generic_save_and_load_user_token() {
        use crate::runbeam_api::types::UserToken;
        let _guard = setup_test_encryption();
        let instance_id = "test-user-token";
        clear_token(instance_id, "user_auth").await.ok();

        let user_token = UserToken::new(
            "user_jwt_token".to_string(),
            Some(1234567890),
            Some(crate::runbeam_api::types::UserInfo {
                id: "user123".to_string(),
                name: "Test User".to_string(),
                email: "test@example.com".to_string(),
            }),
        );

        // Save using generic function
        save_token(instance_id, "user_auth", &user_token)
            .await
            .unwrap();

        // Load using generic function
        let loaded: Option<UserToken> = load_token(instance_id, "user_auth").await.unwrap();
        assert!(loaded.is_some());

        let loaded_token = loaded.unwrap();
        assert_eq!(loaded_token.token, user_token.token);
        assert_eq!(loaded_token.expires_at, user_token.expires_at);
        assert!(loaded_token.user.is_some());

        // Cleanup
        clear_token(instance_id, "user_auth").await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_different_token_types_isolated() {
        use crate::runbeam_api::types::UserToken;
        let _guard = setup_test_encryption();
        let instance_id = "test-isolation";

        // Create different token types
        let user_token = UserToken::new("user_token".to_string(), None, None);

        let machine_token = MachineToken::new(
            "machine_token".to_string(),
            "2099-12-31T23:59:59Z".to_string(),
            "gw_test".to_string(),
            vec![],
        );

        // Save both
        save_token(instance_id, "user_auth", &user_token)
            .await
            .unwrap();
        save_token(instance_id, "auth", &machine_token)
            .await
            .unwrap();

        // Load both - should be independent
        let loaded_user: Option<UserToken> = load_token(instance_id, "user_auth").await.unwrap();
        let loaded_machine: Option<MachineToken> = load_token(instance_id, "auth").await.unwrap();

        assert!(loaded_user.is_some());
        assert!(loaded_machine.is_some());
        assert_eq!(loaded_user.unwrap().token, "user_token");
        assert_eq!(loaded_machine.unwrap().machine_token, "machine_token");

        // Cleanup
        clear_token(instance_id, "user_auth").await.unwrap();
        clear_token(instance_id, "auth").await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_user_token_with_full_metadata() {
        use crate::runbeam_api::types::UserToken;
        let _guard = setup_test_encryption();
        let instance_id = "test-user-full";
        clear_token(instance_id, "user_auth").await.ok();

        let user_token = UserToken::new(
            "detailed_user_token".to_string(),
            Some(2000000000),
            Some(crate::runbeam_api::types::UserInfo {
                id: "user456".to_string(),
                name: "John Doe".to_string(),
                email: "john@example.com".to_string(),
            }),
        );

        // Save and load
        save_token(instance_id, "user_auth", &user_token)
            .await
            .unwrap();
        let loaded: Option<UserToken> = load_token(instance_id, "user_auth").await.unwrap();

        assert!(loaded.is_some());
        let loaded_token = loaded.unwrap();
        assert_eq!(loaded_token.token, "detailed_user_token");
        assert_eq!(loaded_token.expires_at, Some(2000000000));

        let user_info = loaded_token.user.unwrap();
        assert_eq!(user_info.id, "user456");
        assert_eq!(user_info.name, "John Doe");
        assert_eq!(user_info.email, "john@example.com");

        // Cleanup
        clear_token(instance_id, "user_auth").await.unwrap();
    }
}
