use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

/// Storage backend trait for persisting data
///
/// This trait abstracts storage operations to allow for different storage
/// implementations (filesystem, keyring, etc.)
pub trait StorageBackend: Send + Sync {
    /// Write data to storage at the specified path
    fn write_file_str(
        &self,
        path: &str,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>>;

    /// Read data from storage at the specified path
    fn read_file_str(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, StorageError>> + Send + '_>>;

    /// Check if a file exists at the specified path
    fn exists_str(&self, path: &str) -> bool;

    /// Remove a file at the specified path
    fn remove_str(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>>;
}

/// Storage errors
#[derive(Debug)]
pub enum StorageError {
    /// IO error
    Io(std::io::Error),
    /// Configuration or serialization error
    Config(String),
    /// Keyring error
    Keyring(String),
    /// Path error
    Path(String),
    /// Encryption error
    Encryption(String),
    /// Key generation error
    KeyGeneration(String),
    /// Key storage error
    KeyStorage(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "IO error: {}", e),
            StorageError::Config(msg) => write!(f, "Configuration error: {}", msg),
            StorageError::Keyring(msg) => write!(f, "Keyring error: {}", msg),
            StorageError::Path(msg) => write!(f, "Path error: {}", msg),
            StorageError::Encryption(msg) => write!(f, "Encryption error: {}", msg),
            StorageError::KeyGeneration(msg) => write!(f, "Key generation error: {}", msg),
            StorageError::KeyStorage(msg) => write!(f, "Key storage error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err)
    }
}

impl From<keyring::Error> for StorageError {
    fn from(err: keyring::Error) -> Self {
        StorageError::Keyring(err.to_string())
    }
}

/// Keyring-based storage for secure credentials
///
/// This implementation uses the OS-native credential store:
/// - macOS: Keychain
/// - Linux: Secret Service API (freedesktop.org)
/// - Windows: Credential Manager
pub struct KeyringStorage {
    service_name: String,
}

impl KeyringStorage {
    /// Create a new keyring storage with the specified service name
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    /// Get the keyring entry for a specific path
    fn get_entry(&self, path: &str) -> Result<keyring::Entry, StorageError> {
        // Use path as the username/account identifier
        keyring::Entry::new(&self.service_name, path)
            .map_err(|e| StorageError::Keyring(format!("Failed to create keyring entry: {}", e)))
    }
}

impl StorageBackend for KeyringStorage {
    fn write_file_str(
        &self,
        path: &str,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let path = path.to_string();
        let data = data.to_vec();
        let service_name = self.service_name.clone();

        Box::pin(async move {
            let entry = keyring::Entry::new(&service_name, &path).map_err(|e| {
                StorageError::Keyring(format!("Failed to create keyring entry: {}", e))
            })?;

            let data_str = String::from_utf8(data)
                .map_err(|e| StorageError::Config(format!("Invalid UTF-8 data: {}", e)))?;

            entry.set_password(&data_str)?;
            tracing::debug!(
                "Stored data in keyring: service={}, path={}",
                service_name,
                path
            );
            Ok(())
        })
    }

    fn read_file_str(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, StorageError>> + Send + '_>> {
        let path = path.to_string();
        let service_name = self.service_name.clone();

        Box::pin(async move {
            let entry = keyring::Entry::new(&service_name, &path).map_err(|e| {
                StorageError::Keyring(format!("Failed to create keyring entry: {}", e))
            })?;

            let password = entry.get_password()?;
            Ok(password.into_bytes())
        })
    }

    fn exists_str(&self, path: &str) -> bool {
        if let Ok(entry) = self.get_entry(path) {
            entry.get_password().is_ok()
        } else {
            false
        }
    }

    fn remove_str(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let path = path.to_string();
        let service_name = self.service_name.clone();

        Box::pin(async move {
            let entry = keyring::Entry::new(&service_name, &path).map_err(|e| {
                StorageError::Keyring(format!("Failed to create keyring entry: {}", e))
            })?;

            entry.delete_credential()?;
            tracing::debug!(
                "Removed data from keyring: service={}, path={}",
                service_name,
                path
            );
            Ok(())
        })
    }
}

/// Filesystem-based storage for non-secure data or fallback
///
/// # ⚠️ Security Warning
///
/// **DO NOT use this storage backend for sensitive data like authentication tokens!**
/// Data is stored **unencrypted** on disk.
///
/// For secure token storage, use:
/// - `KeyringStorage` for OS keychain storage (preferred)
/// - `EncryptedFilesystemStorage` for encrypted file storage (fallback)
///
/// This implementation is only suitable for:
/// - Non-sensitive configuration data
/// - Development and testing
/// - Temporary files and caches
pub struct FilesystemStorage {
    base_path: PathBuf,
}

impl FilesystemStorage {
    /// Create a new filesystem storage with the specified base path
    pub fn new(base_path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let base_path = base_path.as_ref().to_path_buf();

        if !base_path.exists() {
            std::fs::create_dir_all(&base_path)?;
        }

        Ok(Self { base_path })
    }

    /// Resolve a relative path to an absolute path
    fn resolve_path(&self, path: &str) -> PathBuf {
        self.base_path.join(path)
    }
}

impl StorageBackend for FilesystemStorage {
    fn write_file_str(
        &self,
        path: &str,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let full_path = self.resolve_path(path);
        let data = data.to_vec();

        Box::pin(async move {
            // Create parent directories if needed
            if let Some(parent) = full_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            tokio::fs::write(&full_path, data).await?;
            tracing::debug!("Wrote data to filesystem: {:?}", full_path);
            Ok(())
        })
    }

    fn read_file_str(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, StorageError>> + Send + '_>> {
        let full_path = self.resolve_path(path);

        Box::pin(async move {
            let data = tokio::fs::read(&full_path).await?;
            tracing::debug!("Read data from filesystem: {:?}", full_path);
            Ok(data)
        })
    }

    fn exists_str(&self, path: &str) -> bool {
        let full_path = self.resolve_path(path);
        full_path.exists()
    }

    fn remove_str(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let full_path = self.resolve_path(path);

        Box::pin(async move {
            tokio::fs::remove_file(&full_path).await?;
            tracing::debug!("Removed file from filesystem: {:?}", full_path);
            Ok(())
        })
    }
}

/// Encrypted filesystem storage for secure credential storage
///
/// This implementation encrypts data at rest using the `age` encryption library.
/// It provides a secure alternative to keyring when:
/// - Keyring is unavailable (headless environments, CI/CD)
/// - Platform keyring integration is not possible
/// - Remote/containerized environments
///
/// # Encryption Key Management
///
/// The encryption key is obtained in the following priority order:
/// 1. **Environment Variable**: `RUNBEAM_ENCRYPTION_KEY` (base64-encoded)
/// 2. **Generated Key**: Automatically generated and stored at `~/.runbeam/encryption.key`
///
/// Generated keys are created with restrictive file permissions (0600 on Unix) to prevent
/// unauthorized access.
///
/// # Security Considerations
///
/// - **DO NOT** commit encryption keys to version control
/// - In production, use `RUNBEAM_ENCRYPTION_KEY` environment variable
/// - Protect the `~/.runbeam/encryption.key` file with appropriate file system permissions
/// - Consider key rotation policies for long-lived deployments
/// - In containerized environments, use secrets management (e.g., Docker secrets, k8s secrets)
pub struct EncryptedFilesystemStorage {
    base_path: PathBuf,
    recipient: age::x25519::Recipient,
    identity: age::x25519::Identity,
}

impl EncryptedFilesystemStorage {
    /// Create a new encrypted filesystem storage with an instance-specific key
    ///
    /// Uses `~/.runbeam/<instance_id>` as the base path for storage and keys.
    /// This allows multiple instances to have isolated storage.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - Unique identifier for this instance (e.g., "harmony", "runbeam-cli", "test-123")
    ///
    /// # Returns
    ///
    /// Returns a configured `EncryptedFilesystemStorage` or an error if:
    /// - The base path cannot be created
    /// - Encryption key cannot be loaded or generated
    /// - Key file permissions cannot be set properly
    pub async fn new_with_instance(instance_id: &str) -> Result<Self, StorageError> {
        let home = dirs::home_dir().ok_or_else(|| {
            StorageError::KeyStorage("Cannot determine home directory".to_string())
        })?;

        let base_path = home.join(".runbeam").join(instance_id);
        Self::new_with_key_path(base_path.clone(), base_path.join("encryption.key")).await
    }

    /// Create a new encrypted filesystem storage
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base directory for encrypted file storage
    ///
    /// # Returns
    ///
    /// Returns a configured `EncryptedFilesystemStorage` or an error if:
    /// - The base path cannot be created
    /// - Encryption key cannot be loaded or generated
    /// - Key file permissions cannot be set properly
    pub async fn new(base_path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let base_path = base_path.as_ref().to_path_buf();
        let key_path = Self::get_key_path()?;
        Self::new_with_key_path(base_path, key_path).await
    }

    /// Create a new encrypted filesystem storage with explicit paths
    async fn new_with_key_path(
        base_path: PathBuf,
        key_path: PathBuf,
    ) -> Result<Self, StorageError> {
        // Ensure base directory exists
        if !base_path.exists() {
            tokio::fs::create_dir_all(&base_path).await?;
        }

        // Load or generate encryption key
        let (recipient, identity) = Self::setup_encryption_with_path(&key_path).await?;

        Ok(Self {
            base_path,
            recipient,
            identity,
        })
    }

    /// Setup encryption by loading or generating a key with explicit path
    async fn setup_encryption_with_path(
        key_path: &Path,
    ) -> Result<(age::x25519::Recipient, age::x25519::Identity), StorageError> {
        // Try environment variable first
        if let Ok(key_base64) = std::env::var("RUNBEAM_ENCRYPTION_KEY") {
            tracing::debug!("Using encryption key from RUNBEAM_ENCRYPTION_KEY environment variable");
            return Self::load_key_from_string(&key_base64);
        }

        // Otherwise, load or generate a key file
        if key_path.exists() {
            tracing::debug!("Loading existing encryption key from {:?}", key_path);
            Self::load_key_from_file(key_path).await
        } else {
            tracing::info!(
                "Generating new encryption key and storing at {:?}",
                key_path
            );
            Self::generate_and_store_key(key_path).await
        }
    }

    /// Get the platform-specific path for storing the encryption key
    fn get_key_path() -> Result<PathBuf, StorageError> {
        let home = dirs::home_dir().ok_or_else(|| {
            StorageError::KeyStorage("Cannot determine home directory".to_string())
        })?;

        let key_dir = home.join(".runbeam");
        Ok(key_dir.join("encryption.key"))
    }

    /// Load encryption key from a base64-encoded string
    fn load_key_from_string(
        key_base64: &str,
    ) -> Result<(age::x25519::Recipient, age::x25519::Identity), StorageError> {
        use base64::{engine::general_purpose, Engine as _};

        let key_bytes = general_purpose::STANDARD
            .decode(key_base64)
            .map_err(|e| StorageError::KeyStorage(format!("Invalid base64 key: {}", e)))?;

        let key_str = String::from_utf8(key_bytes)
            .map_err(|e| StorageError::KeyStorage(format!("Invalid UTF-8 in key: {}", e)))?;

        let identity = key_str
            .parse::<age::x25519::Identity>()
            .map_err(|e| StorageError::KeyStorage(format!("Invalid age identity: {}", e)))?;

        let recipient = identity.to_public();

        Ok((recipient, identity))
    }

    /// Load encryption key from a file
    async fn load_key_from_file(
        key_path: &Path,
    ) -> Result<(age::x25519::Recipient, age::x25519::Identity), StorageError> {
        let key_contents = tokio::fs::read_to_string(key_path)
            .await
            .map_err(|e| StorageError::KeyStorage(format!("Failed to read key file: {}", e)))?;

        Self::load_key_from_string(&key_contents)
    }

    /// Generate a new encryption key and store it securely
    async fn generate_and_store_key(
        key_path: &Path,
    ) -> Result<(age::x25519::Recipient, age::x25519::Identity), StorageError> {
        use base64::{engine::general_purpose, Engine as _};
        use secrecy::ExposeSecret;

        // Generate new age identity
        let identity = age::x25519::Identity::generate();
        let identity_str = identity.to_string();

        // Base64 encode for storage (get the underlying string from Secret)
        let identity_str_exposed = identity_str.expose_secret();
        let key_base64 = general_purpose::STANDARD.encode(identity_str_exposed.as_bytes());

        // Ensure parent directory exists
        if let Some(parent) = key_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                StorageError::KeyStorage(format!("Failed to create key directory: {}", e))
            })?;
        }

        // Write key to file
        tokio::fs::write(key_path, &key_base64).await.map_err(|e| {
            StorageError::KeyStorage(format!("Failed to write key file: {}", e))
        })?;

        // Set restrictive permissions on Unix (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(key_path, permissions).map_err(|e| {
                StorageError::KeyStorage(format!("Failed to set key file permissions: {}", e))
            })?;
            tracing::debug!("Set encryption key file permissions to 0600");
        }

        tracing::info!("Generated and stored new encryption key");

        // Return recipient and identity
        let recipient = identity.to_public();

        Ok((recipient, identity))
    }

    /// Resolve a relative path to an absolute path
    fn resolve_path(&self, path: &str) -> PathBuf {
        self.base_path.join(path)
    }

    /// Encrypt data using age encryption
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        use std::io::Write;

        let encryptor = age::Encryptor::with_recipients(vec![Box::new(self.recipient.clone())])
            .expect("Failed to create encryptor with recipient");

        let mut encrypted = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| StorageError::Encryption(format!("Failed to wrap output: {}", e)))?;

        writer
            .write_all(data)
            .map_err(|e| StorageError::Encryption(format!("Failed to encrypt data: {}", e)))?;

        writer
            .finish()
            .map_err(|e| StorageError::Encryption(format!("Failed to finalize encryption: {}", e)))?;

        Ok(encrypted)
    }

    /// Decrypt data using age decryption
    fn decrypt_data(&self, encrypted: &[u8]) -> Result<Vec<u8>, StorageError> {
        use std::io::Read;

        let decryptor = match age::Decryptor::new(encrypted)
            .map_err(|e| StorageError::Encryption(format!("Failed to create decryptor: {}", e)))?
        {
            age::Decryptor::Recipients(d) => d,
            _ => {
                return Err(StorageError::Encryption(
                    "Unexpected decryptor type".to_string(),
                ))
            }
        };

        let mut decrypted = Vec::new();
        let mut reader = decryptor
            .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
            .map_err(|e| StorageError::Encryption(format!("Failed to decrypt data: {}", e)))?;

        reader
            .read_to_end(&mut decrypted)
            .map_err(|e| StorageError::Encryption(format!("Failed to read decrypted data: {}", e)))?;

        Ok(decrypted)
    }
}

impl StorageBackend for EncryptedFilesystemStorage {
    fn write_file_str(
        &self,
        path: &str,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let full_path = self.resolve_path(path);
        let data = data.to_vec();

        Box::pin(async move {
            // Encrypt the data
            let encrypted = self.encrypt_data(&data)?;

            // Create parent directories if needed
            if let Some(parent) = full_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            // Write encrypted data
            tokio::fs::write(&full_path, encrypted).await?;
            tracing::debug!("Wrote encrypted data to filesystem: {:?}", full_path);
            Ok(())
        })
    }

    fn read_file_str(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, StorageError>> + Send + '_>> {
        let full_path = self.resolve_path(path);

        Box::pin(async move {
            // Read encrypted data
            let encrypted = tokio::fs::read(&full_path).await?;

            // Decrypt the data
            let decrypted = self.decrypt_data(&encrypted)?;
            tracing::debug!("Read and decrypted data from filesystem: {:?}", full_path);
            Ok(decrypted)
        })
    }

    fn exists_str(&self, path: &str) -> bool {
        let full_path = self.resolve_path(path);
        full_path.exists()
    }

    fn remove_str(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let full_path = self.resolve_path(path);

        Box::pin(async move {
            tokio::fs::remove_file(&full_path).await?;
            tracing::debug!("Removed encrypted file from filesystem: {:?}", full_path);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use serial_test::serial;

    #[tokio::test]
    async fn test_filesystem_storage_write_and_read() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path()).unwrap();

        let test_data = b"test data";
        storage.write_file_str("test.txt", test_data).await.unwrap();

        assert!(storage.exists_str("test.txt"));

        let read_data = storage.read_file_str("test.txt").await.unwrap();
        assert_eq!(read_data, test_data);
    }

    #[tokio::test]
    async fn test_filesystem_storage_nested_paths() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path()).unwrap();

        let test_data = b"nested data";
        storage
            .write_file_str("nested/path/test.txt", test_data)
            .await
            .unwrap();

        assert!(storage.exists_str("nested/path/test.txt"));

        let read_data = storage.read_file_str("nested/path/test.txt").await.unwrap();
        assert_eq!(read_data, test_data);
    }

    #[tokio::test]
    async fn test_filesystem_storage_remove() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path()).unwrap();

        let test_data = b"test data";
        storage.write_file_str("test.txt", test_data).await.unwrap();
        assert!(storage.exists_str("test.txt"));

        storage.remove_str("test.txt").await.unwrap();
        assert!(!storage.exists_str("test.txt"));
    }

    #[tokio::test]
    async fn test_filesystem_storage_exists_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path()).unwrap();

        assert!(!storage.exists_str("nonexistent.txt"));
    }

    #[tokio::test]
    async fn test_keyring_storage_write_and_read() {
        let storage = KeyringStorage::new("runbeam-sdk-test");

        let test_data = b"{\"test\": \"data\"}";

        // Write data
        if let Err(e) = storage.write_file_str("test-key", test_data).await {
            // Skip test if keyring is not available (e.g., in CI or headless environments)
            eprintln!("Skipping keyring test - keyring unavailable: {}", e);
            return;
        }

        // Check existence - also skip if keyring check fails
        if !storage.exists_str("test-key") {
            eprintln!("Skipping keyring test - keyring check failed after write");
            // Try cleanup anyway
            let _ = storage.remove_str("test-key").await;
            return;
        }

        // Read data
        match storage.read_file_str("test-key").await {
            Ok(read_data) => {
                assert_eq!(read_data, test_data);

                // Cleanup
                storage.remove_str("test-key").await.unwrap();
                assert!(!storage.exists_str("test-key"));
            }
            Err(e) => {
                eprintln!("Skipping keyring test - read failed: {}", e);
                // Try cleanup anyway
                let _ = storage.remove_str("test-key").await;
            }
        }
    }

    #[tokio::test]
    async fn test_encrypted_storage_write_and_read() {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedFilesystemStorage::new(temp_dir.path())
            .await
            .unwrap();

        let test_data = b"sensitive data";
        storage.write_file_str("secret.txt", test_data).await.unwrap();

        assert!(storage.exists_str("secret.txt"));

        let read_data = storage.read_file_str("secret.txt").await.unwrap();
        assert_eq!(read_data, test_data);
    }

    #[tokio::test]
    async fn test_encrypted_storage_encryption_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedFilesystemStorage::new(temp_dir.path())
            .await
            .unwrap();

        let test_data = b"This should be encrypted";
        storage.write_file_str("data.bin", test_data).await.unwrap();

        // Read the raw file to verify it's encrypted (not plaintext)
        let file_path = temp_dir.path().join("data.bin");
        let raw_contents = std::fs::read(&file_path).unwrap();
        
        // Encrypted data should not match plaintext
        assert_ne!(raw_contents.as_slice(), test_data);
        // Should be longer due to age encryption overhead
        assert!(raw_contents.len() > test_data.len());

        // But decryption should return original data
        let decrypted = storage.read_file_str("data.bin").await.unwrap();
        assert_eq!(decrypted, test_data);
    }

    #[tokio::test]
    async fn test_encrypted_storage_remove() {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedFilesystemStorage::new(temp_dir.path())
            .await
            .unwrap();

        let test_data = b"test";
        storage.write_file_str("file.txt", test_data).await.unwrap();
        assert!(storage.exists_str("file.txt"));

        storage.remove_str("file.txt").await.unwrap();
        assert!(!storage.exists_str("file.txt"));
    }

    #[tokio::test]
    #[serial]
    async fn test_encrypted_storage_key_persistence() {
        use std::env;
        
        // Generate a consistent test key for this test
        let identity = age::x25519::Identity::generate();
        let identity_str = identity.to_string();
        use secrecy::ExposeSecret;
        use base64::Engine;
        let key_base64 = base64::engine::general_purpose::STANDARD
            .encode(identity_str.expose_secret().as_bytes());

        // Set environment variable so both instances use the same key
        env::set_var("RUNBEAM_ENCRYPTION_KEY", &key_base64);

        let temp_dir = TempDir::new().unwrap();
        
        // Create first storage instance
        let storage1 = EncryptedFilesystemStorage::new(temp_dir.path())
            .await
            .unwrap();

        let test_data = b"persistent test";
        storage1.write_file_str("data.txt", test_data).await.unwrap();

        // Drop first instance
        drop(storage1);

        // Create second storage instance - should use same key from env var
        let storage2 = EncryptedFilesystemStorage::new(temp_dir.path())
            .await
            .unwrap();

        // Should be able to decrypt data encrypted by first instance
        let read_data = storage2.read_file_str("data.txt").await.unwrap();
        assert_eq!(read_data, test_data);

        // Cleanup
        env::remove_var("RUNBEAM_ENCRYPTION_KEY");
    }

    #[tokio::test]
    #[serial]
    async fn test_encrypted_storage_env_var_key() {
        use std::env;
        use base64::Engine;
        
        // Generate a test key
        let identity = age::x25519::Identity::generate();
        let identity_str = identity.to_string();
        use secrecy::ExposeSecret;
        let key_base64 = base64::engine::general_purpose::STANDARD
            .encode(identity_str.expose_secret().as_bytes());

        // Set environment variable
        env::set_var("RUNBEAM_ENCRYPTION_KEY", &key_base64);

        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedFilesystemStorage::new(temp_dir.path())
            .await
            .unwrap();

        let test_data = b"env var test";
        storage.write_file_str("test.bin", test_data).await.unwrap();
        let read_data = storage.read_file_str("test.bin").await.unwrap();
        
        assert_eq!(read_data, test_data);

        // Cleanup
        env::remove_var("RUNBEAM_ENCRYPTION_KEY");
    }

    #[tokio::test]
    #[serial]
    #[cfg(unix)]
    async fn test_encrypted_storage_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        
        let temp_dir = TempDir::new().unwrap();
        
        // Clear environment variable to force key file generation
        std::env::remove_var("RUNBEAM_ENCRYPTION_KEY");
        
        let _storage = EncryptedFilesystemStorage::new(temp_dir.path())
            .await
            .unwrap();

        // Check that key file was created with 0600 permissions
        let key_path = dirs::home_dir().unwrap().join(".runbeam/encryption.key");
        
        if key_path.exists() {
            let metadata = std::fs::metadata(&key_path).unwrap();
            let permissions = metadata.permissions();
            let mode = permissions.mode();
            
            // On Unix, mode & 0o777 should be 0o600
            assert_eq!(mode & 0o777, 0o600, "Key file should have 0600 permissions");
        }
    }
}
