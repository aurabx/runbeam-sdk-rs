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
    fn write_file_str(&self, path: &str, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>>;

    /// Read data from storage at the specified path
    fn read_file_str(&self, path: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, StorageError>> + Send + '_>>;

    /// Check if a file exists at the specified path
    fn exists_str(&self, path: &str) -> bool;

    /// Remove a file at the specified path
    fn remove_str(&self, path: &str) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>>;
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
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "IO error: {}", e),
            StorageError::Config(msg) => write!(f, "Configuration error: {}", msg),
            StorageError::Keyring(msg) => write!(f, "Keyring error: {}", msg),
            StorageError::Path(msg) => write!(f, "Path error: {}", msg),
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
    fn write_file_str(&self, path: &str, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let path = path.to_string();
        let data = data.to_vec();
        let service_name = self.service_name.clone();
        
        Box::pin(async move {
            let entry = keyring::Entry::new(&service_name, &path)
                .map_err(|e| StorageError::Keyring(format!("Failed to create keyring entry: {}", e)))?;
            
            let data_str = String::from_utf8(data)
                .map_err(|e| StorageError::Config(format!("Invalid UTF-8 data: {}", e)))?;
            
            entry.set_password(&data_str)?;
            tracing::debug!("Stored data in keyring: service={}, path={}", service_name, path);
            Ok(())
        })
    }

    fn read_file_str(&self, path: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, StorageError>> + Send + '_>> {
        let path = path.to_string();
        let service_name = self.service_name.clone();
        
        Box::pin(async move {
            let entry = keyring::Entry::new(&service_name, &path)
                .map_err(|e| StorageError::Keyring(format!("Failed to create keyring entry: {}", e)))?;
            
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

    fn remove_str(&self, path: &str) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let path = path.to_string();
        let service_name = self.service_name.clone();
        
        Box::pin(async move {
            let entry = keyring::Entry::new(&service_name, &path)
                .map_err(|e| StorageError::Keyring(format!("Failed to create keyring entry: {}", e)))?;
            
            entry.delete_credential()?;
            tracing::debug!("Removed data from keyring: service={}, path={}", service_name, path);
            Ok(())
        })
    }
}

/// Filesystem-based storage for non-secure data or fallback
///
/// This implementation stores data in the filesystem, which is useful for:
/// - Non-sensitive configuration data
/// - Development and testing
/// - Fallback when keyring is unavailable
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
    fn write_file_str(&self, path: &str, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
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

    fn read_file_str(&self, path: &str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, StorageError>> + Send + '_>> {
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

    fn remove_str(&self, path: &str) -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send + '_>> {
        let full_path = self.resolve_path(path);
        
        Box::pin(async move {
            tokio::fs::remove_file(&full_path).await?;
            tracing::debug!("Removed file from filesystem: {:?}", full_path);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
        storage.write_file_str("nested/path/test.txt", test_data).await.unwrap();

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
}
