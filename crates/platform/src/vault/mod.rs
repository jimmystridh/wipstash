//! Read-only retrieval of an explicitly provisioned Wipstash credential.
//! No provisioning, unlock prompt, plaintext fallback, environment lookup,
//! network transmission or automatic lookup occurs during construction/tests.
use std::fmt;
use zeroize::Zeroizing;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    InvalidKey,
    NotFound,
    Locked,
    Ambiguous,
    Unavailable,
    InvalidSecret,
}
impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "credential vault: {self:?}")
    }
}
impl std::error::Error for VaultError {}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialKey(String);
impl CredentialKey {
    pub fn new(key: &str) -> Result<Self, VaultError> {
        if key.is_empty()
            || key.len() > 200
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
        {
            return Err(VaultError::InvalidKey);
        }
        Ok(Self(key.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
pub struct Secret(Zeroizing<Vec<u8>>);
impl Secret {
    fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(VaultError::InvalidSecret);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
    /// Only expose within the caller's approved authentication path. Never log,
    /// serialize, place in argv, persist in metadata, or pass to model workers.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
pub trait CredentialVault {
    fn read(&self, key: &CredentialKey) -> Result<Secret, VaultError>;
}
/// Selection only: does not probe or open a real credential store.
pub struct NativeVault;
impl CredentialVault for NativeVault {
    fn read(&self, key: &CredentialKey) -> Result<Secret, VaultError> {
        #[cfg(target_os = "linux")]
        {
            linux::read(key)
        }
        #[cfg(target_os = "macos")]
        {
            macos::read(key)
        }
        #[cfg(windows)]
        {
            windows::read(key)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = key;
            Err(VaultError::Unavailable)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keys_and_secret_output_are_bounded() {
        for bad in ["", "a\0b", "token with spaces"] {
            assert!(CredentialKey::new(bad).is_err());
        }
        assert!(CredentialKey::new("github/project-123").is_ok());
        let secret = Secret::from_bytes(b"fake-test-value").unwrap();
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
        assert_eq!(secret.expose_secret(), b"fake-test-value");
        assert!(Secret::from_bytes(&[]).is_err());
        assert!(Secret::from_bytes(&vec![0; 65537]).is_err());
    }
    #[test]
    fn unavailable_vault_has_no_fallback() {
        struct Unavailable;
        impl CredentialVault for Unavailable {
            fn read(&self, _: &CredentialKey) -> Result<Secret, VaultError> {
                Err(VaultError::Unavailable)
            }
        }
        assert_eq!(
            Unavailable
                .read(&CredentialKey::new("test").unwrap())
                .unwrap_err(),
            VaultError::Unavailable
        );
    }
}
