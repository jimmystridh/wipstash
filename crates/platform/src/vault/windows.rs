use super::*;
use std::ptr::null_mut;
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_NOT_FOUND, ERROR_NO_SUCH_LOGON_SESSION},
    Security::Credentials::*,
};
pub(super) fn read(key: &CredentialKey) -> Result<Secret, VaultError> {
    let target: Vec<u16> = format!("wipstash:{}", key.as_str())
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut raw = null_mut();
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
        return Err(match unsafe { GetLastError() } {
            ERROR_NOT_FOUND => VaultError::NotFound,
            ERROR_NO_SUCH_LOGON_SESSION => VaultError::Locked,
            _ => VaultError::Unavailable,
        });
    }
    struct Buffer(*mut CREDENTIALW);
    impl Drop for Buffer {
        fn drop(&mut self) {
            unsafe {
                CredFree(self.0.cast());
            }
        }
    }
    let buffer = Buffer(raw);
    let value = unsafe { &*buffer.0 };
    if value.CredentialBlob.is_null()
        || value.CredentialBlobSize == 0
        || value.CredentialBlobSize > 65536
    {
        return Err(VaultError::InvalidSecret);
    }
    Secret::from_bytes(unsafe {
        std::slice::from_raw_parts(value.CredentialBlob, value.CredentialBlobSize as usize)
    })
}
