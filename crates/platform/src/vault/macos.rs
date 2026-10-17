use super::*;
use std::{
    ffi::{c_char, c_void},
    ptr::null,
};
type Ref = *const c_void;
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFStringCreateWithCString(allocator: Ref, value: *const c_char, encoding: u32) -> Ref;
    fn CFDictionaryCreate(
        allocator: Ref,
        keys: *const Ref,
        values: *const Ref,
        count: isize,
        key_callbacks: Ref,
        value_callbacks: Ref,
    ) -> Ref;
    fn CFRelease(value: Ref);
    fn CFArrayGetCount(value: Ref) -> isize;
    fn CFArrayGetValueAtIndex(value: Ref, index: isize) -> Ref;
    fn CFDataGetLength(value: Ref) -> isize;
    fn CFDataGetBytePtr(value: Ref) -> *const u8;
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
    static kCFBooleanTrue: Ref;
}
#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecItemCopyMatching(query: Ref, result: *mut Ref) -> i32;
    static kSecClass: Ref;
    static kSecClassGenericPassword: Ref;
    static kSecAttrService: Ref;
    static kSecAttrAccount: Ref;
    static kSecReturnData: Ref;
    static kSecMatchLimit: Ref;
    static kSecMatchLimitAll: Ref;
    static kSecUseAuthenticationUI: Ref;
    static kSecUseAuthenticationUIFail: Ref;
}
struct Owned(Ref);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CFRelease(self.0);
            }
        }
    }
}
fn string(value: &str) -> Result<Owned, VaultError> {
    let value = std::ffi::CString::new(value).map_err(|_| VaultError::InvalidKey)?;
    let result = unsafe { CFStringCreateWithCString(null(), value.as_ptr(), 0x08000100) };
    if result.is_null() {
        Err(VaultError::Unavailable)
    } else {
        Ok(Owned(result))
    }
}
pub(super) fn read(key: &CredentialKey) -> Result<Secret, VaultError> {
    let service = string("wipstash")?;
    let account = string(key.as_str())?;
    unsafe {
        let keys = [
            kSecClass,
            kSecAttrService,
            kSecAttrAccount,
            kSecReturnData,
            kSecMatchLimit,
            kSecUseAuthenticationUI,
        ];
        let values = [
            kSecClassGenericPassword,
            service.0,
            account.0,
            kCFBooleanTrue,
            kSecMatchLimitAll,
            kSecUseAuthenticationUIFail,
        ];
        let query = Owned(CFDictionaryCreate(
            null(),
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as isize,
            (&kCFTypeDictionaryKeyCallBacks as *const u8).cast(),
            (&kCFTypeDictionaryValueCallBacks as *const u8).cast(),
        ));
        if query.0.is_null() {
            return Err(VaultError::Unavailable);
        }
        let mut data = null();
        let status = SecItemCopyMatching(query.0, &mut data);
        let data = Owned(data);
        if status != 0 {
            return Err(match status {
                -25300 => VaultError::NotFound,
                -25308 => VaultError::Locked,
                _ => VaultError::Unavailable,
            });
        }
        if data.0.is_null() {
            return Err(VaultError::InvalidSecret);
        }
        // Search all keychains; never choose an arbitrary matching credential.
        match CFArrayGetCount(data.0) {
            0 => return Err(VaultError::NotFound),
            1 => {}
            _ => return Err(VaultError::Ambiguous),
        }
        let secret_data = CFArrayGetValueAtIndex(data.0, 0);
        if secret_data.is_null() {
            return Err(VaultError::InvalidSecret);
        }
        let length = CFDataGetLength(secret_data);
        if !(1..=65536).contains(&length) {
            return Err(VaultError::InvalidSecret);
        }
        let bytes = CFDataGetBytePtr(secret_data);
        if bytes.is_null() {
            return Err(VaultError::InvalidSecret);
        }
        Secret::from_bytes(std::slice::from_raw_parts(bytes, length as usize))
    }
}
