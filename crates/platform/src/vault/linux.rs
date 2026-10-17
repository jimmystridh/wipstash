//! libsecret Secret Service adapter. Loads the system library only on explicit
//! read. Search requests ALL + LOAD_SECRETS, deliberately never UNLOCK. No
//! subprocess, plaintext fallback, credential creation, or prompt execution.
use super::*;
use std::{
    ffi::{c_char, c_void, CString},
    ptr::null_mut,
};
type Ptr = *mut c_void;
#[repr(C)]
struct GList {
    data: Ptr,
    next: *mut GList,
    prev: *mut GList,
}
struct Library(Ptr);
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.0);
        }
    }
}
impl Library {
    fn open() -> Result<Self, VaultError> {
        let handle = unsafe {
            libc::dlopen(
                c"libsecret-1.so.0".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
        };
        if handle.is_null() {
            Err(VaultError::Unavailable)
        } else {
            Ok(Self(handle))
        }
    }
    fn symbol(&self, name: &std::ffi::CStr) -> Result<Ptr, VaultError> {
        let value = unsafe { libc::dlsym(self.0, name.as_ptr()) };
        if value.is_null() {
            Err(VaultError::Unavailable)
        } else {
            Ok(value)
        }
    }
}
macro_rules! symbol {
    ($library:expr,$name:literal,$ty:ty) => {
        unsafe { std::mem::transmute::<Ptr, $ty>($library.symbol($name)?) }
    };
}
struct Object {
    pointer: Ptr,
    free: unsafe extern "C" fn(Ptr),
}
impl Drop for Object {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe {
                (self.free)(self.pointer);
            }
        }
    }
}
pub(super) fn read(key: &CredentialKey) -> Result<Secret, VaultError> {
    // All library-backed objects are destroyed before dlclose.
    let library = Library::open()?;
    let hash_new = symbol!(
        library,
        c"g_hash_table_new",
        unsafe extern "C" fn(Ptr, Ptr) -> Ptr
    );
    let hash_insert = symbol!(
        library,
        c"g_hash_table_insert",
        unsafe extern "C" fn(Ptr, Ptr, Ptr) -> i32
    );
    let hash_unref = symbol!(library, c"g_hash_table_unref", unsafe extern "C" fn(Ptr));
    let object_unref = symbol!(library, c"g_object_unref", unsafe extern "C" fn(Ptr));
    let error_free = symbol!(library, c"g_error_free", unsafe extern "C" fn(Ptr));
    let list_free = symbol!(library, c"g_list_free", unsafe extern "C" fn(*mut GList));
    let search = symbol!(
        library,
        c"secret_service_search_sync",
        unsafe extern "C" fn(Ptr, Ptr, Ptr, u32, Ptr, *mut Ptr) -> *mut GList
    );
    let locked = symbol!(
        library,
        c"secret_item_get_locked",
        unsafe extern "C" fn(Ptr) -> i32
    );
    let get_secret = symbol!(
        library,
        c"secret_item_get_secret",
        unsafe extern "C" fn(Ptr) -> Ptr
    );
    let value_get = symbol!(
        library,
        c"secret_value_get",
        unsafe extern "C" fn(Ptr, *mut usize) -> *const c_char
    );
    let value_unref = symbol!(library, c"secret_value_unref", unsafe extern "C" fn(Ptr));
    let key = CString::new(key.as_str()).map_err(|_| VaultError::InvalidKey)?;
    let attributes = Object {
        pointer: unsafe {
            hash_new(
                library.symbol(c"g_str_hash")?,
                library.symbol(c"g_str_equal")?,
            )
        },
        free: hash_unref,
    };
    if attributes.pointer.is_null() {
        return Err(VaultError::Unavailable);
    }
    unsafe {
        hash_insert(
            attributes.pointer,
            c"application".as_ptr().cast_mut().cast(),
            c"wipstash".as_ptr().cast_mut().cast(),
        );
        hash_insert(
            attributes.pointer,
            c"account".as_ptr().cast_mut().cast(),
            key.as_ptr().cast_mut().cast(),
        );
    }
    let mut error = null_mut();
    let items = unsafe {
        search(
            null_mut(),
            null_mut(),
            attributes.pointer,
            2 | 8,
            null_mut(),
            &mut error,
        )
    };
    struct Items {
        list: *mut GList,
        unref: unsafe extern "C" fn(Ptr),
        free: unsafe extern "C" fn(*mut GList),
    }
    impl Drop for Items {
        fn drop(&mut self) {
            unsafe {
                let mut node = self.list;
                while !node.is_null() {
                    (self.unref)((*node).data);
                    node = (*node).next;
                }
                (self.free)(self.list);
            }
        }
    }
    let items = Items {
        list: items,
        unref: object_unref,
        free: list_free,
    };
    if !error.is_null() {
        unsafe {
            error_free(error);
        }
        return Err(VaultError::Unavailable);
    }
    if items.list.is_null() {
        return Err(VaultError::NotFound);
    }
    let item = unsafe { &*items.list };
    // Never pick a credential arbitrarily when attributes match several entries.
    if !item.next.is_null() {
        return Err(VaultError::Ambiguous);
    }
    if unsafe { locked(item.data) } != 0 {
        return Err(VaultError::Locked);
    }
    let value = Object {
        pointer: unsafe { get_secret(item.data) },
        free: value_unref,
    };
    if value.pointer.is_null() {
        return Err(VaultError::Unavailable);
    }
    let mut length = 0;
    let bytes = unsafe { value_get(value.pointer, &mut length) };
    if bytes.is_null() || length == 0 || length > 65536 {
        return Err(VaultError::InvalidSecret);
    }
    Secret::from_bytes(unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), length) })
}
