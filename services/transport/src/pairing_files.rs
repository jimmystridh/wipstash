//! Private, create-only pairing files for the current execution account.
//!
//! Unix uses anchored, no-follow directory handles, 0700/0600, and file + parent
//! fsync. Windows uses a protected current-token-user DACL at creation and checks
//! it again on the opened handle. Windows flushes file data, but does not promise
//! directory-entry durability across power loss. These helpers never repair
//! permissions, overwrite existing files, provision another account, or encrypt
//! PEMs: plaintext secrets rely on the verified OS access controls.
use std::{
    io::{self, Read, Write},
    path::{Component, Path},
};

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn clean_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(denied("absolute_clean_private_path_required"));
    }
    Ok(())
}

/// Create one private directory. Its parent must already exist.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    platform::directory(path, true).map(|_| ())
}
/// Verify without creating, chmodding, or changing its DACL.
pub fn validate_private_dir(path: &Path) -> io::Result<()> {
    platform::directory(path, false).map(|_| ())
}
/// Verify an existing regular private file without reading its contents.
pub fn validate_private_file(path: &Path) -> io::Result<()> {
    clean_path(path)?;
    let parent = platform::directory(
        path.parent()
            .ok_or_else(|| denied("missing_private_parent"))?,
        false,
    )?;
    platform::read(path, &parent).map(|_| ())
}
/// Publish a complete new secret file exclusively; an existing name is always
/// an error. Private random staging files are deliberately retained on failure
/// for recovery, never used as completion markers, and never auto-deleted.
/// Unix syncs both content and the publication directory. Windows flushes content
/// and uses a no-replace move, without promising directory-entry crash durability.
pub fn create_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    create_with_hook(path, bytes, |_| Ok(()))
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PublishPoint {
    BeforeWrite,
    AfterSync,
    BeforePublish,
}
fn create_with_hook(
    path: &Path,
    bytes: &[u8],
    mut hook: impl FnMut(PublishPoint) -> io::Result<()>,
) -> io::Result<()> {
    use ring::rand::{SecureRandom, SystemRandom};
    clean_path(path)?;
    if path.file_name().is_none() {
        return Err(denied("missing_private_filename"));
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| denied("missing_private_parent"))?;
    let parent = platform::directory(parent_path, false)?;
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| denied("private_staging_random_source_failed"))?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let staging = parent_path.join(format!(".pairing-stage-{suffix}"));
    let mut file = platform::create(&staging, &parent)?;
    hook(PublishPoint::BeforeWrite)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    hook(PublishPoint::AfterSync)?;
    drop(file);
    hook(PublishPoint::BeforePublish)?;
    platform::publish(&staging, path, &parent)?;
    platform::sync_parent(&parent)
}
/// Read at most `max_bytes`, checking the opened object rather than a pathname.
pub fn read_private_file(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    clean_path(path)?;
    let parent = platform::directory(
        path.parent()
            .ok_or_else(|| denied("missing_private_parent"))?,
        false,
    )?;
    let file = platform::read(path, &parent)?;
    if file.metadata()?.len() > max_bytes as u64 {
        return Err(denied("private_file_too_large"));
    }
    let mut bytes = Vec::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(denied("private_file_too_large"));
    }
    Ok(bytes)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::CString,
        fs::File,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
    };
    pub(super) struct Directory(File);
    fn name(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| denied("invalid_private_path"))
    }
    // C varargs require integer promotion; macOS mode_t is narrower than c_uint.
    #[allow(clippy::unnecessary_cast)]
    fn open_at(parent: &File, name: &CString, flags: i32, mode: libc::mode_t) -> io::Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    fn verify(file: &File, directory: bool) -> io::Result<()> {
        let m = file.metadata()?;
        if m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || (directory && !m.is_dir())
            || (!directory && (!m.is_file() || m.nlink() != 1))
        {
            return Err(denied(
                "private_object_requires_current_owner_and_0700_or_0600",
            ));
        }
        Ok(())
    }
    pub(super) fn directory(path: &Path, create: bool) -> io::Result<Directory> {
        clean_path(path)?;
        let mut current = File::open("/")?;
        let components: Vec<_> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s),
                _ => None,
            })
            .collect();
        if components.is_empty() {
            return Err(denied("private_directory_cannot_be_root"));
        }
        for (i, component) in components.iter().enumerate() {
            let parent_meta = current.metadata()?;
            // Sticky directories prevent other accounts replacing an owned child.
            if parent_meta.mode() & 0o022 != 0 && parent_meta.mode() & 0o1000 == 0 {
                return Err(denied("writable_private_path_ancestor"));
            }
            // An ancestor's owner can otherwise chmod/replace the private tree.
            if parent_meta.uid() != 0 && parent_meta.uid() != unsafe { libc::geteuid() } {
                return Err(denied("untrusted_private_path_ancestor_owner"));
            }
            let component =
                CString::new(component.as_bytes()).map_err(|_| denied("invalid_private_path"))?;
            let last = i + 1 == components.len();
            if last && create {
                let result =
                    unsafe { libc::mkdirat(current.as_raw_fd(), component.as_ptr(), 0o700) };
                if result != 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        return Err(e);
                    }
                } else {
                    current.sync_all()?;
                }
            }
            current = open_at(&current, &component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            if last {
                verify(&current, true)?;
            }
        }
        Ok(Directory(current))
    }
    pub(super) fn create(path: &Path, parent: &Directory) -> io::Result<File> {
        let name = name(Path::new(
            path.file_name()
                .ok_or_else(|| denied("missing_private_filename"))?,
        ))?;
        let file = open_at(
            &parent.0,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        verify(&file, false)?;
        Ok(file)
    }
    pub(super) fn read(path: &Path, parent: &Directory) -> io::Result<File> {
        let name = name(Path::new(
            path.file_name()
                .ok_or_else(|| denied("missing_private_filename"))?,
        ))?;
        // NONBLOCK prevents a malicious FIFO/device from hanging before verification.
        let file = open_at(&parent.0, &name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        verify(&file, false)?;
        Ok(file)
    }
    pub(super) fn publish(
        staging: &Path,
        destination: &Path,
        parent: &Directory,
    ) -> io::Result<()> {
        let source = name(Path::new(
            staging
                .file_name()
                .ok_or_else(|| denied("missing_staging_filename"))?,
        ))?;
        let target = name(Path::new(
            destination
                .file_name()
                .ok_or_else(|| denied("missing_private_filename"))?,
        ))?;
        // Native exclusive rename avoids both overwrite races and the crash
        // window where link+unlink would leave a multiply-linked final secret.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let result = unsafe {
            libc::renameat2(
                parent.0.as_raw_fd(),
                source.as_ptr(),
                parent.0.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                parent.0.as_raw_fd(),
                source.as_ptr(),
                parent.0.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        let result = {
            let _ = (source, target);
            return Err(denied("atomic_private_publication_unsupported_platform"));
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub(super) fn sync_parent(parent: &Directory) -> io::Result<()> {
        parent.0.sync_all()
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::c_void,
        fs::File,
        mem::{size_of, zeroed},
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
        ptr::null_mut,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::{
            Threading::*,
            WindowsProgramming::{DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE},
        },
    };
    pub(super) struct Directory {
        _ancestors: Vec<File>,
        leaf: File,
    }
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Principal {
        buffer: Vec<usize>,
    }
    impl Principal {
        fn current() -> io::Result<Self> {
            unsafe {
                let mut thread_token = null_mut();
                if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) != 0 {
                    CloseHandle(thread_token);
                    return Err(denied("impersonated_account_pairing_not_supported"));
                }
                if GetLastError() != ERROR_NO_TOKEN {
                    return Err(io::Error::last_os_error());
                }
                let mut token = null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let token = Token(token);
                let mut needed = 0;
                GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
                if needed == 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut buffer =
                    vec![0usize; (needed as usize + size_of::<usize>() - 1) / size_of::<usize>()];
                if GetTokenInformation(
                    token.0,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                ) == 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self { buffer })
            }
        }
        fn sid(&self) -> PSID {
            unsafe { (*(self.buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid }
        }
        fn descriptor(&self, directory: bool) -> io::Result<Local> {
            unsafe {
                let mut sid_text = null_mut();
                if ConvertSidToStringSidW(self.sid(), &mut sid_text) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let _sid_text = Local(sid_text.cast());
                let mut len = 0;
                while *sid_text.add(len) != 0 {
                    len += 1;
                }
                let sid = String::from_utf16(std::slice::from_raw_parts(sid_text, len))
                    .map_err(|_| denied("invalid_account_sid"))?;
                // Protected DACL; no inherited ACEs. Owner is explicitly this user.
                let inheritance = if directory { "OICI" } else { "" };
                let sddl: Vec<u16> = format!("O:{sid}D:P(A;{inheritance};FA;;;{sid})")
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                let mut descriptor = null_mut();
                if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                ) == 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(Local(descriptor))
            }
        }
    }
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(denied("invalid_private_path"));
        }
        // Local drive paths only, including canonicalized \\?\ drive paths.
        // Reject UNC, device namespaces, and alternate data streams.
        let drive = match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                std::path::Prefix::Disk(drive) | std::path::Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(denied("private_files_require_local_drive_path")),
            },
            _ => return Err(denied("private_files_require_local_drive_path")),
        };
        let root: Vec<u16> = format!("{}:\\", drive as char)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        match unsafe { GetDriveTypeW(root.as_ptr()) } {
            DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_RAMDISK => {}
            _ => return Err(denied("private_files_require_local_drive")),
        }
        if path.components().any(|component| match component {
            Component::Normal(name) => name.encode_wide().any(|c| c == b':' as u16),
            _ => false,
        }) {
            return Err(denied("private_files_reject_alternate_data_streams"));
        }
        Ok(value.into_iter().chain(Some(0)).collect())
    }
    fn open(path: &Path, directory: bool, create: bool, principal: &Principal) -> io::Result<File> {
        let path = wide(path)?;
        let descriptor = principal.descriptor(directory)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let access = if directory {
            FILE_READ_ATTRIBUTES | READ_CONTROL
        } else if create {
            GENERIC_WRITE | READ_CONTROL
        } else {
            GENERIC_READ | READ_CONTROL
        };
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                access,
                // Hold directories without DELETE sharing to pin every ancestor.
                if directory || !create {
                    FILE_SHARE_READ | FILE_SHARE_WRITE
                } else {
                    0
                },
                &sa,
                if create { CREATE_NEW } else { OPEN_EXISTING },
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        FILE_ATTRIBUTE_NORMAL
                    },
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || (!directory && info.nNumberOfLinks != 1)
        {
            return Err(denied("private_path_reparse_or_nonregular_object"));
        }
        Ok(file)
    }
    fn verify(file: &File, principal: &Principal) -> io::Result<()> {
        unsafe {
            let mut owner = null_mut();
            let mut acl: *mut ACL = null_mut();
            let mut descriptor = null_mut();
            let code = GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            );
            if code != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            let _descriptor = Local(descriptor);
            let mut control = 0;
            let mut revision = 0;
            if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0 {
                return Err(io::Error::last_os_error());
            }
            if owner.is_null()
                || EqualSid(owner, principal.sid()) == 0
                || acl.is_null()
                || (*acl).AceCount != 1
                || IsValidAcl(acl) == 0
            {
                return Err(denied(
                    "private_object_requires_protected_current_account_dacl",
                ));
            }
            let mut ace = null_mut();
            if GetAce(acl, 0, &mut ace) == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = &*(ace.cast::<ACE_HEADER>());
            if header.AceType != 0 || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>() {
                return Err(denied("private_object_requires_standard_allow_ace"));
            }
            let allowed = &*(ace.cast::<ACCESS_ALLOWED_ACE>());
            let ace_sid: PSID = (&allowed.SidStart as *const u32).cast_mut().cast();
            // SID has an eight-byte prefix plus variable subauthorities. Ensure
            // its claimed bytes fit this ACE before handing it to EqualSid.
            if (header.AceSize as u32) < 8 + GetLengthSid(ace_sid) || IsValidSid(ace_sid) == 0 {
                return Err(denied("private_object_has_invalid_account_sid"));
            }
            // A file may inherit this exact sole-user ACL from its verified
            // private parent (SQLite journals do). Directories must be protected.
            let directory = file.metadata()?.is_dir();
            let protected = control & SE_DACL_PROTECTED != 0;
            let flags_ok = if directory {
                protected
                    && allowed.Header.AceFlags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
            } else {
                (protected && allowed.Header.AceFlags == 0)
                    || (!protected && allowed.Header.AceFlags == INHERITED_ACE as u8)
            };
            if allowed.Header.AceType != 0
                || !flags_ok
                || (allowed.Header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>()
                || allowed.Mask != FILE_ALL_ACCESS
                || EqualSid(ace_sid, principal.sid()) == 0
            {
                return Err(denied(
                    "private_object_requires_exclusive_current_account_access",
                ));
            }
            Ok(())
        }
    }
    pub(super) fn directory(path: &Path, create: bool) -> io::Result<Directory> {
        clean_path(path)?;
        wide(path)?;
        let principal = Principal::current()?;
        let mut ancestors = Vec::new();
        let mut cursor = std::path::PathBuf::new();
        let mut leaf = None;
        for component in path.components() {
            cursor.push(component);
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            let last = cursor == path;
            if last && create {
                let descriptor = principal.descriptor(true)?;
                let sa = SECURITY_ATTRIBUTES {
                    nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor.0,
                    bInheritHandle: 0,
                };
                if unsafe { CreateDirectoryW(wide(&cursor)?.as_ptr(), &sa) } == 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                        return Err(e);
                    }
                }
            }
            let file = open(&cursor, true, false, &principal)?;
            if last {
                verify(&file, &principal)?;
                leaf = Some(file);
            } else {
                ancestors.push(file);
            }
        }
        Ok(Directory {
            _ancestors: ancestors,
            leaf: leaf.ok_or_else(|| denied("missing_private_directory"))?,
        })
    }
    pub(super) fn create(path: &Path, parent: &Directory) -> io::Result<File> {
        let principal = Principal::current()?;
        verify(&parent.leaf, &principal)?;
        let file = open(path, false, true, &principal)?;
        verify(&file, &principal)?;
        Ok(file)
    }
    pub(super) fn read(path: &Path, parent: &Directory) -> io::Result<File> {
        let principal = Principal::current()?;
        verify(&parent.leaf, &principal)?;
        let file = open(path, false, false, &principal)?;
        verify(&file, &principal)?;
        Ok(file)
    }
    pub(super) fn publish(
        staging: &Path,
        destination: &Path,
        _parent: &Directory,
    ) -> io::Result<()> {
        // No REPLACE_EXISTING and no COPY_ALLOWED: same-volume atomic no-replace
        // publication. Staging was closed after FlushFileBuffers before this move.
        if unsafe {
            MoveFileExW(
                wide(staging)?.as_ptr(),
                wide(destination)?.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub(super) fn sync_parent(_parent: &Directory) -> io::Result<()> {
        // Win32 has no portable equivalent of POSIX directory fsync. The file
        // itself was flushed; do not claim power-loss durability of its name.
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;
    use std::fs::File;
    pub(super) struct Directory;
    pub(super) fn directory(_: &Path, _: bool) -> io::Result<Directory> {
        Err(denied("private_files_unsupported_platform"))
    }
    pub(super) fn create(_: &Path, _: &Directory) -> io::Result<File> {
        Err(denied("private_files_unsupported_platform"))
    }
    pub(super) fn read(_: &Path, _: &Directory) -> io::Result<File> {
        Err(denied("private_files_unsupported_platform"))
    }
    pub(super) fn publish(_: &Path, _: &Path, _: &Directory) -> io::Result<()> {
        Err(denied("private_files_unsupported_platform"))
    }
    pub(super) fn sync_parent(_: &Directory) -> io::Result<()> {
        Err(denied("private_files_unsupported_platform"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        // Canonicalize the fixture's parent once (e.g. macOS /var -> /private/var).
        let private = root.path().canonicalize().unwrap().join("private");
        ensure_private_dir(&private).unwrap();
        (root, private)
    }
    #[test]
    fn create_read_exclusive_and_bounded() {
        let (_root, dir) = fixture();
        let path = dir.join("synthetic.pem");
        create_private_file(&path, b"synthetic test bytes").unwrap();
        assert_eq!(
            read_private_file(&path, 64).unwrap(),
            b"synthetic test bytes"
        );
        assert!(read_private_file(&path, 2).is_err());
        assert!(create_private_file(&path, b"replacement").is_err());
        assert_eq!(
            read_private_file(&path, 64).unwrap(),
            b"synthetic test bytes"
        );
    }
    #[test]
    fn validation_is_read_only() {
        let (_root, dir) = fixture();
        let missing = dir.join("missing");
        assert!(validate_private_dir(&missing).is_err());
        assert!(!missing.exists());
        assert!(ensure_private_dir(Path::new("relative-private")).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn rejects_public_files_directories_and_links() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (_root, dir) = fixture();
        let path = dir.join("secret");
        create_private_file(&path, b"synthetic").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_file(&path, 64).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&path, dir.join("link")).unwrap();
        assert!(read_private_file(&dir.join("link"), 64).is_err());
        std::fs::hard_link(&path, dir.join("hardlink")).unwrap();
        assert!(read_private_file(&path, 64).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_private_dir(&dir).is_err());
        assert!(create_private_file(&dir.join("new"), b"synthetic").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_ancestor() {
        use std::os::unix::fs::symlink;
        let (root, dir) = fixture();
        let link = root.path().canonicalize().unwrap().join("alias");
        symlink(&dir, &link).unwrap();
        assert!(ensure_private_dir(&link.join("child")).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn rejects_broad_dacl_even_on_readonly_file() {
        use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut};
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                },
                SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            },
        };
        let (_root, dir) = fixture();
        let path = dir.join("synthetic-public.pem");
        create_private_file(&path, b"synthetic").unwrap();
        unsafe {
            let text: Vec<u16> = "D:P(A;;FA;;;WD)".encode_utf16().chain(Some(0)).collect();
            let mut sd: *mut c_void = null_mut();
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    null_mut()
                ),
                0
            );
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let changed = SetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd,
            );
            LocalFree(sd);
            assert_ne!(changed, 0);
        }
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(read_private_file(&path, 64).is_err());
        // Keep cleanup confined to this disposable test file.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn rejects_windows_stream_and_network_paths() {
        let (_root, dir) = fixture();
        assert!(create_private_file(&dir.join("secret:alternate"), b"synthetic").is_err());
        assert!(validate_private_dir(Path::new(r"\\server\share\private")).is_err());
    }

    #[test]
    fn failures_never_publish_partial_final_or_replace_existing() {
        for point in [
            PublishPoint::BeforeWrite,
            PublishPoint::AfterSync,
            PublishPoint::BeforePublish,
        ] {
            let (_root, dir) = fixture();
            let final_path = dir.join("final");
            let fail = |current| {
                if current == point {
                    Err(io::Error::other("synthetic injected fault"))
                } else {
                    Ok(())
                }
            };
            assert!(create_with_hook(&final_path, b"complete synthetic bytes", fail).is_err());
            assert!(!final_path.exists());
            // An interrupted staging file cannot prevent a retry publishing a
            // complete final name; orphan staging bytes remain private.
            create_private_file(&final_path, b"retry complete").unwrap();
            assert_eq!(
                read_private_file(&final_path, 64).unwrap(),
                b"retry complete"
            );
            assert!(create_with_hook(&final_path, b"replacement", fail).is_err());
            assert_eq!(
                read_private_file(&final_path, 64).unwrap(),
                b"retry complete"
            );
            for entry in std::fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pairing-stage-")
                {
                    validate_private_file(&entry.path()).unwrap();
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_reparse_directory_when_symlink_privilege_available() {
        use std::os::windows::fs::symlink_dir;
        let (root, dir) = fixture();
        let alias = root.path().canonicalize().unwrap().join("alias");
        if let Err(error) = symlink_dir(&dir, &alias) {
            // Windows CI without Developer Mode or SeCreateSymbolicLinkPrivilege
            // cannot synthesize this fixture. The ACL tests still run normally.
            if error.raw_os_error() == Some(1314) {
                return;
            }
            panic!("could not create disposable reparse fixture: {error}");
        }
        assert!(validate_private_dir(&alias).is_err());
        assert!(create_private_file(&alias.join("secret"), b"synthetic").is_err());
    }

    #[test]
    fn validation_allows_existing_database_writer_handle() {
        let (_root, dir) = fixture();
        let path = dir.join("database");
        create_private_file(&path, b"synthetic database").unwrap();
        let _writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        validate_private_file(&path).unwrap();
        assert_eq!(read_private_file(&path, 64).unwrap(), b"synthetic database");
    }
}
