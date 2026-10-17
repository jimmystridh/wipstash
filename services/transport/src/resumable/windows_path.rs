//! Conservative Windows storage eligibility, not protection against a malicious
//! same-account process racing path replacement. No directory flush is implied.
use crate::{error, Result};
use std::{
    fs,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf, Prefix},
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        GetDriveTypeW, GetVolumeInformationW, GetVolumePathNameW, FILE_ATTRIBUTE_REPARSE_POINT,
    },
    System::WindowsProgramming::DRIVE_FIXED,
};

fn validate_components(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(error("absolute_transfer_root_required"));
    }
    let mut components = path.components();
    if !matches!(
        components.next(),
        Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    ) {
        return Err(error("resumable_local_ntfs_required"));
    }
    for component in components {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name: Vec<u16> = name.encode_wide().collect();
                if name.iter().any(|c| matches!(*c, 0 | 58)) || matches!(name.last(), Some(32 | 46))
                {
                    return Err(error("transfer_path"));
                }
            }
            _ => return Err(error("transfer_path")),
        }
    }
    Ok(())
}

/// Require an existing local, fixed NTFS directory without reparse ancestors.
pub(super) fn check(root: &Path) -> Result<()> {
    validate_components(root)?;
    let drive = match root.components().next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => return Err(error("resumable_local_ntfs_required")),
        },
        _ => return Err(error("resumable_local_ntfs_required")),
    };
    let drive_root = [drive as u16, b':' as u16, b'\\' as u16, 0];
    // Reject mapped remote drives before metadata calls could follow the path.
    // SAFETY: drive_root is a valid, terminated drive-root string.
    if unsafe { GetDriveTypeW(drive_root.as_ptr()) } != DRIVE_FIXED {
        return Err(error("resumable_local_ntfs_required"));
    }
    let mut current = PathBuf::new();
    for component in root.components() {
        current.push(component);
        // A drive prefix alone (C:) refers to a drive-relative current directory.
        // Inspect it only after the following root separator has been appended.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(error("transfer_symlink"));
        }
        if !metadata.is_dir() {
            return Err(error("transfer_path"));
        }
    }
    let mut wide: Vec<u16> = root.as_os_str().encode_wide().collect();
    if wide.contains(&0) || wide.len() >= 32_767 {
        return Err(error("transfer_path"));
    }
    wide.push(0);
    let mut volume = vec![0u16; 32_768];
    // SAFETY: Both buffers are valid for the supplied lengths and input is NUL terminated.
    if unsafe { GetVolumePathNameW(wide.as_ptr(), volume.as_mut_ptr(), volume.len() as u32) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let end = volume
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(|| error("resumable_local_ntfs_required"))?;
    if end == 0 || volume[end - 1] != b'\\' as u16 {
        return Err(error("resumable_local_ntfs_required"));
    }
    // SAFETY: GetVolumePathNameW returned a terminated volume-root string.
    if unsafe { GetDriveTypeW(volume.as_ptr()) } != DRIVE_FIXED {
        return Err(error("resumable_local_ntfs_required"));
    }
    let mut filesystem = [0u16; 32];
    // SAFETY: Optional outputs are null; the filesystem output buffer has the stated size.
    if unsafe {
        GetVolumeInformationW(
            volume.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if filesystem[..5] != [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0] {
        return Err(error("resumable_local_ntfs_required"));
    }
    Ok(())
}

/// Check each database, journal and lock path before opening it. Only the final
/// regular file may be absent; errors and reparse points must not become absence.
pub(super) fn check_file(path: &Path) -> Result<()> {
    validate_components(path)?;
    check(path.parent().ok_or_else(|| error("transfer_path"))?)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(error("transfer_symlink"));
            }
            if !metadata.is_file() {
                return Err(error("transfer_path"));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_remote_relative_and_alternate_namespaces() {
        for path in [
            r"relative",
            r"C:relative",
            r"\\server\share\staging",
            r"\\?\UNC\server\share\staging",
            r"\\.\C:\staging",
            r"C:\staging:stream",
            r"C:\staging\..\other",
            r"C:\staging.\file",
        ] {
            assert!(validate_components(Path::new(path)).is_err(), "{path}");
        }
        assert!(validate_components(Path::new(r"C:\staging")).is_ok());
        assert!(validate_components(Path::new(r"\\?\C:\staging")).is_ok());
    }
}
