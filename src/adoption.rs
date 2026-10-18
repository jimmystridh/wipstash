//! Conservative, process-crash-recoverable adoption of a sanitized file tree.
//! The caller must serialize access and persist its intent before calling apply.
//! Unix flushes files and directory entries. Windows flushes files and publishes
//! with a same-directory, write-through move; Win32 has no portable directory
//! fsync, so directory-entry durability across power loss is not promised.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MARKER: &str = "complete.json";
static TEMP_ID: AtomicU64 = AtomicU64::new(0);
type Result<T> = std::result::Result<T, String>;
fn io(e: std::io::Error) -> String {
    format!("adoption_io: {e}")
}
fn collision(p: &Path) -> String {
    format!("path_collision: {}", p.display())
}
fn relative(s: &str) -> Result<&Path> {
    let p = Path::new(s);
    if s.is_empty()
        || p.components().any(|c| !matches!(c, Component::Normal(_)))
        || p.components().collect::<PathBuf>().as_os_str() != p.as_os_str()
    {
        return Err(format!("path_collision: unsafe relative path {s:?}"));
    }
    #[cfg(windows)]
    for component in p.components() {
        if let Component::Normal(name) = component {
            windows_filename(name)?;
        }
    }
    Ok(p)
}
// Check every existing component, including the root's ancestors, without following links.
fn checked(p: &Path) -> Result<Option<fs::Metadata>> {
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(io)?.join(p)
    };
    #[cfg(windows)]
    windows::wide(&full)?;
    let mut part = PathBuf::new();
    let mut result = None;
    let count = full.components().count();
    for (i, c) in full.components().enumerate() {
        if matches!(c, Component::ParentDir) {
            return Err(collision(p));
        }
        if matches!(c, Component::CurDir) {
            continue;
        }
        part.push(c.as_os_str());
        // A drive prefix alone is drive-relative (C:), not its root (C:\).
        if matches!(c, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&part) {
            Ok(m) => {
                if unsafe_object(&m) || (i + 1 < count && !m.is_dir()) {
                    return Err(collision(&part));
                }
                result = Some(m);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        }
    }
    Ok(result)
}
fn directory(p: &Path) -> Result<()> {
    match checked(p)? {
        Some(m) if m.is_dir() => Ok(()),
        _ => Err(collision(p)),
    }
}
fn regular(p: &Path) -> Result<fs::Metadata> {
    match checked(p)? {
        Some(m) if m.is_file() => Ok(m),
        _ => Err(collision(p)),
    }
}
fn unsafe_object(m: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return true;
        }
    }
    m.file_type().is_symlink()
}
#[cfg(not(windows))]
fn sync_dir(p: &Path) -> Result<()> {
    directory(p)?;
    File::open(p).map_err(io)?.sync_all().map_err(io)
}
#[cfg(windows)]
fn sync_dir(p: &Path) -> Result<()> {
    // This is validation, not a swallowed failed fsync. Win32 has no portable
    // directory flush. File flush and publication errors still propagate.
    windows::pin_directory(p).map(|_| ())
}
fn open_regular(p: &Path) -> Result<File> {
    regular(p)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    let file = options.open(p).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() || unsafe_object(&metadata) {
        return Err(collision(p));
    }
    Ok(file)
}
fn read_regular(p: &Path) -> Result<Vec<u8>> {
    #[cfg(windows)]
    let _parent = windows::pin_directory(p.parent().ok_or_else(|| collision(p))?)?;
    let mut bytes = Vec::new();
    open_regular(p)?.read_to_end(&mut bytes).map_err(io)?;
    Ok(bytes)
}
fn publish(src: &Path, dst: &Path, replace_existing: bool) -> Result<()> {
    // Both callers stage in the destination's own directory. Do not permit a
    // future caller to accidentally turn publication into a cross-volume copy.
    if src.parent() != dst.parent() {
        return Err("adoption_io: publication requires the same directory".into());
    }
    regular(src)?;
    if let Some(metadata) = checked(dst)? {
        if !replace_existing || !metadata.is_file() {
            return Err(collision(dst));
        }
    }
    #[cfg(windows)]
    {
        windows::publish(src, dst, replace_existing)
    }
    #[cfg(not(windows))]
    {
        fs::rename(src, dst).map_err(io)
    }
}

// Match the reviewed private-file filename rules without imposing private DACLs
// on the user's ordinary workspace files.
#[cfg(any(windows, test))]
fn windows_filename(name: &std::ffi::OsStr) -> Result<()> {
    let name = name.to_string_lossy();
    let base = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if name.ends_with(['.', ' '])
        || name.chars().any(|c| c < ' ' || "<>:\"|?*".contains(c))
        || matches!(
            base.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || ["COM", "LPT"].iter().any(|prefix| {
            base.strip_prefix(prefix).is_some_and(|tail| {
                matches!(
                    tail,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
    {
        return Err(format!("path_collision: unsafe Windows filename {name:?}"));
    }
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt};
    use windows_sys::Win32::{
        Storage::FileSystem::*,
        System::WindowsProgramming::{DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE},
    };

    fn absolute(path: &Path) -> Result<PathBuf> {
        Ok(if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir().map_err(io)?.join(path)
        })
    }

    pub(super) fn wide(path: &Path) -> Result<Vec<u16>> {
        let path = absolute(path)?;
        if !path.is_absolute() {
            return Err(collision(&path));
        }
        // Reject UNC/device namespaces and drive-relative names. A mapped
        // network drive is rejected too; these guarantees concern local storage.
        let drive = match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                std::path::Prefix::Disk(drive) | std::path::Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(collision(&path)),
            },
            _ => return Err(collision(&path)),
        };
        let root: Vec<u16> = format!("{}:\\", drive as char)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        match unsafe { GetDriveTypeW(root.as_ptr()) } {
            DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_RAMDISK => {}
            _ => return Err(collision(&path)),
        }
        for component in path.components() {
            match component {
                Component::Normal(name) => windows_filename(name)?,
                Component::ParentDir => return Err(collision(&path)),
                _ => {}
            }
        }
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(collision(&path));
        }
        value.push(0);
        Ok(value)
    }

    // No delete sharing pins the directory and every ancestor for the lifetime
    // of this guard. OPEN_REPARSE_POINT checks the opened object, including
    // junctions and non-symlink reparse tags, without following it.
    pub(super) fn pin_directory(path: &Path) -> Result<Vec<File>> {
        let path = absolute(path)?;
        wide(&path)?;
        let mut cursor = PathBuf::new();
        let mut handles = Vec::new();
        for component in path.components() {
            cursor.push(component);
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            let file = OpenOptions::new()
                .read(true)
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&cursor)
                .map_err(io)?;
            let metadata = file.metadata().map_err(io)?;
            if !metadata.is_dir() || unsafe_object(&metadata) {
                return Err(collision(&cursor));
            }
            handles.push(file);
        }
        if handles.is_empty() {
            return Err(collision(&path));
        }
        Ok(handles)
    }

    pub(super) fn publish(src: &Path, dst: &Path, replace_existing: bool) -> Result<()> {
        let _parent = pin_directory(src.parent().ok_or_else(|| collision(src))?)?;
        regular(src)?;
        if let Some(metadata) = checked(dst)? {
            if !replace_existing || !metadata.is_file() {
                return Err(collision(dst));
            }
        }
        let flags = MOVEFILE_WRITE_THROUGH
            | if replace_existing {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            };
        // No COPY_ALLOWED: even an unexpected different-volume target must fail,
        // never degrade into copy/delete. Same-directory publication is checked
        // by the common caller, and all staging write handles are already closed.
        if unsafe { MoveFileExW(wide(src)?.as_ptr(), wide(dst)?.as_ptr(), flags) } == 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

fn mkdirs(p: &Path) -> Result<()> {
    if let Some(m) = checked(p)? {
        return if m.is_dir() {
            Ok(())
        } else {
            Err(collision(p))
        };
    }
    if let Some(parent) = p.parent() {
        mkdirs(parent)?;
    }
    #[cfg(windows)]
    let _parent = windows::pin_directory(p.parent().ok_or_else(|| collision(p))?)?;
    fs::create_dir(p).map_err(io)?;
    sync_dir(p)?;
    if let Some(parent) = p.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Fingerprint {
    digest: String,
    mode: u32,
}
fn fingerprint(p: &Path) -> Result<Fingerprint> {
    #[cfg(windows)]
    let _parent = windows::pin_directory(p.parent().ok_or_else(|| collision(p))?)?;
    let mut file = open_regular(p)?;
    let m = file.metadata().map_err(io)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    #[cfg(unix)]
    let mode = m.permissions().mode() & 0o7777;
    #[cfg(not(unix))]
    let mode = u32::from(m.permissions().readonly());
    Ok(Fingerprint {
        digest: format!("{:x}", h.finalize()),
        mode,
    })
}
#[derive(Serialize, Deserialize)]
struct Manifest {
    old: BTreeMap<String, Fingerprint>,
    new: BTreeMap<String, Fingerprint>,
}
fn names(input: &[String]) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for s in input {
        relative(s)?;
        if !result.insert(s.clone()) {
            return Err(format!("path_collision: duplicate path {s}"));
        }
    }
    Ok(result)
}
fn replace(src: &Path, dst: &Path) -> Result<()> {
    #[cfg(windows)]
    let _source_parent = windows::pin_directory(src.parent().ok_or_else(|| collision(src))?)?;
    let mut source = open_regular(src)?;
    let metadata = source.metadata().map_err(io)?;
    let parent = dst.parent().ok_or_else(|| collision(dst))?;
    mkdirs(parent)?;
    #[cfg(windows)]
    let _destination_parent = windows::pin_directory(parent)?;
    if let Some(m) = checked(dst)? {
        if !m.is_file() {
            return Err(collision(dst));
        }
    }
    let (tmp, mut out) = loop {
        let tmp = parent.join(format!(
            ".wipstash-adoption-{}-{}.tmp",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(out) => break (tmp, out),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io(e)),
        }
    };
    let r = (|| {
        std::io::copy(&mut source, &mut out).map_err(io)?;
        out.set_permissions(metadata.permissions()).map_err(io)?;
        out.sync_all().map_err(io)?;
        // Windows publication must not retain an open staging write handle.
        drop(out);
        drop(source);
        publish(&tmp, dst, true)?;
        sync_dir(parent)
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}
fn remove(p: &Path) -> Result<()> {
    #[cfg(windows)]
    let _parent = windows::pin_directory(p.parent().ok_or_else(|| collision(p))?)?;
    regular(p)?;
    fs::remove_file(p).map_err(io)?;
    sync_dir(p.parent().ok_or_else(|| collision(p))?)
}

/// List a sanitized staging tree, rejecting symlinks and special files.
pub fn files(root: &Path) -> Result<Vec<String>> {
    directory(root)?;
    #[cfg(windows)]
    let _root = windows::pin_directory(root)?;
    fn walk(base: &Path, dir: &Path, output: &mut Vec<String>) -> Result<()> {
        for entry in fs::read_dir(dir).map_err(io)? {
            let p = entry.map_err(io)?.path();
            let m = checked(&p)?.ok_or_else(|| collision(&p))?;
            if m.is_dir() {
                walk(base, &p, output)?;
            } else if m.is_file() {
                let s = p
                    .strip_prefix(base)
                    .map_err(|e| e.to_string())?
                    .to_str()
                    .ok_or_else(|| collision(&p))?
                    .to_owned();
                relative(&s)?;
                output.push(s);
            } else {
                return Err(collision(&p));
            }
        }
        Ok(())
    }
    let mut result = Vec::new();
    walk(root, root, &mut result)?;
    result.sort();
    Ok(result)
}

/// Flush backups and publish their marker, then replace only the captured tree.
/// Directory-entry durability is platform-dependent; see the module contract.
/// Existing directories at file destinations are rejected even when empty.
#[cfg(test)]
pub fn apply(
    root: &Path,
    staged: &Path,
    backup: &Path,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    apply_inner(root, None, staged, backup, old_files, new_files)
}

/// Bind adoption to the tree captured before computing its merge. Git stores
/// executable status rather than all permission bits; preserve full live modes
/// in the rollback backup, but compare the representation Git actually captured.
pub fn apply_captured(
    root: &Path,
    captured: &Path,
    staged: &Path,
    backup: &Path,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    directory(captured)?;
    apply_inner(root, Some(captured), staged, backup, old_files, new_files)
}
fn apply_inner(
    root: &Path,
    captured: Option<&Path>,
    staged: &Path,
    backup: &Path,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    directory(root)?;
    directory(staged)?;
    #[cfg(windows)]
    let (_root, _staged) = (
        windows::pin_directory(root)?,
        windows::pin_directory(staged)?,
    );
    let old_names = names(old_files)?;
    let new_names = names(new_files)?;
    let mut manifest = Manifest {
        old: BTreeMap::new(),
        new: BTreeMap::new(),
    };
    // Complete collision and source preflight before ANY live mutation.
    for s in &old_names {
        let actual = fingerprint(&root.join(s))?;
        #[cfg(windows)]
        if actual.mode != 0 {
            // Clearing READONLY during mutation would add an unjournaled state
            // and could prevent rollback. Refuse before any live change instead.
            return Err(format!("adoption_io: readonly Windows adoption file: {s}"));
        }
        if let Some(captured) = captured {
            let expected = fingerprint(&captured.join(s))?;
            #[cfg(unix)]
            let same_mode = (actual.mode & 0o111 != 0) == (expected.mode & 0o111 != 0);
            #[cfg(not(unix))]
            let same_mode = true;
            if actual.digest != expected.digest || !same_mode {
                return Err(format!(
                    "adoption_conflict: live tree changed since capture: {s}"
                ));
            }
        }
        manifest.old.insert(s.clone(), actual);
    }
    for s in &new_names {
        let dest = root.join(s);
        if let Some(m) = checked(&dest)? {
            if !m.is_file() || !old_names.contains(s) {
                return Err(collision(&dest));
            }
        }
        let staged_fingerprint = fingerprint(&staged.join(s))?;
        #[cfg(windows)]
        if staged_fingerprint.mode != 0 {
            return Err(format!("adoption_io: readonly Windows staging file: {s}"));
        }
        manifest.new.insert(s.clone(), staged_fingerprint);
    }
    // No new file may be an ancestor of another new file.
    for s in &new_names {
        let mut parent = Path::new(s).parent();
        while let Some(p) = parent {
            if let Some(t) = p.to_str() {
                if new_names.contains(t) {
                    return Err(collision(p));
                }
            }
            parent = p.parent();
        }
    }
    if checked(backup)?.is_some() {
        return Err(format!(
            "adoption_io: backup already exists: {}",
            backup.display()
        ));
    }
    mkdirs(backup)?;
    #[cfg(windows)]
    let _backup = windows::pin_directory(backup)?;
    let data = backup.join("old");
    mkdirs(&data)?;
    for s in &old_names {
        replace(&root.join(s), &data.join(s))?;
        if fingerprint(&data.join(s))? != manifest.old[s] {
            return Err(format!("adoption_conflict: source changed: {s}"));
        }
    }
    // Marker is the process-recovery boundary: recovery does nothing without it.
    // On Windows, this does not imply directory-entry durability on power loss.
    let temporary = backup.join("complete.tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(io)?;
    f.write_all(&serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
        .map_err(io)?;
    f.sync_all().map_err(io)?;
    drop(f);
    publish(&temporary, &backup.join(MARKER), false)?;
    sync_dir(backup)?;
    // Check again for edits made during the backup, before modifying the live tree.
    for (s, expected) in &manifest.old {
        if fingerprint(&root.join(s))? != *expected {
            return Err(format!("adoption_conflict: source changed: {s}"));
        }
    }
    for s in &new_names {
        if !old_names.contains(s) && checked(&root.join(s))?.is_some() {
            return Err(collision(&root.join(s)));
        }
        if fingerprint(&staged.join(s))? != manifest.new[s] {
            return Err(format!("adoption_conflict: staging changed: {s}"));
        }
    }
    for s in &old_names {
        remove(&root.join(s))?;
    }
    for (i, s) in new_names.iter().enumerate() {
        replace(&staged.join(s), &root.join(s))?;
        if i == 0 && std::env::var("WIPSTASH_FAULT").as_deref() == Ok("adoption_mid_apply") {
            std::process::exit(86);
        }
    }
    sync_dir(root)
}

/// Verify the recorded applied phase still matches the files installed before
/// committing workspace metadata. A later edit is preserved and requires review.
pub fn verify_applied(
    root: &Path,
    backup: &Path,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    directory(root)?;
    #[cfg(windows)]
    let _root = windows::pin_directory(root)?;
    let old_names = names(old_files)?;
    let new_names = names(new_files)?;
    let marker = backup.join(MARKER);
    regular(&marker)?;
    #[cfg(windows)]
    let _backup = windows::pin_directory(backup)?;
    let manifest: Manifest = serde_json::from_slice(&read_regular(&marker)?)
        .map_err(|e| format!("adoption_io: invalid backup marker: {e}"))?;
    if manifest.old.keys().cloned().collect::<BTreeSet<_>>() != old_names
        || manifest.new.keys().cloned().collect::<BTreeSet<_>>() != new_names
    {
        return Err("adoption_io: backup does not match journal".into());
    }
    for (s, expected) in &manifest.new {
        if fingerprint(&root.join(s))? != *expected {
            return Err(format!(
                "adoption_conflict: applied file changed before finalization: {s}"
            ));
        }
    }
    for s in old_names.difference(&new_names) {
        if checked(&root.join(s))?.is_some() {
            return Err(format!(
                "adoption_conflict: removed file reappeared before finalization: {s}"
            ));
        }
    }
    Ok(())
}

/// Recover a complete or partially applied adoption; refuse to clobber later edits.
pub fn rollback(
    root: &Path,
    backup: &Path,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    directory(root)?;
    #[cfg(windows)]
    let _root = windows::pin_directory(root)?;
    let old_names = names(old_files)?;
    let new_names = names(new_files)?;
    let marker = backup.join(MARKER);
    if checked(&marker)?.is_none() {
        return Ok(());
    }
    regular(&marker)?;
    #[cfg(windows)]
    let _backup = windows::pin_directory(backup)?;
    let manifest: Manifest = serde_json::from_slice(&read_regular(&marker)?)
        .map_err(|e| format!("adoption_io: invalid backup marker: {e}"))?;
    if manifest.old.keys().cloned().collect::<BTreeSet<_>>() != old_names
        || manifest.new.keys().cloned().collect::<BTreeSet<_>>() != new_names
    {
        return Err("adoption_io: backup does not match journal".into());
    }
    // Validate all backups and live files before removing anything. An interrupted
    // rollback is safe to retry because original and installed versions are accepted.
    for (s, expected) in &manifest.old {
        if fingerprint(&backup.join("old").join(s))? != *expected {
            return Err(format!("adoption_io: corrupt backup: {s}"));
        }
    }
    for s in old_names.union(&new_names) {
        let p = root.join(s);
        if let Some(m) = checked(&p)? {
            if !m.is_file() {
                return Err(collision(&p));
            }
            let actual = fingerprint(&p)?;
            if manifest.old.get(s) != Some(&actual) && manifest.new.get(s) != Some(&actual) {
                return Err(format!(
                    "adoption_conflict: refusing to overwrite changed file: {s}"
                ));
            }
        }
    }
    for s in new_names.difference(&old_names) {
        let p = root.join(s);
        if checked(&p)?.is_some() {
            remove(&p)?;
        }
    }
    for s in &old_names {
        let destination = root.join(s);
        // An interrupted rollback may already have restored this exact file.
        // Avoid unnecessary replacement, including an original READONLY file
        // retained by a journal created before readonly preflight was added.
        if checked(&destination)?.is_some() && fingerprint(&destination)? == manifest.old[s] {
            continue;
        }
        replace(&backup.join("old").join(s), &destination)?;
    }
    sync_dir(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Sandbox(PathBuf);
    impl Sandbox {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "wipstash-adoption-test-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            // The OS may place temp under an alias (macOS /var -> /private/var).
            Self(p.canonicalize().unwrap())
        }
        fn dir(&self, s: &str) -> PathBuf {
            let p = self.0.join(s);
            fs::create_dir_all(&p).unwrap();
            p
        }
    }
    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn list(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn windows_filename_rules_reject_streams_devices_and_aliases() {
        for name in [
            "CON",
            "NUL.json",
            "COM1.data",
            "LPT¹.txt",
            "CONOUT$",
            "file:stream",
            "trailing.",
            "trailing ",
            "wild*card",
            "bad\0name",
        ] {
            assert!(
                windows_filename(std::ffi::OsStr::new(name)).is_err(),
                "{name}"
            );
        }
        for name in [
            "ordinary.txt",
            ".hidden",
            "space within",
            "COM10.txt",
            "naïve",
        ] {
            windows_filename(std::ffi::OsStr::new(name)).unwrap();
        }
    }
    #[test]
    fn directory_boundary_propagates_missing_and_non_directory_errors() {
        let t = Sandbox::new();
        let dir = t.dir("directory");
        sync_dir(&dir).unwrap();
        fs::write(dir.join("file"), "bytes").unwrap();
        assert!(sync_dir(&dir.join("file")).is_err());
        assert!(sync_dir(&dir.join("missing")).is_err());
    }
    #[test]
    fn publication_rejects_different_parents_and_existing_completion_marker() {
        let t = Sandbox::new();
        let first = t.dir("first");
        let second = t.dir("second");
        let source = first.join("source");
        fs::write(&source, "complete").unwrap();
        assert!(publish(&source, &second.join("destination"), true).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"complete");
        assert!(!second.join("destination").exists());
        let destination = first.join(MARKER);
        fs::write(&destination, "original marker").unwrap();
        assert!(publish(&source, &destination, false).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"original marker");
        assert_eq!(fs::read(&source).unwrap(), b"complete");
    }
    #[cfg(windows)]
    #[test]
    fn windows_parent_guard_prevents_directory_substitution() {
        let t = Sandbox::new();
        let root = t.dir("root");
        let guard = windows::pin_directory(&root).unwrap();
        assert!(fs::rename(&root, t.0.join("moved")).is_err());
        drop(guard);
        fs::rename(&root, t.0.join("moved")).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn windows_publication_propagates_sharing_violation_without_replacing() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let t = Sandbox::new();
        let dir = t.dir("parent");
        let source = dir.join("source");
        let destination = dir.join("destination");
        fs::write(&source, "new").unwrap();
        fs::write(&destination, "original").unwrap();
        let locked = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&destination)
            .unwrap();
        assert!(publish(&source, &destination, true).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert_eq!(fs::read(&source).unwrap(), b"new");
        drop(locked);
        publish(&source, &destination, true).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert!(!source.exists());
    }
    #[cfg(windows)]
    #[test]
    fn windows_readonly_inputs_fail_before_backup_or_live_mutation() {
        for readonly_source in ["root", "stage"] {
            let t = Sandbox::new();
            let root = t.dir("root");
            let stage = t.dir("stage");
            let backup = t.0.join("backup");
            fs::write(root.join("a"), "original").unwrap();
            fs::write(stage.join("a"), "new").unwrap();
            let readonly_path = t.0.join(readonly_source).join("a");
            let mut permissions = fs::metadata(&readonly_path).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&readonly_path, permissions).unwrap();
            let names = list(&["a"]);
            assert!(apply(&root, &stage, &backup, &names, &names)
                .unwrap_err()
                .contains("readonly Windows"));
            assert!(!backup.exists());
            assert_eq!(fs::read(root.join("a")).unwrap(), b"original");
            assert!(fs::metadata(&readonly_path)
                .unwrap()
                .permissions()
                .readonly());
            let mut permissions = fs::metadata(&readonly_path).unwrap().permissions();
            permissions.set_readonly(false);
            fs::set_permissions(&readonly_path, permissions).unwrap();
        }
    }
    #[cfg(windows)]
    #[test]
    fn windows_rollback_retries_already_restored_readonly_original() {
        let t = Sandbox::new();
        let root = t.dir("root");
        let backup = t.dir("backup");
        let data = t.dir("backup/old");
        let original = root.join("a");
        let saved = data.join("a");
        for path in [&original, &saved] {
            fs::write(path, "original").unwrap();
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(path, permissions).unwrap();
        }
        // A retained older journal can contain readonly originals. If this file
        // was restored before interruption, retries must leave it untouched.
        let manifest = Manifest {
            old: BTreeMap::from([("a".into(), fingerprint(&saved).unwrap())]),
            new: BTreeMap::new(),
        };
        fs::write(backup.join(MARKER), serde_json::to_vec(&manifest).unwrap()).unwrap();
        for _ in 0..2 {
            rollback(&root, &backup, &list(&["a"]), &[]).unwrap();
            assert_eq!(fs::read(&original).unwrap(), b"original");
            assert!(fs::metadata(&original).unwrap().permissions().readonly());
        }
        for path in [&original, &saved] {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(false);
            fs::set_permissions(path, permissions).unwrap();
        }
    }
    #[cfg(windows)]
    #[test]
    fn windows_rejects_junctions_and_unsafe_paths_before_live_mutation() {
        let t = Sandbox::new();
        let root = t.dir("root");
        let stage = t.dir("stage");
        let outside = t.dir("outside");
        let backup = t.0.join("backup");
        fs::write(root.join("kept"), "original").unwrap();
        fs::write(outside.join("a"), "outside original").unwrap();
        fs::create_dir(stage.join("linked")).unwrap();
        fs::write(stage.join("linked/a"), "replacement").unwrap();
        // Junction creation does not require symlink privilege or developer mode.
        // The fixture remains canonical for adoption; cmd gets a normal local
        // cwd and relative args because shell extended-path support differs.
        let shell_dir = t.0.to_string_lossy();
        let shell_dir = shell_dir.strip_prefix(r"\\?\").unwrap_or(&shell_dir);
        let result = std::process::Command::new("cmd")
            .current_dir(shell_dir)
            .args(["/d", "/c", "mklink", "/J", r"root\linked", "outside"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "could not create junction fixture: {:?}",
            result
        );
        assert!(files(&root).is_err());
        assert!(sync_dir(&root.join("linked")).is_err());
        let linked_name = Path::new("linked").join("a").to_str().unwrap().to_owned();
        assert!(
            apply(&root, &stage, &backup, &list(&["kept"]), &[linked_name])
                .unwrap_err()
                .starts_with("path_collision:")
        );
        for name in [
            "kept:stream",
            "NUL.txt",
            "trailing.",
            "trailing ",
            "../escape",
        ] {
            assert!(apply(&root, &stage, &backup, &list(&["kept"]), &list(&[name])).is_err());
        }
        for path in [r"\\server\share\directory", r"\\.\C:\directory"] {
            assert!(windows::wide(Path::new(path)).is_err());
        }
        assert!(!backup.exists());
        assert_eq!(fs::read(root.join("kept")).unwrap(), b"original");
        assert_eq!(fs::read(outside.join("a")).unwrap(), b"outside original");
        fs::remove_dir(root.join("linked")).unwrap();
    }
    #[test]
    fn adopts_and_rolls_back_bytes_and_mode_preserving_excluded() {
        let t = Sandbox::new();
        let r = t.dir("root");
        let s = t.dir("stage");
        let b = t.0.join("backup");
        fs::write(r.join("a"), b"original\0bytes").unwrap();
        fs::write(r.join("secret"), b"excluded").unwrap();
        fs::write(s.join("a"), b"new").unwrap();
        fs::create_dir(s.join("sub")).unwrap();
        fs::write(s.join("sub/b"), b"added").unwrap();
        #[cfg(unix)]
        fs::set_permissions(r.join("a"), fs::Permissions::from_mode(0o751)).unwrap();
        let old = list(&["a"]);
        let new = files(&s).unwrap();
        apply(&r, &s, &b, &old, &new).unwrap();
        assert_eq!(fs::read(r.join("a")).unwrap(), b"new");
        assert_eq!(fs::read(r.join("secret")).unwrap(), b"excluded");
        rollback(&r, &b, &old, &new).unwrap();
        rollback(&r, &b, &old, &new).unwrap();
        assert_eq!(fs::read(r.join("a")).unwrap(), b"original\0bytes");
        assert!(!r.join("sub/b").exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(r.join("a")).unwrap().permissions().mode() & 0o777,
            0o751
        );
    }
    #[test]
    fn captured_adoption_refuses_edits_after_merge_input_capture() {
        let t = Sandbox::new();
        let root = t.dir("root");
        let captured = t.dir("captured");
        let staged = t.dir("staged");
        let backup = t.0.join("backup");
        fs::write(root.join("a"), "later private edit").unwrap();
        fs::write(captured.join("a"), "captured original").unwrap();
        fs::write(staged.join("a"), "merged version").unwrap();
        let names = list(&["a"]);
        let error = apply_captured(&root, &captured, &staged, &backup, &names, &names).unwrap_err();
        assert!(error.starts_with("adoption_conflict:"));
        assert_eq!(
            fs::read_to_string(root.join("a")).unwrap(),
            "later private edit"
        );
        assert!(!backup.exists());
    }
    #[cfg(unix)]
    #[test]
    fn captured_adoption_refuses_executable_bit_changes() {
        let t = Sandbox::new();
        let root = t.dir("root");
        let captured = t.dir("captured");
        let staged = t.dir("staged");
        for p in [&root, &captured, &staged] {
            fs::write(p.join("a"), "same bytes").unwrap();
            fs::set_permissions(p.join("a"), fs::Permissions::from_mode(0o644)).unwrap();
        }
        fs::set_permissions(root.join("a"), fs::Permissions::from_mode(0o755)).unwrap();
        let names = list(&["a"]);
        assert!(apply_captured(
            &root,
            &captured,
            &staged,
            &t.0.join("backup"),
            &names,
            &names
        )
        .unwrap_err()
        .contains("changed since capture"));
        assert_eq!(
            fs::metadata(root.join("a")).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    #[test]
    fn collisions_leave_live_tree_untouched() {
        let t = Sandbox::new();
        let r = t.dir("root");
        let s = t.dir("stage");
        let b = t.0.join("backup");
        fs::write(r.join("a"), b"old").unwrap();
        fs::write(r.join("extra"), b"precious").unwrap();
        fs::write(s.join("extra"), b"overwrite").unwrap();
        assert!(apply(&r, &s, &b, &list(&["a"]), &list(&["extra"]))
            .unwrap_err()
            .starts_with("path_collision:"));
        assert_eq!(fs::read(r.join("a")).unwrap(), b"old");
        assert_eq!(fs::read(r.join("extra")).unwrap(), b"precious");
        assert!(!b.exists());
        fs::remove_file(r.join("extra")).unwrap();
        fs::create_dir(r.join("extra")).unwrap();
        assert!(apply(&r, &s, &b, &list(&["a"]), &list(&["extra"]))
            .unwrap_err()
            .starts_with("path_collision:"));
        assert_eq!(fs::read(r.join("a")).unwrap(), b"old");
        assert!(!b.exists());
    }
    #[test]
    fn applied_verification_preserves_later_changes_and_recreated_deletions() {
        let t = Sandbox::new();
        let root = t.dir("root");
        let stage = t.dir("stage");
        let backup = t.0.join("backup");
        fs::write(root.join("a"), "old").unwrap();
        fs::write(root.join("deleted"), "old deletion").unwrap();
        fs::write(stage.join("a"), "new").unwrap();
        let old = list(&["a", "deleted"]);
        let new = list(&["a"]);
        apply(&root, &stage, &backup, &old, &new).unwrap();
        verify_applied(&root, &backup, &old, &new).unwrap();
        fs::write(root.join("a"), "later").unwrap();
        assert!(verify_applied(&root, &backup, &old, &new).is_err());
        assert_eq!(fs::read_to_string(root.join("a")).unwrap(), "later");
        fs::write(root.join("a"), "new").unwrap();
        fs::write(root.join("deleted"), "recreated").unwrap();
        assert!(verify_applied(&root, &backup, &old, &new).is_err());
        assert_eq!(
            fs::read_to_string(root.join("deleted")).unwrap(),
            "recreated"
        );
    }
    #[test]
    fn partial_apply_and_partial_rollback_recover() {
        let t = Sandbox::new();
        let r = t.dir("root");
        let s = t.dir("stage");
        let b = t.0.join("backup");
        fs::write(r.join("a"), b"old a").unwrap();
        fs::write(r.join("b"), b"old b").unwrap();
        fs::write(s.join("a"), b"new a").unwrap();
        fs::write(s.join("c"), b"new c").unwrap();
        let old = list(&["a", "b"]);
        let new = list(&["a", "c"]);
        apply(&r, &s, &b, &old, &new).unwrap();
        fs::remove_file(r.join("c")).unwrap(); // partial application is also a possible partial rollback
        rollback(&r, &b, &old, &new).unwrap();
        assert_eq!(fs::read(r.join("a")).unwrap(), b"old a");
        assert_eq!(fs::read(r.join("b")).unwrap(), b"old b");
    }
    #[test]
    fn rollback_preserves_later_edits_and_partial_backups_are_noop() {
        let t = Sandbox::new();
        let r = t.dir("root");
        let s = t.dir("stage");
        let b = t.0.join("backup");
        fs::write(r.join("a"), b"old").unwrap();
        fs::write(s.join("a"), b"new").unwrap();
        let names = list(&["a"]);
        rollback(&r, &b, &names, &names).unwrap();
        apply(&r, &s, &b, &names, &names).unwrap();
        fs::write(r.join("a"), b"later edit").unwrap();
        assert!(rollback(&r, &b, &names, &names)
            .unwrap_err()
            .starts_with("adoption_conflict:"));
        assert_eq!(fs::read(r.join("a")).unwrap(), b"later edit");
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_and_escapes() {
        let t = Sandbox::new();
        let r = t.dir("root");
        let s = t.dir("stage");
        let b = t.0.join("backup");
        let outside = t.dir("outside");
        std::os::unix::fs::symlink(&outside, r.join("linked")).unwrap();
        fs::create_dir(s.join("linked")).unwrap();
        fs::write(s.join("linked/a"), b"new").unwrap();
        assert!(apply(&r, &s, &b, &[], &list(&["linked/a"]))
            .unwrap_err()
            .starts_with("path_collision:"));
        assert!(apply(&r, &s, &b, &[], &list(&["../escape"]))
            .unwrap_err()
            .starts_with("path_collision:"));
        std::os::unix::fs::symlink(&outside, s.join("symlink")).unwrap();
        assert!(files(&s).is_err());
        assert!(!b.exists());
    }
    #[test]
    fn crash_worker() {
        if let Ok(base) = std::env::var("WIPSTASH_ADOPTION_TEST_ROOT") {
            let p = Path::new(&base);
            apply(
                &p.join("root"),
                &p.join("stage"),
                &p.join("backup"),
                &list(&["a", "b"]),
                &list(&["a", "c"]),
            )
            .unwrap();
            panic!("fault injection did not exit");
        }
    }
    #[test]
    fn process_exit_during_apply_is_recoverable() {
        let t = Sandbox::new();
        let r = t.dir("root");
        let s = t.dir("stage");
        let b = t.0.join("backup");
        fs::write(r.join("a"), b"old a").unwrap();
        fs::write(r.join("b"), b"old b").unwrap();
        fs::write(r.join("keep"), b"untracked").unwrap();
        fs::write(s.join("a"), b"new a").unwrap();
        fs::write(s.join("c"), b"new c").unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                std::thread::current()
                    .name()
                    .unwrap()
                    .replace("process_exit_during_apply_is_recoverable", "crash_worker"),
            )
            .arg("--nocapture")
            .env("WIPSTASH_ADOPTION_TEST_ROOT", &t.0)
            .env("WIPSTASH_FAULT", "adoption_mid_apply")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        assert_eq!(fs::read(r.join("a")).unwrap(), b"new a");
        assert!(!r.join("b").exists());
        assert!(!r.join("c").exists());
        rollback(&r, &b, &list(&["a", "b"]), &list(&["a", "c"])).unwrap();
        assert_eq!(fs::read(r.join("a")).unwrap(), b"old a");
        assert_eq!(fs::read(r.join("b")).unwrap(), b"old b");
        assert_eq!(fs::read(r.join("keep")).unwrap(), b"untracked");
    }
}
