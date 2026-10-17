//! Durable, conservative adoption of a sanitized file tree.
//! The caller must serialize access and persist its intent before calling apply.
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
    Ok(p)
}
// Check every existing component, including the root's ancestors, without following links.
fn checked(p: &Path) -> Result<Option<fs::Metadata>> {
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(io)?.join(p)
    };
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
        match fs::symlink_metadata(&part) {
            Ok(m) => {
                if m.file_type().is_symlink() || (i + 1 < count && !m.is_dir()) {
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
fn sync_dir(p: &Path) -> Result<()> {
    File::open(p).map_err(io)?.sync_all().map_err(io)
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
    let m = regular(p)?;
    let mut file = File::open(p).map_err(io)?;
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
    let metadata = regular(src)?;
    let parent = dst.parent().ok_or_else(|| collision(dst))?;
    mkdirs(parent)?;
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
        std::io::copy(&mut File::open(src).map_err(io)?, &mut out).map_err(io)?;
        out.set_permissions(metadata.permissions()).map_err(io)?;
        out.sync_all().map_err(io)?;
        fs::rename(&tmp, dst).map_err(io)?;
        sync_dir(parent)
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}
fn remove(p: &Path) -> Result<()> {
    regular(p)?;
    fs::remove_file(p).map_err(io)?;
    sync_dir(p.parent().ok_or_else(|| collision(p))?)
}

/// List a sanitized staging tree, rejecting symlinks and special files.
pub fn files(root: &Path) -> Result<Vec<String>> {
    directory(root)?;
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

/// Back up all old files durably, then replace only the captured included tree.
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
    let old_names = names(old_files)?;
    let new_names = names(new_files)?;
    let mut manifest = Manifest {
        old: BTreeMap::new(),
        new: BTreeMap::new(),
    };
    // Complete collision and source preflight before ANY live mutation.
    for s in &old_names {
        let actual = fingerprint(&root.join(s))?;
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
        manifest
            .new
            .insert(s.clone(), fingerprint(&staged.join(s))?);
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
    let data = backup.join("old");
    mkdirs(&data)?;
    for s in &old_names {
        replace(&root.join(s), &data.join(s))?;
        if fingerprint(&data.join(s))? != manifest.old[s] {
            return Err(format!("adoption_conflict: source changed: {s}"));
        }
    }
    // Marker is the durable boundary: recovery does nothing without it.
    let temporary = backup.join("complete.tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(io)?;
    f.write_all(&serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
        .map_err(io)?;
    f.sync_all().map_err(io)?;
    fs::rename(&temporary, backup.join(MARKER)).map_err(io)?;
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

/// Verify the durable applied phase still matches the files installed before
/// committing workspace metadata. A later edit is preserved and requires review.
pub fn verify_applied(
    root: &Path,
    backup: &Path,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    directory(root)?;
    let old_names = names(old_files)?;
    let new_names = names(new_files)?;
    let marker = backup.join(MARKER);
    regular(&marker)?;
    let manifest: Manifest = serde_json::from_slice(&fs::read(&marker).map_err(io)?)
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
    let old_names = names(old_files)?;
    let new_names = names(new_files)?;
    let marker = backup.join(MARKER);
    if checked(&marker)?.is_none() {
        return Ok(());
    }
    regular(&marker)?;
    let manifest: Manifest = serde_json::from_slice(&fs::read(&marker).map_err(io)?)
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
        replace(&backup.join("old").join(s), &root.join(s))?;
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
            Self(p)
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
