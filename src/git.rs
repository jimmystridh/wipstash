//! Byte-preserving Git plumbing. No worktree checkout, filters, hooks, or shell.
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

pub type Result<T> = std::result::Result<T, String>;
pub struct Git {
    pub repo: PathBuf,
}
pub struct Merge {
    pub conflicts: Vec<String>,
    pub tree: String,
    pub clean: bool,
    pub details: String,
}
static NEXT: AtomicU64 = AtomicU64::new(0);
const MAX_BLOB_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TREE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_GIT_OUTPUT: usize = 32 * 1024 * 1024;

fn bounded_output(mut input: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut exceeded = false;
    loop {
        let n = input.read(&mut buffer).map_err(err)?;
        if n == 0 {
            break;
        }
        if output.len().saturating_add(n) <= limit && !exceeded {
            output.extend_from_slice(&buffer[..n]);
        } else {
            exceeded = true;
        }
        // Continue draining so the child cannot block on a full output pipe.
    }
    if exceeded {
        Err("storage_limit: Git output exceeds limit".into())
    } else {
        Ok(output)
    }
}
fn add_snapshot_bytes(total: &mut u64, size: u64) -> Result<()> {
    if size > MAX_BLOB_BYTES {
        return Err("storage_limit: file exceeds 16 MiB".into());
    }
    *total = total.checked_add(size).ok_or("storage_size_overflow")?;
    if *total > MAX_SNAPSHOT_BYTES {
        return Err("storage_limit: snapshot exceeds 64 MiB".into());
    }
    Ok(())
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn command() -> Command {
    let mut c = Command::new("git");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("GIT_") {
            c.env_remove(k);
        }
    }
    let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let hooks = format!("core.hooksPath={null_device}");
    let attributes = format!("core.attributesFile={null_device}");
    let excludes = format!("core.excludesFile={null_device}");
    c.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", null_device)
        .env("GIT_CONFIG_GLOBAL", null_device)
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Wipstash")
        .env("GIT_AUTHOR_EMAIL", "wipstash@localhost")
        .env("GIT_COMMITTER_NAME", "Wipstash")
        .env("GIT_COMMITTER_EMAIL", "wipstash@localhost")
        .arg("--no-pager")
        .args([
            "-c",
            &hooks,
            "-c",
            &attributes,
            "-c",
            &excludes,
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "core.fsync=all",
            "-c",
            "core.fsyncMethod=fsync",
        ]);
    c
}
fn execute(mut c: Command, input: Option<&[u8]>) -> Result<Output> {
    c.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = c.spawn().map_err(err)?;
    // A writer thread also prevents deadlock if Git emits diagnostics while reading.
    let writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().expect("piped stdin");
        let data = bytes.to_vec();
        std::thread::spawn(move || stdin.write_all(&data))
    });
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout = std::thread::spawn(move || bounded_output(stdout, MAX_GIT_OUTPUT));
    let stderr = std::thread::spawn(move || bounded_output(stderr, 1024 * 1024));
    let status = child.wait().map_err(err)?;
    let output = Output {
        status,
        stdout: stdout.join().map_err(|_| "Git output reader panicked")??,
        stderr: stderr.join().map_err(|_| "Git error reader panicked")??,
    };
    if let Some(w) = writer {
        let written = w
            .join()
            .map_err(|_| "Git input writer panicked".to_string())?;
        // Preserve Git's diagnostics on failure, but never report success after a
        // truncated input stream (for example, a broken pipe).
        if output.status.success() {
            written.map_err(|e| format!("git_input_error: {e}"))?;
        }
    }
    Ok(output)
}
fn checked(output: Output) -> Result<Vec<u8>> {
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "git failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}
fn oid(bytes: Vec<u8>) -> Result<String> {
    let s = String::from_utf8(bytes).map_err(err)?.trim().to_owned();
    if (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        Err("invalid Git object id".into())
    }
}
fn valid_oid(s: &str) -> Result<()> {
    if (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("invalid Git object id".into())
    }
}

/// Deliberately conservative portable-name rules for a local prototype.
fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err("unsupported_tree: empty path".into());
    }
    if path.len() > 4096 || path.split('/').count() > 64 {
        return Err("storage_limit: path exceeds 4096 bytes or 64 components".into());
    }
    for component in path.split('/') {
        let stem = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with(['.', ' '])
            || component
                .chars()
                .any(|c| c.is_control() || "\\:*?\"<>|".contains(c))
            || device
            || component.eq_ignore_ascii_case(".git")
        {
            return Err(format!("unsupported_tree: non-portable path {path:?}"));
        }
        // Unicode normalization/case folding differs across filesystems. Fail closed.
        if !component.is_ascii() {
            return Err(format!("unsupported_tree: non-ASCII path {path:?}"));
        }
    }
    Ok(())
}
fn excluded(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == ".git"
        || n == ".env"
        || n.starts_with(".env.")
        || matches!(
            n.as_str(),
            ".wipstash"
                | "credentials"
                | "credentials.json"
                | "credentials.toml"
                | ".credentials"
                | ".aws"
                | ".ssh"
                | ".gnupg"
                | "node_modules"
                | "target"
                | "build"
                | ".cache"
                | "cache"
                | "__pycache__"
                | ".pytest_cache"
                | ".mypy_cache"
                | ".next"
                | ".nuxt"
                | ".turbo"
                | ".codex"
                | ".claude"
                | ".cursor"
                | ".aider"
                | ".agent"
                | ".agents"
                | "transcripts"
                | "agent_transcripts"
                | "agent-transcripts"
        )
        || n.starts_with(".aider.")
        || n.ends_with(".wipstash-invite")
        || n.ends_with(".pem")
        || n.ends_with(".key")
}
pub(crate) fn allowed_path(path: &str) -> Result<()> {
    validate_path(path)?;
    if path.split('/').any(excluded) {
        return Err(format!("unsupported_tree: excluded path {path:?}"));
    }
    Ok(())
}
pub(crate) fn register_path(
    path: &str,
    seen: &mut std::collections::HashMap<String, String>,
) -> Result<()> {
    let mut prefix = String::new();
    for p in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(p);
        let key = prefix.to_ascii_lowercase();
        if let Some(previous) = seen.get(&key) {
            if previous != &prefix {
                return Err(format!(
                    "unsupported_tree: case-fold collision: {previous:?} and {prefix:?}"
                ));
            }
        } else {
            seen.insert(key, prefix.clone());
        }
    }
    Ok(())
}

// Check existing directory components without following symlinks. This catches
// static aliases; cooperative writers are still required against rename races.
fn real_directory(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(err)?.join(path)
    };
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err("unsupported_tree: parent directory traversal".into());
        }
        prefix.push(component);
        // A Windows drive prefix alone is drive-relative (C:) or an incomplete
        // verbatim namespace (\\?\C:), not an ancestor directory. Inspect
        // it only after the following root separator has been appended.
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&prefix)
            .map_err(|e| format!("directory_metadata_error: {}: {e}", prefix.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "unsupported_tree: directory component is not a real directory: {}",
                prefix.display()
            ));
        }
    }
    Ok(())
}

// This is an early, conservative capacity check, not a reservation. Concurrent
// consumers, quotas and filesystem metadata can still cause later writes to fail.
fn required_space(bytes: u64, files: u64) -> Result<u64> {
    bytes
        .checked_add(files.checked_mul(8192).ok_or("storage_size_overflow")?)
        .and_then(|n| n.checked_add(1024 * 1024))
        .ok_or_else(|| "storage_size_overflow".to_string())
}
fn preflight_space(path: &Path, bytes: u64, files: u64) -> Result<()> {
    let required = required_space(bytes, files)?;
    let available =
        fs2::available_space(path).map_err(|e| format!("storage_capacity_error: {e}"))?;
    check_capacity(required, available)
}
fn check_capacity(required: u64, available: u64) -> Result<()> {
    if required > available {
        Err(format!(
            "insufficient_storage: need {required} bytes including reserve; {available} available"
        ))
    } else {
        Ok(())
    }
}
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("storage_sync_error: {}: {e}", path.display()))?;
    #[cfg(not(unix))]
    let _ = path; // Directory fsync requires a native platform adapter.
    Ok(())
}

impl Git {
    pub fn init(path: &Path) -> Result<Self> {
        let argument = wipstash_platform::git_path::argument(path).map_err(err)?;
        fs::create_dir_all(path).map_err(err)?;
        let mut c = command();
        c.args(["init", "--bare", "--template="]).arg(argument);
        checked(execute(c, None)?)?;
        Ok(Self {
            repo: fs::canonicalize(path).map_err(err)?,
        })
    }
    pub fn open(path: &Path) -> Self {
        Self {
            repo: path.to_path_buf(),
        }
    }
    fn cmd(&self, args: &[&str]) -> Result<Command> {
        let mut c = command();
        c.arg("--git-dir")
            .arg(wipstash_platform::git_path::argument(&self.repo).map_err(err)?)
            .args(args);
        Ok(c)
    }
    pub fn run(&self, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
        checked(execute(self.cmd(args)?, input)?)
    }
    /// Local-only Git transport boundary. Keep canonical filesystem identities
    /// separate from Git's process representation and never infer a remote URL.
    pub fn run_local_repository(
        &self,
        args: &[&str],
        repository: &Path,
        trailing: &[&str],
    ) -> Result<Vec<u8>> {
        let canonical =
            fs::canonicalize(repository).map_err(|e| format!("local_repository_path: {e}"))?;
        if !canonical.is_dir() {
            return Err("local_repository_path: directory required".into());
        }
        let argument = wipstash_platform::git_path::argument(&canonical).map_err(err)?;
        let mut command = self.cmd(&[
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=always",
        ])?;
        // The environment allowlist takes precedence over per-protocol config
        // and URL rewrites in a repository; a local-only call cannot use SSH,
        // HTTPS, remote helpers or other transports even if config permits them.
        command.env("GIT_ALLOW_PROTOCOL", "file");
        command.args(args).arg("--").arg(argument).args(trailing);
        checked(execute(command, None)?)
    }

    fn object_size(&self, object: &str) -> Result<u64> {
        valid_oid(object)?;
        String::from_utf8(self.run(&["cat-file", "-s", object], None)?)
            .map_err(err)?
            .trim()
            .parse::<u64>()
            .map_err(err)
    }
    pub(crate) fn verified_object(&self, kind: &str, object: &str) -> Result<Vec<u8>> {
        valid_oid(object)?;
        let size = self.object_size(object)?;
        let limit = if kind == "tree" {
            MAX_TREE_BYTES
        } else {
            MAX_BLOB_BYTES
        };
        if size > limit {
            return Err(format!(
                "storage_limit: {kind} object exceeds {limit} bytes"
            ));
        }
        let bytes = self.run(&["cat-file", kind, object], None)?;
        let actual = oid(self.run(
            &["hash-object", "-t", kind, "--stdin", "--no-filters"],
            Some(&bytes),
        )?)?;
        if actual != object {
            return Err(format!(
                "storage_corruption: {kind} checksum mismatch for {object}"
            ));
        }
        Ok(bytes)
    }
    pub fn head(&self, refname: &str) -> Result<String> {
        oid(self.run(
            &["rev-parse", "--verify", "--end-of-options", refname],
            None,
        )?)
    }
    /// Read an exact, direct ref without treating broken or symbolic refs as absent.
    pub(crate) fn direct_ref(&self, refname: &str) -> Result<Option<String>> {
        if !refname.starts_with("refs/") {
            return Err("reference must start with refs/".into());
        }
        self.run(&["check-ref-format", refname], None)?;
        let symbolic = execute(self.cmd(&["symbolic-ref", "--quiet", refname])?, None)?;
        match symbolic.status.code() {
            Some(0) => return Err("reference_conflict: symbolic pin is not supported".into()),
            Some(1) => {}
            _ => return checked(symbolic).map(|_| None),
        }
        let output = self.run(
            &[
                "for-each-ref",
                "--format=%(refname)%00%(objectname)%00%(symref)",
                refname,
            ],
            None,
        )?;
        if output.is_empty() {
            return Ok(None);
        }
        let output = String::from_utf8(output).map_err(err)?;
        let fields: Vec<_> = output.trim_end_matches('\n').split('\0').collect();
        if fields.len() != 3 || fields[0] != refname || !fields[2].is_empty() {
            return Err("reference_conflict: expected one exact direct reference".into());
        }
        valid_oid(fields[1])?;
        Ok(Some(fields[1].to_owned()))
    }
    /// Create an immutable pin; never overwrite a ref or follow a symbolic ref.
    pub(crate) fn create_ref(&self, refname: &str, object: &str) -> Result<()> {
        valid_oid(object)?;
        if !refname.starts_with("refs/") {
            return Err("reference must start with refs/".into());
        }
        self.run(&["check-ref-format", refname], None)?;
        self.run(
            &[
                "update-ref",
                "--no-deref",
                refname,
                object,
                &"0".repeat(object.len()),
            ],
            None,
        )?;
        Ok(())
    }
    pub fn set_ref(&self, refname: &str, object: &str, old: Option<&str>) -> Result<()> {
        valid_oid(object)?;
        if !refname.starts_with("refs/") {
            return Err("reference must start with refs/".into());
        }
        self.run(&["check-ref-format", refname], None)?;
        let mut args = vec!["update-ref", refname, object];
        if let Some(old) = old {
            valid_oid(old)?;
            args.push(old);
        }
        self.run(&args, None)?;
        Ok(())
    }
    #[cfg(test)]
    pub fn empty_tree(&self) -> Result<String> {
        oid(self.run(&["hash-object", "-w", "-t", "tree", "--stdin"], Some(b""))?)
    }
    pub fn commit(&self, tree: &str, parents: &[String], message: &str) -> Result<String> {
        valid_oid(tree)?;
        let mut args = vec!["commit-tree", tree];
        for p in parents {
            valid_oid(p)?;
            args.extend(["-p", p]);
        }
        oid(self.run(&args, Some(message.as_bytes()))?)
    }
    pub fn tree(&self, commit: &str) -> Result<String> {
        let expr = format!("{commit}^{{tree}}");
        self.head(&expr)
    }
    pub fn ancestor(&self, old: &str, new: &str) -> Result<bool> {
        valid_oid(old)?;
        valid_oid(new)?;
        let output = execute(self.cmd(&["merge-base", "--is-ancestor", old, new])?, None)?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => checked(output).map(|_| false),
        }
    }
    pub fn capture(&self, root: &Path) -> Result<String> {
        real_directory(root)?;
        let root_meta = fs::symlink_metadata(root).map_err(err)?;
        if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
            return Err("unsupported_tree: source must be a real directory".into());
        }
        let mut files = Vec::new();
        let mut seen = std::collections::HashMap::new();
        let canonical_root = fs::canonicalize(root).map_err(err)?;
        let mut total = 0;
        self.walk(
            &canonical_root,
            &canonical_root,
            "",
            &mut files,
            &mut seen,
            &mut total,
        )?;
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let bytes = files.iter().try_fold(0u64, |n, (_, _, b)| {
            n.checked_add(b.len() as u64).ok_or("storage_size_overflow")
        })?;
        preflight_space(&self.repo, bytes, files.len() as u64)?;
        let mut entries = Vec::new();
        for (name, mode, bytes) in files {
            let blob = oid(self.run(
                &["hash-object", "-w", "--stdin", "--no-filters"],
                Some(&bytes),
            )?)?;
            entries.extend_from_slice(format!("{mode} {blob}\t{name}\0").as_bytes());
        }
        let index = self.repo.join(format!(
            "wipstash-index-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // Reserve the name atomically; Git read-tree initializes the empty file.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&index)
            .map_err(err)?;
        let _guard = IndexGuard(index.clone());
        let indexed = |args: &[&str], input: Option<&[u8]>| -> Result<Vec<u8>> {
            let mut c = self.cmd(args)?;
            c.env(
                "GIT_INDEX_FILE",
                wipstash_platform::git_path::argument(&index).map_err(err)?,
            );
            checked(execute(c, input)?)
        };
        indexed(&["read-tree", "--empty"], None)?;
        indexed(&["update-index", "-z", "--index-info"], Some(&entries))?;
        oid(indexed(&["write-tree"], None)?)
    }
    fn walk(
        &self,
        root: &Path,
        dir: &Path,
        relative: &str,
        out: &mut Vec<(String, &'static str, Vec<u8>)>,
        seen: &mut std::collections::HashMap<String, String>,
        total: &mut u64,
    ) -> Result<()> {
        real_directory(dir)?;
        for entry in fs::read_dir(dir).map_err(err)? {
            let entry = entry.map_err(err)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "unsupported_tree: non-UTF-8 filename".to_string())?;
            if excluded(&name) {
                continue;
            }
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let metadata = fs::symlink_metadata(entry.path()).map_err(err)?;
            if entry.file_name() != ".gitignore"
                && self.is_ignored(root, &entry.path(), metadata.is_dir())?
            {
                continue;
            }
            allowed_path(&path)?;
            register_path(&path, seen)?;
            if seen.len() > MAX_ENTRIES {
                return Err("storage_limit: snapshot exceeds 10000 entries".into());
            }
            if metadata.file_type().is_symlink() {
                return Err(format!("unsupported_tree: symlink {path:?}"));
            }
            if metadata.is_dir() {
                self.walk(root, &entry.path(), &path, out, seen, total)?;
            } else if metadata.is_file() {
                add_snapshot_bytes(total, metadata.len())?;
                preflight_space(&self.repo, *total, out.len() as u64 + 1)?;
                #[cfg(unix)]
                let executable = {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let executable = false;
                out.push((path, if executable { "100755" } else { "100644" }, {
                    let bytes = bounded_output(
                        fs::File::open(entry.path()).map_err(err)?,
                        MAX_BLOB_BYTES as usize,
                    )?;
                    if bytes.len() as u64 != metadata.len() {
                        return Err("capture_unstable: file size changed while reading".into());
                    }
                    bytes
                }));
            } else {
                return Err(format!("unsupported_tree: special file {path:?}"));
            }
        }
        Ok(())
    }
    fn is_ignored(&self, root: &Path, path: &Path, is_dir: bool) -> Result<bool> {
        // --no-index means only ignore rules matter; the user's index is never read.
        // Explicit work-tree, current directory and excludesFile isolate this from the
        // caller's checkout and global ignore configuration. Git implements nested
        // rules, negation, escaping, and directory-only patterns itself.
        let mut c = self.cmd(&[])?;
        c.arg("--work-tree")
            .arg(wipstash_platform::git_path::argument(root).map_err(err)?)
            .args([
                "-c",
                "core.bare=false",
                "check-ignore",
                "--no-index",
                "-q",
                "--",
            ]);
        let mut name = wipstash_platform::git_path::argument(path)
            .map_err(err)?
            .into_os_string();
        if is_dir {
            name.push("/");
        }
        c.arg(name).current_dir(root);
        let output = execute(c, None)?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => checked(output).map(|_| false),
        }
    }
    pub fn materialize(&self, treeish: &str, root: &Path) -> Result<()> {
        real_directory(root)?;
        let metadata = fs::symlink_metadata(root).map_err(err)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fs::read_dir(root).map_err(err)?.next().is_some()
        {
            return Err("materialization requires an empty real staging directory".into());
        }
        let tree = self.tree(treeish)?;
        self.verified_object("tree", &tree)?;
        let listing = self.run(&["ls-tree", "-r", "-t", "-z", "--full-tree", &tree], None)?;
        let mut seen = std::collections::HashMap::new();
        let mut exact = HashSet::new();
        let mut tree_paths = HashSet::new();
        let mut entries = Vec::new();
        let mut total = 0;
        // Validate the entire tree and read all blobs before creating any files.
        for item in listing.split(|b| *b == 0).filter(|x| !x.is_empty()) {
            let tab = item
                .iter()
                .position(|b| *b == b'\t')
                .ok_or("malformed ls-tree output")?;
            let header = std::str::from_utf8(&item[..tab]).map_err(err)?;
            let name = std::str::from_utf8(&item[tab + 1..])
                .map_err(|_| "unsupported_tree: non-UTF-8 filename".to_string())?;
            allowed_path(name)?;
            register_path(name, &mut seen)?;
            if seen.len() > MAX_ENTRIES {
                return Err("storage_limit: snapshot exceeds 10000 entries".into());
            }
            let fields: Vec<_> = header.split(' ').collect();
            if fields.len() == 3 && fields[0] == "040000" && fields[1] == "tree" {
                if !tree_paths.insert(name.to_owned()) || exact.contains(name) {
                    return Err("unsupported_tree: duplicate or file/directory collision".into());
                }
                self.verified_object("tree", fields[2])?;
                continue;
            }
            if !exact.insert(name.to_owned()) || tree_paths.contains(name) {
                return Err("unsupported_tree: duplicate path".into());
            }
            if fields.len() != 3 || fields[1] != "blob" || !matches!(fields[0], "100644" | "100755")
            {
                return Err(format!("unsupported_tree: mode/type for {name:?}"));
            }
            valid_oid(fields[2])?;
            add_snapshot_bytes(&mut total, self.object_size(fields[2])?)?;
            preflight_space(root, total, entries.len() as u64 + 1)?;
            let bytes = self.verified_object("blob", fields[2])?;
            entries.push((name.to_owned(), fields[0] == "100755", bytes));
        }
        for name in &exact {
            let mut parent = Path::new(name).parent();
            while let Some(p) = parent {
                if let Some(s) = p.to_str() {
                    if exact.contains(s) {
                        return Err("unsupported_tree: file/directory collision".into());
                    }
                }
                parent = p.parent();
            }
        }
        let bytes = entries.iter().try_fold(0u64, |n, (_, _, b)| {
            n.checked_add(b.len() as u64).ok_or("storage_size_overflow")
        })?;
        preflight_space(root, bytes, entries.len() as u64)?;
        let mut directories = HashSet::new();
        directories.insert(root.to_path_buf());
        for (name, executable, bytes) in entries {
            let target = root.join(name);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(err)?;
                real_directory(parent)?;
                let mut directory = parent;
                while directory.starts_with(root) {
                    directories.insert(directory.to_path_buf());
                    if directory == root {
                        break;
                    }
                    directory = directory.parent().ok_or("invalid staging parent")?;
                }
            }
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(err)?;
            f.write_all(&bytes).map_err(err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(if executable {
                    0o755
                } else {
                    0o644
                }))
                .map_err(err)?;
            }
            #[cfg(not(unix))]
            {
                let _ = executable;
            }
            f.sync_all()
                .map_err(|e| format!("storage_sync_error: {}: {e}", target.display()))?;
        }
        // Flush child directory entries before their parents.
        let mut directories: Vec<_> = directories.into_iter().collect();
        directories.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for directory in directories {
            sync_directory(&directory)?;
        }
        Ok(())
    }
    pub fn merge(&self, left: &str, right: &str) -> Result<Merge> {
        valid_oid(left)?;
        valid_oid(right)?;
        let output = execute(
            self.cmd(&["merge-tree", "--write-tree", "-z", left, right])?,
            None,
        )?;
        let clean = match output.status.code() {
            Some(0) => true,
            Some(1) => false,
            _ => {
                return checked(output).and_then(|_| Err("unexpected merge status".into()));
            }
        };
        let end = output
            .stdout
            .iter()
            .position(|b| *b == 0)
            .ok_or("merge-tree returned no tree")?;
        let tree = oid(output.stdout[..end].to_vec())?;
        let details = String::from_utf8_lossy(&output.stdout[end + 1..]).replace('\0', "\n");
        let mut conflicts = std::collections::BTreeSet::new();
        let tokens: Vec<&[u8]> = output.stdout[end + 1..].split(|b| *b == 0).collect();
        let mut i = 0;
        if !clean {
            while i < tokens.len() && !tokens[i].is_empty() {
                let stage = std::str::from_utf8(tokens[i]).map_err(err)?;
                let (_, path) = stage
                    .split_once('\t')
                    .ok_or("malformed merge conflict stage")?;
                allowed_path(path)?;
                conflicts.insert(path.to_owned());
                i += 1;
            }
            i += 1;
            while i < tokens.len() && !tokens[i].is_empty() {
                let count = std::str::from_utf8(tokens[i])
                    .map_err(err)?
                    .parse::<usize>()
                    .map_err(err)?;
                i += 1;
                if count > 10000 || i + count + 2 > tokens.len() {
                    return Err("malformed merge conflict message".into());
                }
                for path in &tokens[i..i + count] {
                    let path = std::str::from_utf8(path).map_err(err)?;
                    allowed_path(path)?;
                    conflicts.insert(path.to_owned());
                }
                i += count + 2;
            }
            if conflicts.is_empty() {
                return Err("unsupported_tree: conflict without known affected paths".into());
            }
        }
        Ok(Merge {
            tree,
            clean,
            details,
            conflicts: conflicts.into_iter().collect(),
        })
    }
}
struct IndexGuard(PathBuf);
impl Drop for IndexGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(self.0.with_extension("lock"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "wipstash-git-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(fs::canonicalize(p).unwrap())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn canonical_directory_components_include_root_not_bare_prefix() {
        let t = Temp::new();
        // canonicalize produces a verbatim drive path on Windows. The scanner
        // must inspect its root and real descendants, never the bare prefix.
        let root = fs::canonicalize(&t.0).unwrap();
        assert!(real_directory(&root).is_ok());
        let child = root.join("child");
        fs::create_dir(&child).unwrap();
        assert!(real_directory(&child).is_ok());
        let file = child.join("file");
        fs::write(&file, b"fixture").unwrap();
        assert!(real_directory(&file).is_err());
        assert!(real_directory(&file.join("descendant")).is_err());
        assert!(real_directory(&root.join("missing")).is_err());
    }

    #[test]
    fn immutable_reference_creation_never_replaces_existing_pins() {
        let t = Temp::new();
        let git = Git::init(&t.0.join("pins.git")).unwrap();
        let tree = git.empty_tree().unwrap();
        let first = git.commit(&tree, &[], "first").unwrap();
        let second = git.commit(&tree, &[], "second").unwrap();
        let reference = "refs/wipstash/exports/immutable";
        assert_eq!(git.direct_ref(reference).unwrap(), None);
        git.create_ref(reference, &first).unwrap();
        assert!(git.create_ref(reference, &second).is_err());
        assert_eq!(git.direct_ref(reference).unwrap(), Some(first));
        let symbolic = "refs/wipstash/exports/symbolic";
        git.run(&["symbolic-ref", symbolic, reference], None)
            .unwrap();
        assert!(git.direct_ref(symbolic).is_err());
        assert!(git.create_ref(symbolic, &second).is_err());
        assert_eq!(
            git.run(&["symbolic-ref", symbolic], None).unwrap(),
            format!("{reference}\n").as_bytes()
        );
        let dangling = "refs/wipstash/exports/dangling";
        git.run(&["symbolic-ref", dangling, "refs/wipstash/absent"], None)
            .unwrap();
        assert!(git.direct_ref(dangling).is_err());
        assert!(git.create_ref(dangling, &second).is_err());
    }

    #[test]
    fn local_repository_transport_blocks_configured_remote_helpers() {
        let t = Temp::new();
        let source = Git::init(&t.0.join("source.git")).unwrap();
        let destination = Git::init(&t.0.join("destination.git")).unwrap();
        assert!(destination
            .run_local_repository(&["ls-remote", "--refs"], &source.repo, &[])
            .unwrap()
            .is_empty());
        let argument = wipstash_platform::git_path::argument(&source.repo).unwrap();
        // A harmless helper string requires no network even if this guard were
        // broken; the assertion proves Git rejects its transport before launch.
        destination
            .run(&["config", "protocol.ext.allow", "always"], None)
            .unwrap();
        destination
            .run(
                &[
                    "config",
                    "url.ext::git --version.insteadOf",
                    argument.to_str().unwrap(),
                ],
                None,
            )
            .unwrap();
        let failure = destination
            .run_local_repository(&["ls-remote", "--refs"], &source.repo, &[])
            .unwrap_err();
        assert!(failure.contains("transport 'ext' not allowed"), "{failure}");
        assert!(destination
            .run_local_repository(&["ls-remote"], Path::new("ssh://example.invalid/repo"), &[])
            .unwrap_err()
            .starts_with("local_repository_path:"));
    }

    #[test]
    fn exact_roundtrip_and_exclusions() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        let dst = t.0.join("dst");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        let bytes = b"\0binary\r\n<<<<<<< literal\n\xff";
        fs::write(src.join("a.bin"), bytes).unwrap();
        fs::write(src.join(".env"), b"SECRET").unwrap();
        fs::write(src.join("device.wipstash-invite"), b"SYNTHETIC INVITE").unwrap();
        fs::create_dir(src.join("node_modules")).unwrap();
        fs::write(src.join("node_modules/x"), b"cache").unwrap();
        let tree = g.capture(&src).unwrap();
        g.materialize(&tree, &dst).unwrap();
        assert_eq!(fs::read(dst.join("a.bin")).unwrap(), bytes);
        assert!(!dst.join(".env").exists());
        assert!(!dst.join("device.wipstash-invite").exists());
        assert!(!dst.join("node_modules").exists());
        assert!(g.materialize(&tree, &dst).is_err());
    }
    #[test]
    fn rejects_collision_and_portable_escapes() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("A"), b"a").unwrap();
        fs::write(src.join("a"), b"b").unwrap();
        assert!(g.capture(&src).unwrap_err().contains("collision"));
        for name in ["../x", "a/../x", "a\\b", "CON", "x.", "/abs", "a//b"] {
            assert!(validate_path(name).is_err(), "{name}");
        }
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_and_preserves_exec() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        let dst = t.0.join("dst");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::write(src.join("run"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(src.join("run"), fs::Permissions::from_mode(0o755)).unwrap();
        let tree = g.capture(&src).unwrap();
        g.materialize(&tree, &dst).unwrap();
        assert_ne!(
            fs::metadata(dst.join("run")).unwrap().permissions().mode() & 0o111,
            0
        );
        symlink("run", src.join("link")).unwrap();
        assert!(g.capture(&src).unwrap_err().contains("symlink"));
    }
    #[test]
    fn merge_uses_status_not_marker_text() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a"), b"base\n").unwrap();
        let base = g.commit(&g.capture(&src).unwrap(), &[], "base").unwrap();
        fs::write(src.join("a"), b"<<<<<<< literal\n").unwrap();
        let left = g
            .commit(
                &g.capture(&src).unwrap(),
                std::slice::from_ref(&base),
                "left",
            )
            .unwrap();
        fs::write(src.join("a"), b"base\n").unwrap();
        fs::write(src.join("b"), b"right\n").unwrap();
        let right = g
            .commit(
                &g.capture(&src).unwrap(),
                std::slice::from_ref(&base),
                "right",
            )
            .unwrap();
        assert!(g.merge(&left, &right).unwrap().clean);
        fs::write(src.join("a"), b"other\n").unwrap();
        let other = g
            .commit(&g.capture(&src).unwrap(), &[base], "other")
            .unwrap();
        assert!(!g.merge(&left, &other).unwrap().clean);
    }
    #[test]
    fn refuses_unsafe_tree_before_writing() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let dst = t.0.join("dst");
        fs::create_dir(&dst).unwrap();
        let blob = oid(g
            .run(&["hash-object", "-w", "--stdin"], Some(b"outside"))
            .unwrap())
        .unwrap();
        let tree = oid(g
            .run(
                &["mktree"],
                Some(format!("120000 blob {blob}\tlink\n").as_bytes()),
            )
            .unwrap())
        .unwrap();
        assert!(g
            .materialize(&tree, &dst)
            .unwrap_err()
            .contains("unsupported_tree"));
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
        let tree = oid(g
            .run(
                &["mktree"],
                Some(format!("100644 blob {blob}\t.env\n").as_bytes()),
            )
            .unwrap())
        .unwrap();
        assert!(g.materialize(&tree, &dst).unwrap_err().contains("excluded"));
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
    }
    #[test]
    fn attributes_do_not_transform_capture() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        let dst = t.0.join("dst");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::write(src.join(".gitattributes"), b"* text eol=lf\n").unwrap();
        fs::write(src.join("crlf"), b"line\r\n").unwrap();
        let tree = g.capture(&src).unwrap();
        g.materialize(&tree, &dst).unwrap();
        assert_eq!(fs::read(dst.join("crlf")).unwrap(), b"line\r\n");
    }

    #[test]
    fn honors_nested_gitignore_and_negation() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        let dst = t.0.join("dst");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::write(src.join(".gitignore"), b"local/\n*.log\n!keep.log\n").unwrap();
        fs::create_dir(src.join("local")).unwrap();
        fs::write(src.join("local/private"), b"secret").unwrap();
        fs::write(src.join("drop.log"), b"ignored").unwrap();
        fs::write(src.join("keep.log"), b"kept").unwrap();
        fs::create_dir(src.join("nested")).unwrap();
        fs::write(src.join("nested/.gitignore"), b"hidden\n").unwrap();
        fs::write(src.join("nested/hidden"), b"ignored").unwrap();
        fs::write(src.join("nested/visible"), b"kept").unwrap();
        let tree = g.capture(&src).unwrap();
        g.materialize(&tree, &dst).unwrap();
        assert!(!dst.join("local").exists());
        assert!(!dst.join("drop.log").exists());
        assert!(dst.join("keep.log").exists());
        assert!(!dst.join("nested/hidden").exists());
        assert!(dst.join("nested/visible").exists());
        assert!(dst.join(".gitignore").exists());
        assert!(dst.join("nested/.gitignore").exists());
        fs::remove_file(src.join(".gitignore")).unwrap();
        assert!(g.capture(&src).unwrap() != tree);
    }
    #[test]
    fn capacity_preflight_is_checked_and_non_destructive() {
        assert!(check_capacity(100, 99)
            .unwrap_err()
            .contains("insufficient_storage"));
        assert!(check_capacity(100, 100).is_ok());
        assert_eq!(required_space(123, 2).unwrap(), 123 + 16384 + 1048576);
        assert!(required_space(u64::MAX, 1).is_err());
        assert!(required_space(0, u64::MAX).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_ancestors_for_capture_and_materialization() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        fs::create_dir(t.0.join("real")).unwrap();
        fs::create_dir(t.0.join("real/src")).unwrap();
        fs::create_dir(t.0.join("real/dst")).unwrap();
        fs::write(t.0.join("real/src/file"), b"kept").unwrap();
        symlink(t.0.join("real"), t.0.join("alias")).unwrap();
        let tree = g.capture(&t.0.join("real/src")).unwrap();
        assert!(g
            .capture(&t.0.join("alias/src"))
            .unwrap_err()
            .contains("directory component"));
        assert!(g
            .materialize(&tree, &t.0.join("alias/dst"))
            .unwrap_err()
            .contains("directory component"));
        assert_eq!(fs::read_dir(t.0.join("real/dst")).unwrap().count(), 0);
    }

    #[test]
    fn corrupted_blob_fails_before_any_materialization() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        let dst = t.0.join("dst");
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::write(src.join("a-good"), b"good").unwrap();
        fs::write(src.join("z-broken"), b"original").unwrap();
        let tree = g.capture(&src).unwrap();
        let original = oid(g
            .run(&["hash-object", "--stdin"], Some(b"original"))
            .unwrap())
        .unwrap();
        let replacement = oid(g
            .run(&["hash-object", "-w", "--stdin"], Some(b"replacement"))
            .unwrap())
        .unwrap();
        let object_path = |id: &str| g.repo.join("objects").join(&id[..2]).join(&id[2..]);
        // A valid compressed Git object stored under the wrong id defeats mere
        // decompression checks; materialization must verify the content hash.
        fs::remove_file(object_path(&original)).unwrap();
        fs::copy(object_path(&replacement), object_path(&original)).unwrap();
        assert!(g
            .materialize(&tree, &dst)
            .unwrap_err()
            .contains("storage_corruption"));
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
        fs::remove_file(object_path(&original)).unwrap();
        assert!(g.materialize(&tree, &dst).is_err());
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
    }
    #[test]
    fn corrupted_subtree_fails_before_any_materialization() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        let dst = t.0.join("dst");
        fs::create_dir_all(src.join("nested")).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::write(src.join("nested/file"), b"original").unwrap();
        let tree = g.capture(&src).unwrap();
        let subtree = g.head(&format!("{tree}:nested")).unwrap();
        let empty = g.empty_tree().unwrap();
        let object_path = |id: &str| g.repo.join("objects").join(&id[..2]).join(&id[2..]);
        fs::remove_file(object_path(&subtree)).unwrap();
        fs::copy(object_path(&empty), object_path(&subtree)).unwrap();
        assert!(g
            .materialize(&tree, &dst)
            .unwrap_err()
            .contains("storage_corruption"));
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
    }
    #[test]
    fn resource_bounds_reject_large_inputs_before_capture() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let src = t.0.join("src");
        fs::create_dir(&src).unwrap();
        fs::File::create(src.join("large"))
            .unwrap()
            .set_len(MAX_BLOB_BYTES + 1)
            .unwrap();
        assert!(g.capture(&src).unwrap_err().contains("storage_limit"));
        assert!(validate_path(&vec!["nested"; 65].join("/"))
            .unwrap_err()
            .contains("storage_limit"));
        let mut size = MAX_SNAPSHOT_BYTES;
        assert!(add_snapshot_bytes(&mut size, 1)
            .unwrap_err()
            .contains("storage_limit"));
        assert!(bounded_output(&b"too long"[..], 3)
            .unwrap_err()
            .contains("storage_limit"));
    }
    #[test]
    fn oversized_blob_is_rejected_before_materialization() {
        let t = Temp::new();
        let g = Git::init(&t.0.join("repo")).unwrap();
        let dst = t.0.join("dst");
        fs::create_dir(&dst).unwrap();
        let blob = oid(g
            .run(
                &["hash-object", "-w", "--stdin"],
                Some(&vec![0; MAX_BLOB_BYTES as usize + 1]),
            )
            .unwrap())
        .unwrap();
        let tree = oid(g
            .run(
                &["mktree"],
                Some(format!("100644 blob {blob}\tlarge\n").as_bytes()),
            )
            .unwrap())
        .unwrap();
        assert!(g
            .materialize(&tree, &dst)
            .unwrap_err()
            .contains("storage_limit"));
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
    }
}
