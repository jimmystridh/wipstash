//! Durable, explicit-public-root GitHub replication. No network is used at enqueue.
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
const REPO_CONFIG: &str =
    "[core]\n\trepositoryformatversion = 0\n\tbare = true\n\tlogallrefupdates = false\n";
pub type Result<T> = std::result::Result<T, String>;
pub type Refs = BTreeMap<String, String>;
fn err<T>(r: impl Into<std::result::Result<T, rusqlite::Error>>) -> Result<T> {
    r.into().map_err(|_| "backup_storage_error".into())
}
fn ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn oid(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    pub owner: String,
    pub repository: String,
    pub namespace: String,
    pub credential_helper: String,
}
impl GithubConfig {
    pub fn validate(&self) -> Result<()> {
        if !ident(&self.owner)
            || !ident(&self.repository)
            || !ident(&self.namespace)
            || !matches!(
                self.credential_helper.as_str(),
                "osxkeychain" | "manager" | "libsecret"
            )
        {
            return Err("invalid_github_configuration".into());
        }
        Ok(())
    }
    pub fn url(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "https://github.com/{}/{}.git",
            self.owner, self.repository
        ))
    }
    pub fn prefix(&self) -> String {
        format!("refs/heads/{}/", self.namespace)
    }
}
fn git_command(repo: &Path, args: &[String], protocol: Option<&str>) -> Result<Command> {
    // The managed spool/fresh-store repository is the only execution cwd. Never
    // execute Git in an arbitrary source checkout or inherit credentials/tracing.
    if repo.join("config").exists()
        && fs::read(repo.join("config")).map_err(|_| "unsafe_spool_config")?
            != REPO_CONFIG.as_bytes()
    {
        return Err("unsafe_spool_config".into());
    }
    let mut c = Command::new("git");
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "never")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(wipstash_platform::git_path::argument(repo).map_err(|_| "unsupported_git_path")?)
        .args([
            "-c",
            if cfg!(windows) {
                "core.hooksPath=NUL"
            } else {
                "core.hooksPath=/dev/null"
            },
            "-c",
            "protocol.allow=never",
            "-c",
            "http.sslVerify=true",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.lowSpeedLimit=1",
            "-c",
            "http.lowSpeedTime=60",
            "-c",
            "credential.helper=",
            "-c",
            "credential.useHttpPath=true",
            "-c",
            "push.followTags=false",
            "-c",
            "push.recurseSubmodules=no",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // OS credential helpers need their existing vault session; no tokens are read
    // by this service. Only these session locator variables cross the boundary.
    for key in [
        "HOME",
        "USERPROFILE",
        "SystemRoot",
        "WINDIR",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        if let Some(v) = std::env::var_os(key) {
            c.env(key, v);
        }
    }
    if let Some(protocol) = protocol {
        // This allowlist also defeats per-protocol config and URL rewrites.
        c.env("GIT_ALLOW_PROTOCOL", protocol);
    }
    Ok(c)
}
fn git(repo: &Path, args: &[String]) -> Result<Vec<u8>> {
    git_transport(repo, args, None)
}
fn git_transport(repo: &Path, args: &[String], protocol: Option<&str>) -> Result<Vec<u8>> {
    let c = git_command(repo, args, protocol)?;
    let executable = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|p| p.is_absolute())
        .map(|p| p.join(if cfg!(windows) { "git.exe" } else { "git" }))
        .find(|p| p.is_file())
        .and_then(|p| fs::canonicalize(p).ok())
        .ok_or("git_executable_unavailable")?;
    let launch = wipstash_platform::Launch {
        executable,
        arguments: c.get_args().map(|s| s.to_owned()).collect(),
        directory: fs::canonicalize(repo).map_err(|_| "invalid_git_directory")?,
        environment: c
            .get_envs()
            .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
            .collect(),
        purpose: wipstash_platform::Purpose::CooperativeCommand,
    };
    bounded_git_process(
        &launch,
        std::time::Duration::from_secs(120),
        16 * 1024 * 1024,
    )
}

/// Concurrent pipe draining prevents output backpressure from bypassing the process
/// deadline. Never retain or report Git stderr (it may contain credential details).
fn bounded_git_process(
    launch: &wipstash_platform::Launch,
    timeout: std::time::Duration,
    limit: usize,
) -> Result<Vec<u8>> {
    use std::{sync::mpsc, time::Duration};
    let mut child =
        wipstash_platform::ManagedProcess::spawn_piped(launch).map_err(|_| "git_spawn_failed")?;
    let (mut stdout, mut stderr) = child.take_output().ok_or("git_stdout_unavailable")?;
    let (out_tx, out_rx) = mpsc::channel();
    let (err_tx, err_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 8192];
            let mut exceeded = false;
            loop {
                let n = stdout.read(&mut chunk).map_err(|_| "git_read_failed")?;
                if n == 0 {
                    break;
                }
                let retained = n.min(limit.saturating_sub(bytes.len()));
                bytes.extend_from_slice(&chunk[..retained]);
                exceeded |= retained < n;
            }
            if exceeded {
                Err("git_output_limit".into())
            } else {
                Ok(bytes)
            }
        })();
        let _ = out_tx.send(result);
    });
    std::thread::spawn(move || {
        let result = std::io::copy(&mut stderr, &mut std::io::sink())
            .map(|_| ())
            .map_err(|_| "git_read_failed");
        let _ = err_tx.send(result);
    });
    let outcome = child
        .finish(timeout)
        .map_err(|_| "git_process_cleanup_failed")?;
    // Detached Unix descendants are not contained. A held-open pipe must fail
    // closed rather than turn a subprocess deadline into an unbounded join.
    let output = out_rx
        .recv_timeout(Duration::from_millis(200))
        .map_err(|_| "git_output_incomplete");
    let errors = err_rx
        .recv_timeout(Duration::from_millis(200))
        .map_err(|_| "git_output_incomplete");
    match outcome.completion {
        wipstash_platform::Completion::TimedOut => Err("git_timeout".into()),
        wipstash_platform::Completion::Exited { code: Some(0) } => {
            errors??;
            output?
        }
        _ => Err("git_operation_failed".into()),
    }
}

fn strings(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}
fn init(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|_| "fresh_directory_required")?;
    git(path, &strings(&["init", "--bare", "--template="]))?;
    let mut f = fs::File::create(path.join("config")).map_err(|_| "storage_unavailable")?;
    f.write_all(REPO_CONFIG.as_bytes())
        .map_err(|_| "storage_unavailable")?;
    f.sync_all().map_err(|_| "storage_unavailable")?;
    Ok(())
}
fn parse_refs(bytes: &[u8], prefix: &str) -> Result<Refs> {
    let mut refs = Refs::new();
    for line in std::str::from_utf8(bytes)
        .map_err(|_| "invalid_refs")?
        .lines()
    {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 2
            || !oid(f[0])
            || !allowed_ref(f[1], prefix)
            || refs.insert(f[1].into(), f[0].into()).is_some()
        {
            return Err("unexpected_public_ref".into());
        }
    }
    Ok(refs)
}
fn allowed_ref(r: &str, prefix: &str) -> bool {
    r.strip_prefix(prefix).is_some_and(|s| {
        s == "integration" || s == "metadata" || s.strip_prefix("proposals/").is_some_and(ident)
    })
}
pub trait Remote {
    fn refs(&mut self, repo: &Path, prefix: &str) -> Result<Refs>;
    fn push(&mut self, repo: &Path, expected: &Refs, next: &Refs) -> Result<()>;
    fn fetch(&mut self, repo: &Path, refs: &Refs) -> Result<()>;
}
pub struct Github {
    config: GithubConfig,
}
impl Github {
    pub fn new(config: GithubConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }
    fn args(&self) -> Vec<String> {
        vec![
            "-c".into(),
            "protocol.https.allow=always".into(),
            "-c".into(),
            format!("credential.helper={}", self.config.credential_helper),
        ]
    }
}
impl Remote for Github {
    fn refs(&mut self, repo: &Path, prefix: &str) -> Result<Refs> {
        if prefix != self.config.prefix() {
            return Err("namespace_mismatch".into());
        }
        let mut a = self.args();
        a.extend(strings(&[
            "ls-remote",
            "--refs",
            &self.config.url()?,
            &format!("{prefix}*"),
        ]));
        parse_refs(&git_transport(repo, &a, Some("https"))?, prefix)
    }
    fn push(&mut self, repo: &Path, expected: &Refs, next: &Refs) -> Result<()> {
        if next.keys().any(|r| !allowed_ref(r, &self.config.prefix())) {
            return Err("unexpected_public_ref".into());
        }
        let mut a = self.args();
        a.extend(strings(&[
            "push",
            "--atomic",
            "--no-follow-tags",
            "--porcelain",
        ]));
        // Exact leases prevent the ls-remote/push race, including creation races.
        // validate_transition has already established fast-forward public history.
        for r in next.keys() {
            a.push(format!(
                "--force-with-lease={r}:{}",
                expected.get(r).map(String::as_str).unwrap_or("")
            ));
        }
        a.push(self.config.url()?);
        for (r, o) in next {
            a.push(format!("{o}:{r}"));
        }
        git_transport(repo, &a, Some("https"))?;
        Ok(())
    }
    fn fetch(&mut self, repo: &Path, refs: &Refs) -> Result<()> {
        let mut a = self.args();
        a.extend(strings(&[
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--recurse-submodules=no",
            &self.config.url()?,
        ]));
        for (r, o) in refs {
            if !allowed_ref(r, &self.config.prefix()) || !oid(o) {
                return Err("unexpected_public_ref".into());
            }
            a.push(format!("{o}:{r}"));
        }
        git_transport(repo, &a, Some("https"))?;
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Snapshot {
    pub watermark: i64,
    pub refs: Refs,
}
#[derive(Debug, Serialize)]
pub struct Status {
    pub verified_watermark: i64,
    pub pending: i64,
    pub last_error: Option<String>,
}
pub struct Outbox {
    db: Connection,
    spool: PathBuf,
    config: GithubConfig,
}
impl Outbox {
    pub fn open(directory: &Path, config: GithubConfig) -> Result<Self> {
        config.validate()?;
        fs::create_dir_all(directory).map_err(|_| "storage_unavailable")?;
        let spool = directory.join("public.git");
        if !spool.exists() {
            init(&spool)?;
        }
        let db = err(Connection::open(directory.join("outbox.sqlite")))?;
        err(db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS jobs(seq INTEGER PRIMARY KEY AUTOINCREMENT, snapshot TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS status(id INTEGER PRIMARY KEY CHECK(id=1), snapshot TEXT, error TEXT); INSERT OR IGNORE INTO status(id) VALUES(1);"))?;
        let serialized = serde_json::to_string(&config).map_err(|_| "invalid_config")?;
        err(db.execute("INSERT OR IGNORE INTO config VALUES(1,?1)", [&serialized]))?;
        let saved: String =
            err(db.query_row("SELECT value FROM config WHERE id=1", [], |r| r.get(0)))?;
        if saved != serialized {
            return Err("backup_destination_changed".into());
        }
        Ok(Self { db, spool, config })
    }
    /// Enqueue an existing sanitized local-public-backup repository. This never
    /// contacts GitHub. Source refs are copied into private spool pins before intent.
    pub fn enqueue(&mut self, source: &Path) -> Result<Snapshot> {
        let source = fs::canonicalize(source).map_err(|_| "invalid_public_source")?;
        let process_source =
            wipstash_platform::git_path::argument(&source).map_err(|_| "unsupported_git_path")?;
        let source = process_source.to_str().ok_or("invalid_public_source")?;
        let prefix = "refs/heads/wipstash/";
        let bytes = git_transport(
            &self.spool,
            &strings(&[
                "-c",
                "protocol.file.allow=always",
                "-c",
                "protocol.https.allow=never",
                "ls-remote",
                "--refs",
                "--",
                source,
                &format!("{prefix}*"),
            ]),
            Some("file"),
        )?;
        let source_refs = parse_refs(&bytes, prefix)?;
        let mut a = strings(&[
            "-c",
            "protocol.file.allow=always",
            "-c",
            "protocol.https.allow=never",
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--recurse-submodules=no",
            "--",
            source,
        ]);
        // Object-specific fetch avoids importing source config, tags or private refs.
        for o in source_refs.values() {
            a.push(o.clone());
        }
        git_transport(&self.spool, &a, Some("file"))?;
        let refs = source_refs
            .iter()
            .map(|(r, o)| (r.replacen(prefix, &self.config.prefix(), 1), o.clone()))
            .collect();
        let snapshot = verify(&self.spool, &self.config.prefix(), &refs)?;
        let previous: Option<String> = err(self
            .db
            .query_row(
                "SELECT snapshot FROM jobs ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(s) = previous {
            let p: Snapshot = serde_json::from_str(&s).map_err(|_| "corrupt_outbox")?;
            validate_transition(&self.spool, &p, &snapshot, &self.config.prefix())?;
            if p.refs == snapshot.refs {
                return Ok(snapshot);
            }
        }
        for o in snapshot.refs.values() {
            git(
                &self.spool,
                &strings(&["update-ref", &format!("refs/wipstash/outbox/{o}"), o]),
            )?;
        }
        err(self.db.execute(
            "INSERT INTO jobs(snapshot) VALUES(?1)",
            [serde_json::to_string(&snapshot).map_err(|_| "invalid_snapshot")?],
        ))?;
        Ok(snapshot)
    }
    pub fn status(&self) -> Result<Status> {
        let (s, e): (Option<String>, Option<String>) =
            err(self
                .db
                .query_row("SELECT snapshot,error FROM status WHERE id=1", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                }))?;
        let pending = err(self
            .db
            .query_row("SELECT count(*) FROM jobs WHERE done=0", [], |r| r.get(0)))?;
        Ok(Status {
            verified_watermark: s
                .map(|s| serde_json::from_str::<Snapshot>(&s).map(|s| s.watermark))
                .transpose()
                .map_err(|_| "corrupt_outbox")?
                .unwrap_or(0),
            pending,
            last_error: e,
        })
    }
    /// One bounded worker iteration. Retry after restart; only a fresh fetch and
    /// exact ref verification advance the watermark. Coordinator never waits here.
    pub fn drain_one(&mut self, remote: &mut impl Remote) -> Result<bool> {
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.spool.parent().unwrap().join("worker.lock"))
            .map_err(|_| "worker_lock_failed")?;
        lock.try_lock_exclusive()
            .map_err(|_| "worker_already_running")?;
        let result = self.drain_inner(remote);
        let result = match &result {
            Err(e) => err(self
                .db
                .execute("UPDATE status SET error=?1 WHERE id=1", [e]))
            .and(result),
            Ok(_) => result,
        };
        // Explicit release covers a failed verification followed immediately by retry.
        // Do not leave a shared advisory lock held through inherited file descriptions.
        FileExt::unlock(&lock).map_err(|_| "worker_unlock_failed")?;
        result
    }
    fn drain_inner(&mut self, remote: &mut impl Remote) -> Result<bool> {
        let job: Option<(i64, String)> = err(self
            .db
            .query_row(
                "SELECT seq,snapshot FROM jobs WHERE done=0 ORDER BY seq LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        let Some((seq, s)) = job else {
            return Ok(false);
        };
        let next: Snapshot = serde_json::from_str(&s).map_err(|_| "corrupt_outbox")?;
        let previous: Option<String> =
            err(self
                .db
                .query_row("SELECT snapshot FROM status WHERE id=1", [], |r| r.get(0)))?;
        let expected = previous
            .map(|p| serde_json::from_str::<Snapshot>(&p).map(|p| p.refs))
            .transpose()
            .map_err(|_| "corrupt_outbox")?
            .unwrap_or_default();
        let actual = remote.refs(&self.spool, &self.config.prefix())?;
        if actual != next.refs {
            if actual != expected {
                return Err("remote_diverged".into());
            }
            remote.push(&self.spool, &expected, &next.refs)?;
        }
        let fresh = self
            .spool
            .parent()
            .unwrap()
            .join(format!("verification-{seq}"));
        // An interrupted verification directory is retained for diagnosis. Use a
        // distinct generation rather than deleting user data or trusting old objects.
        let mut n = 0;
        let path = loop {
            let p = fresh.with_extension(format!("{n}.git"));
            if !p.exists() {
                break p;
            }
            n += 1;
        };
        init(&path)?;
        remote.fetch(&path, &next.refs)?;
        let verified = verify(&path, &self.config.prefix(), &next.refs)?;
        if verified.watermark != next.watermark
            || remote.refs(&path, &self.config.prefix())? != next.refs
        {
            return Err("remote_verification_failed".into());
        }
        let tx = err(self.db.transaction())?;
        err(tx.execute("UPDATE jobs SET done=1 WHERE seq=?1", [seq]))?;
        err(tx.execute("UPDATE status SET snapshot=?1,error=NULL WHERE id=1", [s]))?;
        err(tx.commit())?;
        Ok(true)
    }
}
fn ancestor(repo: &Path, a: &str, b: &str) -> bool {
    git(repo, &strings(&["merge-base", "--is-ancestor", a, b])).is_ok()
}
fn validate_transition(repo: &Path, old: &Snapshot, new: &Snapshot, prefix: &str) -> Result<()> {
    if new.watermark < old.watermark {
        return Err("watermark_regressed".into());
    }
    for (r, o) in &old.refs {
        let n = new.refs.get(r).ok_or("retained_ref_missing")?;
        if r.contains("/proposals/") {
            if o != n {
                return Err("proposal_changed".into());
            }
        } else if !ancestor(repo, o, n) {
            return Err("public_history_diverged".into());
        }
    }
    if new.refs.keys().any(|r| !allowed_ref(r, prefix)) {
        return Err("unexpected_public_ref".into());
    }
    Ok(())
}
/// Verify object connectivity, sanitized schema and pair binding in a fresh store.
pub fn verify(repo: &Path, prefix: &str, refs: &Refs) -> Result<Snapshot> {
    let snapshot = verify_one(repo, prefix, refs)?;
    let meta = refs
        .get(&format!("{prefix}metadata"))
        .ok_or("missing_metadata")?;
    let lineage = String::from_utf8(git(repo, &strings(&["rev-list", meta]))?)
        .map_err(|_| "invalid_metadata_lineage")?;
    for ancestor_meta in lineage.lines().filter(|o| *o != meta) {
        let bytes = git(
            repo,
            &strings(&["show", &format!("{ancestor_meta}:metadata.json")]),
        )?;
        let m: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_metadata_lineage")?;
        let proposals: Refs = serde_json::from_value(m["proposals"].clone())
            .map_err(|_| "invalid_metadata_lineage")?;
        let mut old: Refs = proposals
            .iter()
            .map(|(id, o)| (format!("{prefix}proposals/{id}"), o.clone()))
            .collect();
        old.insert(format!("{prefix}metadata"), ancestor_meta.into());
        old.insert(
            format!("{prefix}integration"),
            m["integration"]
                .as_str()
                .ok_or("invalid_metadata_lineage")?
                .into(),
        );
        verify_one(repo, prefix, &old)?;
    }
    Ok(snapshot)
}
fn verify_one(repo: &Path, prefix: &str, refs: &Refs) -> Result<Snapshot> {
    if refs.keys().any(|r| !allowed_ref(r, prefix)) {
        return Err("unexpected_public_ref".into());
    }
    let root = refs
        .get(&format!("{prefix}integration"))
        .ok_or("missing_integration")?;
    let meta = refs
        .get(&format!("{prefix}metadata"))
        .ok_or("missing_metadata")?;
    for o in refs.values() {
        if !oid(o) {
            return Err("invalid_oid".into());
        }
        git(
            repo,
            &strings(&["cat-file", "-e", &format!("{o}^{{commit}}")]),
        )?;
    }
    git(repo, &strings(&["fsck", "--strict", "--no-reflogs"]))?;
    if git(repo, &strings(&["ls-tree", "--name-only", "-z", meta]))? != b"metadata.json\0" {
        return Err("private_metadata_tree_entry".into());
    }
    let bytes = git(repo, &strings(&["show", &format!("{meta}:metadata.json")]))?;
    let m: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_manifest")?;
    let keys = m.as_object().ok_or("invalid_manifest")?;
    if keys.keys().any(|k| {
        !matches!(
            k.as_str(),
            "format"
                | "watermark"
                | "integration"
                | "proposals"
                | "proposal_metadata"
                | "events"
                | "recovery"
        )
    }) || !matches!(
        m["format"].as_str(),
        Some("wipstash-public-metadata-v1" | "wipstash-public-metadata-v2")
    ) || m["integration"] != *root
    {
        return Err("invalid_manifest".into());
    }
    if m["format"] == "wipstash-public-metadata-v1" && m.get("recovery").is_some() {
        return Err("invalid_v1_recovery".into());
    }
    if m["format"] == "wipstash-public-metadata-v2" {
        validate_recovery(&m["recovery"])?;
    }
    let watermark = m["watermark"]
        .as_i64()
        .filter(|n| *n >= 0)
        .ok_or("invalid_watermark")?;
    let proposals: Refs =
        serde_json::from_value(m["proposals"].clone()).map_err(|_| "invalid_proposals")?;
    for object in validate_recovery_links(&m, &proposals)? {
        if !proposals.values().any(|o| o == &object) && !ancestor(repo, &object, root) {
            return Err("nonpublic_recovery_object".into());
        }
    }
    let expected: Refs = proposals
        .iter()
        .map(|(id, o)| (format!("{prefix}proposals/{id}"), o.clone()))
        .chain([
            (format!("{prefix}integration"), root.clone()),
            (format!("{prefix}metadata"), meta.clone()),
        ])
        .collect();
    if &expected != refs {
        return Err("proposal_pair_mismatch".into());
    }
    let mut previous = 0;
    let mut terminal = BTreeMap::new();
    for e in m["events"].as_array().ok_or("invalid_events")? {
        if e.as_object()
            .ok_or("invalid_event")?
            .keys()
            .any(|k| !matches!(k.as_str(), "seq" | "kind" | "proposal" | "commit" | "head"))
        {
            return Err("private_event_field".into());
        }
        previous = e["seq"]
            .as_i64()
            .filter(|n| *n > previous && *n <= watermark)
            .ok_or("invalid_event_order")?;
        let id = e
            .get("proposal")
            .map(|v| v.as_str().filter(|s| ident(s)).ok_or("invalid_proposal"))
            .transpose()?;
        let kind = e["kind"].as_str().ok_or("invalid_event")?;
        match kind {
            "published" => {
                let id = id.ok_or("missing_proposal")?;
                if proposals.get(id).map(String::as_str) != e["commit"].as_str()
                    || terminal.contains_key(id)
                {
                    return Err("invalid_published_event".into());
                }
            }
            "integrated" | "already_included" => {
                let head = e["head"]
                    .as_str()
                    .filter(|s| oid(s))
                    .ok_or("invalid_head")?;
                if !ancestor(repo, head, root) {
                    return Err("nonpublic_head".into());
                }
                if let Some(id) = id {
                    if terminal.insert(id, kind).is_some() {
                        return Err("duplicate_terminal".into());
                    }
                }
            }
            "cancelled" | "superseded" => {
                if terminal
                    .insert(id.ok_or("missing_proposal")?, kind)
                    .is_some()
                {
                    return Err("duplicate_terminal".into());
                }
            }
            _ => return Err("invalid_event_kind".into()),
        }
    }
    let mut orders = std::collections::BTreeSet::new();
    for (id, p) in m["proposal_metadata"]
        .as_object()
        .ok_or("missing_proposal_metadata")?
    {
        validate_provenance(p)?;
        if !proposals.contains_key(id)
            || p.as_object()
                .ok_or("invalid_proposal_metadata")?
                .keys()
                .any(|k| {
                    !matches!(
                        k.as_str(),
                        "state"
                            | "base"
                            | "head"
                            | "queue_order"
                            | "intent"
                            | "ownership"
                            | "evidence"
                            | "repaired"
                            | "policy_sha256"
                            | "original_state"
                            | "resolution"
                    )
                })
        {
            return Err("invalid_proposal_metadata".into());
        }
        if p.get("intent")
            .is_some_and(|v| !v.as_str().is_some_and(|s| s.len() <= 4096))
        {
            return Err("invalid_intent".into());
        }
        let state = p["state"].as_str().ok_or("invalid_state")?;
        if !matches!(
            state,
            "coordinator_accepted"
                | "local_queued"
                | "quarantined"
                | "recovery_quarantined"
                | "integrated"
                | "already_included"
                | "cancelled"
            | "superseded"
        ) || terminal.get(id.as_str()).is_some_and(|s| *s != state)
            || (matches!(state, "integrated" | "already_included" | "cancelled"
            | "superseded")
                && !terminal.contains_key(id.as_str()))
        {
            return Err("invalid_state".into());
        }
        if !p["queue_order"]
            .as_i64()
            .is_some_and(|n| n > 0 && orders.insert(n))
        {
            return Err("invalid_queue_order".into());
        }
        for key in ["base", "head"] {
            if !p[key].is_null() {
                let o = p[key]
                    .as_str()
                    .filter(|s| oid(s))
                    .ok_or("invalid_queue_oid")?;
                if !ancestor(repo, o, root) {
                    return Err("nonpublic_queue_oid".into());
                }
            }
        }
    }
    Ok(Snapshot {
        watermark,
        refs: refs.clone(),
    })
}
/// Restore to an absent directory; unresolved public proposals stay quarantined.
/// Executable policy, private identities and device credentials are never restored.
pub fn restore(
    remote: &mut impl Remote,
    config: &GithubConfig,
    destination: &Path,
) -> Result<Snapshot> {
    config.validate()?;
    init(destination)?;
    let refs = remote.refs(destination, &config.prefix())?;
    remote.fetch(destination, &refs)?;
    let snapshot = verify(destination, &config.prefix(), &refs)?;
    if remote.refs(destination, &config.prefix())? != refs {
        return Err("remote_changed_during_restore".into());
    }
    Ok(snapshot)
}

fn validate_recovery(v: &Value) -> Result<()> {
    fn keys(v: &Value, names: &[&str]) -> Result<()> {
        if v.as_object()
            .is_none_or(|o| o.keys().any(|k| !names.contains(&k.as_str())))
        {
            return Err("invalid_public_recovery_fields".into());
        }
        Ok(())
    }
    fn id(v: &Value) -> bool {
        v.as_str().is_some_and(ident)
    }
    fn hash(v: &Value) -> bool {
        v.as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    }
    fn positive(v: &Value) -> bool {
        v.as_i64().is_some_and(|n| n > 0)
    }
fn task(t: &Value) -> Result<()> {
    keys(t, &["proposal","workspace","state","reason","base","proposal_commit","current_head","conflict_paths","checks","policy_sha256","attempt","max_attempts","lineage","next_action","semantic_correctness_claimed"])?;
    if !id(&t["proposal"]) { return Err("invalid_resolution_proposal".into()); }
    if !t["workspace"].is_null() || !matches!(t["state"].as_str(),Some("action_required"|"escalated")) || !matches!(t["reason"].as_str(),Some("merge_conflict"|"required_checks_failed"|"policy_evaluation_failed")) || t["semantic_correctness_claimed"] != false || t["max_attempts"] != 3 || !t["attempt"].as_u64().is_some_and(|n| n<=3) { return Err("invalid_resolution_task".into()); }
    for key in ["base","proposal_commit","current_head"] {
        if !t[key].as_str().is_some_and(oid) { return Err("invalid_resolution_task_oid".into()); }
    }
    if !t["policy_sha256"].as_str().is_some_and(|s|s.len()==64 && s.bytes().all(|b|b.is_ascii_hexdigit())) || !t["next_action"].as_str().is_some_and(|s|s.len()<=1024) {return Err("invalid_resolution_task".into());}
    let paths=t["conflict_paths"].as_array().ok_or("invalid_resolution_paths")?;
    if paths.len()>10000 { return Err("invalid_resolution_paths".into()); }
    let mut seen=std::collections::HashSet::new();
    for p in paths {let p=p.as_str().ok_or("invalid_resolution_paths")?; if p.len()>4096 || !seen.insert(p) {return Err("invalid_resolution_paths".into());} if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.chars().any(char::is_control) || p.split('/').any(|s| s.is_empty() || matches!(s,"."|"..")) {return Err("invalid_resolution_paths".into());}}
    keys(&t["lineage"], &["parent","root","attempt"])?;
    if !id(&t["lineage"]["root"]) { return Err("invalid_resolution_root".into()); }
    if !t["lineage"]["parent"].is_null() {if !id(&t["lineage"]["parent"]) { return Err("invalid_resolution_parent".into()); }}
    if t["lineage"]["attempt"]!=t["attempt"] {return Err("invalid_resolution_lineage".into());}
    let checks=t["checks"].as_array().ok_or("invalid_resolution_checks")?;
    if checks.len()>64 {return Err("invalid_resolution_checks".into());}
    for c in checks {
        keys(c, &["id_sha256","required","success","exit_code","timed_out","checkout_unchanged","stdout_prefix_sha256","stderr_prefix_sha256","stdout_bytes","stderr_bytes","output_truncated","output_collection_complete","execution_is_os_sandboxed"])?;
        for (key,v) in c.as_object().ok_or("invalid_resolution_checks")? {
            let valid = match key.as_str() {
                "id_sha256"|"stdout_prefix_sha256"|"stderr_prefix_sha256" => v.as_str().is_some_and(|s|s.len()==64 && s.bytes().all(|b|b.is_ascii_hexdigit())),
                "candidate_tree" => v.as_str().is_some_and(oid),
                "stdout_bytes"|"stderr_bytes" => v.as_u64().is_some(),
                "exit_code" => v.is_null() || v.as_i64().is_some_and(|n|i32::try_from(n).is_ok()),
                _ => v.is_boolean(),
            };
            if !valid {return Err("invalid_resolution_checks".into());}
        }
    }
    if serde_json::to_vec(t).map_err(|e|e.to_string())?.len()>8192 {return Err("resolution_task_too_large".into());}
    Ok(())
}
    fn receipt(v: &Value) -> Result<()> {
        keys(
            v,
            &[
                "recipient",
                "authority_proposal",
                "revision",
                "state",
                "integration_head",
                "evidence",
                "repaired",
                "resolution_task",
            ],
        )?;
        if !id(&v["recipient"])
            || !id(&v["authority_proposal"])
            || !positive(&v["revision"])
            || !matches!(
                v["state"].as_str(),
                Some(
                    "coordinator_accepted"
                        | "quarantined"
                        | "integrated"
                        | "already_included"
                        | "cancelled"
            | "superseded"
                )
            )
            || (matches!(v["state"].as_str(), Some("integrated" | "already_included"))
                != v["integration_head"].is_string())
            || !v["evidence"].as_str().is_some_and(|s| {
                matches!(
                    s,
                    "unchecked" | "checks_executed" | "agent_resolved_unchecked"
                )
            })
            || !v["repaired"].is_boolean()
            || (!v["integration_head"].is_null()
                && !v["integration_head"].as_str().is_some_and(oid))
        {
            return Err("invalid_public_receipt".into());
        }
        if let Some(t) = v.get("resolution_task").filter(|t| !t.is_null()) {
            if v["state"] != "quarantined" { return Err("invalid_resolution_task_state".into()); }
            task(t)?;
        }
        Ok(())
    }
    keys(
        v,
        &[
            "version",
            "activation_required",
            "policy_sha256",
            "policy_required",
            "sync_binding",
            "origins",
            "imports",
            "exports",
            "observations",
            "repair_budgets",
            "operations",
            "replay",
        ],
    )?;
    if v["version"] != 2
        || v["activation_required"] != true
        || !hash(&v["policy_sha256"])
        || !v["policy_required"].is_boolean()
    {
        return Err("invalid_public_recovery_gate".into());
    }
    let b = &v["sync_binding"];
    if !b.is_null() {
        keys(
            b,
            &["project", "authority", "epoch", "device", "role", "peers"],
        )?;
        if !["project", "authority", "device"]
            .iter()
            .all(|k| id(&b[*k]))
            || !positive(&b["epoch"])
            || !matches!(b["role"].as_str(), Some("client" | "authority"))
            || b["peers"]
                .as_array()
                .is_none_or(|a| a.is_empty() || a.len() > 100 || !a.iter().all(id))
        {
            return Err("invalid_public_binding".into());
        }
    }
    if let Some(replay) = v.get("replay").filter(|v| !v.is_null()) {
        keys(replay, &["binding", "events"])?;
        let b = &replay["binding"];
        keys(b, &["project", "authority", "epoch", "cursor", "head"])?;
        if !id(&b["project"])
            || !id(&b["authority"])
            || !positive(&b["epoch"])
            || b["cursor"].as_i64().is_none_or(|n| n < 0)
            || (!b["head"].is_null() && !b["head"].as_str().is_some_and(oid))
        {
            return Err("invalid_public_replay_binding".into());
        }
        if v["sync_binding"].is_null()
            || !["project", "authority", "epoch"]
                .iter()
                .all(|k| b[*k] == v["sync_binding"][*k])
        {
            return Err("invalid_public_replay_authority".into());
        }
        let mut seq = 0;
        let mut head = Value::Null;
        let mut operations = std::collections::BTreeSet::new();
        for r in replay["events"]
            .as_array()
            .ok_or("invalid_public_replay_events")?
        {
            keys(r, &["sequence", "operation", "digest", "envelope"])?;
            if !positive(&r["sequence"])
                || r["sequence"].as_i64() != Some(seq + 1)
                || !id(&r["operation"])
                || !operations.insert(r["operation"].as_str().unwrap())
                || !hash(&r["digest"])
            {
                return Err("invalid_public_replay_order".into());
            }
            let e = &r["envelope"];
            keys(
                e,
                &[
                    "version",
                    "project",
                    "authority",
                    "epoch",
                    "device",
                    "sequence",
                    "operation",
                    "event",
                ],
            )?;
            if e["version"] != 1
                || e["sequence"] != r["sequence"]
                || e["operation"] != r["operation"]
                || !id(&e["device"])
                || !["project", "authority", "epoch"]
                    .iter()
                    .all(|k| b[*k] == e[*k])
            {
                return Err("invalid_public_replay_envelope".into());
            }
            keys(&e["event"], &["kind", "head"])?;
            if e["event"]["kind"] != "head_advanced"
                || !e["event"]["head"].as_str().is_some_and(oid)
            {
                return Err("invalid_public_replay_event".into());
            }
            seq += 1;
            head = e["event"]["head"].clone();
        }
        if b["cursor"] != seq || b["head"] != head {
            return Err("invalid_public_replay_cursor".into());
        }
    }
    for name in [
        "origins",
        "imports",
        "exports",
        "observations",
        "repair_budgets",
        "operations",
    ] {
        for r in v[name]
            .as_array()
            .ok_or("invalid_public_recovery_records")?
        {
            match name {
                "operations" => {
                    keys(r, &["id", "digest", "result"])?;
                    if !id(&r["id"]) || !hash(&r["digest"]) {
                        return Err("invalid_public_operation".into());
                    }
                    let s = &r["result"];
                    keys(
                        s,
                        &[
                            "ok",
                            "state",
                            "proposal",
                            "commit",
                            "base",
                            "durability",
                            "replication",
                        ],
                    )?;
                    if s["ok"] != true
                        || !id(&s["proposal"])
                        || !s["state"]
                            .as_str()
                            .is_some_and(|s| public_state(s) || s == "queued_offline")
                    {
                        return Err("invalid_public_operation_result".into());
                    }
                    for k in ["commit", "base"] {
                        if s.get(k).is_some_and(|v| !v.as_str().is_some_and(oid)) {
                            return Err("invalid_public_operation_oid".into());
                        }
                    }
                    if s.get("durability").is_some_and(|v| {
                        !matches!(v.as_str(), Some("coordinator_saved" | "local_saved"))
                    }) || s.get("replication").is_some_and(|v| v != "not_configured")
                    {
                        return Err("invalid_public_operation_evidence".into());
                    }
                }
                "origins" => {
                    keys(r, &["proposal", "device", "source_proposal"])?;
                    if !["proposal", "device", "source_proposal"]
                        .iter()
                        .all(|k| id(&r[*k]))
                    {
                        return Err("invalid_public_origin".into());
                    }
                }
                "imports" => {
                    keys(r, &["device", "operation", "digest", "result"])?;
                    if !id(&r["device"]) || !id(&r["operation"]) || !hash(&r["digest"]) {
                        return Err("invalid_public_import".into());
                    }
                    let s = &r["result"];
                    keys(
                        s,
                        &[
                            "ok",
                            "state",
                            "proposal",
                            "source_proposal",
                            "head",
                            "duplicate",
                            "authenticated",
                            "sequence",
                            "files_changed",
                            "remote_observation",
                        ],
                    )?;
                    if s["ok"] != true
                        || s["authenticated"] != false
                        || !s["state"].as_str().is_some_and(|s| {
                            public_state(s) || matches!(s, "cached" | "receipt_recorded")
                        })
                    {
                        return Err("invalid_public_result".into());
                    }
                    for k in ["proposal", "source_proposal"] {
                        if s.get(k).is_some_and(|v| !id(v)) {
                            return Err("invalid_public_result_id".into());
                        }
                    }
                    if s.get("head").is_some_and(|v| !v.as_str().is_some_and(oid)) {
                        return Err("invalid_public_result_head".into());
                    }
                    for k in ["duplicate", "files_changed"] {
                        if s.get(k).is_some_and(|v| !v.is_boolean()) {
                            return Err("invalid_public_result_bool".into());
                        }
                    }
                    if s.get("sequence").is_some_and(|v| !positive(v)) {
                        return Err("invalid_public_result_sequence".into());
                    }
                    if let Some(o) = s.get("remote_observation") {
                        receipt(o)?;
                    }
                }
                "observations" => {
                    keys(r, &["proposal", "revision", "digest", "receipt"])?;
                    if !id(&r["proposal"])
                        || !positive(&r["revision"])
                        || !hash(&r["digest"])
                        || r["revision"] != r["receipt"]["revision"]
                    {
                        return Err("invalid_public_observation".into());
                    }
                    receipt(&r["receipt"])?;
                }
                "repair_budgets" => {
                    keys(r, &["proposal", "attempts", "seconds"])?;
                    if !r["proposal"].as_str().is_some_and(oid)
                        || !["attempts", "seconds"]
                            .iter()
                            .all(|k| r[*k].as_i64().is_some_and(|n| n >= 0))
                    {
                        return Err("invalid_public_budget".into());
                    }
                }
                "exports" => {
                    keys(r, &["operation", "request_digest", "manifest"])?;
                    if !id(&r["operation"]) || !hash(&r["request_digest"]) {
                        return Err("invalid_public_export".into());
                    }
                    let m = &r["manifest"];
                    keys(
                        m,
                        &[
                            "version",
                            "project",
                            "authority",
                            "epoch",
                            "device",
                            "operation",
                            "kind",
                            "head",
                            "base",
                            "proposal",
                            "intent",
                            "envelope",
                            "receipt",
                            "resolution",
                            "payload_len",
                            "payload_sha256",
                        ],
                    )?;
                    if m["version"] != 1
                        || m["operation"] != r["operation"]
                        || !["project", "authority", "device", "operation"]
                            .iter()
                            .all(|k| id(&m[*k]))
                        || !positive(&m["epoch"])
                        || !matches!(m["kind"].as_str(), Some("head" | "proposal" | "receipt"))
                        || !m["head"].as_str().is_some_and(oid)
                        || !hash(&m["payload_sha256"])
                        || m["payload_len"].as_u64().is_none()
                    {
                        return Err("invalid_public_manifest".into());
                    }
                    if !m["base"].is_null() && !m["base"].as_str().is_some_and(oid)
                        || !m["proposal"].is_null() && !id(&m["proposal"])
                        || !m["intent"].is_null()
                            && !m["intent"].as_str().is_some_and(|s| s.len() <= 4096)
                    {
                        return Err("invalid_public_manifest_proposal".into());
                    }
                    if !m["resolution"].is_null() {
                        if m["kind"] != "proposal" { return Err("invalid_public_manifest_resolution".into()); }
                        validate_provenance(&serde_json::json!({"resolution":m["resolution"]}))?;
                    }
                    let shape_ok = match m["kind"].as_str() {
                        Some("head") => {
                            m["base"].is_null()
                                && m["proposal"].is_null()
                                && m["intent"].is_null()
                                && m["receipt"].is_null()
                                && m["envelope"].is_object()
                        }
                        Some("proposal") => {
                            m["base"].is_string()
                                && id(&m["proposal"])
                                && m["intent"].is_string()
                                && m["receipt"].is_null()
                                && m["envelope"].is_null()
                        }
                        Some("receipt") => {
                            m["base"].is_string()
                                && id(&m["proposal"])
                                && m["intent"].is_null()
                                && m["envelope"].is_null()
                                && m["receipt"].is_object()
                                && (m["receipt"]["resolution_task"].is_object() || m["payload_len"] == 0)
                        }
                        _ => false,
                    };
                    if !shape_ok {
                        return Err("invalid_public_manifest_shape".into());
                    }
                    if !m["receipt"].is_null() {
                        receipt(&m["receipt"])?;
                        if let Some(task) = m["receipt"].get("resolution_task").filter(|t| !t.is_null()) {
                            if task["proposal"] != m["proposal"] || task["base"] != m["base"] || task["proposal_commit"] != m["head"] {
                                return Err("invalid_public_task_binding".into());
                            }
                        }
                    }
                    let e = &m["envelope"];
                    if !e.is_null() {
                        keys(
                            e,
                            &[
                                "version",
                                "project",
                                "authority",
                                "epoch",
                                "device",
                                "sequence",
                                "operation",
                                "event",
                            ],
                        )?;
                        if e["version"] != 1
                            || !positive(&e["sequence"])
                            || !["project", "authority", "epoch", "device", "operation"]
                                .iter()
                                .all(|k| e[*k] == m[*k])
                        {
                            return Err("invalid_public_envelope".into());
                        }
                        keys(&e["event"], &["kind", "head"])?;
                        if e["event"]["kind"] != "head_advanced" || e["event"]["head"] != m["head"]
                        {
                            return Err("invalid_public_envelope_event".into());
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}
fn public_state(state: &str) -> bool {
    matches!(
        state,
        "coordinator_accepted"
            | "local_queued"
            | "quarantined"
            | "recovery_quarantined"
            | "integrated"
            | "already_included"
            | "cancelled"
            | "superseded"
    )
}

fn validate_provenance(p: &Value) -> Result<()> {
    if let Some(r) = p.get("resolution").filter(|r| !r.is_null()) {
        if r.as_object().is_none_or(|o| o.len() != 3 || o.keys().any(|k| !matches!(k.as_str(), "parent" | "root" | "attempt")))
            || !r["parent"].as_str().is_some_and(ident)
            || !r["root"].as_str().is_some_and(ident)
            || !r["attempt"].as_u64().is_some_and(|n| (1..=3).contains(&n)) {
            return Err("invalid_public_resolution_lineage".into());
        }
    }
    if p.get("original_state")
        .is_some_and(|v| !v.as_str().is_some_and(public_state))
    {
        return Err("invalid_public_original_state".into());
    }
    if p.get("evidence").is_some_and(|v| {
        !matches!(
            v.as_str(),
            Some("unchecked" | "checks_executed" | "agent_resolved_unchecked")
        )
    }) || p.get("repaired").is_some_and(|v| !v.is_boolean())
        || p.get("policy_sha256").is_some_and(|v| {
            !v.is_null()
                && !v
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        })
    {
        return Err("invalid_public_provenance".into());
    }
    if let Some(o) = p.get("ownership") {
        if o.as_object().is_none_or(|o| {
            o.len() != 3
                || o.keys()
                    .any(|k| !matches!(k.as_str(), "kind" | "device" | "source_proposal"))
        }) || !matches!(
            o["kind"].as_str(),
            Some("local_authority" | "remote_device")
        ) || (!o["device"].is_null() && !o["device"].as_str().is_some_and(ident))
            || !o["source_proposal"].as_str().is_some_and(ident)
            || (o["kind"] == "remote_device" && o["device"].is_null())
        {
            return Err("invalid_public_ownership".into());
        }
    }
    Ok(())
}

fn validate_recovery_links(m: &Value, proposals: &BTreeMap<String, String>) -> Result<Vec<String>> {
    if m["format"] != "wipstash-public-metadata-v2" {
        return Ok(vec![]);
    }
    let v = &m["recovery"];
    let mut objects = Vec::new();
    let known = |p: &Value| p.as_str().is_some_and(|p| proposals.contains_key(p));
    for name in [
        "origins",
        "imports",
        "exports",
        "observations",
        "repair_budgets",
        "operations",
    ] {
        let mut identities = std::collections::BTreeSet::new();
        for r in v[name]
            .as_array()
            .ok_or("invalid_public_recovery_records")?
        {
            let identity = match name {
                "origins" | "observations" | "repair_budgets" => r["proposal"].to_string(),
                "operations" => r["id"].to_string(),
                "imports" => format!("{}:{}", r["device"], r["operation"]),
                "exports" => r["operation"].to_string(),
                _ => unreachable!(),
            };
            if !identities.insert(identity) {
                return Err("duplicate_public_recovery_identity".into());
            }
            match name {
                "origins" => {
                    if !known(&r["proposal"]) {
                        return Err("public_origin_without_proposal".into());
                    }
                    let owner =
                        &m["proposal_metadata"][r["proposal"].as_str().unwrap()]["ownership"];
                    if owner["device"] != r["device"]
                        || owner["source_proposal"] != r["source_proposal"]
                        || owner["kind"] != "remote_device"
                    {
                        return Err("public_origin_ownership_mismatch".into());
                    }
                }
                "operations" => {
                    let result = &r["result"];
                    if !known(&result["proposal"]) {
                        return Err("public_operation_without_proposal".into());
                    }
                    if let Some(commit) = result.get("commit") {
                        if proposals
                            .get(result["proposal"].as_str().unwrap())
                            .map(String::as_str)
                            != commit.as_str()
                        {
                            return Err("public_operation_commit_mismatch".into());
                        }
                    }
                    for k in ["commit", "base"] {
                        if let Some(o) = result[k].as_str() {
                            objects.push(o.into());
                        }
                    }
                }
                "imports" => {
                    let result = &r["result"];
                    if result.get("proposal").is_some_and(|p| !known(p)) {
                        return Err("public_import_without_proposal".into());
                    }
                    if let Some(o) = result["head"].as_str() {
                        objects.push(o.into());
                    }
                    if let Some(o) = result["remote_observation"]["integration_head"].as_str() {
                        objects.push(o.into());
                    }
                    for key in ["proposal_commit", "current_head"] {
                        if let Some(o) = result["remote_observation"]["resolution_task"][key].as_str() { objects.push(o.into()); }
                    }
                }
                "observations" => {
                    if !known(&r["proposal"]) {
                        return Err("public_observation_without_proposal".into());
                    }
                    if let Some(o) = r["receipt"]["integration_head"].as_str() {
                        objects.push(o.into());
                    }
                    for key in ["proposal_commit", "current_head"] {
                        if let Some(o) = r["receipt"]["resolution_task"][key].as_str() { objects.push(o.into()); }
                    }
                }
                "repair_budgets" => {
                    if !proposals
                        .values()
                        .any(|o| Some(o.as_str()) == r["proposal"].as_str())
                    {
                        return Err("public_budget_without_proposal".into());
                    }
                }
                "exports" => {
                    let e = &r["manifest"];
                    if !v["sync_binding"].is_null()
                        && !["project", "authority", "epoch", "device"]
                            .iter()
                            .all(|k| e[*k] == v["sync_binding"][*k])
                    {
                        return Err("public_export_binding_mismatch".into());
                    }
                    let p = match e["kind"].as_str() {
                        Some("proposal") => Some(&e["proposal"]),
                        Some("receipt") => Some(&e["receipt"]["authority_proposal"]),
                        _ => None,
                    };
                    if let Some(p) = p {
                        if !known(p)
                            || proposals.get(p.as_str().unwrap()).map(String::as_str)
                                != e["head"].as_str()
                        {
                            return Err("public_export_proposal_mismatch".into());
                        }
                    }
                    for key in ["head", "base"] {
                        if let Some(o) = e[key].as_str() {
                            objects.push(o.into());
                        }
                    }
                    if let Some(o) = e["receipt"]["integration_head"].as_str() {
                        objects.push(o.into());
                    }
                    for key in ["proposal_commit", "current_head"] {
                        if let Some(o) = e["receipt"]["resolution_task"][key].as_str() { objects.push(o.into()); }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    if let Some(replay) = v.get("replay").filter(|r| !r.is_null()) {
        for e in replay["events"]
            .as_array()
            .ok_or("invalid_public_replay_events")?
        {
            objects.push(
                e["envelope"]["event"]["head"]
                    .as_str()
                    .ok_or("invalid_public_replay_head")?
                    .into(),
            );
        }
    }
    Ok(objects)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn resolution_receipts_allow_only_sanitized_bounded_tasks() {
        let task = serde_json::json!({"proposal":"p","workspace":null,"state":"action_required","reason":"merge_conflict","base":"a".repeat(40),"proposal_commit":"b".repeat(40),"current_head":"c".repeat(40),"conflict_paths":["file.rs"],"checks":[{"id_sha256":"d".repeat(64),"success":false}],"policy_sha256":"e".repeat(64),"attempt":0,"max_attempts":3,"lineage":{"parent":null,"root":"p","attempt":0},"next_action":"Open isolated checkout","semantic_correctness_claimed":false});
        let receipt = serde_json::json!({"recipient":"device","authority_proposal":"remote-p","revision":1,"state":"quarantined","integration_head":null,"evidence":"unchecked","repaired":false,"resolution_task":task});
        let mut recovery = serde_json::json!({"version":2,"activation_required":true,"policy_sha256":"a".repeat(64),"policy_required":false,"sync_binding":null,"origins":[],"imports":[],"exports":[],"observations":[{"proposal":"p","revision":1,"digest":"f".repeat(64),"receipt":receipt}],"repair_budgets":[],"operations":[]});
        validate_recovery(&recovery).unwrap();
        for field in ["spawn_error", "stdout", "argv", "candidate_tree"] {
            let mut invalid = recovery.clone();
            invalid["observations"][0]["receipt"]["resolution_task"]["checks"][0][field] = serde_json::json!("PRIVATE_CANARY");
            assert!(validate_recovery(&invalid).is_err(), "accepted {field}");
        }
        recovery["observations"][0]["receipt"]["resolution_task"]["workspace"] = serde_json::json!("PRIVATE_OWNER");
        assert!(validate_recovery(&recovery).is_err());
        for attempt in [0,4] {
            assert!(validate_provenance(&serde_json::json!({"resolution":{"parent":"p","root":"p","attempt":attempt}})).is_err());
        }
    }

    #[test]
    fn managed_git_capture_times_out_and_caps_output_without_network() {
        use std::time::{Duration, Instant};
        let d = tempfile::tempdir().unwrap();
        let mut launch = wipstash_platform::Launch {
            executable: fs::canonicalize("/bin/sh").unwrap(),
            arguments: vec!["-c".into(), "sleep 1".into()],
            directory: d.path().to_owned(),
            environment: vec![("PATH".into(), "/usr/bin:/bin".into())],
            purpose: wipstash_platform::Purpose::CooperativeCommand,
        };
        let start = Instant::now();
        assert_eq!(
            bounded_git_process(&launch, Duration::from_millis(20), 16).unwrap_err(),
            "git_timeout"
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        launch.arguments = vec![
            "-c".into(),
            "printf '012345678901234567890123456789'; printf 'secret stderr' >&2".into(),
        ];
        assert_eq!(
            bounded_git_process(&launch, Duration::from_secs(2), 16).unwrap_err(),
            "git_output_limit"
        );
        launch.arguments = vec![
            "-c".into(),
            "printf public; printf 'secret stderr' >&2".into(),
        ];
        assert_eq!(
            bounded_git_process(&launch, Duration::from_secs(2), 16).unwrap(),
            b"public"
        );
    }
    #[test]
    fn canonical_local_enqueue_preserves_identity() {
        let f = Fixture::new();
        let moved_source = f._dir.path().join("source with spaces.git");
        fs::rename(&f.source, &moved_source).unwrap();
        let source = fs::canonicalize(&moved_source).unwrap();
        let out = f._dir.path().join("canonical outbox with spaces");
        fs::create_dir(&out).unwrap();
        let out = fs::canonicalize(out).unwrap();
        let mut queue = Outbox::open(&out, config()).unwrap();
        let snapshot = queue.enqueue(&source).unwrap();
        assert_eq!(snapshot.refs["refs/heads/project/integration"], f.root);
        assert_eq!(queue.spool, out.join("public.git"));
        assert_eq!(fs::canonicalize(&moved_source).unwrap(), source);
    }
    #[test]
    fn git_protocol_defaults_and_github_override_are_separate() {
        let f = Fixture::new();
        // Read effective command configuration only: no transport or credentials.
        let query = strings(&["config", "--get-regexp", "^protocol\\."]);
        let defaults = String::from_utf8(git(&f.source, &query).unwrap()).unwrap();
        assert_eq!(defaults, "protocol.allow never\n");
        let github = Github { config: config() };
        let mut args = github.args();
        args.extend(query);
        let configured = String::from_utf8(git(&f.source, &args).unwrap()).unwrap();
        assert!(configured.contains("protocol.allow never\n"));
        assert!(configured.contains("protocol.https.allow always\n"));
        assert!(!configured.contains("protocol.file.allow"));
        for protocol in ["file", "https"] {
            let command = git_command(&f.source, &[], Some(protocol)).unwrap();
            assert_eq!(
                command
                    .get_envs()
                    .find(|(key, _)| *key == "GIT_ALLOW_PROTOCOL")
                    .unwrap()
                    .1,
                Some(std::ffi::OsStr::new(protocol))
            );
        }
        assert_eq!(
            github.config.url().unwrap(),
            "https://github.com/fixture/public.git"
        );
    }
    fn config() -> GithubConfig {
        GithubConfig {
            owner: "fixture".into(),
            repository: "public".into(),
            namespace: "project".into(),
            credential_helper: "libsecret".into(),
        }
    }
    fn input(repo: &Path, args: &[&str], bytes: &[u8]) -> String {
        let mut c = Command::new("git");
        c.arg("--git-dir")
            .arg(wipstash_platform::git_path::argument(repo).unwrap())
            .args(args)
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut p = c.spawn().unwrap();
        p.stdin.take().unwrap().write_all(bytes).unwrap();
        let out = p.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().into()
    }
    fn commit(repo: &Path, tree: &str, parent: Option<&str>) -> String {
        let mut a = vec!["commit-tree", tree];
        if let Some(p) = parent {
            a.extend(["-p", p]);
        }
        input(repo, &a, b"public fixture\n")
    }
    fn manifest_commit(repo: &Path, m: &Value, parent: Option<&str>) -> String {
        let blob = input(
            repo,
            &["hash-object", "-w", "--stdin"],
            &serde_json::to_vec(m).unwrap(),
        );
        let tree = input(
            repo,
            &["mktree"],
            format!("100644 blob {blob}\tmetadata.json\n").as_bytes(),
        );
        commit(repo, &tree, parent)
    }
    struct Fixture {
        _dir: tempfile::TempDir,
        source: PathBuf,
        remote: Local,
        out: PathBuf,
        root: String,
        private: String,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source.git");
            init(&source).unwrap();
            let empty = input(&source, &["mktree"], b"");
            let root = commit(&source, &empty, None);
            let private = input(
                &source,
                &["hash-object", "-w", "--stdin"],
                b"private unreachable credential fixture",
            );
            let proposal = commit(&source, &empty, Some(&root));
            let m = serde_json::json!({"format":"wipstash-public-metadata-v1","integration":root,"watermark":3,"proposals":{"accepted":proposal},"proposal_metadata":{"accepted":{"state":"coordinator_accepted","base":root,"head":null,"queue_order":1}},"events":[{"seq":3,"kind":"published","proposal":"accepted","commit":proposal}]});
            let meta = manifest_commit(&source, &m, None);
            for (r, o) in [
                ("integration", &root),
                ("metadata", &meta),
                ("proposals/accepted", &proposal),
            ] {
                git(
                    &source,
                    &strings(&["update-ref", &format!("refs/heads/wipstash/{r}"), o]),
                )
                .unwrap();
            }
            git(
                &source,
                &strings(&["update-ref", "refs/wipstash/private/checkpoint", &root]),
            )
            .unwrap();
            let remote = dir.path().join("remote.git");
            init(&remote).unwrap();
            let out = dir.path().join("outbox");
            Self {
                _dir: dir,
                source,
                remote: Local {
                    path: remote,
                    fail: false,
                    after_push: false,
                    fetch_fail: false,
                },
                out,
                root,
                private,
            }
        }
    }
    struct Local {
        path: PathBuf,
        fail: bool,
        after_push: bool,
        fetch_fail: bool,
    }
    impl Remote for Local {
        fn refs(&mut self, repo: &Path, prefix: &str) -> Result<Refs> {
            parse_refs(
                &git(
                    repo,
                    &strings(&[
                        "-c",
                        "protocol.file.allow=always",
                        "ls-remote",
                        "--refs",
                        self.path.to_str().unwrap(),
                        &format!("{prefix}*"),
                    ]),
                )?,
                prefix,
            )
        }
        fn push(&mut self, repo: &Path, expected: &Refs, next: &Refs) -> Result<()> {
            if self.fail {
                return Err("fixture_offline".into());
            }
            let mut a = strings(&[
                "-c",
                "protocol.file.allow=always",
                "push",
                "--atomic",
                "--no-follow-tags",
            ]);
            for r in next.keys() {
                a.push(format!(
                    "--force-with-lease={r}:{}",
                    expected.get(r).map(String::as_str).unwrap_or("")
                ));
            }
            a.push(self.path.to_str().unwrap().into());
            for (r, o) in next {
                a.push(format!("{o}:{r}"));
            }
            git(repo, &a)?;
            if self.after_push {
                return Err("fixture_interrupted_after_push".into());
            }
            Ok(())
        }
        fn fetch(&mut self, repo: &Path, refs: &Refs) -> Result<()> {
            if self.fetch_fail {
                return Err("fixture_fetch_offline".into());
            }
            let mut a = strings(&[
                "-c",
                "protocol.file.allow=always",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                self.path.to_str().unwrap(),
            ]);
            for (r, o) in refs {
                a.push(format!("{o}:{r}"));
            }
            git(repo, &a)?;
            Ok(())
        }
    }
    #[test]
    fn destination_validation_rejects_injection_and_plaintext_helpers() {
        let c = config();
        assert_eq!(c.url().unwrap(), "https://github.com/fixture/public.git");
        for field in ["https://evil", "foo/bar", "a?token=secret", "a.git\n", ""] {
            let mut d = c.clone();
            d.repository = field.into();
            assert!(d.validate().is_err());
        }
        for helper in ["store", "cache", "!shell", "manager --arg"] {
            let mut d = c.clone();
            d.credential_helper = helper.into();
            assert!(d.validate().is_err());
        }
    }
    #[test]
    fn real_git_roundtrip_is_public_only_and_fresh() {
        let mut f = Fixture::new();
        let mut out = Outbox::open(&f.out, config()).unwrap();
        let s = out.enqueue(&f.source).unwrap();
        assert_eq!(s.watermark, 3);
        assert_eq!(out.status().unwrap().verified_watermark, 0);
        assert!(out.drain_one(&mut f.remote).unwrap());
        assert_eq!(out.status().unwrap().verified_watermark, 3);
        assert_eq!(out.status().unwrap().pending, 0);
        assert!(git(&f.remote.path, &strings(&["cat-file", "-e", &f.private])).is_err());
        let dest = f._dir.path().join("fresh.git");
        assert_eq!(
            restore(&mut f.remote, &config(), &dest).unwrap().refs,
            s.refs
        );
        assert!(git(&dest, &strings(&["cat-file", "-e", &f.private])).is_err());
        assert!(restore(&mut f.remote, &config(), &dest).is_err());
    }
    #[test]
    fn durable_outage_and_after_push_replay() {
        let mut f = Fixture::new();
        {
            let mut out = Outbox::open(&f.out, config()).unwrap();
            out.enqueue(&f.source).unwrap();
            f.remote.fail = true;
            assert!(out.drain_one(&mut f.remote).is_err());
            assert_eq!(out.status().unwrap().verified_watermark, 0);
        }
        f.remote.fail = false;
        f.remote.after_push = true;
        {
            let mut out = Outbox::open(&f.out, config()).unwrap();
            assert!(out.drain_one(&mut f.remote).is_err());
            assert_eq!(out.status().unwrap().pending, 1);
        }
        f.remote.after_push = false;
        let mut out = Outbox::open(&f.out, config()).unwrap();
        assert!(out.drain_one(&mut f.remote).unwrap());
        assert_eq!(out.status().unwrap().verified_watermark, 3);
    }
    fn upgrade_v2(f: &Fixture) -> Value {
        let raw = git(
            &f.source,
            &strings(&["show", "refs/heads/wipstash/metadata:metadata.json"]),
        )
        .unwrap();
        let mut m: Value = serde_json::from_slice(&raw).unwrap();
        m["format"] = serde_json::json!("wipstash-public-metadata-v2");
        m["proposal_metadata"]["accepted"]["intent"] = serde_json::json!("Accepted public intent");
        m["recovery"] = serde_json::json!({"version":2,"activation_required":true,"policy_sha256":"a".repeat(64),"policy_required":true,"sync_binding":null,"origins":[],"imports":[],"exports":[],"observations":[],"repair_budgets":[{"proposal":m["proposals"]["accepted"],"attempts":2,"seconds":120}],"operations":[]});
        let meta = manifest_commit(&f.source, &m, None);
        git(
            &f.source,
            &strings(&["update-ref", "refs/heads/wipstash/metadata", &meta]),
        )
        .unwrap();
        m
    }
    #[test]
    fn v2_fresh_fetch_and_lost_ack_preserve_recovery_metadata() {
        let mut f = Fixture::new();
        let expected = upgrade_v2(&f);
        let mut out = Outbox::open(&f.out, config()).unwrap();
        out.enqueue(&f.source).unwrap();
        f.remote.after_push = true;
        assert!(out.drain_one(&mut f.remote).is_err());
        assert_eq!(out.status().unwrap().verified_watermark, 0);
        drop(out);
        f.remote.after_push = false;
        let mut out = Outbox::open(&f.out, config()).unwrap();
        assert!(out.drain_one(&mut f.remote).unwrap());
        assert_eq!(out.status().unwrap().verified_watermark, 3);
        let raw = git(
            &f.remote.path,
            &strings(&["show", "refs/heads/project/metadata:metadata.json"]),
        )
        .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&raw).unwrap(), expected);
        assert!(git(&f.remote.path, &strings(&["cat-file", "-e", &f.private])).is_err());
    }
    #[test]
    fn v2_rejects_private_fields_and_unfenced_restore_schema_before_enqueue() {
        for mutation in [
            "private_path",
            "unfenced",
            "opaque_receipt",
            "unknown_budget",
        ] {
            let f = Fixture::new();
            let mut m = upgrade_v2(&f);
            match mutation {
                "private_path" => {
                    m["recovery"]["source_path"] = serde_json::json!("/PRIVATE_CANARY")
                }
                "unfenced" => m["recovery"]["activation_required"] = serde_json::json!(false),
                "opaque_receipt" => {
                    m["recovery"]["observations"] = serde_json::json!([{"proposal":"accepted","revision":1,"digest":"a".repeat(64),"receipt":{"output":"PRIVATE_CANARY"}}])
                }
                "unknown_budget" => {
                    m["recovery"]["repair_budgets"][0]["argv"] =
                        serde_json::json!(["PRIVATE_CANARY"])
                }
                _ => unreachable!(),
            }
            let meta = manifest_commit(&f.source, &m, None);
            git(
                &f.source,
                &strings(&["update-ref", "refs/heads/wipstash/metadata", &meta]),
            )
            .unwrap();
            let mut out = Outbox::open(&f.out, config()).unwrap();
            assert!(out.enqueue(&f.source).is_err(), "accepted {mutation}");
            assert_eq!(out.status().unwrap().pending, 0);
        }
    }
    #[test]
    fn fresh_fetch_failure_never_advances_watermark() {
        let mut f = Fixture::new();
        let mut out = Outbox::open(&f.out, config()).unwrap();
        out.enqueue(&f.source).unwrap();
        f.remote.fetch_fail = true;
        assert!(out.drain_one(&mut f.remote).is_err());
        assert_eq!(out.status().unwrap().verified_watermark, 0);
        f.remote.fetch_fail = false;
        assert!(out.drain_one(&mut f.remote).unwrap());
    }
    #[test]
    fn remote_divergence_and_partial_pair_fail_closed() {
        let mut f = Fixture::new();
        let mut out = Outbox::open(&f.out, config()).unwrap();
        let s = out.enqueue(&f.source).unwrap();
        let root = s.refs["refs/heads/project/integration"].clone();
        f.remote
            .push(
                &out.spool,
                &Refs::new(),
                &BTreeMap::from([("refs/heads/project/integration".into(), root)]),
            )
            .unwrap();
        assert_eq!(out.drain_one(&mut f.remote).unwrap_err(), "remote_diverged");
        assert_eq!(out.status().unwrap().verified_watermark, 0);
    }
    #[test]
    fn unknown_namespace_branch_blocks_before_push() {
        let mut f = Fixture::new();
        let mut out = Outbox::open(&f.out, config()).unwrap();
        out.enqueue(&f.source).unwrap();
        git(
            &f.remote.path,
            &strings(&[
                "-c",
                "protocol.file.allow=always",
                "fetch",
                f.source.to_str().unwrap(),
                &format!("{}:refs/heads/project/secret", f.root),
            ]),
        )
        .unwrap();
        assert!(out.drain_one(&mut f.remote).is_err());
        assert_eq!(out.status().unwrap().verified_watermark, 0);
    }
    #[test]
    fn hidden_private_file_in_metadata_ancestor_is_rejected_before_transport() {
        let f = Fixture::new();
        let m = upgrade_v2(&f);
        let blob = input(
            &f.source,
            &["hash-object", "-w", "--stdin"],
            &serde_json::to_vec(&m).unwrap(),
        );
        let tree = input(
            &f.source,
            &["mktree"],
            format!(
                "100644 blob {blob}\tmetadata.json\n100644 blob {}\tprivate-output\n",
                f.private
            )
            .as_bytes(),
        );
        let hidden = commit(&f.source, &tree, None);
        let clean = manifest_commit(&f.source, &m, Some(&hidden));
        git(
            &f.source,
            &strings(&["update-ref", "refs/heads/wipstash/metadata", &clean]),
        )
        .unwrap();
        let mut out = Outbox::open(&f.out, config()).unwrap();
        assert!(out
            .enqueue(&f.source)
            .unwrap_err()
            .contains("private_metadata_tree_entry"));
        assert!(git(&f.remote.path, &strings(&["cat-file", "-e", &f.private])).is_err());
    }
    #[test]
    fn hostile_metadata_is_rejected_without_export() {
        let f = Fixture::new();
        let meta = String::from_utf8(
            git(
                &f.source,
                &strings(&["show", "refs/heads/wipstash/metadata:metadata.json"]),
            )
            .unwrap(),
        )
        .unwrap();
        let mut m: Value = serde_json::from_str(&meta).unwrap();
        m["policy"] = serde_json::json!({"command":"secret executable"});
        let oid = manifest_commit(&f.source, &m, None);
        git(
            &f.source,
            &strings(&["update-ref", "refs/heads/wipstash/metadata", &oid]),
        )
        .unwrap();
        let mut out = Outbox::open(&f.out, config()).unwrap();
        assert!(out.enqueue(&f.source).is_err());
        assert_eq!(out.status().unwrap().pending, 0);
    }
    #[test]
    fn configuration_is_pinned_and_spool_config_poisoning_rejected() {
        let f = Fixture::new();
        Outbox::open(&f.out, config()).unwrap();
        let mut c = config();
        c.repository = "other".into();
        assert!(Outbox::open(&f.out, c).is_err());
        fs::write(
            f.out.join("public.git/config"),
            "[url \"https://evil.invalid/\"]\n insteadOf = https://github.com/\n",
        )
        .unwrap();
        let mut out = Outbox::open(&f.out, config()).unwrap();
        assert!(out.enqueue(&f.source).is_err());
    }
}
