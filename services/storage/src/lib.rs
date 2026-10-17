//! Cooperative storage admission and conservative, explicit loose-object collection.
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime},
};
#[path = "../../../src/replication.rs"]
mod replication;
pub type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub entries: u64,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budget {
    pub max_bytes: u64,
    pub max_entries: u64,
    pub reserve_bytes: u64,
}
fn safe_path(p: &Path) -> Result<()> {
    if !p.is_absolute() {
        return Err("absolute path required".into());
    }
    let mut q = PathBuf::new();
    for c in p.components() {
        if matches!(c, Component::ParentDir | Component::CurDir) {
            return Err("dot path forbidden".into());
        }
        q.push(c);
        let m = fs::symlink_metadata(&q).map_err(err)?;
        if m.file_type().is_symlink() {
            return Err("symlink forbidden".into());
        }
    }
    Ok(())
}
fn walk(p: &Path, u: &mut Usage, limit: u64, files: &mut Vec<PathBuf>) -> Result<()> {
    if p.components().count() > 128 {
        return Err("directory depth limit".into());
    }
    let m = fs::symlink_metadata(p).map_err(err)?;
    if m.file_type().is_symlink() || (!m.is_dir() && !m.is_file()) {
        return Err("symlink or special file forbidden".into());
    }
    u.entries = u.entries.checked_add(1).ok_or("entry overflow")?;
    if u.entries > limit {
        return Err("entry budget exceeded".into());
    }
    u.logical_bytes = u
        .logical_bytes
        .checked_add(m.len())
        .ok_or("byte overflow")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        u.allocated_bytes = u
            .allocated_bytes
            .checked_add(m.blocks().checked_mul(512).ok_or("byte overflow")?)
            .ok_or("byte overflow")?;
        if m.is_file() && m.nlink() != 1 {
            return Err("hardlinked file forbidden".into());
        }
    }
    #[cfg(not(unix))]
    {
        u.allocated_bytes = u.logical_bytes;
    }
    if m.is_dir() {
        for e in fs::read_dir(p).map_err(err)? {
            walk(&e.map_err(err)?.path(), u, limit, files)?;
        }
    } else {
        files.push(p.to_path_buf());
    }
    Ok(())
}
/// Read-only preflight. Roots must exist, be absolute and disjoint. No reservation.
pub fn usage(roots: &[PathBuf], max_entries: u64) -> Result<Usage> {
    let mut seen = Vec::new();
    let mut u = Usage::default();
    for root in roots {
        safe_path(root)?;
        let root = fs::canonicalize(root).map_err(err)?;
        if seen
            .iter()
            .any(|p: &PathBuf| p.starts_with(&root) || root.starts_with(p))
        {
            return Err("overlapping roots".into());
        }
        seen.push(root.clone());
        walk(&root, &mut u, max_entries, &mut Vec::new())?;
    }
    Ok(u)
}
pub fn admit(
    roots: &[PathBuf],
    budget: Budget,
    incoming_bytes: u64,
    incoming_entries: u64,
) -> Result<Usage> {
    let u = usage(roots, budget.max_entries)?;
    let bytes = u
        .logical_bytes
        .max(u.allocated_bytes)
        .checked_add(incoming_bytes)
        .and_then(|n| n.checked_add(budget.reserve_bytes))
        .ok_or("byte overflow")?;
    if bytes > budget.max_bytes
        || u.entries
            .checked_add(incoming_entries)
            .ok_or("entry overflow")?
            > budget.max_entries
    {
        return Err("storage_pressure: admission rejected".into());
    }
    for root in roots {
        if fs2::available_space(root).map_err(err)?
            < incoming_bytes
                .checked_add(budget.reserve_bytes)
                .ok_or("byte overflow")?
        {
            return Err("insufficient_storage".into());
        }
    }
    Ok(u)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    pub oid: String,
    pub bytes: u64,
    pub modified_secs: u64,
    pub digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    pub repository: String,
    pub minimum_age_secs: u64,
    pub protected_roots: BTreeSet<String>,
    pub reachable: BTreeSet<String>,
    pub candidates: Vec<Candidate>,
    pub journal_digest: String,
    pub reference_digest: String,
}
#[derive(Debug, Serialize)]
pub struct Collection {
    pub removed_objects: u64,
    pub removed_logical_bytes: u64,
    pub before: Usage,
    pub after: Usage,
}
fn lock(state: &Path) -> Result<File> {
    safe_path(state)?;
    safe_path(&state.join("state.lock"))?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(state.join("state.lock"))
        .map_err(err)?;
    fs2::FileExt::lock_exclusive(&f).map_err(err)?;
    Ok(f)
}
fn tokens(bytes: &[u8]) -> BTreeSet<String> {
    bytes
        .split(|b| !b.is_ascii_hexdigit())
        .filter(|s| s.len() == 40 && s.iter().any(|b| *b != b'0'))
        .map(|s| String::from_utf8_lossy(s).to_lowercase())
        .collect()
}
fn json_roots(value: &serde_json::Value, roots: &mut BTreeSet<String>, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err("nested journal encoding limit".into());
    }
    match value {
        serde_json::Value::String(s) => {
            roots.extend(tokens(s.as_bytes()));
            if let Ok(nested) = serde_json::from_str::<serde_json::Value>(s) {
                json_roots(&nested, roots, depth + 1)?
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                json_roots(item, roots, depth + 1)?
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                roots.extend(tokens(key.as_bytes()));
                json_roots(item, roots, depth + 1)?
            }
        }
        _ => {}
    }
    Ok(())
}
fn file_hash(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(err)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer).map_err(err)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn journal(state: &Path) -> Result<(BTreeSet<String>, BTreeSet<String>, String)> {
    let p = state.join("state.sqlite");
    safe_path(&p)?;
    let db = Connection::open_with_flags(p, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
    if db
        .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
        .map_err(err)?
        != 1
    {
        return Err("unknown schema version".into());
    }
    if db
        .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
        .map_err(err)?
        != "ok"
    {
        return Err("journal integrity failure".into());
    }
    for query in [
        "SELECT count(*) FROM promotions WHERE state != 'committed'",
        "SELECT count(*) FROM adoptions WHERE state NOT IN ('committed','rolled_back')",
        "SELECT count(*) FROM commands WHERE state IN ('running','uncertain')",
    ] {
        if db
            .query_row(query, [], |r| r.get::<_, u64>(0))
            .map_err(err)?
            > 0
        {
            return Err("recovery required before collection".into());
        }
    }
    let allowed = [
        "meta",
        "workspaces",
        "checkpoints",
        "proposals",
        "operations",
        "candidates",
        "promotions",
        "adoptions",
        "adoption_conflicts",
        "commands",
        "events",
        "sqlite_sequence",
        "sync_exports",
        "sync_proposal_origins",
        "sync_remote_status",
        "sync_imports",
        "backup_state",
        "replication_binding",
        "replication_events",
    ];
    let mut s = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .map_err(err)?;
    let tables = s
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(err)?;
    let schemas = [
 ("meta","key,value"),("workspaces","id,path,base,checkpoint,generation"),
 ("checkpoints","id,workspace,commit_oid,tree,base,generation"),
 ("proposals","id,workspace,checkpoint,commit_oid,base,intent,state,head,details"),
 ("operations","id,digest,request,result"),("candidates","id,head,proposal,tree,policy_hash,evidence,state"),
 ("promotions","id,proposal,old,new,state"),("adoptions","id,workspace,old_base,target,commit_oid,tree,old_files,new_files,stage,backup,state,generation"),
 ("adoption_conflicts","id,workspace,target,base,generation,state"),("commands","id,workspace,state,generation"),
 ("events","seq,kind,data"),("sqlite_sequence","name,seq"),
 ("sync_exports","operation,request_digest,manifest"),("sync_proposal_origins","proposal,device,source_proposal"),
 ("sync_remote_status","proposal,revision,digest,receipt"),("sync_imports","device,operation,digest,result"),
 ("backup_state","id,destination,watermark,root,metadata,pending_watermark,pending_root,pending_metadata,error,queue_snapshot"),
 ("replication_binding","singleton,project,authority,epoch,cursor,head"),("replication_events","sequence,operation,digest,envelope")];
    for required in &allowed[..11] {
        if !tables.iter().any(|t| t == required) {
            return Err(format!("missing journal table: {required}"));
        }
    }
    let mut roots = BTreeSet::new();
    let mut required_roots = BTreeSet::new();
    let mut journal_bytes = 0usize;
    let mut digest = Sha256::new();
    for table in tables {
        if !allowed.contains(&table.as_str()) {
            return Err(format!("unknown journal table: {table}"));
        }
        let expected = schemas
            .iter()
            .find(|(name, _)| *name == table)
            .ok_or("unknown schema")?
            .1;
        let mut columns_stmt = db
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .map_err(err)?;
        let names = columns_stmt
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(err)?
            .join(",");
        if names != expected
            && !(table == "backup_state" && format!("{names},queue_snapshot") == expected)
        {
            return Err(format!("unknown columns in {table}"));
        }
        digest.update(table.as_bytes());
        digest.update(names.as_bytes());
        let mut s = db
            .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
            .map_err(err)?;
        let columns = s.column_count();
        let mut rows = s.query([]).map_err(err)?;
        while let Some(row) = rows.next().map_err(err)? {
            for i in 0..columns {
                let v = row.get_ref(i).map_err(err)?;
                let b = match v {
                    ValueRef::Text(t) => {
                        if t.len() > 64 * 1024 * 1024 {
                            return Err("journal field limit".into());
                        }
                        t.to_vec()
                    }
                    ValueRef::Blob(_) => return Err("unknown binary journal encoding".into()),
                    _ => format!("{v:?}").into_bytes(),
                };
                journal_bytes = journal_bytes
                    .checked_add(b.len())
                    .ok_or("journal size overflow")?;
                if journal_bytes > 64 * 1024 * 1024 {
                    return Err("journal scan limit".into());
                }
                let column = names.split(',').nth(i).ok_or("unknown column")?;
                let oid_column = match table.as_str() {
                    "workspaces" => matches!(column, "base" | "checkpoint"),
                    "checkpoints" => matches!(column, "commit_oid" | "tree" | "base"),
                    "proposals" => matches!(column, "commit_oid" | "base" | "head"),
                    "candidates" => matches!(column, "head" | "tree"),
                    "promotions" => matches!(column, "old" | "new"),
                    "adoptions" => matches!(column, "old_base" | "target" | "commit_oid" | "tree"),
                    "adoption_conflicts" => matches!(column, "target" | "base"),
                    "backup_state" => matches!(
                        column,
                        "root" | "metadata" | "pending_root" | "pending_metadata"
                    ),
                    "replication_binding" => column == "head",
                    _ => false,
                };
                if oid_column && !matches!(v, ValueRef::Null) {
                    if b.len() != 40 || !b.iter().all(|c| c.is_ascii_hexdigit()) {
                        return Err("invalid journal object ID".into());
                    }
                    required_roots
                        .insert(String::from_utf8(b.clone()).map_err(err)?.to_lowercase());
                }
                roots.extend(tokens(&b));
                if matches!(v, ValueRef::Text(_)) {
                    match serde_json::from_slice::<serde_json::Value>(&b) {
                        Ok(json) => json_roots(&json, &mut roots, 0)?,
                        Err(_)
                            if matches!(
                                (table.as_str(), column),
                                ("operations", "request" | "result")
                                    | ("events", "data")
                                    | ("sync_exports", "manifest")
                                    | ("sync_remote_status", "receipt")
                                    | ("sync_imports", "result")
                                    | ("backup_state", "queue_snapshot")
                                    | ("candidates", "evidence")
                                    | ("proposals", "details")
                                    | ("adoptions", "old_files" | "new_files")
                                    | ("replication_events", "envelope")
                            ) || (table == "meta"
                                && column == "value"
                                && matches!(
                                    row.get_ref(0).map_err(err)?,
                                    ValueRef::Text(b"policy" | b"sync_config")
                                ))
                                || b.first().is_some_and(|b| matches!(b, b'{' | b'[' | b'"')) =>
                        {
                            return Err("invalid journal JSON".into())
                        }
                        Err(_) => {}
                    }
                }
                digest.update((b.len() as u64).to_le_bytes());
                digest.update(b);
            }
        }
    }
    required_roots.extend(roots.iter().cloned());
    Ok((roots, required_roots, format!("{:x}", digest.finalize())))
}
fn replay_journal(state: &Path) -> Result<(BTreeSet<String>, String)> {
    let path = state.join("sync-replay.sqlite");
    if !path.exists() {
        return Ok((BTreeSet::new(), "absent".into()));
    }
    safe_path(&path)?;
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
    if db
        .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
        .map_err(err)?
        != 0
        || db
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .map_err(err)?
            != "ok"
    {
        return Err("unknown or corrupt replay journal".into());
    }
    let mut stmt = db
        .prepare(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view','trigger') ORDER BY name",
        )
        .map_err(err)?;
    let tables = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(err)?;
    if tables != ["replication_binding", "replication_events"] {
        return Err("unknown replay schema".into());
    }
    for (table, expected) in [
        (
            "replication_binding",
            "singleton,project,authority,epoch,cursor,head",
        ),
        ("replication_events", "sequence,operation,digest,envelope"),
    ] {
        let mut stmt = db
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(err)?;
        let columns = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(err)?
            .join(",");
        if columns != expected {
            return Err("unknown replay columns".into());
        }
    }
    if db
        .query_row("SELECT count(*) FROM replication_binding", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(err)?
        != 1
    {
        return Err("invalid replay binding count".into());
    }
    let (project, authority, epoch, cursor, head): (String, String, u64, u64, Option<String>) = db
        .query_row(
            "SELECT project,authority,epoch,cursor,head FROM replication_binding WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .map_err(err)?;
    let project_id = replication::Id::try_from(project.clone())?;
    let authority_id = replication::Id::try_from(authority.clone())?;
    if epoch == 0 || epoch > i64::MAX as u64 || cursor > 1_000_000 {
        return Err("replay counter limit".into());
    }
    let mut roots = BTreeSet::new();
    let mut digest = Sha256::new();
    digest.update(serde_json::to_vec(&(&project, &authority, epoch, cursor, &head)).map_err(err)?);
    let mut stmt = db
        .prepare(
            "SELECT sequence,operation,digest,envelope FROM replication_events ORDER BY sequence",
        )
        .map_err(err)?;
    let mut rows = stmt.query([]).map_err(err)?;
    let mut sequence = 0u64;
    let mut last_head: Option<String> = None;
    let mut total = 0usize;
    while let Some(row) = rows.next().map_err(err)? {
        sequence += 1;
        let n: u64 = row.get(0).map_err(err)?;
        let operation: String = row.get(1).map_err(err)?;
        let saved_digest: String = row.get(2).map_err(err)?;
        let bytes = match row.get_ref(3).map_err(err)? {
            ValueRef::Text(t) => t,
            _ => return Err("invalid replay encoding".into()),
        };
        total = total
            .checked_add(bytes.len())
            .ok_or("replay size overflow")?;
        if total > 64 * 1024 * 1024 {
            return Err("replay scan limit".into());
        }
        let envelope = replication::decode(bytes)?;
        let canonical = serde_json::to_vec(&envelope).map_err(err)?;
        if n != sequence
            || envelope.sequence != sequence
            || envelope.epoch != epoch
            || envelope.project != project_id
            || envelope.authority != authority_id
            || String::from(envelope.operation.clone()) != operation
            || format!("{:x}", Sha256::digest(&canonical)) != saved_digest
        {
            return Err("inconsistent replay event".into());
        }
        let oid = match &envelope.event {
            replication::Event::HeadAdvanced { head } => {
                last_head = Some(head.clone());
                head
            }
            replication::Event::ProposalAccepted { head, .. } => head,
        };
        if oid.len() != 40 {
            return Err("unsupported replay object format".into());
        }
        roots.insert(oid.clone());
        digest.update((canonical.len() as u64).to_le_bytes());
        digest.update(canonical);
    }
    if cursor != sequence || head != last_head {
        return Err("inconsistent replay cursor or head".into());
    }
    if let Some(head) = head {
        roots.insert(head);
    }
    Ok((roots, format!("{:x}", digest.finalize())))
}
// Run plumbing in a fresh repository: never load the source repository's config,
// hooks, alternates, attributes, replace refs or environment overrides.
struct View {
    dir: tempfile::TempDir,
    objects: PathBuf,
}
impl View {
    fn run(&self, args: &[&str], input: &str) -> Result<String> {
        let mut c = Command::new("git");
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("GIT_") {
                c.env_remove(k);
            }
        }
        c.env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_TERMINAL_PROMPT", "0");
        c.arg("--no-pager")
            .arg("--git-dir")
            .arg(self.dir.path())
            .env("GIT_OBJECT_DIRECTORY", &self.objects)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().map_err(err)?;
        let mut stdin = child.stdin.take().unwrap();
        let data = input.as_bytes().to_vec();
        let writer = std::thread::spawn(move || stdin.write_all(&data));
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        fn bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>> {
            let mut data = Vec::new();
            let mut buf = [0; 8192];
            let mut overflow = false;
            loop {
                let n = reader.read(&mut buf).map_err(err)?;
                if n == 0 {
                    break;
                }
                if data.len().saturating_add(n) > limit {
                    overflow = true
                } else if !overflow {
                    data.extend_from_slice(&buf[..n]);
                }
            }
            if overflow {
                Err("Git output limit".into())
            } else {
                Ok(data)
            }
        }
        let output = std::thread::spawn(move || bounded(stdout, 64 * 1024 * 1024));
        let errors = std::thread::spawn(move || bounded(stderr, 1024 * 1024));
        let status = child.wait().map_err(err)?;
        writer.join().map_err(|_| "writer panic")?.map_err(err)?;
        let stdout = output.join().map_err(|_| "reader panic")??;
        let stderr = errors.join().map_err(|_| "reader panic")??;
        let out = std::process::Output {
            status,
            stdout,
            stderr,
        };
        if !out.status.success() {
            return Err(format!(
                "Git validation failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        String::from_utf8(out.stdout).map_err(err)
    }
    fn new(repo: &Path) -> Result<Self> {
        let dir = tempfile::tempdir().map_err(err)?;
        fs::create_dir(dir.path().join("refs")).map_err(err)?;
        fs::write(dir.path().join("HEAD"), "ref: refs/heads/unused\n").map_err(err)?;
        fs::write(
            dir.path().join("config"),
            "[core]\nrepositoryformatversion = 0\nbare = true\n",
        )
        .map_err(err)?;
        Ok(Self {
            dir,
            objects: repo.join("objects"),
        })
    }
}
fn inspect(state: &Path, repository: &str, age: u64) -> Result<Plan> {
    if age < 86400 {
        return Err("minimum retention is one day".into());
    }
    let parts: Vec<_> = repository.split('/').collect();
    if repository != "coordinator.git"
        && !(parts.len() == 3
            && parts[0] == "locals"
            && parts[2] == "objects.git"
            && !parts[1].is_empty()
            && parts[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return Err("unexpected repository path".into());
    }
    let repo = state.join(repository);
    safe_path(&repo)?;
    let mut files = Vec::new();
    walk(state, &mut Usage::default(), 1_000_000, &mut files)?;
    for p in &files {
        if p.extension().is_some_and(|e| e == "sqlite")
            && p != &state.join("state.sqlite")
            && p != &state.join("repair-budget.sqlite")
            && p != &state.join("sync-replay.sqlite")
        {
            return Err("unsupported auxiliary journal; recover or upgrade collector".into());
        }
    }
    let (mut db_roots, mut required_roots, journal_digest) = journal(state)?;
    let (replay_roots, replay_digest) = replay_journal(state)?;
    db_roots.extend(replay_roots.iter().cloned());
    required_roots.extend(replay_roots);
    let journal_digest = format!("{journal_digest}:{replay_digest}");
    if repo.join("objects/info/alternates").exists()
        || repo.join("objects/info/http-alternates").exists()
        || repo.join("shallow").exists()
    {
        return Err("alternate or shallow store unsupported".into());
    }
    for entry in fs::read_dir(&repo).map_err(err)? {
        let name = entry.map_err(err)?.file_name();
        if ![
            "HEAD",
            "config",
            "description",
            "hooks",
            "info",
            "objects",
            "refs",
            "logs",
            "packed-refs",
        ]
        .iter()
        .any(|allowed| name == *allowed)
        {
            return Err("unknown repository structure or pseudoref".into());
        }
    }
    let info = repo.join("info");
    if info.exists() {
        for entry in fs::read_dir(info).map_err(err)? {
            if entry.map_err(err)?.file_name() != "exclude" {
                return Err("unsupported repository info file".into());
            }
        }
    }
    let view = View::new(&repo)?;
    let all = view.run(
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
        "",
    )?;
    let present: BTreeSet<_> = all.lines().map(str::to_owned).collect();
    if present
        .iter()
        .any(|oid| oid.len() != 40 || !oid.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("unsupported object format".into());
    }
    let mut all_present = present.clone();
    let mut repositories = vec![state.join("coordinator.git")];
    let locals = state.join("locals");
    if locals.exists() {
        for e in fs::read_dir(&locals).map_err(err)? {
            repositories.push(e.map_err(err)?.path().join("objects.git"));
        }
    }
    for other in repositories {
        if other == repo {
            continue;
        }
        safe_path(&other)?;
        if other.join("objects/info/alternates").exists()
            || other.join("objects/info/http-alternates").exists()
            || other.join("shallow").exists()
        {
            return Err("alternate or shallow store unsupported".into());
        }
        all_present.extend(
            View::new(&other)?
                .run(
                    &[
                        "cat-file",
                        "--batch-all-objects",
                        "--batch-check=%(objectname)",
                    ],
                    "",
                )?
                .lines()
                .map(str::to_owned),
        );
    }
    if !required_roots.is_subset(&all_present) {
        return Err("missing journal-protected object".into());
    }
    let mut protected_roots: BTreeSet<_> = db_roots.intersection(&present).cloned().collect();
    files.sort();
    let mut ref_digest = Sha256::new();
    for p in &files {
        if p.starts_with(repo.join("refs"))
            || p.starts_with(repo.join("logs"))
            || p == &repo.join("packed-refs")
            || p == &repo.join("HEAD")
        {
            if fs::metadata(p).map_err(err)?.len() > 64 * 1024 * 1024 {
                return Err("reference scan limit".into());
            }
            let b = fs::read(p).map_err(err)?;
            let text = std::str::from_utf8(&b).map_err(|_| "unknown reference encoding")?;
            let oid_valid = |s: &str| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit());
            if !text.ends_with('\n') {
                return Err("truncated reference metadata".into());
            }
            if p.starts_with(repo.join("refs")) {
                if !oid_valid(text.trim_end_matches('\n')) {
                    return Err("unknown reference format".into());
                }
            } else if p == &repo.join("HEAD") {
                let value = text.trim_end_matches('\n');
                if !oid_valid(value)
                    && !value.strip_prefix("ref: refs/").is_some_and(|v| {
                        !v.is_empty() && !v.contains(char::is_whitespace) && !v.contains("..")
                    })
                {
                    return Err("unknown HEAD format".into());
                }
            } else if p == &repo.join("packed-refs") {
                for line in text.lines() {
                    if line.starts_with("# pack-refs with:") {
                        continue;
                    }
                    if let Some(oid) = line.strip_prefix('^') {
                        if oid_valid(oid) {
                            continue;
                        }
                    }
                    if !line.split_once(' ').is_some_and(|(oid, name)| {
                        oid_valid(oid)
                            && name.starts_with("refs/")
                            && !name.contains(char::is_whitespace)
                    }) {
                        return Err("unknown packed-reference format".into());
                    }
                }
            } else {
                for line in text.lines() {
                    let mut fields = line.splitn(3, ' ');
                    let old = fields.next().unwrap_or("");
                    let new = fields.next().unwrap_or("");
                    let rest = fields.next().unwrap_or("");
                    if !oid_valid(old) || !oid_valid(new) || !rest.contains('\t') {
                        return Err("unknown reflog format".into());
                    }
                }
            }
            ref_digest.update(
                p.strip_prefix(&repo)
                    .map_err(err)?
                    .to_string_lossy()
                    .as_bytes(),
            );
            ref_digest.update((b.len() as u64).to_le_bytes());
            ref_digest.update(&b);
            for oid in tokens(&b) {
                if !present.contains(&oid) {
                    return Err("missing reference or reflog object".into());
                }
                protected_roots.insert(oid);
            }
        }
    }
    if protected_roots.is_empty() {
        return Err("no protected roots; uninitialized or inconsistent store".into());
    }
    let input = protected_roots
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    // fsck also rejects corrupt/missing dependencies before any deletion.
    let args = vec!["fsck", "--full", "--no-reflogs", "--no-dangling"];
    view.run(&args, "")?;
    let reachable: BTreeSet<_> = view
        .run(
            &["rev-list", "--objects", "--no-object-names", "--stdin"],
            &input,
        )?
        .lines()
        .map(str::to_owned)
        .collect();
    let mut candidates = Vec::new();
    let now = SystemTime::now();
    for p in files {
        let Ok(rel) = p.strip_prefix(repo.join("objects")) else {
            continue;
        };
        let components: Vec<_> = rel.components().collect();
        if components.len() != 2 {
            continue;
        }
        let a = components[0].as_os_str().to_string_lossy();
        let b = components[1].as_os_str().to_string_lossy();
        if a.len() != 2
            || b.len() != 38
            || !a.bytes().chain(b.bytes()).all(|x| x.is_ascii_hexdigit())
        {
            continue;
        }
        let oid = format!("{a}{b}");
        if reachable.contains(&oid) || protected_roots.contains(&oid) {
            continue;
        }
        let m = fs::metadata(&p).map_err(err)?;
        let modified = m.modified().map_err(err)?;
        if now
            .duration_since(modified)
            .unwrap_or(Duration::ZERO)
            .as_secs()
            < age
        {
            continue;
        }
        candidates.push(Candidate {
            oid,
            bytes: m.len(),
            modified_secs: modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(err)?
                .as_secs(),
            digest: file_hash(&p)?,
        });
    }
    candidates.sort_by(|a, b| a.oid.cmp(&b.oid));
    Ok(Plan {
        repository: repository.into(),
        minimum_age_secs: age,
        protected_roots,
        reachable,
        candidates,
        journal_digest,
        reference_digest: format!("{:x}", ref_digest.finalize()),
    })
}
pub fn plan(state: &Path, repository: &str, minimum_age_secs: u64) -> Result<Plan> {
    let _lock = lock(state)?;
    inspect(state, repository, minimum_age_secs)
}
/// Explicit application only. All cooperating writers must use state.lock.
pub fn apply(state: &Path, expected: &Plan) -> Result<Collection> {
    let _lock = lock(state)?;
    let current = inspect(state, &expected.repository, expected.minimum_age_secs)?;
    if &current != expected {
        return Err("stale collection plan".into());
    }
    let before = usage(&[state.to_path_buf()], 1_000_000)?;
    let repo = state.join(&expected.repository);
    let mut removed = 0;
    for c in &expected.candidates {
        let p = repo.join("objects").join(&c.oid[..2]).join(&c.oid[2..]);
        fs::remove_file(&p).map_err(err)?;
        removed += c.bytes;
        #[cfg(unix)]
        File::open(p.parent().unwrap())
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
    }
    let after_plan = inspect(state, &expected.repository, expected.minimum_age_secs)?;
    if after_plan.protected_roots != expected.protected_roots
        || after_plan.reachable != expected.reachable
        || after_plan.journal_digest != expected.journal_digest
        || after_plan.reference_digest != expected.reference_digest
    {
        return Err("protected-root verification failed; stop writers and inspect recovery".into());
    }
    Ok(Collection {
        removed_objects: expected.candidates.len() as u64,
        removed_logical_bytes: removed,
        before,
        after: usage(&[state.to_path_buf()], 1_000_000)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn command(repo: &Path, args: &[&str], input: &[u8]) -> String {
        let mut c = Command::new("git");
        c.arg("--git-dir")
            .arg(repo)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let o = child.wait_with_output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap().trim().into()
    }
    fn fixture() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("coordinator.git");
        assert!(Command::new("git")
            .args(["init", "--bare"])
            .arg(&repo)
            .output()
            .unwrap()
            .status
            .success());
        File::create(d.path().join("state.lock")).unwrap();
        let db = Connection::open(d.path().join("state.sqlite")).unwrap();
        db.execute_batch(" CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);\n CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY,path TEXT UNIQUE NOT NULL,base TEXT NOT NULL,checkpoint TEXT,generation INTEGER NOT NULL DEFAULT 0);\n CREATE TABLE IF NOT EXISTS checkpoints(id TEXT PRIMARY KEY,workspace TEXT NOT NULL REFERENCES workspaces(id),commit_oid TEXT NOT NULL,tree TEXT NOT NULL,base TEXT NOT NULL,generation INTEGER NOT NULL);\n CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,checkpoint TEXT NOT NULL,commit_oid TEXT NOT NULL,base TEXT NOT NULL,intent TEXT NOT NULL,state TEXT NOT NULL,head TEXT,details TEXT);\n CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,digest TEXT NOT NULL,request TEXT NOT NULL,result TEXT);\n CREATE TABLE IF NOT EXISTS candidates(id TEXT PRIMARY KEY,head TEXT NOT NULL,proposal TEXT NOT NULL,tree TEXT NOT NULL,policy_hash TEXT NOT NULL,evidence TEXT NOT NULL,state TEXT NOT NULL);\n CREATE TABLE IF NOT EXISTS promotions(id TEXT PRIMARY KEY,proposal TEXT NOT NULL,old TEXT NOT NULL,new TEXT NOT NULL,state TEXT NOT NULL);\n CREATE TABLE IF NOT EXISTS adoptions(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,old_base TEXT NOT NULL,target TEXT NOT NULL,commit_oid TEXT NOT NULL,tree TEXT NOT NULL,old_files TEXT NOT NULL,new_files TEXT NOT NULL,stage TEXT NOT NULL,backup TEXT NOT NULL,state TEXT NOT NULL,generation INTEGER NOT NULL);\n CREATE TABLE IF NOT EXISTS adoption_conflicts(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,target TEXT NOT NULL,base TEXT NOT NULL,generation INTEGER NOT NULL,state TEXT NOT NULL);\n CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,workspace TEXT NOT NULL REFERENCES workspaces(id),state TEXT NOT NULL,generation INTEGER NOT NULL);\n CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,data TEXT NOT NULL);\n PRAGMA user_version=1;").unwrap();
        d
    }
    fn blob(d: &Path, bytes: &[u8]) -> String {
        command(
            &d.join("coordinator.git"),
            &["hash-object", "-w", "--stdin"],
            bytes,
        )
    }
    fn age(d: &Path, oid: &str) {
        let p = d
            .join("coordinator.git/objects")
            .join(&oid[..2])
            .join(&oid[2..]);
        let file = File::open(p).unwrap();
        file.set_times(
            std::fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(172800)),
        )
        .unwrap();
    }
    #[test]
    fn aged_unreachable_reclaimed_pending_and_acknowledged_pins_survive() {
        let d = fixture();
        let live = blob(d.path(), b"live checkpoint");
        let pending = blob(d.path(), b"pending operation");
        let acknowledged = blob(d.path(), b"acknowledged operation");
        let mut seed = 0x12345678u32;
        let garbage_bytes: Vec<u8> = (0..262144)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        let garbage = blob(d.path(), &garbage_bytes);
        let young = blob(d.path(), b"young unreachable");
        for oid in [&live, &pending, &acknowledged, &garbage] {
            age(d.path(), oid)
        }
        command(
            &d.path().join("coordinator.git"),
            &["update-ref", "refs/wipstash/checkpoints/live", &live],
            b"",
        );
        let db = Connection::open(d.path().join("state.sqlite")).unwrap();
        db.execute(
            "INSERT INTO operations VALUES('pending','digest',?1,NULL)",
            [format!("{{\"checkpoint\":\"{pending}\"}}")],
        )
        .unwrap();
        db.execute(
            "INSERT INTO operations VALUES('ack','digest','{}',?1)",
            [format!("{{\"commit\":\"{acknowledged}\"}}")],
        )
        .unwrap();
        drop(db);
        let p = plan(d.path(), "coordinator.git", 86400).unwrap();
        assert_eq!(p.candidates.len(), 1);
        assert_eq!(p.candidates[0].oid, garbage);
        let report = apply(d.path(), &p).unwrap();
        assert_eq!(report.removed_objects, 1);
        assert!(report.removed_logical_bytes > 250000);
        assert!(report.after.logical_bytes < report.before.logical_bytes);
        for oid in [live, pending, acknowledged, young] {
            command(
                &d.path().join("coordinator.git"),
                &["cat-file", "-e", &oid],
                b"",
            );
        }
        println!(
            "reclaimed {} bytes; preserved pending/acknowledged/checkpoint roots",
            report.removed_logical_bytes
        );
    }
    #[test]
    fn stale_journal_and_recovery_refuse_collection() {
        let d = fixture();
        let live = blob(d.path(), b"root");
        command(
            &d.path().join("coordinator.git"),
            &["update-ref", "refs/wipstash/recovery/live", &live],
            b"",
        );
        let p = plan(d.path(), "coordinator.git", 86400).unwrap();
        let db = Connection::open(d.path().join("state.sqlite")).unwrap();
        db.execute(
            "INSERT INTO operations VALUES('new','digest','{}',NULL)",
            [],
        )
        .unwrap();
        assert!(apply(d.path(), &p).unwrap_err().contains("stale"));
        db.execute("INSERT INTO adoptions VALUES('id','w','old','target','commit','tree','[]','[]','stage','backup','applying',0)",[]).unwrap();
        assert!(plan(d.path(), "coordinator.git", 86400)
            .unwrap_err()
            .contains("recovery required"));
    }
    #[test]
    fn quota_and_path_boundaries() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("data"), vec![1; 10000]).unwrap();
        let roots = vec![d.path().to_path_buf()];
        let u = usage(&roots, 100).unwrap();
        assert!(u.logical_bytes >= 10000);
        assert!(admit(
            &roots,
            Budget {
                max_bytes: 100,
                max_entries: 100,
                reserve_bytes: 0
            },
            0,
            0
        )
        .is_err());
        assert!(usage(&roots, 1).is_err());
        assert!(usage(&[d.path().to_path_buf(), d.path().to_path_buf()], 100).is_err());
        assert!(admit(
            &roots,
            Budget {
                max_bytes: u64::MAX,
                max_entries: 100,
                reserve_bytes: 1
            },
            u64::MAX,
            0
        )
        .is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlinks_and_hardlinks_fail_closed() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("one"), b"x").unwrap();
        symlink("one", d.path().join("link")).unwrap();
        assert!(usage(&[d.path().to_path_buf()], 100).is_err());
        fs::remove_file(d.path().join("link")).unwrap();
        fs::hard_link(d.path().join("one"), d.path().join("two")).unwrap();
        assert!(usage(&[d.path().to_path_buf()], 100).is_err());
    }
    #[test]
    fn unknown_schema_and_alternates_refuse() {
        let d = fixture();
        let db = Connection::open(d.path().join("state.sqlite")).unwrap();
        db.execute("CREATE TABLE unknown(data TEXT)", []).unwrap();
        assert!(plan(d.path(), "coordinator.git", 86400)
            .unwrap_err()
            .contains("unknown journal table"));
        db.execute("DROP TABLE unknown", []).unwrap();
        fs::write(
            d.path().join("coordinator.git/objects/info/alternates"),
            "/tmp/never-follow",
        )
        .unwrap();
        assert!(plan(d.path(), "coordinator.git", 86400)
            .unwrap_err()
            .contains("alternate"));
        assert!(plan(d.path(), "../source", 86400).is_err());
        assert!(plan(d.path(), "coordinator.git", 0).is_err());
    }
    #[test]
    fn missing_typed_pin_and_changed_schema_fail_closed() {
        let d = fixture();
        let root = blob(d.path(), b"live");
        command(
            &d.path().join("coordinator.git"),
            &["update-ref", "refs/wipstash/checkpoints/live", &root],
            b"",
        );
        let db = Connection::open(d.path().join("state.sqlite")).unwrap();
        db.execute(
            "INSERT INTO workspaces VALUES('w','/unused',?1,NULL,0)",
            ["1111111111111111111111111111111111111111"],
        )
        .unwrap();
        assert!(plan(d.path(), "coordinator.git", 86400)
            .unwrap_err()
            .contains("missing journal-protected"));
        db.execute("DELETE FROM workspaces", []).unwrap();
        db.execute("ALTER TABLE operations ADD COLUMN surprise TEXT", [])
            .unwrap();
        assert!(plan(d.path(), "coordinator.git", 86400)
            .unwrap_err()
            .contains("unknown columns"));
    }
    #[test]
    fn malicious_source_config_is_not_loaded() {
        let d = fixture();
        let root = blob(d.path(), b"live");
        command(
            &d.path().join("coordinator.git"),
            &["update-ref", "refs/wipstash/checkpoints/live", &root],
            b"",
        );
        fs::write(
            d.path().join("coordinator.git/config"),
            "[include]\npath=/nonexistent/forbidden\n[core]\nrepositoryformatversion=999999\n",
        )
        .unwrap();
        assert!(plan(d.path(), "coordinator.git", 86400).is_ok());
    }
    #[test]
    fn tree_descendants_of_pending_operation_remain() {
        let d = fixture();
        let content = blob(d.path(), b"pending tree content");
        let tree = command(
            &d.path().join("coordinator.git"),
            &["mktree"],
            format!("100644 blob {content}\tfile\n").as_bytes(),
        );
        age(d.path(), &tree);
        age(d.path(), &content);
        let db = Connection::open(d.path().join("state.sqlite")).unwrap();
        db.execute(
            "INSERT INTO operations VALUES('pending','digest',?1,NULL)",
            [format!("{{\"tree\":\"{tree}\"}}")],
        )
        .unwrap();
        let p = plan(d.path(), "coordinator.git", 86400).unwrap();
        assert!(p.candidates.is_empty());
        assert!(p.reachable.contains(&content));
        apply(d.path(), &p).unwrap();
    }
}
