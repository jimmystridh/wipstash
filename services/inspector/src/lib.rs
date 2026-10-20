//! A separate, source-read-only inspection boundary. Never calls the engine.
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    pub status: u16,
}
fn error(code: &'static str, status: u16) -> Error {
    Error { code, status }
}
fn storage<E>(_: E) -> Error {
    error("state_unavailable", 503)
}
#[derive(Clone)]
pub struct Inspector {
    state: PathBuf,
    pub authority: String,
    pub allowed_origin: Option<String>,
}
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub origin: Option<String>,
}
struct Snapshot {
    db: Connection,
    _temp: tempfile::TempDir,
    _lock: File,
}
#[derive(Serialize, Debug)]
struct Entry {
    id: String,
    workspace: String,
    kind: String,
    title: String,
    status: String,
    commit: String,
    base: String,
    generation: Option<i64>,
    sequence: Option<i64>,
}
#[derive(Serialize, Debug)]
struct Change {
    path: String,
    status: String,
    additions: Option<u64>,
    deletions: Option<u64>,
    binary: bool,
}
impl Inspector {
    pub fn new(
        state: impl AsRef<Path>,
        authority: String,
        allowed_origin: Option<String>,
    ) -> Result<Self> {
        let addr: std::net::SocketAddr = authority
            .parse()
            .map_err(|_| error("invalid_loopback_authority", 400))?;
        if !addr.ip().is_loopback() {
            return Err(error("loopback_required", 400));
        }
        if let Some(origin) = &allowed_origin {
            let u = url::Url::parse(origin).map_err(|_| error("invalid_origin", 400))?;
            if u.scheme() != "http"
                || !matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
                || u.path() != "/"
                || u.query().is_some()
                || u.fragment().is_some()
                || !u.username().is_empty()
                || u.password().is_some()
            {
                return Err(error("loopback_origin_required", 400));
            }
        }
        Ok(Self {
            state: fs::canonicalize(state).map_err(storage)?,
            authority,
            allowed_origin,
        })
    }
    fn snapshot(&self) -> Result<Snapshot> {
        let lock =
            File::open(contained(&self.state, &self.state.join("state.lock"))?).map_err(storage)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match fs2::FileExt::try_lock_shared(&lock) {
                Ok(()) => break,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => return Err(error("state_busy", 503)),
            }
        }
        let temp = tempfile::tempdir().map_err(storage)?;
        for name in ["state.sqlite", "state.sqlite-wal"] {
            let source = self.state.join(name);
            match fs::metadata(&source) {
                Ok(m) => {
                    if !m.is_file() || m.len() > 256 * 1024 * 1024 {
                        return Err(error("state_size_limit", 413));
                    }
                    fs::copy(contained(&self.state, &source)?, temp.path().join(name))
                        .map_err(storage)?;
                }
                Err(e) if name.ends_with("-wal") && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(storage(e)),
            }
        }
        let db = Connection::open_with_flags(
            temp.path().join("state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        let query_deadline = Instant::now() + Duration::from_secs(2);
        db.progress_handler(10_000, Some(move || Instant::now() >= query_deadline))
            .map_err(storage)?;
        db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN;")
            .map_err(storage)?;
        Ok(Snapshot {
            db,
            _temp: temp,
            _lock: lock,
        })
    }
    /// Admission is independent of source state, allowing the UI to show busy/offline errors.
    pub fn admit(
        &self,
        method: &str,
        target: &str,
        host: &str,
        origin: Option<&str>,
        fetch_site: Option<&str>,
    ) -> Result<()> {
        if method != "GET" {
            return Err(error("method_not_allowed", 405));
        }
        if host != self.authority {
            return Err(error("invalid_host", 403));
        }
        if let Some(o) = origin {
            if o != format!("http://{}", self.authority)
                && Some(o) != self.allowed_origin.as_deref()
            {
                return Err(error("origin_denied", 403));
            }
        }
        if matches!(fetch_site, Some("cross-site")) {
            return Err(error("cross_site_denied", 403));
        }
        if target.len() > 8192 || !target.starts_with('/') || target.starts_with("//") {
            return Err(error("invalid_request", 400));
        }
        Ok(())
    }
    pub fn handle(
        &self,
        method: &str,
        target: &str,
        host: &str,
        origin: Option<&str>,
        fetch_site: Option<&str>,
    ) -> Response {
        let result = (|| {
            self.admit(method, target, host, origin, fetch_site)?;
            let u = url::Url::parse(&format!("http://localhost{target}"))
                .map_err(|_| error("invalid_request", 400))?;
            let mut q = HashMap::new();
            for (k, v) in u.query_pairs() {
                if q.insert(k.into_owned(), v.into_owned()).is_some() {
                    return Err(error("duplicate_parameter", 400));
                }
            }
            if !matches!(
                u.path(),
                "/api/overview" | "/api/history" | "/api/changes" | "/api/diff"
            ) {
                return Err(error("not_found", 404));
            }
            let s = self.snapshot()?;
            match u.path() {
                "/api/overview" => self.overview(&s.db),
                "/api/history" => self.history(&s.db, &q),
                "/api/changes" => {
                    let e = entry(&s.db, required(&q, "entry")?)?;
                    let files = self.changes(&e)?;
                    let (limit, offset) = pagination(&q)?;
                    let next =
                        (files.len() > offset.saturating_add(limit)).then_some(offset + limit);
                    Ok(
                        json!({"files":files.into_iter().skip(offset).take(limit).collect::<Vec<_>>(),"next_offset":next,"comparison":comparison(&e)}),
                    )
                }
                "/api/diff" => {
                    let e = entry(&s.db, required(&q, "entry")?)?;
                    self.diff(&e, required(&q, "path")?)
                }
                _ => Err(error("not_found", 404)),
            }
        })();
        let (status, value) = match result {
            Ok(v) => (200, v),
            Err(e) => (
                e.status,
                json!({"error":{"code":e.code,"message":e.code.replace('_'," ")}}),
            ),
        };
        Response {
            status,
            body: serde_json::to_vec(&value).unwrap(),
            origin: origin
                .filter(|o| Some(*o) == self.allowed_origin.as_deref())
                .map(str::to_owned),
        }
    }
    fn overview(&self, db: &Connection) -> Result<Value> {
        let mut s = db
            .prepare("SELECT id,generation,base,checkpoint FROM workspaces ORDER BY id LIMIT 1001")
            .map_err(storage)?;
        let ws=s.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"generation":r.get::<_,i64>(1)?,"base":r.get::<_,String>(2)?,"checkpoint":r.get::<_,Option<String>>(3)?}))).map_err(storage)?.collect::<std::result::Result<Vec<_>,_>>().map_err(storage)?;
        let mut s=db.prepare("SELECT id,workspace,checkpoint,intent,state,head FROM proposals ORDER BY rowid DESC LIMIT 1001").map_err(storage)?;
        let ps=s.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"workspace":r.get::<_,String>(1)?,"checkpoint":r.get::<_,String>(2)?,"message":r.get::<_,String>(3)?,"state":r.get::<_,String>(4)?,"head":r.get::<_,Option<String>>(5)?}))).map_err(storage)?.collect::<std::result::Result<Vec<_>,_>>().map_err(storage)?;
        let mut s=db.prepare("SELECT id,workspace,target,base,generation,state FROM adoption_conflicts ORDER BY rowid DESC LIMIT 1001").map_err(storage)?;
        let cs=s.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"workspace":r.get::<_,String>(1)?,"target":r.get::<_,String>(2)?,"base":r.get::<_,String>(3)?,"generation":r.get::<_,i64>(4)?,"state":r.get::<_,String>(5)?}))).map_err(storage)?.collect::<std::result::Result<Vec<_>,_>>().map_err(storage)?;
        if ws.len() > 1000 || ps.len() > 1000 || cs.len() > 1000 {
            return Err(error("overview_size_limit", 413));
        }
        Ok(json!({"read_only":true,"workspaces":ws,"proposals":ps,"conflicts":cs}))
    }
    fn history(&self, db: &Connection, q: &HashMap<String, String>) -> Result<Value> {
        let (limit, offset) = pagination(q)?;
        let kind = q.get("kind").map(String::as_str).unwrap_or("private");
        if !matches!(kind, "private" | "shared") {
            return Err(error("invalid_kind", 400));
        }
        let query = if kind == "private" {
            entry_select("checkpoint").to_owned()
        } else {
            format!(
                "{} UNION ALL {}",
                entry_select("proposal"),
                entry_select("promotion")
            )
        };
        let query=format!("SELECT * FROM ({query}) WHERE (?1 IS NULL OR workspace=?1) ORDER BY sequence DESC,source DESC,ordinal DESC LIMIT ?2 OFFSET ?3");
        let mut stmt = db.prepare(&query).map_err(storage)?;
        let mut entries = stmt
            .query_map(
                rusqlite::params![
                    q.get("workspace").filter(|s| !s.is_empty()),
                    (limit + 1) as i64,
                    offset as i64
                ],
                entry_row,
            )
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let next = (entries.len() > limit).then_some(offset + limit);
        entries.truncate(limit);
        Ok(json!({"entries":entries,"next_offset":next}))
    }
    fn repo(&self, e: &Entry) -> Result<PathBuf> {
        if !identifier(&e.workspace) && e.kind != "promotion" {
            return Err(error("invalid_stored_workspace", 503));
        }
        if !oid(&e.commit) || !oid(&e.base) {
            return Err(error("invalid_stored_object", 503));
        }
        let mut public = self.state.join("coordinator.git");
        if public.exists() {
            public = contained(&self.state, &public)?;
        }
        let repo = if e.kind == "promotion"
            || e.kind == "proposal"
                && public.is_dir()
                && git(
                    &public,
                    &["cat-file", "-e", &format!("{}^{{commit}}", e.commit)],
                    1024,
                )
                .is_ok()
        {
            public
        } else {
            self.state
                .join("locals")
                .join(&e.workspace)
                .join("objects.git")
        };
        let canonical = fs::canonicalize(repo).map_err(storage)?;
        if !canonical.starts_with(&self.state) {
            return Err(error("repository_outside_state", 403));
        }
        Ok(canonical)
    }
    fn changes(&self, e: &Entry) -> Result<Vec<Change>> {
        let repo = self.repo(e)?;
        let output = git(
            &repo,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--numstat",
                "-z",
                &e.base,
                &e.commit,
                "--",
            ],
            2 * 1024 * 1024,
        )?;
        if output.1 {
            return Err(error("changed_files_limit", 413));
        }
        let mut files = Vec::new();
        for record in output.0.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let mut fields = record.splitn(3, |b| *b == b'\t');
            let a = fields.next().unwrap_or_default();
            let d = fields.next().ok_or(error("invalid_git_output", 503))?;
            let p = fields.next().ok_or(error("invalid_git_output", 503))?;
            let path = String::from_utf8(p.to_vec()).map_err(|_| error("non_utf8_path", 422))?;
            files.push(Change {
                path,
                status: "modified".into(),
                additions: std::str::from_utf8(a).ok().and_then(|s| s.parse().ok()),
                deletions: std::str::from_utf8(d).ok().and_then(|s| s.parse().ok()),
                binary: a == b"-",
            });
        }
        // Name-status is a separate byte-safe stream; rename detection is disabled.
        let status = git(
            &repo,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--name-status",
                "-z",
                &e.base,
                &e.commit,
                "--",
            ],
            2 * 1024 * 1024,
        )?;
        if status.1 {
            return Err(error("changed_files_limit", 413));
        }
        let parts: Vec<_> = status
            .0
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .collect();
        let map: HashMap<_, _> = parts
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| (p[1], p[0]))
            .collect();
        for f in &mut files {
            f.status = match map.get(f.path.as_bytes()).and_then(|x| x.first()) {
                Some(b'A') => "added",
                Some(b'D') => "deleted",
                Some(b'T') => "type_changed",
                _ => "modified",
            }
            .into();
        }
        Ok(files)
    }
    fn diff(&self, e: &Entry, path: &str) -> Result<Value> {
        if path.is_empty() || path.len() > 4096 || path.contains('\0') {
            return Err(error("invalid_path", 400));
        }
        let change = self
            .changes(e)?
            .into_iter()
            .find(|c| c.path == path)
            .ok_or(error("file_not_found", 404))?;
        if change.binary {
            return Ok(json!({"path":path,"text":"","binary":true,"truncated":false}));
        }
        let (bytes, truncated) = git(
            &self.repo(e)?,
            &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--no-color",
                "--unified=3",
                &e.base,
                &e.commit,
                "--",
                path,
            ],
            256 * 1024,
        )?;
        Ok(
            json!({"path":path,"text":String::from_utf8_lossy(&bytes),"binary":false,"truncated":truncated}),
        )
    }
}
fn comparison(e: &Entry) -> &'static str {
    match e.kind.as_str() {
        "checkpoint" => "adopted_base",
        "promotion" => "previous_shared_head",
        _ => "proposal_base",
    }
}
fn entry_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
    Ok(Entry {
        id: r.get(0)?,
        workspace: r.get(1)?,
        kind: r.get(2)?,
        title: r.get(3)?,
        status: r.get(4)?,
        commit: r.get(5)?,
        base: r.get(6)?,
        generation: r.get(7)?,
        sequence: r.get(8)?,
    })
}
fn entry(db: &Connection, id: &str) -> Result<Entry> {
    let (kind, id) = id.split_once(':').ok_or(error("invalid_entry", 400))?;
    if !identifier(id) {
        return Err(error("invalid_entry", 400));
    }
    if !matches!(kind, "checkpoint" | "proposal" | "promotion") {
        return Err(error("invalid_entry", 400));
    }
    let query = format!("SELECT * FROM ({}) WHERE id=?1", entry_select(kind));
    db.query_row(&query, [format!("{kind}:{id}")], entry_row)
        .optional()
        .map_err(storage)?
        .ok_or(error("entry_not_found", 404))
}
fn contained(root: &Path, path: &Path) -> Result<PathBuf> {
    let p = fs::canonicalize(path).map_err(storage)?;
    if !p.starts_with(root) {
        return Err(error("path_outside_state", 403));
    }
    Ok(p)
}
fn entry_select(kind: &str) -> &'static str {
    match kind{
 "checkpoint"=>"SELECT 'checkpoint:'||c.id AS id,c.workspace,'checkpoint','Recovery record '||c.id,'local_saved',c.commit_oid,c.base,c.generation,(SELECT MAX(e.seq) FROM events e WHERE e.kind='checkpoint' AND json_extract(CASE WHEN json_valid(e.data) THEN e.data ELSE '{}' END,'$.checkpoint')=c.id) AS sequence,c.rowid AS ordinal,0 AS source FROM checkpoints c",
 "proposal"=>"SELECT 'proposal:'||p.id AS id,p.workspace,'proposal',p.intent,p.state,p.commit_oid,p.base,NULL,(SELECT MAX(e.seq) FROM events e WHERE e.kind='published' AND json_extract(CASE WHEN json_valid(e.data) THEN e.data ELSE '{}' END,'$.proposal')=p.id) AS sequence,p.rowid AS ordinal,0 AS source FROM proposals p",
 _=>"SELECT 'promotion:'||p.id AS id,COALESCE(q.workspace,'') AS workspace,'promotion','Shared integration '||p.id,p.state,p.new,p.old,NULL,(SELECT MAX(e.seq) FROM events e WHERE e.kind='integrated' AND json_extract(CASE WHEN json_valid(e.data) THEN e.data ELSE '{}' END,'$.proposal')=p.proposal AND json_extract(CASE WHEN json_valid(e.data) THEN e.data ELSE '{}' END,'$.head')=p.new) AS sequence,p.rowid AS ordinal,1 AS source FROM promotions p LEFT JOIN proposals q ON q.id=p.proposal"
}
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn required<'a>(q: &'a HashMap<String, String>, key: &str) -> Result<&'a str> {
    q.get(key)
        .map(String::as_str)
        .ok_or(error("missing_parameter", 400))
}
fn pagination(q: &HashMap<String, String>) -> Result<(usize, usize)> {
    let parse = |k: &str, default, max| -> Result<usize> {
        match q.get(k) {
            None => Ok(default),
            Some(v) => v
                .parse::<usize>()
                .ok()
                .filter(|n| *n <= max)
                .ok_or(error("invalid_pagination", 400)),
        }
    };
    let l = parse("limit", 50, 200)?;
    if l == 0 {
        return Err(error("invalid_pagination", 400));
    }
    Ok((l, parse("offset", 0, 1_000_000)?))
}
fn drain(mut r: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut b = [0; 8192];
    loop {
        match r.read(&mut b) {
            Ok(0) => break,
            Err(e) => return Err(e),
            Ok(n) => {
                let keep = n.min(limit - out.len());
                out.extend_from_slice(&b[..keep]);
                truncated |= keep < n;
            }
        }
    }
    Ok((out, truncated))
}
fn git(repo: &Path, args: &[&str], limit: usize) -> Result<(Vec<u8>, bool)> {
    let process_path = wipstash_platform::git_path::argument(repo)
        .map_err(|_| error("unsupported_git_path", 422))?;
    let mut c = Command::new("git");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("GIT_") {
            c.env_remove(k);
        }
    }
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    c.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_CONFIG_SYSTEM", null)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_LITERAL_PATHSPECS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .arg("--no-pager")
        .arg("--git-dir")
        .arg(process_path)
        .args([
            "-c",
            &format!("core.hooksPath={null}"),
            "-c",
            &format!("core.attributesFile={null}"),
            "-c",
            "diff.algorithm=myers",
            "-c",
            "diff.renames=false",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().map_err(storage)?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || drain(stdout, limit));
    let err = std::thread::spawn(move || drain(stderr, 8192));
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let output = out.join().map_err(storage)?.map_err(storage)?;
    err.join().map_err(storage)?.map_err(storage)?;
    match status {
        None => Err(error("git_timeout", 503)),
        Some(s) if !s.success() => Err(error("objects_unavailable", 503)),
        _ => Ok(output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inspector() -> (tempfile::TempDir, Inspector) {
        let dir = tempfile::tempdir().unwrap();
        let i = Inspector::new(dir.path(), "127.0.0.1:47831".into(), None).unwrap();
        (dir, i)
    }
    #[test]
    fn admission_requires_loopback_host_and_origin() {
        let (_d, i) = inspector();
        assert_eq!(
            i.handle("POST", "/api/overview", &i.authority, None, None)
                .status,
            405
        );
        assert_eq!(
            i.handle("GET", "/api/overview", "evil.test", None, None)
                .status,
            403
        );
        assert_eq!(
            i.handle(
                "GET",
                "/api/overview",
                &i.authority,
                Some("http://evil.test"),
                None
            )
            .status,
            403
        );
        assert_eq!(
            i.handle(
                "GET",
                "/api/overview",
                &i.authority,
                None,
                Some("cross-site")
            )
            .status,
            403
        );
        assert!(Inspector::new(".", "0.0.0.0:47831".into(), None).is_err());
    }
    #[test]
    fn no_initialization_even_on_read() {
        let (d, i) = inspector();
        assert_eq!(
            i.handle("GET", "/api/overview", &i.authority, None, None)
                .status,
            503
        );
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
        assert_eq!(
            i.handle("GET", "/api/unknown", &i.authority, None, None)
                .status,
            404
        );
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }
    #[test]
    fn lock_contention_is_bounded() {
        let (d, i) = inspector();
        let lock = File::create(d.path().join("state.lock")).unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        let start = Instant::now();
        let r = i.handle("GET", "/api/overview", &i.authority, None, None);
        assert_eq!(r.status, 503);
        assert!(String::from_utf8(r.body).unwrap().contains("state_busy"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn output_is_bounded_and_errors_not_swallowed() {
        assert_eq!(drain(&b"abcdef"[..], 3).unwrap(), (b"abc".to_vec(), true));
        struct Bad;
        impl Read for Bad {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("failed"))
            }
        }
        assert!(drain(Bad, 2).is_err());
    }
    #[test]
    fn query_only_snapshot_cannot_write() {
        let (d, i) = inspector();
        File::create(d.path().join("state.lock")).unwrap();
        let db = Connection::open(d.path().join("state.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE x(n INTEGER); INSERT INTO x VALUES(1);")
            .unwrap();
        drop(db);
        let before = fs::read(d.path().join("state.sqlite")).unwrap();
        let snapshot = i.snapshot().unwrap();
        assert!(snapshot.db.execute("INSERT INTO x VALUES(2)", []).is_err());
        assert_eq!(
            snapshot
                .db
                .query_row("SELECT n FROM x", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(snapshot);
        assert_eq!(before, fs::read(d.path().join("state.sqlite")).unwrap());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 2);
    }
    #[test]
    fn sqlite_runtime_meets_security_floor() {
        assert!(
            rusqlite::version_number() >= 3_051_003,
            "{}",
            rusqlite::version()
        );
    }
    #[test]
    fn cors_requires_exact_configured_origin() {
        let d = tempfile::tempdir().unwrap();
        let i = Inspector::new(
            d.path(),
            "127.0.0.1:47831".into(),
            Some("http://127.0.0.1:8080".into()),
        )
        .unwrap();
        let r = i.handle(
            "GET",
            "/api/unknown",
            &i.authority,
            Some("http://127.0.0.1:8080"),
            None,
        );
        assert_eq!(r.status, 404);
        assert_eq!(r.origin.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(
            i.handle(
                "GET",
                "/api/unknown",
                &i.authority,
                Some("http://127.0.0.1:8081"),
                None
            )
            .status,
            403
        );
    }
}
