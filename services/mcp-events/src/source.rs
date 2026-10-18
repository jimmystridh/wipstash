//! Read-only bridge. Never invokes the engine (even status can recover state).
use ring::digest::{digest, SHA256};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    path::{Path, PathBuf},
};
#[derive(Debug, Clone)]
pub struct Transition {
    pub id: String,
    pub name: String,
    pub project: String,
    pub workspace: Option<String>,
    pub proposal: Option<String>,
    pub occurred_at: i64,
    pub status: String,
}
pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:".contains(&c))
}
fn stable(parts: &[&str]) -> String {
    let h = digest(
        &SHA256,
        &serde_json::to_vec(parts).expect("string array serializes"),
    );
    format!(
        "evt_{}",
        h.as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
fn db(path: &Path) -> Result<(Connection, File), String> {
    let lock = File::open(path.join("state.lock")).map_err(|_| "project_unavailable")?;
    fs2::FileExt::try_lock_shared(&lock).map_err(|error| {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
            "project_busy"
        } else {
            "project_unavailable"
        }
    })?;
    let conn =
        Connection::open_with_flags(path.join("state.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| "project_unavailable")?;
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|_| "project_unavailable")?;
    let has_meta: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
            [],
            |r| r.get(0),
        )
        .map_err(|_| "project_unavailable")?;
    if has_meta {
        let config: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key='sync_config'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|_| "project_unavailable")?;
        if let Some(config) = config {
            let config: Value = serde_json::from_str(&config).map_err(|_| "project_unavailable")?;
            if config["role"] == "client" {
                return Err("authority_source_required".into());
            }
        }
    }
    Ok((conn, lock))
}
pub struct Source {
    projects: BTreeMap<String, PathBuf>,
    cursors: BTreeMap<String, i64>,
    pub degraded: bool,
}
impl Source {
    pub fn new(projects: BTreeMap<String, PathBuf>) -> Result<Self, String> {
        if projects.keys().any(|p| !identifier(p)) {
            return Err("invalid_project_id".into());
        }
        let mut s = Self {
            projects,
            cursors: BTreeMap::new(),
            degraded: false,
        };
        for (p, path) in &s.projects {
            if let Ok((c, _l)) = db(path) {
                if let Ok(seq) = c.query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| {
                    r.get::<_, i64>(0)
                }) {
                    s.cursors.insert(p.clone(), seq);
                    continue;
                }
            }
            s.degraded = true;
        }
        Ok(s)
    }
    pub fn poll(&mut self, now: i64) -> Vec<Transition> {
        let mut output = Vec::new();
        for (project, path) in &self.projects {
            let result = (|| -> Result<Vec<Transition>, String> {
                let (c, _lock) = db(path)?;
                let end: i64 = c
                    .query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| r.get(0))
                    .map_err(|_| "project_unavailable")?;
                let Some(cursor) = self.cursors.get(project).copied() else {
                    self.cursors.insert(project.clone(), end);
                    return Ok(Vec::new());
                };
                if end < cursor {
                    self.cursors.insert(project.clone(), end);
                    return Err("event_source_reset".into());
                }
                let mut stmt=c.prepare("SELECT seq,kind,CASE WHEN length(CAST(data AS BLOB))<=65536 THEN data ELSE NULL END FROM events WHERE seq>?1 ORDER BY seq LIMIT 1025").map_err(|_|"project_unavailable")?;
                let rows = stmt
                    .query_map([cursor], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, Option<String>>(2)?,
                        ))
                    })
                    .map_err(|_| "project_unavailable")?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| "project_unavailable")?;
                self.cursors.insert(project.clone(), end);
                if rows.len() > 1024 {
                    return Err("event_source_overflow".into());
                }
                let mut result = Vec::new();
                for (seq, kind, raw) in rows {
                    if !matches!(
                        kind.as_str(),
                        "quarantined" | "integrated" | "already_included"
                    ) {
                        continue;
                    }
                    let Some(raw) = raw else {
                        self.degraded = true;
                        continue;
                    };
                    let data: Value =
                        serde_json::from_str(&raw).map_err(|_| "event_source_invalid")?;
                    let Some(at) = data["_occurred_at"].as_i64() else {
                        self.degraded = true;
                        continue;
                    };
                    if at > now || now.saturating_sub(at) >= 300 {
                        self.degraded = true;
                        continue;
                    }
                    let proposal = data["proposal"]
                        .as_str()
                        .filter(|p| identifier(p))
                        .ok_or("event_source_invalid")?;
                    let current: Option<(String, String)> = c
                        .query_row(
                            "SELECT workspace,state FROM proposals WHERE id=?1",
                            [proposal],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()
                        .map_err(|_| "project_unavailable")?;
                    let Some((workspace, state)) = current else {
                        continue;
                    };
                    if !identifier(&workspace) {
                        return Err("event_source_invalid".into());
                    }
                    if kind == "quarantined" && state != "quarantined" {
                        continue;
                    }
                    let (name, status) = if kind == "quarantined" {
                        let status = match data["resolution_task"]["reason"].as_str() {
                            Some("merge_conflict") => "conflict",
                            Some("required_checks_failed") => "checks_failed",
                            _ => "policy_error",
                        };
                        ("action_required", status)
                    } else {
                        (
                            "proposal.integrated",
                            if kind == "already_included" {
                                "already_included"
                            } else {
                                "integrated"
                            },
                        )
                    };
                    result.push(Transition {
                        id: stable(&[project, name, &seq.to_string()]),
                        name: name.into(),
                        project: project.clone(),
                        workspace: Some(workspace),
                        proposal: Some(proposal.into()),
                        occurred_at: at,
                        status: status.into(),
                    });
                    if kind == "integrated" {
                        let head = data["head"]
                            .as_str()
                            .filter(|h| h.len() == 40 && h.bytes().all(|c| c.is_ascii_hexdigit()))
                            .ok_or("event_source_invalid")?;
                        let name = "public_head.advanced";
                        result.push(Transition {
                            id: stable(&[project, name, head]),
                            name: name.into(),
                            project: project.clone(),
                            workspace: None,
                            proposal: Some(proposal.into()),
                            occurred_at: at,
                            status: "advanced".into(),
                        });
                    }
                }
                Ok(result)
            })();
            match result {
                Ok(events) => output.extend(events),
                // Writers briefly hold the state lock. Preserve the cursor and retry;
                // contention alone does not imply a lost event or degraded delivery.
                Err(error) if error == "project_busy" => {}
                Err(_) => self.degraded = true,
            }
        }
        output
    }
    pub fn status(
        &self,
        project: &str,
        workspace: Option<&str>,
        proposal: Option<&str>,
    ) -> Result<Value, String> {
        let path = self.projects.get(project).ok_or("unknown_project")?;
        if workspace.is_some_and(|v| !identifier(v)) || proposal.is_some_and(|v| !identifier(v)) {
            return Err("invalid_filter".into());
        }
        let (c, _lock) = db(path)?;
        let mut stmt=c.prepare("SELECT id,workspace,state FROM proposals WHERE (?1 IS NULL OR workspace=?1) AND (?2 IS NULL OR id=?2) ORDER BY rowid DESC LIMIT 101").map_err(|_|"project_unavailable")?;
        let mut rows = stmt
            .query_map(rusqlite::params![workspace, proposal], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| "project_unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "project_unavailable")?;
        let truncated = rows.len() > 100;
        rows.truncate(100);
        let proposals: Vec<Value> = rows
            .into_iter()
            .filter(|(p, w, _)| identifier(p) && identifier(w))
            .map(|(p, w, s)| {
                let safe = match s.as_str() {
                    "pending"
                    | "local_queued"
                    | "coordinator_accepted"
                    | "quarantined"
                    | "integrated"
                    | "already_included"
                    | "superseded"
                    | "cancelled" => s.as_str(),
                    _ => "unknown",
                };
                json!({"proposal_id":p,"workspace_id":w,"status":safe})
            })
            .collect();
        let observed:Option<(i64,Option<String>)>=c.query_row("SELECT seq,CASE WHEN length(CAST(data AS BLOB))<=65536 AND json_valid(data) THEN json_extract(data,'$.head') ELSE NULL END FROM events WHERE kind IN ('initialized','integrated') ORDER BY seq DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|"project_unavailable")?;
        let head = observed.and_then(|(_, h)| {
            h.filter(|h| h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(|h| json!({"head_id":h}))
        });
        let has_promotions:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='promotions')",[],|r|r.get(0)).map_err(|_|"project_unavailable")?;
        let promotion_pending: bool = has_promotions
            && c.query_row(
                "SELECT EXISTS(SELECT 1 FROM promotions WHERE state='intent')",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "project_unavailable")?;
        Ok(
            json!({"project_id":project,"proposals":proposals,"last_committed_public_head":head,"promotion_pending":promotion_pending,"truncated":truncated,"recheck_required":true}),
        )
    }
    pub fn still_relevant(&self, event: &Transition) -> bool {
        if event.name != "action_required" {
            return true;
        }
        let Some(p) = event.proposal.as_deref() else {
            return false;
        };
        self.status(&event.project, None, Some(p))
            .ok()
            .and_then(|v| v["proposals"].as_array().cloned())
            .is_some_and(|p| p.iter().any(|p| p["status"] == "quarantined"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Connection, BTreeMap<String, PathBuf>) {
        let d = tempfile::tempdir().unwrap();
        File::create(d.path().join("state.lock")).unwrap();
        let c = Connection::open(d.path().join("state.sqlite")).unwrap();
        c.execute_batch("CREATE TABLE events(seq INTEGER PRIMARY KEY,kind TEXT,data TEXT); CREATE TABLE proposals(id TEXT PRIMARY KEY,workspace TEXT,state TEXT); INSERT INTO proposals VALUES('p1','w1','quarantined');").unwrap();
        let p = BTreeMap::from([("project1".into(), d.path().to_path_buf())]);
        (d, c, p)
    }
    fn append(c: &Connection, at: i64) {
        c.execute("INSERT INTO events(kind,data) VALUES('quarantined',?1)",[json!({"proposal":"p1","_occurred_at":at,"resolution_task":{"reason":"merge_conflict","path":"/secret","checks":["private-output"]},"private_wip":"password"}).to_string()]).unwrap();
    }
    #[test]
    fn transient_writer_contention_preserves_cursor_without_false_degradation() {
        let (d, c, p) = fixture();
        let mut source = Source::new(p).unwrap();
        let lock = File::open(d.path().join("state.lock")).unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        append(&c, 1000);
        assert!(source.poll(1000).is_empty());
        assert!(!source.degraded);
        fs2::FileExt::unlock(&lock).unwrap();
        assert_eq!(source.poll(1001).len(), 1);
        assert!(!source.degraded);
        assert!(source.poll(1001).is_empty());
    }
    #[test]
    fn startup_and_restart_do_not_replay_but_new_attempt_is_distinct() {
        let (_d, c, p) = fixture();
        append(&c, 1000);
        let mut s = Source::new(p.clone()).unwrap();
        assert!(s.poll(1000).is_empty());
        append(&c, 1001);
        let a = s.poll(1001);
        assert_eq!(a.len(), 1);
        assert!(s.poll(1001).is_empty());
        append(&c, 1002);
        let b = s.poll(1002);
        assert_ne!(a[0].id, b[0].id);
        assert_eq!(b[0].status, "conflict");
        assert!(Source::new(p).unwrap().poll(1002).is_empty());
    }
    #[test]
    fn stale_superseded_and_private_content_never_escape() {
        let (_d, c, p) = fixture();
        let mut s = Source::new(p).unwrap();
        append(&c, 100);
        assert!(s.poll(400).is_empty());
        assert!(s.degraded);
        append(&c, 401);
        c.execute("UPDATE proposals SET state='superseded'", [])
            .unwrap();
        assert!(s.poll(401).is_empty());
        let v = s.status("project1", None, None).unwrap().to_string();
        assert!(!v.contains("private"));
        assert!(!v.contains("secret"));
    }
    #[test]
    fn overflow_is_bounded_and_visible() {
        let (_d, c, p) = fixture();
        let mut s = Source::new(p).unwrap();
        for _ in 0..1025 {
            append(&c, 1000);
        }
        assert!(s.poll(1000).is_empty());
        assert!(s.degraded);
        assert!(s.poll(1000).is_empty());
    }
    #[test]
    fn already_included_does_not_advance_head_and_filters_are_bound() {
        let (_d, c, p) = fixture();
        let mut s = Source::new(p).unwrap();
        c.execute(
            "INSERT INTO events(kind,data) VALUES('already_included',?1)",
            [json!({"proposal":"p1","_occurred_at":1000}).to_string()],
        )
        .unwrap();
        let es = s.poll(1000);
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].name, "proposal.integrated");
        assert!(s.status("other", None, None).is_err());
        assert!(s.status("project1", Some("../../private"), None).is_err());
        assert_eq!(
            s.status("project1", Some("w2"), None).unwrap()["proposals"],
            json!([])
        );
    }
    #[test]
    fn oversized_private_records_are_not_materialized_or_delivered() {
        let (_d, c, p) = fixture();
        let mut s = Source::new(p).unwrap();
        c.execute(
            "INSERT INTO events(kind,data) VALUES('quarantined',?1)",
            [
                json!({"proposal":"p1","_occurred_at":1000,"private":"x".repeat(65537)})
                    .to_string(),
            ],
        )
        .unwrap();
        assert!(s.poll(1000).is_empty());
        assert!(s.degraded);
    }
    #[test]
    fn status_exposes_only_committed_head_observation_and_pending_recovery() {
        let (_d, c, p) = fixture();
        let s = Source::new(p).unwrap();
        let h = "a".repeat(40);
        c.execute(
            "INSERT INTO events(kind,data) VALUES('integrated',?1)",
            [json!({"head":h,"private_path":"/secret"}).to_string()],
        )
        .unwrap();
        c.execute_batch(
            "CREATE TABLE promotions(state TEXT); INSERT INTO promotions VALUES('intent');",
        )
        .unwrap();
        let v = s.status("project1", None, None).unwrap();
        assert_eq!(v["last_committed_public_head"]["head_id"], h);
        assert_eq!(v["promotion_pending"], true);
        assert!(v["last_committed_public_head"].get("sequence").is_none());
        assert!(!v.to_string().contains("secret"));
    }
}
