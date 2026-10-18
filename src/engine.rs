#[path = "engine_feedback.rs"]
mod feedback;
#[path = "engine_resolution.rs"]
mod resolution;
#[path = "engine_sync.rs"]
mod sync;
use crate::{adoption, git::Git};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};
type R<T> = Result<T, String>;
const HEAD: &str = "refs/wipstash/integration";
#[track_caller]
fn sql<T>(v: rusqlite::Result<T>) -> R<T> {
    let caller = std::panic::Location::caller();
    v.map_err(|e| match &e {
        rusqlite::Error::SqliteFailure(code, _) => format!(
            "storage_error: {e}; sqlite_code={:?}; extended_code={}; site={}:{}",
            code.code,
            code.extended_code,
            caller.file(),
            caller.line()
        ),
        _ => format!(
            "storage_error: {e}; site={}:{}",
            caller.file(),
            caller.line()
        ),
    })
}
fn sqlite_diagnostics_requested(value: Option<&str>) -> bool {
    value == Some("1")
}
fn sqlite_phase(started: std::time::Instant, phase: &str) {
    if sqlite_diagnostics_requested(std::env::var("WIPSTASH_SQLITE_DIAGNOSTICS").ok().as_deref()) {
        // Fixed phase labels only: no SQL, request payloads, or user paths.
        eprintln!(
            "wipstash_sqlite_phase pid={} phase={} elapsed_ms={}",
            std::process::id(),
            phase,
            started.elapsed().as_millis()
        );
    }
}
fn io<T>(v: std::io::Result<T>) -> R<T> {
    v.map_err(|e| format!("io_error: {e}"))
}
fn field<'a>(r: &'a Value, k: &str) -> R<&'a str> {
    r[k].as_str()
        .ok_or_else(|| format!("invalid_request: missing {k}"))
}
fn ident(s: &str) -> R<()> {
    if s.is_empty()
        || s.len() > 100
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Err("invalid_request: invalid identifier".into())
    } else {
        Ok(())
    }
}
fn digest(r: &Value) -> String {
    format!("{:x}", Sha256::digest(serde_json::to_vec(r).unwrap()))
}
fn fault(name: &str) {
    if std::env::var("WIPSTASH_FAULT").ok().as_deref() == Some(name) {
        std::process::exit(86)
    }
}
fn event(db: &Connection, kind: &str, data: &Value) -> R<()> {
    let mut data = data.clone();
    data["_occurred_at"] = json!(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs());
    sql(db.execute(
        "INSERT INTO events(kind,data) VALUES(?1,?2)",
        params![kind, data.to_string()],
    ))?;
    Ok(())
}
fn finish(db: &Connection, id: &str, result: &Value) -> R<()> {
    // Decorate before the transactional finish too, so crash recovery and a
    // normal response persist the same advisory context at this generation.
    let request: Option<String> = sql(db
        .query_row("SELECT request FROM operations WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional())?;
    let result = request
        .and_then(|r| serde_json::from_str::<Value>(&r).ok())
        .map(|r| feedback::complete(db, &r, result.clone()))
        .unwrap_or_else(|| result.clone());
    sql(db.execute(
        "UPDATE operations SET result=?2 WHERE id=?1",
        params![id, result.to_string()],
    ))?;
    Ok(())
}
/// Structured, read-only recovery advice for failures before operation journaling.
pub fn error_response(error: &str) -> Value {
    feedback::error(error)
}
#[derive(Debug)]
struct Workspace {
    path: PathBuf,
    base: String,
    checkpoint: Option<String>,
    generation: i64,
}
fn ws(db: &Connection, id: &str) -> R<Workspace> {
    ident(id)?;
    sql(db.query_row(
        "SELECT path,base,checkpoint,generation FROM workspaces WHERE id=?1",
        [id],
        |r| {
            Ok(Workspace {
                path: PathBuf::from(r.get::<_, String>(0)?),
                base: r.get(1)?,
                checkpoint: r.get(2)?,
                generation: r.get(3)?,
            })
        },
    ))
    .map_err(|_| "workspace_not_found".into())
}
fn local(state: &Path, id: &str) -> Git {
    Git::open(&state.join("locals").join(id).join("objects.git"))
}
fn coordinator(state: &Path) -> Git {
    Git::open(&state.join("coordinator.git"))
}
fn generation(r: &Value, w: &Workspace) -> R<()> {
    if r["expected_generation"].as_i64() != Some(w.generation) {
        Err(format!("generation_mismatch: current {}", w.generation))
    } else {
        Ok(())
    }
}
fn transfer(from: &Git, to: &Git, oid: &str, reference: &str) -> R<()> {
    // A reachable public root is the only fetch want; private ancestry is never a parent.
    to.run_local_repository(
        &[
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--recurse-submodules=no",
        ],
        &from.repo,
        &[&format!("{oid}:{reference}")],
    )?;
    Ok(())
}
fn init_db(db: &Connection) -> R<()> {
    sql(db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY,path TEXT UNIQUE NOT NULL,base TEXT NOT NULL,checkpoint TEXT,generation INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS checkpoints(id TEXT PRIMARY KEY,workspace TEXT NOT NULL REFERENCES workspaces(id),commit_oid TEXT NOT NULL,tree TEXT NOT NULL,base TEXT NOT NULL,generation INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,checkpoint TEXT NOT NULL,commit_oid TEXT NOT NULL,base TEXT NOT NULL,intent TEXT NOT NULL,state TEXT NOT NULL,head TEXT,details TEXT);
 CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,digest TEXT NOT NULL,request TEXT NOT NULL,result TEXT);
 CREATE TABLE IF NOT EXISTS candidates(id TEXT PRIMARY KEY,head TEXT NOT NULL,proposal TEXT NOT NULL,tree TEXT NOT NULL,policy_hash TEXT NOT NULL,evidence TEXT NOT NULL,state TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS promotions(id TEXT PRIMARY KEY,proposal TEXT NOT NULL,old TEXT NOT NULL,new TEXT NOT NULL,state TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS adoptions(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,old_base TEXT NOT NULL,target TEXT NOT NULL,commit_oid TEXT NOT NULL,tree TEXT NOT NULL,old_files TEXT NOT NULL,new_files TEXT NOT NULL,stage TEXT NOT NULL,backup TEXT NOT NULL,state TEXT NOT NULL,generation INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS adoption_conflicts(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,target TEXT NOT NULL,base TEXT NOT NULL,generation INTEGER NOT NULL,state TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,workspace TEXT NOT NULL REFERENCES workspaces(id),state TEXT NOT NULL,generation INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,data TEXT NOT NULL);
 PRAGMA user_version=1;"))?;
    resolution::schema(db)?;
    Ok(())
}
fn recover(state: &Path, db: &Connection, local_only: bool) -> R<()> {
    // Upgrade incomplete operations from before the command journal existed.
    // Also conservatively fence a crash in the narrow pre-journal window.
    let mut pending = sql(db.prepare("SELECT o.id,o.request FROM operations o LEFT JOIN commands c ON c.id=o.id WHERE o.result IS NULL AND c.id IS NULL"))?;
    let pending =
        sql(pending.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
    for (id, request) in pending {
        let request: Value = serde_json::from_str(&request).map_err(|e| e.to_string())?;
        if request["op"] != "command_run" {
            continue;
        }
        let Some(wid) = request["workspace"].as_str() else {
            continue;
        };
        let Ok(w) = ws(db, wid) else {
            continue;
        };
        sql(db.execute_batch("BEGIN IMMEDIATE"))?;
        sql(db.execute(
            "INSERT INTO commands(id,workspace,state,generation) VALUES(?1,?2,'running',?3)",
            params![id, wid, w.generation + 1],
        ))?;
        sql(db.execute(
            "UPDATE workspaces SET generation=generation+1 WHERE id=?1",
            [wid],
        ))?;
        sql(db.execute_batch("COMMIT"))?;
    }
    // A persisted running intent outlived its engine lock owner. Never replay it:
    // descendants may still write, and PID reuse makes blind termination unsafe.
    let mut commands =
        sql(db.prepare("SELECT id,workspace,generation FROM commands WHERE state='running'"))?;
    let interrupted = sql(commands.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    }))?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|e| e.to_string())?;
    for (id, wid, generation) in interrupted {
        sql(db.execute_batch("BEGIN IMMEDIATE"))?;
        sql(db.execute("UPDATE commands SET state='uncertain' WHERE id=?1", [&id]))?;
        finish(
            db,
            &id,
            &json!({"ok":false,"state":"interrupted","generation":generation,"error":{"code":"writer_recovery_required","message":"Command outcome is unknown; stop unmanaged writers, then explicitly acknowledge with command_recover. Command was not replayed."}}),
        )?;
        event(
            db,
            "command_interrupted",
            &json!({"operation_id":id,"workspace":wid}),
        )?;
        sql(db.execute_batch("COMMIT"))?;
    }
    let git = coordinator(state);
    // Private adoption recovery is independent of coordinator availability.
    // Only promotion replay requires the shared object store.
    if git.repo.exists() {
        let mut stmt =
            sql(db.prepare("SELECT id,proposal,old,new FROM promotions WHERE state='intent'"))?;
        let rows = sql(stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        }))?;
        for row in rows {
            let (id, p, old, new) = sql(row)?;
            let head = git.head(HEAD)?;
            if head == old {
                git.set_ref(HEAD, &new, Some(&old))?;
            } else {
                let first =
                    String::from_utf8(git.run(&["rev-list", "--first-parent", &head], None)?)
                        .map_err(|e| e.to_string())?;
                if !first.lines().any(|x| x == new) {
                    if local_only {
                        continue;
                    }
                    return Err("recovery_required: unexpected integration head".into());
                }
            }
            sql(db.execute_batch("BEGIN IMMEDIATE"))?;
            sql(db.execute("UPDATE promotions SET state='committed' WHERE id=?1", [&id]))?;
            sql(db.execute(
                // A prior retry may have left evidence for another candidate.
                // Recovery proves the public CAS, not which old details apply.
                "UPDATE proposals SET state='integrated',head=?2,details=NULL WHERE id=?1",
                params![p, new],
            ))?;
            event(
                db,
                "integrated",
                &json!({"proposal":p,"head":new,"evidence":"unchecked","recovered":true}),
            )?;
            sql(db.execute_batch("COMMIT"))?;
        }
    }
    let mut stmt=sql(db.prepare("SELECT id,workspace,old_files,new_files,backup,state FROM adoptions WHERE state IN ('applying','applied')"))?;
    let rows = sql(stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
        ))
    }))?;
    for row in rows {
        let (id, wid, old, new, backup, phase) = sql(row)?;
        ensure_writer_idle(db, &wid)
            .map_err(|e| format!("recovery_required: adoption recovery blocked: {e}"))?;
        let w = ws(db, &wid)?;
        let old: Vec<String> = serde_json::from_str(&old).map_err(|e| e.to_string())?;
        let new: Vec<String> = serde_json::from_str(&new).map_err(|e| e.to_string())?;
        if phase == "applied" {
            adoption::verify_applied(&w.path, Path::new(&backup), &old, &new)
                .map_err(|e| format!("recovery_required: {e}"))?;
            finalize_adoption(db, &id)?;
        } else {
            adoption::rollback(&w.path, Path::new(&backup), &old, &new)
                .map_err(|e| format!("recovery_required: {e}"))?;
            sql(db.execute(
                "UPDATE adoptions SET state='rolled_back' WHERE id=?1",
                [&id],
            ))?;
            let result = json!({"ok":false,"state":"rolled_back","error":{"code":"adoption_rolled_back","message":"Interrupted adoption rolled back; use a new operation ID"},"generation":w.generation});
            finish(db, &id, &result)?;
            event(db, "adoption_rolled_back", &json!({"operation_id":id}))?;
        }
    }
    Ok(())
}
fn finalize_adoption(db: &Connection, id: &str) -> R<Value> {
    let (wid, target, commit, tree, g): (String, String, String, String, i64) = sql(db.query_row(
        "SELECT workspace,target,commit_oid,tree,generation FROM adoptions WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    ))?;
    let result = json!({"ok":true,"state":"committed","adopted":target,"commit":commit,"tree":tree,"generation":g+1,"durability":"local_saved","replication":"not_configured"});
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    sql(db.execute(
        "UPDATE workspaces SET base=?2,checkpoint=?3,generation=?4 WHERE id=?1",
        params![wid, target, commit, g + 1],
    ))?;
    sql(db.execute("UPDATE adoptions SET state='committed' WHERE id=?1", [id]))?;
    finish(db, id, &result)?;
    event(
        db,
        "adopted",
        &json!({"workspace":wid,"target":target,"operation_id":id}),
    )?;
    sql(db.execute_batch("COMMIT"))?;
    Ok(result)
}
pub fn execute(state: &Path, r: Value) -> R<Value> {
    let diagnostic_start = std::time::Instant::now();
    sqlite_phase(diagnostic_start, "entered");
    if r["op"] == "sync_binding_status" {
        return sync::binding_status(state);
    }
    io(fs::create_dir_all(state))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        io(fs::set_permissions(
            state,
            fs::Permissions::from_mode(0o700),
        ))?;
    }
    let lock = io(OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("state.lock")))?;
    sqlite_phase(diagnostic_start, "state_lock_waiting");
    fs2::FileExt::lock_exclusive(&lock).map_err(|e| e.to_string())?;
    sqlite_phase(diagnostic_start, "state_lock_acquired");
    let db = sql(Connection::open(state.join("state.sqlite")))?;
    sqlite_phase(diagnostic_start, "sqlite_opened");
    sql(db.busy_timeout(std::time::Duration::from_secs(30)))?;
    init_db(&db)?;
    sqlite_phase(diagnostic_start, "sqlite_initialized");
    let op = field(&r, "op")?;
    if op == "recovery_status" {
        return crate::restore::recovery_status(&db);
    }
    if op == "recovery_activate" {
        return crate::restore::activate(&db, &r);
    }
    if crate::restore::recovery_status(&db)?["activation_required"] == true
        && matches!(
            op,
            "init"
                | "restore"
                | "sync_configure"
                | "sync_initialize_authority"
                | "sync_add_peer"
                | "sync_import"
                | "sync_export"
                | "sync_reexport"
                | "sync_export_current_head"
                | "publish"
                | "integrate"
                | "retry_proposal"
                | "resolution_open"
                | "resolution_submit"
                | "cancel"
                | "backup_flush"
                | "backup_tick"
        )
    {
        return Err("public_recovery_activation_required: review recovery_status, restore the matching policy, and explicitly activate the recovered authority".into());
    }
    recover(state, &db, matches!(op, "checkpoint" | "command_run"))?;
    sync::recover_head(state, &db)?;
    sqlite_phase(diagnostic_start, "recovery_complete");
    if sync::is_client(&db)?
        && matches!(
            op,
            "init"
                | "restore"
                | "integrate"
                | "configure"
                | "retry_proposal"
                | "backup_flush"
                | "backup_tick"
        )
    {
        return Err("authority_required: operation unavailable on a client public cache".into());
    }
    if op == "restore" {
        return crate::restore::restore(state, &db, Path::new(field(&r, "destination")?));
    }
    if op == "sync_configure" {
        return sync::configure(state, &db, &r);
    }
    if op == "init" {
        return initialize(state, &db, &r).map(|v| feedback::complete(&db, &r, v));
    }
    if sql(db
        .query_row("SELECT value FROM meta WHERE key='authority'", [], |row| {
            row.get::<_, String>(0)
        })
        .optional())?
    .is_none()
    {
        return Err("project_not_initialized".into());
    }
    let mutating = matches!(
        op,
        "open"
            | "checkpoint"
            | "publish"
            | "adopt"
            | "cancel"
            | "command_run"
            | "command_recover"
            | "configure"
            | "resolve_adoption"
            | "resolution_open"
            | "resolution_submit"
            | "backup_flush"
            | "retry_proposal"
            | "sync_initialize_authority"
            | "sync_add_peer"
    );
    let id = if mutating {
        let id = field(&r, "operation_id")?;
        ident(id)?;
        Some(id)
    } else {
        None
    };
    if let Some(id) = id {
        let existing: Option<(String, Option<String>)> = sql(db
            .query_row(
                "SELECT digest,result FROM operations WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional())?;
        if let Some((d, result)) = existing {
            if d != digest(&r) {
                return Err(
                    "idempotency_mismatch: operation ID already binds a different request".into(),
                );
            }
            if let Some(result) = result {
                return serde_json::from_str(&result).map_err(|e| e.to_string());
            }
        } else {
            sql(db.execute(
                "INSERT INTO operations(id,digest,request) VALUES(?1,?2,?3)",
                params![id, digest(&r), r.to_string()],
            ))?;
        }
    }
    let fenced = if matches!(
        op,
        "checkpoint" | "publish" | "adopt" | "resolve_adoption" | "command_run"
    ) {
        ensure_writer_idle(&db, field(&r, "workspace")?)
    } else {
        Ok(())
    };
    sqlite_phase(diagnostic_start, "dispatch");
    let result = fenced.and_then(|()| match op {
        "sync_export" | "sync_reexport" => sync::export(state, &db, &r),
        "sync_export_history" => sync::export_history(&db, &r),
        "sync_export_lookup" => sync::export_lookup(&db, &r),
        "sync_import" => sync::import(state, &db, &r),
        "sync_status" => sync::status(state, &db),
        "sync_initialize_authority" => sync::initialize_authority(state, &db, &r),
        "sync_add_peer" => sync::add_peer(&db, &r),
        "sync_pending" => sync::pending(&db, &r),
        "sync_export_current_head" => sync::export_current_head(state, &db, &r),
        "resolution_tasks" => resolution::tasks(&db, &r),
        "resolution_open" => resolution::open(state, &db, &r),
        "resolution_submit" => resolution::submit(state, &db, &r),
        "open" => open(state, &db, &r),
        "status" => status(state, &db, &r),
        "checkpoint" => checkpoint(state, &db, &r),
        "publish" => publish(state, &db, &r),
        "integrate" => integrate(state, &db, &r),
        "adopt" => adopt(state, &db, &r),
        "updates" => {
            let wid = field(&r, "workspace")?;
            let w = ws(&db, wid)?;
            let online = coordinator(state).repo.exists();
            let git = local(state, wid);
            let latest = if online {
                let h = coordinator(state).head(HEAD)?;
                transfer(&coordinator(state), &git, &h, HEAD)?;
                h
            } else {
                git.head(HEAD)?
            };
            Ok(
                json!({"ok":true,"adopted":w.base,"latest":latest,"coordinator_online":online && !sync::is_client(&db)?,"cached":!online || sync::is_client(&db)?,"remote_contact_unverified":sync::is_client(&db)?,"generation":w.generation,"files_changed":false,"resolution_tasks":resolution::tasks(&db,&r)?["tasks"]}),
            )
        }
        "operation_status" => {
            if r.get("include_record").is_some_and(|v| !v.is_boolean()) {
                return Err("invalid_request: include_record must be boolean".into());
            }
            let record: Option<(String, Option<String>)> = sql(db.query_row(
                "SELECT request,result FROM operations WHERE id=?1",
                [field(&r, "operation_id")?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional())?;
            let (request, result) = record.ok_or("operation_not_found: no journaled operation has this ID")?;
            let result = result
                .map(|v|serde_json::from_str::<Value>(&v).map_err(|e|e.to_string())).transpose()?;
            Ok(if r["include_record"] == true {
                let request: Value = serde_json::from_str(&request).map_err(|e| e.to_string())?;
                json!({"ok":true,"operation_id":r["operation_id"],"request":request,"recorded":true,
                    "state":if result.is_some(){"completed"}else{"pending"},"result":result})
            } else {
                result.unwrap_or_else(||json!({"ok":true,"state":"pending"}))
            })
        }
        "proposal_status" => proposal_status(&db, field(&r, "proposal")?),
        "events" => events(&db, r["cursor"].as_i64().unwrap_or(0)),
        "retry_proposal" => {
            let p = field(&r, "proposal")?;
            let n=sql(db.execute("UPDATE proposals SET state='coordinator_accepted' WHERE id=?1 AND state='quarantined'",[p]))?;
            if n == 0 {
                Err("already_terminal: only quarantined proposals can retry".into())
            } else {
                event(&db, "proposal_retried", &json!({"proposal":p}))?;
                Ok(json!({"ok":true,"proposal":p,"state":"coordinator_accepted"}))
            }
        }
        "cancel" => cancel(&db, &r),
        "command_run" => command_run(state, &db, &r),
        "command_recover" => command_recover(&db, &r),
        "configure" => configure(&db, &r),
        "resolve_adoption" => resolve_adoption(state, &db, &r),
        "backup_verify_restore" => {
            crate::backup::verify_restore(Path::new(field(&r, "destination")?))
        }
        "backup_tick" => {
            let b = crate::backup::status(&db)?;
            if b["state"] == "not_configured" || b["state"] == "complete" {
                Ok(b)
            } else {
                crate::backup::flush(
                    state,
                    &db,
                    Path::new(
                        b["destination"]
                            .as_str()
                            .ok_or("backup_destination_missing")?,
                    ),
                )
            }
        }
        "backup_status" => crate::backup::status(&db),
        "backup_flush" => crate::backup::flush(state, &db, Path::new(field(&r, "destination")?)),
        _ => Err("unsupported_operation".into()),
    }).map(|value| feedback::complete(&db, &r, value));
    sqlite_phase(diagnostic_start, "dispatch_complete");
    match (id, result) {
        (Some(id), Ok(value)) => {
            finish(&db, id, &value)?;
            Ok(value)
        }
        (Some(id), Err(error)) => {
            let value = feedback::complete(&db, &r, error_response(&error));
            finish(&db, id, &value)?;
            Ok(value)
        }
        (None, value) => value,
    }
}
fn initialize(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    if coordinator(state).repo.exists() {
        return Err("already_initialized".into());
    }
    let source = PathBuf::from(field(r, "source")?);
    let source = io(source.canonicalize())?;
    let state_abs = io(state.canonicalize())?;
    if source.starts_with(&state_abs) || state_abs.starts_with(&source) {
        return Err("invalid_root: source and state must not overlap".into());
    }
    let git = Git::init(&state.join("coordinator.git"))?;
    let tree = git.capture(&source)?;
    let commit = git.commit(&tree, &[], "Wipstash initial public import")?;
    git.set_ref(HEAD, &commit, None)?;
    sql(db.execute(
        "INSERT INTO meta(key,value) VALUES('authority','local-single-authority-v1')",
        [],
    ))?;
    event(db, "initialized", &json!({"head":commit}))?;
    Ok(json!({"ok":true,"state":"initialized","head":commit,"evidence":"unchecked"}))
}
fn open(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let id = field(r, "workspace")?;
    ident(id)?;
    // Reject duplicate identity before creating a directory, fetching into the
    // existing private store, or materializing any files at the requested path.
    let exists: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspaces WHERE id=?1)",
        [id],
        |row| row.get(0),
    ))?;
    if exists {
        return Err("workspace_exists: workspace identifier is already registered".into());
    }
    let path = PathBuf::from(field(r, "path")?);
    if !path.is_absolute() {
        return Err("invalid_root: path must be absolute".into());
    }
    io(fs::create_dir_all(&path))?;
    let path = io(path.canonicalize())?;
    let state_abs = io(state.canonicalize())?;
    if path.starts_with(&state_abs) || state_abs.starts_with(&path) {
        return Err("invalid_root: workspace and daemon state overlap".into());
    }
    if io(fs::read_dir(&path))?.next().is_some() {
        return Err("path_collision: workspace must be empty".into());
    }
    let mut stmt = sql(db.prepare("SELECT path FROM workspaces"))?;
    for p in sql(stmt.query_map([], |r| r.get::<_, String>(0)))? {
        let p = PathBuf::from(sql(p)?);
        if path.starts_with(&p) || p.starts_with(&path) {
            return Err("path_collision: workspace roots overlap".into());
        }
    }
    let head = coordinator(state).head(HEAD)?;
    let git = Git::init(&state.join("locals").join(id).join("objects.git"))?;
    transfer(&coordinator(state), &git, &head, HEAD)?;
    git.materialize(&head, &path)?;
    sql(db.execute(
        "INSERT INTO workspaces(id,path,base) VALUES(?1,?2,?3)",
        params![id, path.to_string_lossy(), head],
    ))?;
    event(db, "workspace_opened", &json!({"workspace":id,"head":head}))?;
    Ok(
        json!({"ok":true,"workspace":id,"path":path,"generation":0,"adopted":head,"profile":"cooperative-local","writer_recovery_required":false,"warning":"Unmanaged writers must be stopped; native agent tool interception is not implemented"}),
    )
}
fn checkpoint(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let wid = field(r, "workspace")?;
    let w = ws(db, wid)?;
    generation(r, &w)?;
    let id = field(r, "operation_id")?;
    let git = local(state, wid);
    let tree = git.capture(&w.path)?;
    let check = git.capture(&w.path)?;
    if tree != check {
        return Err("snapshot_unstable: files changed during capture".into());
    }
    let parent = w.checkpoint.clone().unwrap_or(w.base.clone());
    let commit = git.commit(&tree, &[parent], &format!("private checkpoint {id}"))?;
    git.set_ref(&format!("refs/wipstash/checkpoints/{id}"), &commit, None)?;
    fault("checkpoint_after_pin");
    let result = json!({"ok":true,"state":"durable","checkpoint":id,"commit":commit,"tree":tree,"adopted":w.base,"generation":w.generation+1,"durability":"local_saved","replication":"not_configured","warning":"Coherent capture requires cooperative writers"});
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    sql(db.execute("INSERT OR IGNORE INTO checkpoints(id,workspace,commit_oid,tree,base,generation) VALUES(?1,?2,?3,?4,?5,?6)",params![id,wid,commit,tree,w.base,w.generation+1]))?;
    sql(db.execute(
        "UPDATE workspaces SET checkpoint=?2,generation=generation+1 WHERE id=?1",
        params![wid, commit],
    ))?;
    finish(db, id, &result)?;
    event(db, "checkpoint", &json!({"workspace":wid,"checkpoint":id}))?;
    sql(db.execute_batch("COMMIT"))?;
    fault("checkpoint_after_commit");
    Ok(result)
}
fn publish(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let wid = field(r, "workspace")?;
    let resolution_checkout: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM resolution_sessions WHERE workspace=?1)",
        [wid],
        |row| row.get(0),
    ))?;
    if resolution_checkout {
        return Err("resolution_submit_required: use resolution_submit to preserve ownership and bounded task lineage".into());
    }
    let _ = ws(db, wid)?;
    let cp = field(r, "checkpoint")?;
    let id = field(r, "operation_id")?;
    let (tree, base, cp_generation): (String, String, i64) = sql(db.query_row(
        "SELECT tree,base,generation FROM checkpoints WHERE id=?1 AND workspace=?2",
        params![cp, wid],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ))
    .map_err(|_| "checkpoint_not_found".to_string())?;
    let intent = field(r, "intent")?;
    if intent.len() > 4096 {
        return Err("invalid_request: intent too large".into());
    }
    let git = local(state, wid);
    let commit = git.commit(
        &tree,
        std::slice::from_ref(&base),
        &format!("proposal {id}"),
    )?;
    git.set_ref(&format!("refs/wipstash/exports/{id}"), &commit, None)?;
    let online = coordinator(state).repo.exists() && !sync::is_client(db)?;
    if online {
        transfer(
            &git,
            &coordinator(state),
            &commit,
            &format!("refs/wipstash/proposals/{id}"),
        )?;
    }
    fault("publish_after_pin");
    let phase = if online {
        "coordinator_accepted"
    } else {
        "local_queued"
    };
    let result = json!({"ok":true,"state":if online{"coordinator_accepted"}else{"queued_offline"},"proposal":id,"checkpoint":cp,"checkpoint_generation":cp_generation,"commit":commit,"base":base,"durability":if online{"coordinator_saved"}else{"local_saved"},"replication":"not_configured"});
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    sql(db.execute("INSERT OR IGNORE INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,wid,cp,commit,base,intent,phase]))?;
    finish(db, id, &result)?;
    event(db, "published", &json!({"proposal":id,"commit":commit}))?;
    sql(db.execute_batch("COMMIT"))?;
    Ok(result)
}
fn integrate(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let max_proposals = match r.get("max_proposals") {
        None => i64::MAX,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=32).contains(n))
            .ok_or("invalid_integration_batch")? as i64,
    };
    if sync::is_client(db)? {
        return Err("authority_required: clients cannot integrate their public cache".into());
    }
    let git = coordinator(state);
    if !git.repo.exists() {
        return Err("coordinator_unreachable: local coordinator storage unavailable".into());
    }
    let mut pending = sql(db.prepare(
        "SELECT id,workspace,commit_oid FROM proposals WHERE state='local_queued' ORDER BY rowid LIMIT ?1",
    ))?;
    for row in sql(pending.query_map([max_proposals], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    }))? {
        let (id, wid, commit) = sql(row)?;
        transfer(
            &local(state, &wid),
            &git,
            &commit,
            &format!("refs/wipstash/proposals/{id}"),
        )?;
        sql(db.execute(
            "UPDATE proposals SET state='coordinator_accepted' WHERE id=?1",
            [&id],
        ))?;
        event(db, "published", &json!({"proposal":id,"commit":commit}))?;
    }
    let mut stmt = sql(db.prepare(
        "SELECT id,commit_oid FROM proposals WHERE state='coordinator_accepted' ORDER BY rowid LIMIT ?1",
    ))?;
    let rows = sql(stmt.query_map([max_proposals], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    }))?;
    let mut outcomes = vec![];
    for row in rows {
        let (id, p) = sql(row)?;
        let head = git.head(HEAD)?;
        let mut merge = git.merge(&head, &p)?;
        let policy_text: Option<String> = sql(db
            .query_row("SELECT value FROM meta WHERE key='policy'", [], |row| {
                row.get(0)
            })
            .optional())?;
        let policy: Value = serde_json::from_str(policy_text.as_deref().unwrap_or("{}"))
            .map_err(|e| e.to_string())?;
        let evaluation = crate::policy::evaluate(
            state,
            &git,
            &head,
            &p,
            &merge.tree,
            !merge.clean,
            &merge.conflicts,
            &policy,
        ).unwrap_or_else(|error| crate::policy::Evaluation {
            tree: merge.tree.clone(), accepted: false, repaired: false,
            details: json!({"head":head,"proposal":p,"input_tree":merge.tree,"candidate_tree":merge.tree,"conflicted":!merge.clean,"conflict_paths":merge.conflicts,"policy_sha256":digest(&policy),"checks":[],"accepted":false,"evaluation_error":error,"semantic_correctness_claimed":false}),
        });
        let candidate_id = format!(
            "candidate-{}",
            digest(&json!({"proposal":id,"head":head,"evidence":evaluation.details}))
        );
        sql(db.execute("INSERT OR IGNORE INTO candidates(id,head,proposal,tree,policy_hash,evidence,state) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![candidate_id,head,p,evaluation.tree,digest(&policy),evaluation.details.to_string(),if evaluation.accepted{"ready"}else{"failed"}]))?;
        merge.tree = evaluation.tree;
        merge.clean = evaluation.accepted;
        merge.details = evaluation.details.to_string();
        let evidence = if policy["checks"].as_array().is_some_and(|a| !a.is_empty()) {
            "checks_executed"
        } else if evaluation.repaired {
            "agent_resolved_unchecked"
        } else {
            "unchecked"
        };
        if !merge.clean {
            sql(db.execute(
                "UPDATE proposals SET state='quarantined',details=?2 WHERE id=?1",
                params![id, merge.details],
            ))?;
            let task = resolution::task(db, &id)?;
            event(
                db,
                "quarantined",
                &json!({"proposal":id,"resolution_task":task}),
            )?;
            outcomes.push(json!({"proposal":id,"state":"quarantined","reason":"conflict_or_policy_rejection","details":evaluation.details,"resolution_task":task,
                "validation":feedback::validation(Some(&evaluation.details),"quarantined",feedback::policy_counts(db).0,Some(&p),false),
                "next_action":feedback::proposal_action_for_store(db,&id,"quarantined",task.as_ref())}));
            continue;
        }
        if merge.tree == git.tree(&head)? {
            sql(db.execute(
                "UPDATE proposals SET state='already_included',head=?2,details=?3 WHERE id=?1",
                params![id, head, evaluation.details.to_string()],
            ))?;
            event(db, "already_included", &json!({"proposal":id,"head":head}))?;
            outcomes.push(json!({"proposal":id,"state":"already_included","head":head,"evidence":"unchecked",
                "validation":feedback::validation(Some(&evaluation.details),"already_included",feedback::policy_counts(db).0,Some(&p),false),
                "next_action":feedback::proposal_action_for_store(db,&id,"already_included",None)}));
            continue;
        }
        let commit=git.commit(&merge.tree,&[head.clone(),p.clone()],&format!("Wipstash integration\noperation: integration-{id}\nproposal: {id}\nevidence: {evidence}"))?;
        git.set_ref(&format!("refs/wipstash/candidates/{id}"), &commit, None)?;
        sql(db.execute(
            "INSERT INTO promotions(id,proposal,old,new,state) VALUES(?1,?2,?3,?4,'intent')",
            params![format!("integration-{id}"), id, head, commit],
        ))?;
        fault("promotion_before_cas");
        git.set_ref(HEAD, &commit, Some(&head))?;
        fault("promotion_after_cas");
        sql(db.execute_batch("BEGIN IMMEDIATE"))?;
        sql(db.execute(
            "UPDATE promotions SET state='committed' WHERE proposal=?1",
            [&id],
        ))?;
        sql(db.execute(
            "UPDATE proposals SET state='integrated',head=?2,details=?3 WHERE id=?1",
            params![id, commit, evaluation.details.to_string()],
        ))?;
        event(
            db,
            "integrated",
            &json!({"proposal":id,"head":commit,"evidence":evidence}),
        )?;
        sql(db.execute_batch("COMMIT"))?;
        outcomes.push(json!({"proposal":id,"state":"integrated","head":commit,"evidence":evidence,"repaired":evaluation.repaired,
            "validation":feedback::validation(Some(&evaluation.details),"integrated",feedback::policy_counts(db).0,Some(&p),false),
            "next_action":feedback::proposal_action_for_store(db,&id,"integrated",None)}));
    }
    Ok(json!({"ok":true,"head":git.head(HEAD)?,"outcomes":outcomes,"evidence":"unchecked"}))
}
fn adopt(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let wid = field(r, "workspace")?;
    let w = ws(db, wid)?;
    generation(r, &w)?;
    let id = field(r, "operation_id")?;
    let online = coordinator(state).repo.exists();
    let shared = if online {
        coordinator(state)
    } else {
        local(state, wid)
    };
    let latest = shared.head(HEAD)?;
    let target = field(r, "target")?;
    if !online && target == "latest" {
        return Err(
            "coordinator_unreachable: latest is unknown; specify a cached authoritative OID".into(),
        );
    }
    let target = if target == "latest" {
        latest.clone()
    } else {
        target.to_string()
    };
    if target.len() != 40 || !target.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid_target".into());
    }
    // Require a first-parent authoritative version, never a proposal-side ancestor.
    let first = String::from_utf8(shared.run(&["rev-list", "--first-parent", &latest], None)?)
        .map_err(|e| e.to_string())?;
    if !first.lines().any(|v| v == target) || !shared.ancestor(&w.base, &target)? {
        return Err("stale_head: target is not an authoritative descendant of adopted base".into());
    }
    let git = local(state, wid);
    if online {
        transfer(
            &shared,
            &git,
            &target,
            &format!("refs/wipstash/prefetch/{id}"),
        )?;
        // Cache the head only after importing its objects too. An explicit
        // target may be older than latest, so fetching target alone is insufficient.
        transfer(&shared, &git, &latest, HEAD)?;
    }
    let tree = git.capture(&w.path)?;
    if tree != git.capture(&w.path)? {
        return Err("snapshot_unstable".into());
    }
    let private = git.commit(
        &tree,
        &[w.checkpoint.clone().unwrap_or(w.base.clone())],
        &format!("pre-adoption {id}"),
    )?;
    git.set_ref(&format!("refs/wipstash/recovery/{id}"), &private, None)?;
    // Private history may contain older shared merges; explicit current base is retained by ancestry.
    let merge = git.merge(&private, &target)?;
    if !merge.clean {
        sql(db.execute("INSERT OR REPLACE INTO adoption_conflicts(id,workspace,target,base,generation,state) VALUES(?1,?2,?3,?4,?5,'conflict')",params![id,wid,target,w.base,w.generation]))?;
        return Ok(
            json!({"candidate":id,"ok":false,"state":"conflict","error":{"code":"adoption_conflict","message":"Private edits conflict with target; workspace untouched"},"recovery_commit":private,"target":target,"generation":w.generation}),
        );
    }
    let commit = git.commit(
        &merge.tree,
        &[private, target.clone()],
        &format!("private adoption {id}"),
    )?;
    git.set_ref(&format!("refs/wipstash/adoptions/{id}"), &commit, None)?;
    let txroot = state.join("transactions").join(id);
    io(fs::create_dir_all(&txroot))?;
    let oldstage = txroot.join("old");
    let stage = txroot.join("new");
    let backup = txroot.join("backup");
    if oldstage.exists() {
        io(fs::remove_dir_all(&oldstage))?;
    }
    if stage.exists() {
        io(fs::remove_dir_all(&stage))?;
    }
    io(fs::create_dir_all(&oldstage))?;
    io(fs::create_dir_all(&stage))?;
    git.materialize(&tree, &oldstage)?;
    git.materialize(&merge.tree, &stage)?;
    let oldfiles = adoption::files(&oldstage)?;
    let newfiles = adoption::files(&stage)?;
    sql(db.execute("INSERT OR REPLACE INTO adoptions(id,workspace,old_base,target,commit_oid,tree,old_files,new_files,stage,backup,state,generation) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'applying',?11)",params![id,wid,w.base,target,commit,merge.tree,serde_json::to_string(&oldfiles).unwrap(),serde_json::to_string(&newfiles).unwrap(),stage.to_string_lossy(),backup.to_string_lossy(),w.generation]))?;
    fault("adoption_after_intent");
    if let Err(e) =
        adoption::apply_captured(&w.path, &oldstage, &stage, &backup, &oldfiles, &newfiles)
    {
        adoption::rollback(&w.path, &backup, &oldfiles, &newfiles)
            .map_err(|err| format!("recovery_required: {err}"))?;
        sql(db.execute("UPDATE adoptions SET state='rolled_back' WHERE id=?1", [id]))?;
        return Err(e);
    }
    sql(db.execute("UPDATE adoptions SET state='applied' WHERE id=?1", [id]))?;
    fault("adoption_after_apply");
    finalize_adoption(db, id)
}
fn status(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let head = coordinator(state).head(HEAD).ok();
    if let Some(wid) = r["workspace"].as_str() {
        let w = ws(db, wid)?;
        let git = local(state, wid);
        let fenced = ensure_writer_idle(db, wid).is_err();
        let dirty = if fenced {
            None
        } else {
            let tree = git.capture(&w.path)?;
            let saved = git.tree(w.checkpoint.as_deref().unwrap_or(&w.base))?;
            Some(tree != saved)
        };
        let tasks = resolution::tasks(db, r)?["tasks"].clone();
        let summaries = recent_proposals(db, wid)?;
        let next = if fenced {
            feedback::action(Some("status"),"Stop and verify unmanaged writers before explicitly acknowledging command_recover.",json!({"workspace":wid}))
        } else if let Some(task) = tasks.as_array().and_then(|a| a.first()) {
            let mut action = feedback::proposal_action_for_store(
                db,
                task["proposal"].as_str().unwrap_or(""),
                "quarantined",
                Some(task),
            );
            action["arguments"]["workspace"] = json!(wid);
            action
        } else if dirty == Some(true) {
            feedback::action(None,"Uncheckpointed private WIP is present. Checkpoint it only if explicitly intended; an existing checkpoint can be published without capturing newer WIP. Preserve the caller's exact checkpoint choice.",json!({"workspace":wid}))
        } else if let Some(p) = summaries["proposals"].as_array().and_then(|a| {
            a.iter().find(|p| {
                matches!(
                    p["state"].as_str(),
                    Some("local_queued" | "coordinator_accepted" | "queued_offline")
                )
            })
        }) {
            p["next_action"].clone()
        } else if head.as_ref().is_some_and(|h| h != &w.base) {
            feedback::action(Some("updates"),"Public updates are available. Read them before explicitly deciding whether to adopt.",json!({"workspace":wid}))
        } else {
            feedback::action(
                None,
                "Review the recent proposal summary before choosing the next explicit action; older proposals may be truncated.",
                json!({}),
            )
        };
        let mut result = json!({"ok":true,"workspace":wid,"path":w.path,"adopted":w.base,"latest":head,"cached_head":git.head(HEAD).ok(),"coordinator_online":head.is_some() && !sync::is_client(db)?,"remote_contact_unverified":sync::is_client(db)?,"public_store_role":if sync::is_client(db)?{"client_cache"}else{"authority"},"checkpoint_commit":w.checkpoint,"generation":w.generation,"dirty":dirty,"replication":"not_configured","profile":"cooperative-local","writer_recovery_required":fenced,"resolution_tasks":tasks,"next_action":next});
        for (key, value) in summaries.as_object().unwrap() {
            result[key] = value.clone();
        }
        Ok(result)
    } else {
        let count: i64 = sql(db.query_row("SELECT COUNT(*) FROM workspaces", [], |r| r.get(0)))?;
        Ok(
            json!({"ok":true,"head":head,"workspaces":count,"evidence":"unchecked","public_store_role":if sync::is_client(db)?{"client_cache"}else{"authority"},"remote_contact_unverified":sync::is_client(db)?,"replication":if sync::is_client(db)?{"trusted_directory_exchange"}else{"not_configured"}}),
        )
    }
}
fn recent_proposals(db: &Connection, wid: &str) -> R<Value> {
    let total: i64 = sql(db.query_row(
        "SELECT COUNT(*) FROM proposals WHERE workspace=?1",
        [wid],
        |r| r.get(0),
    ))?;
    let mut statement = sql(
        db.prepare("SELECT id FROM proposals WHERE workspace=?1 ORDER BY rowid DESC LIMIT ?2")
    )?;
    let ids = sql(
        statement.query_map(params![wid, feedback::PROPOSAL_LIMIT], |r| {
            r.get::<_, String>(0)
        }),
    )?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|e| e.to_string())?;
    let mut proposals = Vec::with_capacity(ids.len());
    for id in ids {
        let p = proposal_status(db, &id)?;
        proposals.push(json!({"proposal":id,"state":p["state"],"commit":p["commit"],"head":p["head"],
            "validation":p["validation"],"next_action":p["next_action"],
            "resolution_required":p["resolution_task"].is_object(),"remote_observation":p["remote_observation"].is_object()}));
    }
    Ok(
        json!({"proposals":proposals,"proposals_total":total,"proposals_limit":feedback::PROPOSAL_LIMIT,
        "proposals_truncated":total > feedback::PROPOSAL_LIMIT}),
    )
}
fn proposal_status(db: &Connection, id: &str) -> R<Value> {
    let (state, commit, head, details, workspace): (
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    ) = sql(db.query_row(
        "SELECT state,commit_oid,head,details,workspace FROM proposals WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    ))?;
    let detail: Option<Value> = details.and_then(|d| serde_json::from_str(&d).ok());
    let evidence = match detail.as_ref() {
        Some(d)
            if d["public_queue_snapshot"]["evidence"]
                .as_str()
                .is_some_and(|e| {
                    matches!(
                        e,
                        "checks_executed" | "agent_resolved_unchecked" | "unchecked"
                    )
                }) =>
        {
            d["public_queue_snapshot"]["evidence"].as_str().unwrap()
        }
        Some(d) if d["checks"].as_array().is_some_and(|a| !a.is_empty()) => "checks_executed",
        Some(d) if d["repaired"] == true => "agent_resolved_unchecked",
        _ => "unchecked",
    };
    let task = resolution::task(db, id)?;
    let next = |phase: &str| {
        let mut action = feedback::proposal_action_for_store(db, id, phase, task.as_ref());
        if matches!(action["op"].as_str(), Some("resolution_open" | "updates")) {
            action["arguments"]["workspace"] = json!(workspace);
        }
        action
    };
    if let Some(observed) = sync::observed_status(db, id)? {
        return Ok(
            json!({"ok":true,"proposal":id,"state":observed["state"],"local_state":state,"commit":commit,"head":observed["integration_head"],"evidence":observed["evidence"],"remote_observation":observed,"details":null,"resolution_task":task,
                "validation":feedback::validation(None,observed["state"].as_str().unwrap_or(""),None,Some(&commit),true),
                "next_action":next(observed["state"].as_str().unwrap_or(""))}),
        );
    }
    Ok(
        json!({"ok":true,"proposal":id,"state":state,"commit":commit,"head":head,"details":detail,"evidence":evidence,"origin":sync::proposal_origin(db,id)?,"resolution_task":task,"resolution":resolution::lineage(db,id)?,
            "validation":feedback::validation(detail.as_ref(),&state,feedback::policy_counts(db).0,Some(&commit),false),
            "next_action":next(&state)}),
    )
}
fn events(db: &Connection, cursor: i64) -> R<Value> {
    let mut stmt =
        sql(db.prepare("SELECT seq,kind,data FROM events WHERE seq>?1 ORDER BY seq LIMIT 1000"))?;
    let mut out = vec![];
    for row in sql(stmt.query_map([cursor], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    }))? {
        let (s, k, d) = sql(row)?;
        out.push(json!({"seq":s,"kind":k,"data":serde_json::from_str::<Value>(&d).unwrap()}));
    }
    let last = out
        .last()
        .map(|v| v["seq"].as_i64().unwrap())
        .unwrap_or(cursor);
    Ok(json!({"ok":true,"events":out,"cursor":last}))
}
fn cancel(db: &Connection, r: &Value) -> R<Value> {
    let p = field(r, "proposal")?;
    sync::check_cancel(db, p)?;
    let n=sql(db.execute("UPDATE proposals SET state='cancelled' WHERE id=?1 AND state IN ('local_queued','coordinator_accepted','quarantined')",[p]))?;
    if n == 0 {
        return Err("already_terminal: cannot cancel integrated or missing proposal".into());
    }
    event(db, "cancelled", &json!({"proposal":p}))?;
    Ok(json!({"ok":true,"proposal":p,"state":"cancelled"}))
}
fn ensure_writer_idle(db: &Connection, wid: &str) -> R<()> {
    let count: i64 = sql(db.query_row(
        "SELECT COUNT(*) FROM commands WHERE workspace=?1 AND state IN ('running','uncertain')",
        [wid],
        |r| r.get(0),
    ))?;
    if count != 0 {
        Err("writer_recovery_required: stop unmanaged writers and acknowledge with command_recover before capturing or modifying this workspace".into())
    } else {
        Ok(())
    }
}
fn command_recover(db: &Connection, r: &Value) -> R<Value> {
    let wid = field(r, "workspace")?;
    let w = ws(db, wid)?;
    generation(r, &w)?;
    if r["confirm_writers_stopped"] != true {
        return Err("writer_confirmation_required: confirm_writers_stopped must be true after all unmanaged writers have been stopped".into());
    }
    let id = field(r, "operation_id")?;
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    let count = sql(db.execute(
        "UPDATE commands SET state='acknowledged' WHERE workspace=?1 AND state='uncertain'",
        [wid],
    ))?;
    if count == 0 {
        sql(db.execute_batch("ROLLBACK"))?;
        return Err("no_interrupted_command: workspace has no uncertain command".into());
    }
    sql(db.execute(
        "UPDATE workspaces SET generation=generation+1 WHERE id=?1",
        [wid],
    ))?;
    let result = json!({"ok":true,"state":"acknowledged","generation":w.generation+1,"commands_acknowledged":count,"warning":"Caller attested writers are stopped; no process containment was established"});
    finish(db, id, &result)?;
    event(
        db,
        "command_recovery_acknowledged",
        &json!({"workspace":wid,"operation_id":id}),
    )?;
    sql(db.execute_batch("COMMIT"))?;
    Ok(result)
}
fn command_run(_state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let wid = field(r, "workspace")?;
    let w = ws(db, wid)?;
    generation(r, &w)?;
    crate::policy::validate_command(r)?;
    let id = field(r, "operation_id")?;
    // Invalidate old generation tokens durably before any command can write.
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    sql(db.execute(
        "INSERT INTO commands(id,workspace,state,generation) VALUES(?1,?2,'running',?3)",
        params![id, wid, w.generation + 1],
    ))?;
    sql(db.execute(
        "UPDATE workspaces SET generation=generation+1 WHERE id=?1",
        [wid],
    ))?;
    sql(db.execute_batch("COMMIT"))?;
    let execution = crate::policy::run(
        r,
        &w.path,
        &w.base,
        "",
        "",
        std::time::Instant::now() + std::time::Duration::from_secs(600),
    );
    // Incomplete pipes are evidence of a possible escaped writer. This cannot
    // detect an arbitrary detached process that closes its pipes.
    let uncertain = match &execution {
        Err(_) => true,
        Ok(v) => v["output_collection_complete"] == false,
    };
    let phase = if uncertain { "uncertain" } else { "exited" };
    let result = match execution {
        Ok(execution) => {
            json!({"ok":!uncertain,"state":phase,"execution":execution,"generation":w.generation+1,"writer_recovery_required":uncertain,"warning":"Cooperative broker only; detached writers cannot be reliably detected or contained"})
        }
        Err(error) => {
            json!({"ok":false,"state":phase,"generation":w.generation+1,"error":{"code":"writer_recovery_required","message":error}})
        }
    };
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    sql(db.execute(
        "UPDATE commands SET state=?2 WHERE id=?1",
        params![id, phase],
    ))?;
    finish(db, id, &result)?;
    event(
        db,
        "command_finished",
        &json!({"workspace":wid,"operation_id":id,"state":phase}),
    )?;
    sql(db.execute_batch("COMMIT"))?;
    Ok(result)
}

fn configure(db: &Connection, r: &Value) -> R<Value> {
    let policy = r.get("policy").cloned().unwrap_or(json!({"checks":[]}));
    if !policy.is_object() {
        return Err("invalid_request: policy must be an object".into());
    }
    crate::policy::validate_policy(&policy)?;
    sql(db.execute("INSERT INTO meta(key,value) VALUES('policy',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[policy.to_string()]))?;
    event(
        db,
        "policy_changed",
        &json!({"policy_hash":digest(&policy)}),
    )?;
    Ok(
        json!({"ok":true,"state":"configured","policy_hash":digest(&policy),"checks":policy.get("checks").cloned().unwrap_or(json!([]))}),
    )
}
fn resolve_adoption(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let wid = field(r, "workspace")?;
    let w = ws(db, wid)?;
    generation(r, &w)?;
    let candidate = field(r, "candidate")?;
    let target = field(r, "target")?;
    let cp = field(r, "checkpoint")?;
    let id = field(r, "operation_id")?;
    let (cwid, ctarget, base, g, phase): (String, String, String, i64, String) = sql(db
        .query_row(
            "SELECT workspace,target,base,generation,state FROM adoption_conflicts WHERE id=?1",
            [candidate],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        ))?;
    if cwid != wid
        || ctarget != target
        || base != w.base
        || g + 1 != w.generation
        || phase != "conflict"
    {
        return Err(
            "stale_adoption_candidate: target, base, or workspace generation changed".into(),
        );
    }
    let (commit, tree): (String, String) = sql(db.query_row(
        "SELECT commit_oid,tree FROM checkpoints WHERE id=?1 AND workspace=?2",
        params![cp, wid],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ))?;
    let git = local(state, wid);
    if w.checkpoint.as_deref() != Some(&commit) || git.capture(&w.path)? != tree {
        return Err(
            "stale_adoption_candidate: selected resolution differs from live workspace".into(),
        );
    }
    let resolved = git.commit(
        &tree,
        &[commit, target.to_string()],
        &format!("explicit adoption resolution {id} candidate {candidate}"),
    )?;
    git.set_ref(&format!("refs/wipstash/adoptions/{id}"), &resolved, None)?;
    let result = json!({"ok":true,"state":"committed","adopted":target,"commit":resolved,"tree":tree,"generation":w.generation+1,"resolution":"explicit_checkpoint","candidate":candidate,"durability":"local_saved"});
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    sql(db.execute(
        "UPDATE workspaces SET base=?2,checkpoint=?3,generation=generation+1 WHERE id=?1",
        params![wid, target, resolved],
    ))?;
    sql(db.execute(
        "UPDATE adoption_conflicts SET state='resolved' WHERE id=?1",
        [candidate],
    ))?;
    finish(db, id, &result)?;
    event(
        db,
        "adoption_resolved",
        &json!({"workspace":wid,"target":target,"candidate":candidate,"operation_id":id}),
    )?;
    sql(db.execute_batch("COMMIT"))?;
    Ok(result)
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Project(PathBuf);
    impl Project {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "wipstash-engine-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("source")).unwrap();
            fs::write(root.join("source/a"), "original").unwrap();
            let p = Self(root);
            p.request(json!({"op":"init","source":p.0.join("source")}));
            for w in ["A", "B"] {
                p.request(json!({"op":"open","workspace":w,"path":p.0.join(w),"operation_id":format!("open-{w}")}));
            }
            p
        }
        fn request(&self, r: Value) -> Value {
            let v = execute(&self.0.join("state"), r).unwrap();
            assert_eq!(v["ok"], true, "{v}");
            v
        }
        fn publish(&self, i: u64) -> String {
            fs::write(self.0.join("A").join(format!("file-{i}")), i.to_string()).unwrap();
            self.request(json!({"op":"checkpoint","workspace":"A","expected_generation":i,"operation_id":format!("cp-{i}")}));
            self.request(json!({"op":"publish","workspace":"A","checkpoint":format!("cp-{i}"),"intent":"test","operation_id":format!("pub-{i}")}));
            self.request(json!({"op":"integrate"}));
            self.request(json!({"op":"status"}))["head"]
                .as_str()
                .unwrap()
                .into()
        }
    }
    impl Drop for Project {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn canonical_local_repository_transfer_opens_two_workspaces() {
        let p = Project::new();
        let state = fs::canonicalize(p.0.join("state")).unwrap();
        let public = coordinator(&state).head(HEAD).unwrap();
        for workspace in ["A", "B"] {
            assert_eq!(local(&state, workspace).head(HEAD).unwrap(), public);
            assert_eq!(
                fs::read(p.0.join(workspace).join("a")).unwrap(),
                b"original"
            );
        }
    }

    #[test]
    fn feedback_checkpoint_and_error_replays_preserve_the_original_observation() {
        let p = Project::new();
        let first = json!({"op":"checkpoint","workspace":"A","expected_generation":0,"operation_id":"feedback-cp"});
        let saved = p.request(first.clone());
        assert_eq!(saved["checkpoint"], "feedback-cp");
        assert_eq!(saved["checkpoint_generation"], 1);
        assert_eq!(saved["current_generation"], 1);
        assert_eq!(saved["validation"]["state"], "unchecked");
        assert_eq!(saved["validation"]["scope"], "private_checkpoint");
        p.request(json!({"op":"checkpoint","workspace":"A","expected_generation":1,"operation_id":"feedback-cp-2"}));
        assert_eq!(p.request(first), saved);
        assert_eq!(
            p.request(json!({"op":"operation_status","operation_id":"feedback-cp"})),
            saved
        );
        let stale = json!({"op":"checkpoint","workspace":"A","expected_generation":0,"operation_id":"feedback-stale"});
        let failed = execute(&p.0.join("state"), stale.clone()).unwrap();
        assert_eq!(failed["error"]["code"], "generation_mismatch");
        assert_eq!(failed["current_generation"], 2);
        assert_eq!(failed["current_generation_workspace"], "A");
        assert_eq!(failed["checkpoint"], "feedback-cp-2");
        assert_eq!(failed["next_action"]["arguments"]["workspace"], "A");
        p.request(json!({"op":"checkpoint","workspace":"A","expected_generation":2,"operation_id":"feedback-cp-3"}));
        assert_eq!(execute(&p.0.join("state"), stale).unwrap(), failed);
        assert_eq!(
            execute(
                &p.0.join("state"),
                json!({"op":"operation_status","operation_id":"feedback-stale"})
            )
            .unwrap(),
            failed
        );
        let record = p.request(
            json!({"op":"operation_status","operation_id":"feedback-stale","include_record":true}),
        );
        assert_eq!(record["recorded"], true);
        assert_eq!(record["state"], "completed");
        assert_eq!(record["result"], failed);
        assert_eq!(
            record["request"],
            json!({"op":"checkpoint","workspace":"A","expected_generation":0,"operation_id":"feedback-stale"})
        );
        assert!(execute(
            &p.0.join("state"),
            json!({"op":"operation_status","operation_id":"unknown"})
        )
        .unwrap_err()
        .starts_with("operation_not_found:"));
        assert!(execute(
            &p.0.join("state"),
            json!({"op":"operation_status","operation_id":"feedback-cp","include_record":"true"})
        )
        .unwrap_err()
        .starts_with("invalid_request:"));
        let db = Connection::open(p.0.join("state/state.sqlite")).unwrap();
        db.execute("INSERT INTO operations VALUES('feedback-pending','digest','{\"op\":\"checkpoint\"}',NULL)",[]).unwrap();
        assert_eq!(
            p.request(json!({"op":"operation_status","operation_id":"feedback-pending"})),
            json!({"ok":true,"state":"pending"})
        );
        let pending = p.request(json!({"op":"operation_status","operation_id":"feedback-pending","include_record":true}));
        assert_eq!(pending["state"], "pending");
        assert_eq!(pending["result"], Value::Null);
        assert_eq!(pending["request"], json!({"op":"checkpoint"}));
    }

    #[test]
    fn feedback_status_is_bounded_and_preserves_selected_checkpoint_identity() {
        let p = Project::new();
        let initial = p.request(json!({"op":"status","workspace":"A"}));
        assert_eq!(initial["checkpoint"], Value::Null);
        assert_eq!(initial["checks_configured"], 0);
        assert_eq!(initial["required_checks_configured"], 0);
        p.request(json!({"op":"checkpoint","workspace":"A","expected_generation":0,"operation_id":"feedback-selected"}));
        p.request(json!({"op":"checkpoint","workspace":"A","expected_generation":1,"operation_id":"feedback-latest"}));
        for i in 0..12 {
            let published = p.request(json!({"op":"publish","workspace":"A","checkpoint":"feedback-selected","intent":"synthetic bounded summary","operation_id":format!("feedback-pub-{i}")}));
            assert_eq!(published["checkpoint"], "feedback-selected");
            assert_eq!(published["checkpoint_generation"], 1);
            assert_eq!(published["current_generation"], 2);
            assert_eq!(published["validation"]["state"], "unchecked");
        }
        let status = p.request(json!({"op":"status","workspace":"A"}));
        assert_eq!(status["checkpoint"], "feedback-latest");
        assert_eq!(status["checkpoint_generation"], 2);
        assert_eq!(status["proposals_total"], 12);
        assert_eq!(status["proposals_limit"], 10);
        assert_eq!(status["proposals_truncated"], true);
        let summaries = status["proposals"].as_array().unwrap();
        assert_eq!(summaries.len(), 10);
        assert_eq!(summaries[0]["proposal"], "feedback-pub-11");
        assert_eq!(summaries[9]["proposal"], "feedback-pub-2");
        assert!(summaries.iter().all(|s| s.get("details").is_none()));
        assert_eq!(
            p.request(json!({"op":"status","workspace":"B"}))["proposals_total"],
            0
        );
        // Configuration alone is safe: no integrate, command_run, or policy
        // runner occurs after this deliberately nonexistent check is configured.
        p.request(json!({"op":"configure","operation_id":"feedback-configure","policy":{"checks":[{"id":"never-executed","argv":["never-executed"],"required":false}]}}));
        let pending = p.request(json!({"op":"proposal_status","proposal":"feedback-pub-11"}));
        assert_eq!(pending["validation"]["state"], "pending");
        assert_eq!(pending["checks_configured"], 1);
        assert_eq!(pending["required_checks_configured"], 0);
    }

    #[test]
    fn feedback_dirty_status_preserves_explicit_older_publication_choice() {
        let p = Project::new();
        fs::write(p.0.join("A/a"), "safe selected content\n").unwrap();
        p.request(json!({"op":"checkpoint","workspace":"A","expected_generation":0,"operation_id":"chosen-public-snapshot"}));
        fs::write(p.0.join("A/private-checkpoint"), "PRIVATE_SNAPSHOT_CANARY").unwrap();
        let private = p.request(json!({"op":"checkpoint","workspace":"A","expected_generation":1,"operation_id":"newer-private-snapshot"}));
        fs::write(p.0.join("A/private-live"), "PRIVATE_LIVE_CANARY").unwrap();
        let db = Connection::open(p.0.join("state/state.sqlite")).unwrap();
        let before: i64 = db
            .query_row("SELECT COUNT(*) FROM checkpoints", [], |r| r.get(0))
            .unwrap();
        let status = p.request(json!({"op":"status","workspace":"A"}));
        assert_eq!(status["dirty"], true);
        assert_eq!(status["checkpoint"], "newer-private-snapshot");
        assert_eq!(status["next_action"]["op"], Value::Null);
        assert!(status["next_action"]["reason"]
            .as_str()
            .unwrap()
            .contains("Preserve the caller's exact checkpoint choice"));
        assert!(status["next_action"]["arguments"]
            .get("expected_generation")
            .is_none());
        assert_eq!(status["generation"], 2);
        let after: i64 = db
            .query_row("SELECT COUNT(*) FROM checkpoints", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, after);
        let published = p.request(json!({"op":"publish","workspace":"A","checkpoint":"chosen-public-snapshot","intent":"explicit older safe checkpoint","operation_id":"publish-chosen-snapshot"}));
        assert_eq!(published["checkpoint"], "chosen-public-snapshot");
        assert_eq!(
            p.request(json!({"op":"integrate"}))["outcomes"][0]["state"],
            "integrated"
        );
        let git = coordinator(&p.0.join("state"));
        let head = git.head(HEAD).unwrap();
        assert_eq!(
            git.run(&["show", &format!("{head}:a")], None).unwrap(),
            b"safe selected content\n"
        );
        for path in ["private-checkpoint", "private-live"] {
            assert!(git.run(&["show", &format!("{head}:{path}")], None).is_err());
        }
        assert!(git
            .run(
                &["cat-file", "-e", private["commit"].as_str().unwrap()],
                None
            )
            .is_err());
        assert_eq!(
            fs::read_to_string(p.0.join("A/private-checkpoint")).unwrap(),
            "PRIVATE_SNAPSHOT_CANARY"
        );
        assert_eq!(
            fs::read_to_string(p.0.join("A/private-live")).unwrap(),
            "PRIVATE_LIVE_CANARY"
        );
        let status = p.request(json!({"op":"status","workspace":"A"}));
        assert_eq!(status["generation"], 2);
        assert_eq!(status["checkpoint"], "newer-private-snapshot");
    }

    #[test]
    fn feedback_resolution_failure_reports_isolated_generation_and_prioritizes_task() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        let db = Connection::open(p.0.join("state/state.sqlite")).unwrap();
        db.execute("UPDATE workspaces SET generation=7 WHERE id='fix'", [])
            .unwrap();
        let mut request = resolution_request(&opened, "feedback-stale-resolution");
        request["expected_head"] = json!("0".repeat(40));
        let result = execute(&p.0.join("state"), request).unwrap();
        assert_eq!(result["current_generation"], 7);
        assert_eq!(result["current_generation_workspace"], "fix");
        assert_eq!(result["error"]["code"], "stale_resolution");
        assert_eq!(result["next_action"]["arguments"]["workspace"], "B");
        fs::write(p.0.join("B/private-unpublished"), "private WIP").unwrap();
        let status = p.request(json!({"op":"status","workspace":"B"}));
        assert_eq!(status["dirty"], true);
        assert_eq!(status["next_action"]["op"], "resolution_open");
        assert_eq!(status["next_action"]["arguments"]["workspace"], "B");
        assert!(status["resolution_tasks"][0]["next_action"].is_string());
        assert_eq!(
            status["resolution_tasks"][0]["next_action_hint"]["op"],
            "resolution_open"
        );
        // Wire tasks remain untouched by local-only feedback decoration.
        let task = resolution::task(&db, "conflict-pub-B").unwrap().unwrap();
        assert!(task.get("next_action_hint").is_none());
        assert!(task.get("validation").is_none());
    }

    #[test]
    fn feedback_zero_check_resolution_is_unchecked_despite_legacy_pending_flag() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        let submitted = p.request(resolution_request(&opened, "unchecked-resolution-submit"));
        assert_eq!(submitted["checks_pending"], true);
        assert_eq!(submitted["checks_configured"], 0);
        assert_eq!(submitted["validation"]["state"], "unchecked");
        assert_eq!(submitted["next_action"]["op"], "proposal_status");
        assert_eq!(submitted["next_action"]["reason"], "Proposal is queued. Observe its result; integration and adoption are separate actions.");
    }

    #[test]
    fn feedback_resolution_heads_distinguish_capture_from_checkout_basis() {
        let p = Project::new();
        let task = conflicting_task(&p);
        let captured = task["current_head"].clone();
        assert_eq!(task["captured_head"], captured);
        assert_eq!(task["current_head_scope"], "captured_at_quarantine");
        fs::write(p.0.join("A/independent"), "accepted later\n").unwrap();
        p.request(json!({"op":"checkpoint","workspace":"A","expected_generation":1,"operation_id":"heads-later-cp"}));
        p.request(json!({"op":"publish","workspace":"A","checkpoint":"heads-later-cp","intent":"advance head","operation_id":"heads-later-pub"}));
        assert_eq!(
            p.request(json!({"op":"integrate"}))["outcomes"][0]["state"],
            "integrated"
        );
        let request = json!({"op":"resolution_open","workspace":"B","proposal":"conflict-pub-B","resolution_workspace":"heads-fix","path":p.0.join("heads-fix"),"operation_id":"heads-open"});
        let opened = p.request(request.clone());
        assert_eq!(opened["resolution_head"], opened["current_head"]);
        assert_eq!(opened["current_head_scope"], "resolution_checkout_basis");
        assert_ne!(opened["resolution_head"], captured);
        assert_eq!(opened["task"]["captured_head"], captured);
        assert_eq!(opened["task"]["current_head"], captured);
        assert_eq!(p.request(request), opened);
        assert_eq!(
            p.request(json!({"op":"operation_status","operation_id":"heads-open"})),
            opened
        );
        let db = Connection::open(p.0.join("state/state.sqlite")).unwrap();
        let wire_task = resolution::task(&db, "conflict-pub-B").unwrap().unwrap();
        assert!(wire_task.get("captured_head").is_none());
        assert!(wire_task.get("current_head_scope").is_none());
        fs::write(p.0.join("heads-fix/a"), "explicit combined result\n").unwrap();
        p.request(json!({"op":"checkpoint","workspace":"heads-fix","expected_generation":0,"operation_id":"heads-fixed-cp"}));
        let mut submit = json!({"op":"resolution_submit","workspace":"B","proposal":"conflict-pub-B","resolution_workspace":"heads-fix","checkpoint":"heads-fixed-cp","expected_head":captured,"resolved_conflicts":["a"],"operation_id":"heads-reject-capture"});
        let rejected = execute(&p.0.join("state"), submit.clone()).unwrap();
        assert_eq!(rejected["error"]["code"], "stale_resolution");
        submit["operation_id"] = json!("heads-submit-current");
        submit["expected_head"] = opened["resolution_head"].clone();
        assert_eq!(p.request(submit)["ok"], true);
    }

    #[test]
    fn feedback_recovered_promotion_does_not_reuse_prior_candidate_validation() {
        let p = Project::new();
        fs::write(p.0.join("A/a"), "new public candidate").unwrap();
        p.request(json!({"op":"checkpoint","workspace":"A","expected_generation":0,"operation_id":"feedback-recovery-cp"}));
        let proposal = p.request(json!({"op":"publish","workspace":"A","checkpoint":"feedback-recovery-cp","intent":"synthetic promotion recovery","operation_id":"feedback-recovery-pub"}));
        let state = p.0.join("state");
        let git = coordinator(&state);
        let old = git.head(HEAD).unwrap();
        let commit = proposal["commit"].as_str().unwrap();
        let tree = git.tree(commit).unwrap();
        let new = git
            .commit(
                &tree,
                &[old.clone(), commit.into()],
                "synthetic interrupted integration",
            )
            .unwrap();
        let db = Connection::open(state.join("state.sqlite")).unwrap();
        let obsolete = json!({"proposal":commit,"candidate_tree":"obsolete","accepted":true,
            "policy":{"checks":[{"id":"old"}]},"checks":[{"id":"old","success":true,"checkout_unchanged":true,"candidate_tree":"obsolete"}]});
        db.execute(
            "UPDATE proposals SET details=?1 WHERE id='feedback-recovery-pub'",
            [obsolete.to_string()],
        )
        .unwrap();
        db.execute("INSERT INTO promotions VALUES('feedback-recovery','feedback-recovery-pub',?1,?2,'intent')",params![old,new]).unwrap();
        git.set_ref(HEAD, &new, Some(&old)).unwrap();
        // Safe synthetic journal state: no command, fault hook, or runner starts.
        db.execute(
            "INSERT INTO meta VALUES('policy',?1)",
            [json!({"checks":[{"id":"never-executed","argv":["never-executed"]}]}).to_string()],
        )
        .unwrap();
        let recovered =
            p.request(json!({"op":"proposal_status","proposal":"feedback-recovery-pub"}));
        assert_eq!(recovered["state"], "integrated");
        assert_eq!(recovered["head"], new);
        assert_eq!(recovered["details"], Value::Null);
        assert_eq!(recovered["validation"]["state"], "unchecked");
        assert_eq!(recovered["checks_configured"], 1);
        assert_eq!(fs::read_to_string(p.0.join("B/a")).unwrap(), "original");
    }

    #[test]
    fn interrupted_command_is_never_replayed_and_fences_workspace() {
        let p = Project::new();
        let state = p.0.join("state");
        let request = json!({"op":"command_run","workspace":"B","expected_generation":0,"operation_id":"interrupted-command","argv":["must-never-execute"]});
        let db = Connection::open(state.join("state.sqlite")).unwrap();
        db.execute(
            "INSERT INTO operations(id,digest,request) VALUES('interrupted-command',?1,?2)",
            params![digest(&request), request.to_string()],
        )
        .unwrap();
        db.execute("INSERT INTO commands(id,workspace,state,generation) VALUES('interrupted-command','B','running',1)", []).unwrap();
        db.execute("UPDATE workspaces SET generation=1 WHERE id='B'", [])
            .unwrap();
        drop(db);
        let result = execute(&state, request.clone()).unwrap();
        assert_eq!(result["error"]["code"], "writer_recovery_required");
        assert_eq!(result["state"], "interrupted");
        assert_eq!(execute(&state, request).unwrap(), result);
        assert_eq!(
            p.request(json!({"op":"status","workspace":"B"}))["writer_recovery_required"],
            true
        );
        let cp = execute(&state, json!({"op":"checkpoint","workspace":"B","expected_generation":1,"operation_id":"blocked-cp"})).unwrap();
        assert_eq!(cp["error"]["code"], "writer_recovery_required");
        let missing_confirmation = execute(&state, json!({"op":"command_recover","workspace":"B","expected_generation":1,"operation_id":"no-confirm"})).unwrap();
        assert_eq!(
            missing_confirmation["error"]["code"],
            "writer_confirmation_required"
        );
        let ack = p.request(json!({"op":"command_recover","workspace":"B","expected_generation":1,"operation_id":"ack","confirm_writers_stopped":true}));
        assert_eq!(ack["generation"], 2);
        p.request(json!({"op":"checkpoint","workspace":"B","expected_generation":2,"operation_id":"after-ack"}));
    }
    #[test]
    fn legacy_unjournaled_command_is_fenced_without_replay() {
        let p = Project::new();
        let state = p.0.join("state");
        let request = json!({"op":"command_run","workspace":"B","expected_generation":0,"operation_id":"legacy","argv":["must-never-execute"]});
        let db = Connection::open(state.join("state.sqlite")).unwrap();
        db.execute(
            "INSERT INTO operations(id,digest,request) VALUES('legacy',?1,?2)",
            params![digest(&request), request.to_string()],
        )
        .unwrap();
        drop(db);
        let result = execute(&state, request).unwrap();
        assert_eq!(result["error"]["code"], "writer_recovery_required");
        assert_eq!(result["generation"], 1);
        let status = p.request(json!({"op":"status","workspace":"B"}));
        assert_eq!(status["generation"], 1);
        assert_eq!(status["dirty"], Value::Null);
        assert_eq!(status["next_action"]["op"], "status");
        assert!(status["next_action"]["reason"]
            .as_str()
            .unwrap()
            .contains("command_recover"));
    }
    #[test]
    fn failed_command_launch_invalidates_generation_and_is_idempotent() {
        let p = Project::new();
        let request = json!({"op":"command_run","workspace":"B","expected_generation":0,"operation_id":"no-program","argv":[p.0.join("nonexistent-program")]});
        let first = p.request(request.clone());
        assert_eq!(first["generation"], 1);
        assert_eq!(first["execution"]["success"], false);
        assert!(first["execution"]["spawn_error"].is_string());
        assert_eq!(p.request(request), first);
        let status = p.request(json!({"op":"status","workspace":"B"}));
        assert_eq!(status["generation"], 1);
        assert_eq!(status["writer_recovery_required"], false);
    }
    #[test]
    fn duplicate_workspace_open_does_not_create_destination_or_change_cache() {
        let p = Project::new();
        let state = p.0.join("state");
        let old = local(&state, "B").head(HEAD).unwrap();
        p.publish(0);
        let destination = p.0.join("unregistered");
        let r = execute(
            &state,
            json!({"op":"open","workspace":"B","path":destination,"operation_id":"duplicate-open"}),
        )
        .unwrap();
        assert_eq!(r["ok"], false);
        assert_eq!(r["error"]["code"], "workspace_exists");
        assert!(!destination.exists());
        assert_eq!(local(&state, "B").head(HEAD).unwrap(), old);
        assert_eq!(fs::read_to_string(p.0.join("B/a")).unwrap(), "original");
    }
    #[test]
    fn older_authoritative_adoption_fetches_latest_cache_objects() {
        let p = Project::new();
        let target = p.publish(0);
        let latest = p.publish(1);
        p.request(json!({"op":"adopt","workspace":"B","target":target,"expected_generation":0,"operation_id":"adopt-old"}));
        assert!(p.0.join("B/file-0").exists());
        assert!(!p.0.join("B/file-1").exists());
        fs::rename(p.0.join("state/coordinator.git"), p.0.join("offline.git")).unwrap();
        let updates = p.request(json!({"op":"updates","workspace":"B"}));
        assert_eq!(updates["latest"], latest);
        p.request(json!({"op":"adopt","workspace":"B","target":latest,"expected_generation":1,"operation_id":"adopt-cached"}));
        assert!(p.0.join("B/file-1").exists());
    }
    #[test]
    fn applied_adoption_recovery_refuses_later_edits_without_advancing_metadata() {
        let p = Project::new();
        let state = p.0.join("state");
        let root = p.0.join("B");
        let stage = p.0.join("stage");
        let backup = p.0.join("backup");
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join("a"), "installed").unwrap();
        let names = vec!["a".to_string()];
        adoption::apply(&root, &stage, &backup, &names, &names).unwrap();
        let db = Connection::open(state.join("state.sqlite")).unwrap();
        db.execute("INSERT INTO adoptions(id,workspace,old_base,target,commit_oid,tree,old_files,new_files,stage,backup,state,generation) VALUES('interrupted','B','','','','','[\"a\"]','[\"a\"]',?1,?2,'applied',0)", params![stage.to_string_lossy(),backup.to_string_lossy()]).unwrap();
        fs::write(root.join("a"), "later edit").unwrap();
        let error = execute(&state, json!({"op":"status","workspace":"B"})).unwrap_err();
        assert!(error.starts_with("recovery_required:"));
        assert_eq!(fs::read_to_string(root.join("a")).unwrap(), "later edit");
        assert_eq!(ws(&db, "B").unwrap().generation, 0);
        let phase: String = db
            .query_row(
                "SELECT state FROM adoptions WHERE id='interrupted'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(phase, "applied");
    }
    #[test]
    fn offline_checkpoint_recovers_interrupted_private_adoption_first() {
        let p = Project::new();
        let state = p.0.join("state");
        let root = p.0.join("B");
        let stage = p.0.join("stage");
        let backup = p.0.join("backup");
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join("a"), "partially applied").unwrap();
        let names = vec!["a".to_string()];
        adoption::apply(&root, &stage, &backup, &names, &names).unwrap();
        // Reproduce the persisted applying phase of a process killed before
        // its phase transition. Recovery must not depend on the public store.
        let db = Connection::open(state.join("state.sqlite")).unwrap();
        db.execute("INSERT INTO adoptions(id,workspace,old_base,target,commit_oid,tree,old_files,new_files,stage,backup,state,generation) VALUES('interrupted','B','','','','','[\"a\"]','[\"a\"]',?1,?2,'applying',0)", params![stage.to_string_lossy(),backup.to_string_lossy()]).unwrap();
        drop(db);
        fs::rename(state.join("coordinator.git"), p.0.join("offline.git")).unwrap();
        let cp = p.request(json!({"op":"checkpoint","workspace":"B","expected_generation":0,"operation_id":"offline-cp"}));
        assert_eq!(fs::read_to_string(root.join("a")).unwrap(), "original");
        let git = local(&state, "B");
        let blob = git
            .run(
                &["show", &format!("{}:a", cp["commit"].as_str().unwrap())],
                None,
            )
            .unwrap();
        assert_eq!(blob, b"original");
        let db = Connection::open(state.join("state.sqlite")).unwrap();
        let phase: String = db
            .query_row(
                "SELECT state FROM adoptions WHERE id='interrupted'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(phase, "rolled_back");
    }
    fn conflicting_task(p: &Project) -> Value {
        for (wid, text) in [("A", "current\n"), ("B", "proposal\n")] {
            fs::write(p.0.join(wid).join("a"), text).unwrap();
            p.request(json!({"op":"checkpoint","workspace":wid,"expected_generation":0,"operation_id":format!("conflict-cp-{wid}")}));
            p.request(json!({"op":"publish","workspace":wid,"checkpoint":format!("conflict-cp-{wid}"),"intent":"conflict fixture","operation_id":format!("conflict-pub-{wid}")}));
        }
        let outcome = p.request(json!({"op":"integrate"}));
        assert_eq!(outcome["outcomes"][0]["state"], "integrated");
        assert_eq!(
            outcome["outcomes"][1]["resolution_task"]["state"],
            "action_required"
        );
        p.request(json!({"op":"resolution_tasks","workspace":"B"}))["tasks"][0].clone()
    }
    fn open_resolution(p: &Project, name: &str) -> Value {
        p.request(json!({"op":"resolution_open","workspace":"B","proposal":"conflict-pub-B","resolution_workspace":name,"path":p.0.join(name),"operation_id":format!("open-{name}")}))
    }
    #[test]
    fn resolution_returns_owner_task_and_keeps_private_wip_isolated() {
        let p = Project::new();
        let task = conflicting_task(&p);
        assert_eq!(task["reason"], "merge_conflict");
        assert_eq!(task["conflict_paths"], json!(["a"]));
        fs::write(p.0.join("B/private"), "private WIP").unwrap();
        assert!(
            p.request(json!({"op":"resolution_tasks","workspace":"A"}))["tasks"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let bad=execute(&p.0.join("state"),json!({"op":"resolution_open","workspace":"A","proposal":"conflict-pub-B","resolution_workspace":"bad","path":p.0.join("bad"),"operation_id":"bad-open"})).unwrap();
        assert_eq!(bad["error"]["code"], "resolution_owner_mismatch");
        let opened = open_resolution(&p, "fix");
        assert!(!p.0.join("fix/private").exists());
        assert_eq!(fs::read_to_string(p.0.join("B/a")).unwrap(), "proposal\n");
        assert_eq!(
            fs::read_to_string(p.0.join("B/private")).unwrap(),
            "private WIP"
        );
        let current = PathBuf::from(opened["side_paths"]["current"].as_str().unwrap());
        assert_eq!(fs::read_to_string(current.join("a")).unwrap(), "current\n");
        assert!(fs::read_to_string(p.0.join("fix/a"))
            .unwrap()
            .contains("<<<<<<<"));
    }
    #[test]
    fn resolution_submit_rejects_markers_and_is_idempotent_after_fix() {
        let p = Project::new();
        conflicting_task(&p);
        let opened = open_resolution(&p, "fix");
        p.request(json!({"op":"checkpoint","workspace":"fix","expected_generation":0,"operation_id":"marker-cp"}));
        let request = json!({"op":"resolution_submit","workspace":"B","proposal":"conflict-pub-B","resolution_workspace":"fix","checkpoint":"marker-cp","expected_head":opened["current_head"],"resolved_conflicts":["a"],"operation_id":"marker-submit"});
        let bad = execute(&p.0.join("state"), request).unwrap();
        assert_eq!(bad["error"]["code"], "unresolved_conflict_markers");
        fs::write(p.0.join("fix/a"), "explicit combined result\n").unwrap();
        p.request(json!({"op":"checkpoint","workspace":"fix","expected_generation":1,"operation_id":"fixed-cp"}));
        let direct=execute(&p.0.join("state"),json!({"op":"publish","workspace":"fix","checkpoint":"fixed-cp","intent":"bypass","operation_id":"bypass"})).unwrap();
        assert_eq!(direct["error"]["code"], "resolution_submit_required");
        let request = json!({"op":"resolution_submit","workspace":"B","proposal":"conflict-pub-B","resolution_workspace":"fix","checkpoint":"fixed-cp","expected_head":opened["current_head"],"resolved_conflicts":["a"],"operation_id":"fixed-submit"});
        let result = p.request(request.clone());
        assert_eq!(result["attempt"], 1);
        assert_eq!(p.request(request), result);
        assert_eq!(
            p.request(json!({"op":"proposal_status","proposal":"conflict-pub-B"}))["state"],
            "superseded"
        );
        assert_eq!(
            p.request(json!({"op":"integrate"}))["outcomes"][0]["state"],
            "integrated"
        );
        let public = coordinator(&p.0.join("state"));
        assert_eq!(
            public
                .run(
                    &["show", &format!("{}:a", public.head(HEAD).unwrap())],
                    None
                )
                .unwrap(),
            b"explicit combined result\n"
        );
        assert_eq!(fs::read_to_string(p.0.join("B/a")).unwrap(), "proposal\n");
    }
    fn fixed_resolution(p: &Project) -> Value {
        conflicting_task(p);
        let opened = open_resolution(p, "fix");
        fs::write(p.0.join("fix/a"), "resolved\n").unwrap();
        p.request(json!({"op":"checkpoint","workspace":"fix","expected_generation":0,"operation_id":"fixed-cp"}));
        opened
    }
    fn resolution_request(opened: &Value, id: &str) -> Value {
        json!({"op":"resolution_submit","workspace":"B","proposal":"conflict-pub-B","resolution_workspace":"fix","checkpoint":"fixed-cp","expected_head":opened["current_head"],"resolved_conflicts":["a"],"operation_id":id})
    }
    fn queue_public_change(p: &Project, name: &str, path: &str, contents: &str) {
        p.request(json!({"op":"open","workspace":name,"path":p.0.join(name),"operation_id":format!("open-{name}")}));
        fs::write(p.0.join(name).join(path), contents).unwrap();
        p.request(json!({"op":"checkpoint","workspace":name,"expected_generation":0,"operation_id":format!("cp-{name}")}));
        p.request(json!({"op":"publish","workspace":name,"checkpoint":format!("cp-{name}"),"intent":"new public work","operation_id":format!("pub-{name}")}));
    }
    fn integrate_one(p: &Project) -> Value {
        let result = p.request(json!({"op":"integrate","max_proposals":1}));
        assert_eq!(result["outcomes"].as_array().unwrap().len(), 1);
        result["outcomes"][0].clone()
    }
    fn public_bytes(p: &Project, head: &str, path: &str) -> Vec<u8> {
        coordinator(&p.0.join("state"))
            .run(&["show", &format!("{head}:{path}")], None)
            .unwrap()
    }
    #[test]
    fn resolution_disjoint_head_advance_remerges_without_reopening() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        queue_public_change(&p, "newer", "other", "unrelated\n");
        let advanced = integrate_one(&p)["head"].as_str().unwrap().to_owned();
        let request = resolution_request(&opened, "advanced-submit");
        let result = p.request(request.clone());
        assert_eq!(result["head_advanced"], true);
        assert_eq!(result["observed_head"], advanced);
        assert_eq!(result["base"], opened["current_head"]);
        assert_eq!(result["checks_pending"], true);
        assert_eq!(result["state"], "coordinator_accepted");
        assert_eq!(result["attempt"], 1);
        assert_eq!(p.request(request), result);
        assert_eq!(p.request(json!({"op":"status"}))["head"], advanced);
        let public = coordinator(&p.0.join("state"));
        let parents = public
            .run(
                &[
                    "rev-list",
                    "--parents",
                    "-n",
                    "1",
                    result["commit"].as_str().unwrap(),
                ],
                None,
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(parents)
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>(),
            vec![
                result["commit"].as_str().unwrap(),
                opened["current_head"].as_str().unwrap()
            ]
        );
        assert_eq!(integrate_one(&p)["state"], "integrated");
        let head = public.head(HEAD).unwrap();
        assert_eq!(public_bytes(&p, &head, "a"), b"resolved\n");
        assert_eq!(public_bytes(&p, &head, "other"), b"unrelated\n");
        assert_eq!(fs::read_to_string(p.0.join("fix/a")).unwrap(), "resolved\n");
        assert!(!p.0.join("fix/other").exists());
        assert_eq!(
            local(&p.0.join("state"), "fix").head(HEAD).unwrap(),
            opened["current_head"]
        );
        assert_eq!(fs::read_to_string(p.0.join("B/a")).unwrap(), "proposal\n");
    }
    #[test]
    fn resolution_overlapping_head_advance_is_rejected_without_consuming_attempt() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        queue_public_change(&p, "newer", "a", "newer overlapping intent\n");
        let advanced = integrate_one(&p)["head"].as_str().unwrap().to_owned();
        let request = resolution_request(&opened, "stale-submit");
        let result = execute(&p.0.join("state"), request.clone()).unwrap();
        assert_eq!(result["error"]["code"], "stale_resolution");
        assert_eq!(execute(&p.0.join("state"), request).unwrap(), result);
        let task = p.request(json!({"op":"resolution_tasks","workspace":"B"}))["tasks"][0].clone();
        assert_eq!(task["attempt"], 0);
        assert_eq!(p.request(json!({"op":"status"}))["head"], advanced);
        assert_eq!(
            public_bytes(&p, &advanced, "a"),
            b"newer overlapping intent\n"
        );
        assert_eq!(fs::read_to_string(p.0.join("fix/a")).unwrap(), "resolved\n");
        assert!(coordinator(&p.0.join("state"))
            .head("refs/wipstash/proposals/stale-submit")
            .is_err());
        assert!(local(&p.0.join("state"), "B")
            .head("refs/wipstash/exports/stale-submit")
            .is_err());
        assert_ne!(
            open_resolution(&p, "fresh")["current_head"],
            opened["current_head"]
        );
    }
    #[test]
    fn resolution_multiple_head_moves_before_integration_preserve_every_change() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        queue_public_change(&p, "first", "first", "first public change\n");
        let first = integrate_one(&p)["head"].as_str().unwrap().to_owned();
        queue_public_change(&p, "second", "second", "second public change\n");
        queue_public_change(&p, "third", "third", "third public change\n");
        let submitted = p.request(resolution_request(&opened, "moving-submit"));
        assert_eq!(submitted["observed_head"], first);
        for _ in 0..3 {
            assert_eq!(integrate_one(&p)["state"], "integrated");
        }
        let public = coordinator(&p.0.join("state"));
        let head = public.head(HEAD).unwrap();
        for path in ["first", "second", "third"] {
            assert_eq!(
                public_bytes(&p, &head, path),
                format!("{path} public change\n").as_bytes()
            );
        }
        assert_eq!(public_bytes(&p, &head, "a"), b"resolved\n");
        assert!(public.ancestor(&first, &head).unwrap());
    }
    #[test]
    fn resolution_overlap_after_preflight_returns_successor_task() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        queue_public_change(&p, "first", "first", "disjoint\n");
        integrate_one(&p);
        queue_public_change(&p, "later", "a", "later overlapping intent\n");
        let submitted = p.request(resolution_request(&opened, "later-submit"));
        assert_eq!(submitted["head_advanced"], true);
        let latest = integrate_one(&p)["head"].as_str().unwrap().to_owned();
        let outcome = integrate_one(&p);
        assert_eq!(outcome["state"], "quarantined");
        assert_eq!(outcome["resolution_task"]["proposal"], "later-submit");
        assert_eq!(outcome["resolution_task"]["attempt"], 1);
        assert_eq!(outcome["resolution_task"]["reason"], "merge_conflict");
        assert_eq!(outcome["resolution_task"]["conflict_paths"], json!(["a"]));
        assert_eq!(p.request(json!({"op":"status"}))["head"], latest);
        assert_eq!(
            public_bytes(&p, &latest, "a"),
            b"later overlapping intent\n"
        );
        assert_eq!(fs::read_to_string(p.0.join("fix/a")).unwrap(), "resolved\n");
    }
    #[test]
    fn resolution_advanced_head_retains_owner_head_checkpoint_and_generation_fences() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        queue_public_change(&p, "newer", "other", "unrelated\n");
        let latest = integrate_one(&p)["head"].clone();
        for (key, value, error) in [
            ("workspace", json!("A"), "resolution_owner_mismatch"),
            ("expected_head", latest, "stale_resolution"),
            ("expected_head", json!("0".repeat(40)), "stale_resolution"),
            (
                "resolved_conflicts",
                json!([]),
                "resolution_attestation_required",
            ),
        ] {
            let mut request = resolution_request(&opened, &format!("bad-{key}-{}", digest(&value)));
            request[key] = value;
            assert_eq!(
                execute(&p.0.join("state"), request).unwrap()["error"]["code"],
                error
            );
        }
        let mut foreign = resolution_request(&opened, "foreign-checkpoint");
        foreign["checkpoint"] = json!("conflict-cp-B");
        assert_eq!(execute(&p.0.join("state"), foreign).unwrap()["ok"], false);
        fs::write(p.0.join("fix/a"), "unchecked live change\n").unwrap();
        assert_eq!(
            execute(
                &p.0.join("state"),
                resolution_request(&opened, "changed-live")
            )
            .unwrap()["error"]["code"],
            "stale_resolution_checkpoint"
        );
        fs::write(p.0.join("fix/a"), "resolved\n").unwrap();
        // Model a completed command/recovery generation advance without launching
        // a process. Identical bytes and checkpoint identity do not waive fencing.
        let db = Connection::open(p.0.join("state/state.sqlite")).unwrap();
        db.execute(
            "UPDATE workspaces SET generation=generation+1 WHERE id='fix'",
            [],
        )
        .unwrap();
        assert_eq!(
            execute(
                &p.0.join("state"),
                resolution_request(&opened, "old-generation")
            )
            .unwrap()["error"]["code"],
            "stale_resolution_checkpoint"
        );
        p.request(json!({"op":"checkpoint","workspace":"fix","expected_generation":2,"operation_id":"fresh-cp"}));
        assert_eq!(
            execute(
                &p.0.join("state"),
                resolution_request(&opened, "old-checkpoint")
            )
            .unwrap()["error"]["code"],
            "stale_resolution_checkpoint"
        );
        let mut request = resolution_request(&opened, "fresh-generation");
        request["checkpoint"] = json!("fresh-cp");
        assert_eq!(p.request(request)["attempt"], 1);
    }
    #[test]
    fn resolution_advanced_candidate_still_fails_closed_under_current_policy() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        queue_public_change(&p, "newer", "other", "unrelated\n");
        let latest = integrate_one(&p)["head"].clone();
        p.request(resolution_request(&opened, "policy-submit"));
        // Corrupt stored policy is rejected before any command can start. Actual
        // required-check failure coverage lives in the native CI stress campaign.
        let db = Connection::open(p.0.join("state/state.sqlite")).unwrap();
        db.execute(
            "INSERT OR REPLACE INTO meta VALUES('policy',?1)",
            [json!({"checks":[{"id":"never-start","argv":[]}]}).to_string()],
        )
        .unwrap();
        let outcome = integrate_one(&p);
        assert_eq!(outcome["state"], "quarantined");
        assert_eq!(outcome["resolution_task"]["attempt"], 1);
        assert_eq!(
            outcome["resolution_task"]["reason"],
            "policy_evaluation_failed"
        );
        assert_eq!(p.request(json!({"op":"status"}))["head"], latest);
        p.request(json!({"op":"configure","policy":{},"operation_id":"restore-policy"}));
        let next = p.request(json!({"op":"resolution_open","workspace":"B","proposal":"policy-submit","resolution_workspace":"next","path":p.0.join("next"),"operation_id":"open-next"}));
        assert_eq!(next["conflict_paths"], json!([]));
        p.request(json!({"op":"checkpoint","workspace":"next","expected_generation":0,"operation_id":"next-cp"}));
        let result = p.request(json!({"op":"resolution_submit","workspace":"B","proposal":"policy-submit","resolution_workspace":"next","checkpoint":"next-cp","expected_head":next["current_head"],"resolved_conflicts":[],"operation_id":"next-submit"}));
        assert_eq!(result["attempt"], 2);
        assert_eq!(integrate_one(&p)["state"], "integrated");
    }
    #[test]
    fn resolution_advanced_candidate_never_exports_private_ancestors_or_adopts_wip() {
        let p = Project::new();
        let opened = fixed_resolution(&p);
        fs::write(p.0.join("fix/private-ancestor"), "private ancestor only\n").unwrap();
        let private = p.request(json!({"op":"checkpoint","workspace":"fix","expected_generation":1,"operation_id":"private-cp"}));
        let private_git = local(&p.0.join("state"), "fix");
        let private_blob = String::from_utf8(
            private_git
                .run(
                    &[
                        "rev-parse",
                        &format!("{}:private-ancestor", private["commit"].as_str().unwrap()),
                    ],
                    None,
                )
                .unwrap(),
        )
        .unwrap();
        fs::remove_file(p.0.join("fix/private-ancestor")).unwrap();
        p.request(json!({"op":"checkpoint","workspace":"fix","expected_generation":2,"operation_id":"selected-cp"}));
        fs::write(p.0.join("B/private-wip"), "original owner private WIP\n").unwrap();
        fs::write(p.0.join("B/.env"), "synthetic excluded canary\n").unwrap();
        let owner_before = local(&p.0.join("state"), "B")
            .capture(&p.0.join("B").canonicalize().unwrap())
            .unwrap();
        queue_public_change(&p, "newer", "other", "unrelated\n");
        integrate_one(&p);
        let mut request = resolution_request(&opened, "private-safe-submit");
        request["checkpoint"] = json!("selected-cp");
        p.request(request);
        assert_eq!(integrate_one(&p)["state"], "integrated");
        let public = coordinator(&p.0.join("state"));
        let head = public.head(HEAD).unwrap();
        assert_eq!(public_bytes(&p, &head, "a"), b"resolved\n");
        assert_eq!(public_bytes(&p, &head, "other"), b"unrelated\n");
        for oid in [private["commit"].as_str().unwrap(), private_blob.trim()] {
            assert!(public.run(&["cat-file", "-e", oid], None).is_err());
            assert!(local(&p.0.join("state"), "B")
                .run(&["cat-file", "-e", oid], None)
                .is_err());
        }
        assert_eq!(
            local(&p.0.join("state"), "B")
                .capture(&p.0.join("B").canonicalize().unwrap())
                .unwrap(),
            owner_before
        );
        assert_eq!(
            fs::read_to_string(p.0.join("B/.env")).unwrap(),
            "synthetic excluded canary\n"
        );
        assert_eq!(
            fs::read_to_string(p.0.join("B/private-wip")).unwrap(),
            "original owner private WIP\n"
        );
        assert_eq!(fs::read_to_string(p.0.join("fix/a")).unwrap(), "resolved\n");
        assert!(!p.0.join("fix/other").exists());
    }
}

#[cfg(test)]
mod sqlite_diagnostic_tests {
    use super::*;
    #[test]
    fn extended_io_error_preserves_primary_code_and_callsite() {
        let code = rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR_SHMSIZE);
        let error = sql::<()>(Err(rusqlite::Error::SqliteFailure(
            code,
            Some("disk I/O error".into()),
        )))
        .unwrap_err();
        assert!(
            error.starts_with("storage_error: disk I/O error; sqlite_code="),
            "{error}"
        );
        assert!(error.contains("extended_code=4874"), "{error}");
        assert!(error.contains("engine.rs:"), "{error}");
        assert_eq!(error.split(':').next(), Some("storage_error"));
    }
    #[test]
    fn phase_tracing_requires_explicit_opt_in() {
        for value in [None, Some(""), Some("0"), Some("true")] {
            assert!(!sqlite_diagnostics_requested(value));
        }
        assert!(sqlite_diagnostics_requested(Some("1")));
    }
}
