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
fn sql<T>(v: rusqlite::Result<T>) -> R<T> {
    v.map_err(|e| format!("storage_error: {e}"))
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
    sql(db.execute(
        "INSERT INTO events(kind,data) VALUES(?1,?2)",
        params![kind, data.to_string()],
    ))?;
    Ok(())
}
fn finish(db: &Connection, id: &str, result: &Value) -> R<()> {
    sql(db.execute(
        "UPDATE operations SET result=?2 WHERE id=?1",
        params![id, result.to_string()],
    ))?;
    Ok(())
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
                "UPDATE proposals SET state='integrated',head=?2 WHERE id=?1",
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
    fs2::FileExt::lock_exclusive(&lock).map_err(|e| e.to_string())?;
    let db = sql(Connection::open(state.join("state.sqlite")))?;
    sql(db.busy_timeout(std::time::Duration::from_secs(30)))?;
    init_db(&db)?;
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
                | "sync_import"
                | "sync_export"
                | "sync_reexport"
                | "sync_export_current_head"
                | "publish"
                | "integrate"
                | "retry_proposal"
                | "cancel"
                | "backup_flush"
                | "backup_tick"
        )
    {
        return Err("public_recovery_activation_required: review recovery_status, restore the matching policy, and explicitly activate the recovered authority".into());
    }
    recover(state, &db, matches!(op, "checkpoint" | "command_run"))?;
    sync::recover_head(state, &db)?;
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
        return initialize(state, &db, &r);
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
            | "backup_flush"
            | "retry_proposal"
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
    let result = fenced.and_then(|()| match op {
        "sync_export" | "sync_reexport" => sync::export(state, &db, &r),
        "sync_export_history" => sync::export_history(&db, &r),
        "sync_export_lookup" => sync::export_lookup(&db, &r),
        "sync_import" => sync::import(state, &db, &r),
        "sync_status" => sync::status(state, &db),
        "sync_pending" => sync::pending(&db, &r),
        "sync_export_current_head" => sync::export_current_head(state, &db, &r),
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
                json!({"ok":true,"adopted":w.base,"latest":latest,"coordinator_online":online && !sync::is_client(&db)?,"cached":!online || sync::is_client(&db)?,"remote_contact_unverified":sync::is_client(&db)?,"generation":w.generation,"files_changed":false}),
            )
        }
        "operation_status" => {
            let result: Option<String> = sql(db.query_row(
                "SELECT result FROM operations WHERE id=?1",
                [field(&r, "operation_id")?],
                |r| r.get(0),
            ))?;
            Ok(match result {
                Some(v) => serde_json::from_str(&v).map_err(|e| e.to_string())?,
                None => json!({"ok":true,"state":"pending"}),
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
    });
    match (id, result) {
        (Some(id), Ok(value)) => {
            finish(&db, id, &value)?;
            Ok(value)
        }
        (Some(id), Err(error)) => {
            let code = error.split(':').next().unwrap_or("internal_error");
            let value = json!({"ok":false,"error":{"code":code,"message":error}});
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
    let _ = ws(db, wid)?;
    let cp = field(r, "checkpoint")?;
    let id = field(r, "operation_id")?;
    let (tree, base): (String, String) = sql(db.query_row(
        "SELECT tree,base FROM checkpoints WHERE id=?1 AND workspace=?2",
        params![cp, wid],
        |r| Ok((r.get(0)?, r.get(1)?)),
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
    let result = json!({"ok":true,"state":if online{"coordinator_accepted"}else{"queued_offline"},"proposal":id,"commit":commit,"base":base,"durability":if online{"coordinator_saved"}else{"local_saved"},"replication":"not_configured"});
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
        )?;
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
            event(db, "quarantined", &json!({"proposal":id}))?;
            outcomes.push(json!({"proposal":id,"state":"quarantined","reason":"conflict_or_policy_rejection","details":evaluation.details}));
            continue;
        }
        if merge.tree == git.tree(&head)? {
            sql(db.execute(
                "UPDATE proposals SET state='already_included',head=?2 WHERE id=?1",
                params![id, head],
            ))?;
            event(db, "already_included", &json!({"proposal":id,"head":head}))?;
            outcomes.push(json!({"proposal":id,"state":"already_included","head":head,"evidence":"unchecked"}));
            continue;
        }
        let commit=git.commit(&merge.tree,&[head.clone(),p],&format!("Wipstash integration\noperation: integration-{id}\nproposal: {id}\nevidence: {evidence}"))?;
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
        outcomes.push(json!({"proposal":id,"state":"integrated","head":commit,"evidence":evidence,"repaired":evaluation.repaired}));
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
        Ok(
            json!({"ok":true,"workspace":wid,"path":w.path,"adopted":w.base,"latest":head,"cached_head":git.head(HEAD).ok(),"coordinator_online":head.is_some() && !sync::is_client(db)?,"remote_contact_unverified":sync::is_client(db)?,"public_store_role":if sync::is_client(db)?{"client_cache"}else{"authority"},"checkpoint_commit":w.checkpoint,"generation":w.generation,"dirty":dirty,"replication":"not_configured","profile":"cooperative-local","writer_recovery_required":fenced}),
        )
    } else {
        let count: i64 = sql(db.query_row("SELECT COUNT(*) FROM workspaces", [], |r| r.get(0)))?;
        Ok(
            json!({"ok":true,"head":head,"workspaces":count,"evidence":"unchecked","public_store_role":if sync::is_client(db)?{"client_cache"}else{"authority"},"remote_contact_unverified":sync::is_client(db)?,"replication":if sync::is_client(db)?{"trusted_directory_exchange"}else{"not_configured"}}),
        )
    }
}
fn proposal_status(db: &Connection, id: &str) -> R<Value> {
    let (state, commit, head, details): (String, String, Option<String>, Option<String>) = sql(db
        .query_row(
            "SELECT state,commit_oid,head,details FROM proposals WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
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
    if let Some(observed) = sync::observed_status(db, id)? {
        return Ok(
            json!({"ok":true,"proposal":id,"state":observed["state"],"local_state":state,"commit":commit,"head":observed["integration_head"],"evidence":observed["evidence"],"remote_observation":observed,"details":null}),
        );
    }
    Ok(
        json!({"ok":true,"proposal":id,"state":state,"commit":commit,"head":head,"details":detail,"evidence":evidence,"origin":sync::proposal_origin(db,id)?}),
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
}
