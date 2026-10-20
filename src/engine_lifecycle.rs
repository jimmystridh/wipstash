use super::*;
use fs2::FileExt;

pub(super) fn ensure_open(db: &Connection, wid: &str) -> R<()> {
    let closed: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_lifecycle WHERE workspace=?1 AND state='archived')",
        [wid],
        |r| r.get(0),
    ))?;
    if closed {
        Err("workspace_closed: use workspace_reopen before editing or sharing".into())
    } else {
        Ok(())
    }
}
fn lease(state: &Path, wid: &str) -> R<Option<fs::File>> {
    ident(wid)?;
    let path = state.join("workspace-leases").join(format!("{wid}.lock"));
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("lease_unavailable: {e}")),
    };
    file.try_lock_exclusive()
        .map_err(|_| "workspace_busy: a launched session still owns this directory".to_owned())?;
    Ok(Some(file))
}
pub(super) fn inventory_local(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let after = r["cursor"].as_u64().unwrap_or(0);
    let limit = r["limit"].as_u64().unwrap_or(16);
    if !(1..=32).contains(&limit) || after > i64::MAX as u64 {
        return Err("invalid_page".into());
    }
    let mut statement =
        sql(db.prepare("SELECT id FROM workspaces ORDER BY rowid LIMIT ?1 OFFSET ?2"))?;
    let ids = sql(statement.query_map(params![limit, after], |r| r.get::<_, String>(0)))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    let mut result = Vec::new();
    for id in ids {
        let w = ws(db, &id)?;
        let inspected = if r["inspect_files"] == false {
            observation::workspace_summary(db, &id)
        } else {
            experience::workspace_state(state, db, &id)
        };
        let mut entry = match inspected {
            Ok(v) => v,
            Err(e) => {
                json!({"inspection_available":false,"inspection_error":e,"has_unshared_changes":null,"workspace_state":sql(db.query_row("SELECT COALESCE((SELECT state FROM workspace_lifecycle WHERE workspace=?1),'open')",[&id],|r|r.get::<_,String>(0)))?})
            }
        };
        let last:Option<i64>=sql(db.query_row("SELECT MAX(CAST(json_extract(data,'$._occurred_at') AS INTEGER)) FROM events WHERE json_extract(data,'$.workspace')=?1",[&id],|r|r.get(0)))?;
        entry["workspace"] = json!(id);
        entry["path"] = json!(w.path);
        entry["generation"] = json!(w.generation);
        entry["last_activity"] = json!(last);
        entry["session_active"] = match lease(state, &id) {
            Ok(Some(_)) => json!(false),
            Ok(None) => Value::Null,
            Err(_) => json!(true),
        };
        entry["claims"] = coordination::list(db, Some(&id), 0, 16)?;
        result.push(entry);
    }
    let total: u64 = sql(db.query_row("SELECT COUNT(*) FROM workspaces", [], |r| r.get(0)))?;
    Ok(
        json!({"ok":true,"workspaces":result,"next_cursor":after+result.len() as u64,"has_more":after+ (result.len() as u64)<total,"total":total,"files_changed":false}),
    )
}
pub(super) fn change(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let wid = field(r, "workspace")?;
    let w = ws(db, wid)?;
    generation(r, &w)?;
    if r["op"] == "workspace_reopen" {
        sql(db.execute("INSERT INTO workspace_lifecycle VALUES(?1,'open',NULL,'reopened') ON CONFLICT(workspace) DO UPDATE SET state='open',closed_at=NULL,reason='reopened'",[wid]))?;
        event(db, "workspace_reopened", &json!({"workspace":wid}))?;
        return Ok(
            json!({"ok":true,"workspace":wid,"workspace_state":"open","generation":w.generation,"files_changed":false}),
        );
    }
    if r["confirm_writers_stopped"] != true {
        return Err("writer_confirmation_required: confirm that all native writers have stopped before archiving".into());
    }
    let _lease = lease(state, wid)?;
    if sync::is_client(db)?
        && !crate::audit::archive_delivery_ready(state, field(r, "operation_id")?)?
    {
        return Err(
            "workspace_pending_delivery: audit evidence still awaits authority acknowledgement"
                .into(),
        );
    }
    let own_claims = coordination::list(db, Some(wid), 0, 32)?;
    if own_claims["claims"]
        .as_array()
        .is_some_and(|c| !c.is_empty())
    {
        return Err("workspace_busy: complete or release active task claims first".into());
    }
    let status = experience::workspace_state(state, db, wid)?;
    if status["has_unshared_changes"] != false || status["workspace_mode"] != "ordinary" {
        return Err("workspace_has_unshared_work: preserve and reconcile local, pending, or blocked work before archiving".into());
    }
    if sync::is_client(db)? {
        let pending: bool = sql(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM coordination_outbox WHERE receipt IS NULL)",
            [],
            |r| r.get(0),
        ))?;
        if pending {
            return Err("workspace_busy: coordination delivery is pending".into());
        }
    }
    let reason = r["reason"].as_str().unwrap_or("completed");
    if reason.len() > 1024 {
        return Err("invalid_request: archive reason too long".into());
    }
    sql(db.execute("INSERT INTO workspace_lifecycle VALUES(?1,'archived',?2,?3) ON CONFLICT(workspace) DO UPDATE SET state='archived',closed_at=excluded.closed_at,reason=excluded.reason",params![wid,coordination::now(),reason]))?;
    event(
        db,
        "workspace_archived",
        &json!({"workspace":wid,"files_deleted":false,"reason":reason}),
    )?;
    Ok(
        json!({"ok":true,"workspace":wid,"workspace_state":"archived","generation":w.generation,"files_deleted":false,"files_changed":false,"path":w.path,"recoverable":true}),
    )
}

pub(super) fn inventory(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let mut page = inventory_local(state, db, r)?;
    page["remote_hosts"] = coordination::workspace_reports(
        db,
        r["remote_cursor"].as_u64().unwrap_or(0),
        r["limit"].as_u64().unwrap_or(16),
    )?;
    Ok(page)
}
