use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
pub(super) fn schema(db: &Connection) -> R<()> {
    sql(db.execute_batch("CREATE TABLE IF NOT EXISTS task_claims(id TEXT PRIMARY KEY,device TEXT NOT NULL,workspace TEXT NOT NULL,session TEXT NOT NULL,task TEXT NOT NULL,title TEXT NOT NULL,criteria TEXT NOT NULL,paths TEXT NOT NULL,expires INTEGER NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS coordination_outbox(id TEXT PRIMARY KEY,request TEXT NOT NULL,receipt TEXT);
CREATE TABLE IF NOT EXISTS workspace_reports(device TEXT NOT NULL,cursor INTEGER NOT NULL,received INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(device,cursor));
CREATE TABLE IF NOT EXISTS coordination_cache(id INTEGER PRIMARY KEY CHECK(id=1),fetched INTEGER NOT NULL,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS coordination_comments(seq INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,subject_type TEXT NOT NULL,subject_id TEXT NOT NULL,device TEXT NOT NULL,workspace TEXT NOT NULL,body TEXT NOT NULL,mentions TEXT NOT NULL,created INTEGER NOT NULL);
"))?;
    Ok(())
}
fn config(db: &Connection) -> R<Option<Value>> {
    sql(db
        .query_row("SELECT value FROM meta WHERE key='sync_config'", [], |r| {
            r.get::<_, String>(0)
        })
        .optional())?
    .map(|v| serde_json::from_str(&v).map_err(|e| e.to_string()))
    .transpose()
}
pub(super) fn device(db: &Connection) -> R<String> {
    Ok(config(db)?
        .and_then(|c| c["device"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "local".into()))
}
fn bounded(r: &Value, key: &str, max: usize) -> R<String> {
    let s = field(r, key)?;
    if s.trim().is_empty() || s.len() > max {
        return Err(format!("invalid_request: invalid {key}"));
    }
    Ok(s.into())
}
fn paths(r: &Value) -> R<Vec<String>> {
    let paths: Vec<String> = serde_json::from_value(r["paths"].clone())
        .map_err(|_| "invalid_request: paths must be an array")?;
    if paths.is_empty() || paths.len() > 32 {
        return Err("invalid_request: declare 1 through 32 paths".into());
    }
    let mut result = std::collections::BTreeSet::new();
    for path in paths {
        let path = path.trim_end_matches('/');
        if path.len() > 512
            || path.split('/').any(|c| c == ".." || c == ".")
            || path.contains('\\')
            || path.contains('*')
        {
            return Err(
                "invalid_request: paths must be literal repo-relative files or directories".into(),
            );
        }
        crate::git::allowed_path(path)?;
        result.insert(path.to_owned());
    }
    Ok(result.into_iter().collect())
}
fn overlap(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|s| s.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|s| s.starts_with('/'))
}
fn server_list(db: &Connection, workspace: Option<&str>, cursor: u64, limit: u64) -> R<Value> {
    if cursor > i64::MAX as u64 || !(1..=32).contains(&limit) {
        return Err("invalid_page".into());
    }
    let mut q=sql(db.prepare("SELECT id,device,workspace,session,task,title,criteria,paths,expires,revision,state FROM task_claims WHERE state='active' AND expires>?1 AND (?2 IS NULL OR workspace=?2) ORDER BY created,id LIMIT ?3 OFFSET ?4"))?;
    let rows=sql(q.query_map(params![now(),workspace,limit+1,cursor],|r|Ok(json!({"claim_id":r.get::<_,String>(0)?,"device":r.get::<_,String>(1)?,"workspace":r.get::<_,String>(2)?,"session_id":r.get::<_,String>(3)?,"task_id":r.get::<_,String>(4)?,"title":r.get::<_,String>(5)?,"acceptance_criteria":r.get::<_,String>(6)?,"paths":serde_json::from_str::<Value>(&r.get::<_,String>(7)?).unwrap_or(Value::Null),"expires_at":r.get::<_,i64>(8)?,"revision":r.get::<_,u64>(9)?,"state":r.get::<_,String>(10)?}))))?;
    let mut claims = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    let more = claims.len() > limit as usize;
    claims.truncate(limit as usize);
    Ok(
        json!({"ok":true,"claims":claims,"server_time":now(),"confirmed":true,"advisory":true,"next_cursor":cursor+claims.len() as u64,"has_more":more}),
    )
}
pub(super) fn list(db: &Connection, workspace: Option<&str>, cursor: u64, limit: u64) -> R<Value> {
    if !sync::is_client(db)? {
        return server_list(db, workspace, cursor, limit);
    }
    if cursor > i64::MAX as u64 || !(1..=32).contains(&limit) {
        return Err("invalid_page".into());
    }
    let cached: Option<(i64, String)> = sql(db
        .query_row(
            "SELECT fetched,data FROM coordination_cache WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    let mut value = if let Some((fetched, raw)) = cached {
        let mut v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let claims = v["claims"]
            .as_array()
            .ok_or("invalid_coordination_cache")?
            .iter()
            .filter(|c| workspace.is_none_or(|w| c["workspace"] == w))
            .filter(|c| {
                c["expires_at"].as_i64().is_some_and(|expiry| {
                    expiry
                        > v["server_time"]
                            .as_i64()
                            .unwrap_or(0)
                            .saturating_add(now().saturating_sub(fetched))
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        let start = (cursor as usize).min(claims.len());
        let end = (start + limit as usize).min(claims.len());
        v["claims"] = json!(&claims[start..end]);
        v["next_cursor"] = json!(end);
        v["has_more"] = json!(end < claims.len());
        v["fetched_at"] = json!(fetched);
        v["lease_time_is_estimate"] = json!(true);
        v["stale"] = json!(now().saturating_sub(fetched) > 30);
        v
    } else {
        json!({"ok":true,"claims":[],"confirmed":false,"stale":true,"has_more":false})
    };
    for key in ["commits", "comments", "repairs", "repo_health", "binding"] {
        value.as_object_mut().unwrap().remove(key);
    }
    value["remote_cache"] = json!(true);
    value["authority_contact_verified"] = json!(false);
    let mut q = sql(db.prepare(
        "SELECT id,request,receipt FROM coordination_outbox WHERE json_extract(request,'$.op')!='workspace_report' ORDER BY rowid DESC LIMIT 16",
    ))?;
    let replies = sql(q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
        ))
    }))?;
    let mut commands = Vec::new();
    for row in replies {
        let (id, raw, receipt) = sql(row)?;
        let r: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if workspace.is_none_or(|w| r["workspace"] == w) {
            commands.push(json!({"operation_id":id,"state":if receipt.is_some(){"acknowledged"}else{"queued"},"result":receipt.map(|r|serde_json::from_str::<Value>(&r)).transpose().map_err(|e|e.to_string())?}));
        }
    }
    value["commands"] = json!(commands);
    Ok(value)
}
fn validate(r: &Value) -> R<()> {
    if r.to_string().len() > 24 * 1024 {
        return Err("invalid_request: task declaration too large".into());
    }
    let op = field(r, "op")?;
    ident(field(r, "workspace")?)?;
    ident(field(r, "operation_id")?)?;
    if op == "task_claim" {
        ident(field(r, "task_id")?)?;
        bounded(r, "title", 512)?;
        bounded(r, "acceptance_criteria", 4096)?;
        paths(r)?;
    } else if op == "task_update" {
        ident(field(r, "claim_id")?)?;
        if !matches!(r["action"].as_str(), Some("renew" | "complete" | "release"))
            || r["expected_revision"].as_u64().is_none()
        {
            return Err(
                "invalid_request: task update requires action and expected_revision".into(),
            );
        }
    } else {
        return Err("unsupported_coordination_operation".into());
    }
    if (op == "task_claim" || r["action"] == "renew")
        && !r
            .get("lease_seconds")
            .map_or(Some(300), Value::as_u64)
            .is_some_and(|n| (15..=3600).contains(&n))
    {
        return Err("invalid_request: lease_seconds must be 15 through 3600".into());
    }
    Ok(())
}
fn apply(db: &Connection, r: &Value, actor: &str) -> R<Value> {
    if r["op"] == "repair_pickup" {
        return validation::pickup(db, r, actor);
    }
    if r["op"] == "comment_add" {
        return add_comment(db, r, actor);
    }
    if r["op"] == "repair_update" {
        return validation::update(db, r, actor);
    }
    if r["op"] == "workspace_report" {
        let report = &r["report"];
        if r.to_string().len() > 24 * 1024
            || report["workspaces"].as_array().is_none_or(|a| a.len() > 16)
            || report["cursor"].as_u64().is_none()
            || report["total"].as_u64().is_none()
        {
            return Err("invalid_request: bounded workspace report required".into());
        }
        for w in report["workspaces"].as_array().unwrap() {
            ident(field(w, "workspace")?)?;
        }
        sql(db.execute("INSERT INTO workspace_reports VALUES(?1,?2,?3,?4) ON CONFLICT(device,cursor) DO UPDATE SET received=excluded.received,data=excluded.data",params![actor,report["cursor"].as_u64(),now(),report.to_string()]))?;
        event(
            db,
            "workspace_report_received",
            &json!({"device":actor,"workspaces":report["workspaces"].as_array().unwrap().len(),"origin":"agent_reported"}),
        )?;
        return Ok(
            json!({"ok":true,"received_at":now(),"origin":"agent_reported","server_verified_files":false}),
        );
    }
    validate(r)?;
    let wid = field(r, "workspace")?;
    if r["op"] == "task_claim" {
        let declared = paths(r)?;
        let task = field(r, "task_id")?;
        let mut q=sql(db.prepare("SELECT id,workspace,task,title,paths,device FROM task_claims WHERE state='active' AND expires>?1"))?;
        let rows = sql(q.query_map([now()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        }))?;
        let mut overlaps = Vec::new();
        for row in rows {
            let (id, owner, other, title, raw, device) = sql(row)?;
            let other_paths: Vec<String> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            if other == task
                || declared
                    .iter()
                    .any(|a| other_paths.iter().any(|b| overlap(a, b)))
            {
                overlaps.push(json!({"claim_id":id,"workspace":owner,"device":device,"task_id":other,"title":title,"same_task":other==task,"paths":other_paths}));
            }
        }
        let id = format!("claim-{}", digest(&json!([actor, r["operation_id"]])));
        let expires = now() + r["lease_seconds"].as_i64().unwrap_or(300);
        let session = r["session_id"].as_str().unwrap_or(wid);
        if session.len() > 256 {
            return Err("invalid_request: session_id too long".into());
        }
        sql(db.execute(
            "INSERT INTO task_claims VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1,'active',?10)",
            params![
                id,
                actor,
                wid,
                session,
                task,
                field(r, "title")?,
                field(r, "acceptance_criteria")?,
                serde_json::to_string(&declared).unwrap(),
                expires,
                now()
            ],
        ))?;
        event(
            db,
            "task_claimed",
            &json!({"workspace":wid,"device":actor,"claim_id":id,"task_id":task,"expires_at":expires,"overlaps":overlaps.len()}),
        )?;
        return Ok(
            json!({"ok":true,"confirmed":true,"claim_id":id,"revision":1,"state":"active","expires_at":expires,"server_time":now(),"overlaps":overlaps.iter().take(16).collect::<Vec<_>>(),"overlaps_total":overlaps.len(),"overlaps_truncated":overlaps.len()>16,"advisory":true,"files_locked":false}),
        );
    }
    let id = field(r, "claim_id")?;
    let row: Option<(String, String, i64, u64, String)> = sql(db
        .query_row(
            "SELECT device,workspace,expires,revision,state FROM task_claims WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional())?;
    let (device, owner, expires, revision, phase) = row.ok_or("task_not_found")?;
    if device != actor || owner != wid {
        return Err("task_owner_mismatch".into());
    }
    if r["expected_revision"] != revision {
        return Err(
            "task_revision_mismatch: inspect the current task before another update".into(),
        );
    }
    if phase != "active" || expires <= now() {
        return Err("task_lease_expired: claim a new task or inspect its completed state".into());
    }
    let action = field(r, "action")?;
    let next = if action == "renew" {
        "active"
    } else if action == "complete" {
        "completed"
    } else {
        "released"
    };
    let expires = if action == "renew" {
        now() + r["lease_seconds"].as_i64().unwrap_or(300)
    } else {
        expires
    };
    sql(db.execute(
        "UPDATE task_claims SET revision=revision+1,state=?2,expires=?3 WHERE id=?1",
        params![id, next, expires],
    ))?;
    event(
        db,
        "task_updated",
        &json!({"workspace":wid,"device":actor,"claim_id":id,"state":next,"revision":revision+1}),
    )?;
    Ok(
        json!({"ok":true,"confirmed":true,"claim_id":id,"revision":revision+1,"state":next,"expires_at":expires,"server_time":now(),"advisory":true}),
    )
}
fn transactional(db: &Connection, ledger: &str, r: &Value, actor: &str) -> R<Value> {
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    let result = apply(db, r, actor).and_then(|v| {
        finish(db, ledger, &v)?;
        Ok(v)
    });
    match result {
        Ok(v) => {
            sql(db.execute_batch("COMMIT"))?;
            Ok(v)
        }
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn validate_comment(r: &Value) -> R<()> {
    ident(field(r, "operation_id")?)?;
    ident(field(r, "workspace")?)?;
    if !matches!(r["subject_type"].as_str(), Some("task" | "repair")) {
        return Err("invalid_request: subject_type must be task or repair".into());
    }
    ident(field(r, "subject_id")?)?;
    bounded(r, "body", 4096)?;
    if let Some(mentions) = r.get("mentions") {
        let a = mentions
            .as_array()
            .filter(|a| a.len() <= 8)
            .ok_or("invalid_request: mentions must contain at most 8 workspace IDs")?;
        for w in a {
            ident(
                w.as_str()
                    .ok_or("invalid_request: mention must be a workspace ID")?,
            )?;
        }
    }
    Ok(())
}

fn add_comment(db: &Connection, r: &Value, actor: &str) -> R<Value> {
    validate_comment(r)?;
    let exists: bool = if r["subject_type"] == "task" {
        sql(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_claims WHERE id=?1)",
            [field(r, "subject_id")?],
            |r| r.get(0),
        ))?
    } else {
        sql(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM repair_incidents WHERE id=?1)",
            [field(r, "subject_id")?],
            |r| r.get(0),
        ))?
    };
    if !exists {
        return Err("comment_subject_not_found".into());
    }
    let id = format!("comment-{}", digest(&json!([actor, r["operation_id"]])));
    sql(db.execute("INSERT INTO coordination_comments(id,subject_type,subject_id,device,workspace,body,mentions,created) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![id,field(r,"subject_type")?,field(r,"subject_id")?,actor,field(r,"workspace")?,field(r,"body")?,r.get("mentions").cloned().unwrap_or(json!([])).to_string(),now()]))?;
    event(
        db,
        "coordination_comment_added",
        &json!({"comment_id":id,"device":actor,"workspace":r["workspace"],"subject_type":r["subject_type"],"subject_id":r["subject_id"],"mentions":r.get("mentions").cloned().unwrap_or(json!([]))}),
    )?;
    Ok(
        json!({"ok":true,"confirmed":true,"comment_id":id,"delivered":true,"read_by_recipient":false}),
    )
}

fn comment_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(
        json!({"cursor":r.get::<_,u64>(0)?,"comment_id":r.get::<_,String>(1)?,"subject_type":r.get::<_,String>(2)?,"subject_id":r.get::<_,String>(3)?,"device":r.get::<_,String>(4)?,"workspace":r.get::<_,String>(5)?,"body":r.get::<_,String>(6)?,"mentions":serde_json::from_str::<Value>(&r.get::<_,String>(7)?).unwrap_or(json!([])),"created_at":r.get::<_,i64>(8)?,"content_is_untrusted":true}),
    )
}
fn recent_comments(db: &Connection) -> R<Vec<Value>> {
    let mut q=sql(db.prepare("SELECT seq,id,subject_type,subject_id,device,workspace,body,mentions,created FROM coordination_comments ORDER BY seq DESC LIMIT 128"))?;
    let rows = sql(q.query_map([], comment_row))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
}

pub(super) fn comments(db: &Connection, r: &Value) -> R<Value> {
    let cursor = r["cursor"].as_u64().unwrap_or(0);
    let limit = r["limit"].as_u64().unwrap_or(16);
    if !(1..=32).contains(&limit) || cursor > i64::MAX as u64 {
        return Err("invalid_page: limit must be 1 through 32".into());
    }
    let remote = sync::is_client(db)?;
    let mut all = if remote {
        let raw: Option<String> = sql(db
            .query_row("SELECT data FROM coordination_cache WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional())?;
        raw.map(|s| serde_json::from_str::<Value>(&s))
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or(json!({}))["comments"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        let mut q=sql(db.prepare("SELECT seq,id,subject_type,subject_id,device,workspace,body,mentions,created FROM coordination_comments WHERE seq>?1 AND (?2 IS NULL OR subject_id=?2) AND (?3 IS NULL OR subject_type=?3) ORDER BY seq LIMIT ?4"))?;
        let rows = sql(q.query_map(
            params![
                cursor,
                r["subject_id"].as_str(),
                r["subject_type"].as_str(),
                limit + 1
            ],
            comment_row,
        ))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?
    };
    all.retain(|c| {
        c["cursor"].as_u64().is_some_and(|n| n > cursor)
            && r["subject_id"]
                .as_str()
                .is_none_or(|id| c["subject_id"] == id)
            && r["subject_type"]
                .as_str()
                .is_none_or(|kind| c["subject_type"] == kind)
    });
    all.sort_by_key(|c| c["cursor"].as_u64());
    let more = all.len() > limit as usize;
    all.truncate(limit as usize);
    let next = all
        .last()
        .and_then(|c| c["cursor"].as_u64())
        .unwrap_or(cursor);
    Ok(
        json!({"ok":true,"comments":all,"next_cursor":next,"has_more":more,"remote_cache":remote,"history_window":if remote{"latest_128_from_authority"}else{"full_authority_history"},"read_by_recipient":false}),
    )
}

pub(super) fn comment_notices(db: &Connection, wid: &str) -> R<Value> {
    let mut all = if sync::is_client(db)? {
        let raw: Option<String> = sql(db
            .query_row("SELECT data FROM coordination_cache WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional())?;
        raw.map(|s| serde_json::from_str::<Value>(&s))
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or(json!({}))["comments"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        recent_comments(db)?
    };
    all.retain(|c| {
        c["workspace"] != wid
            && c["mentions"]
                .as_array()
                .is_some_and(|m| m.iter().any(|v| v == wid))
    });
    all.sort_by_key(|c| std::cmp::Reverse(c["cursor"].as_u64()));
    all.truncate(8);
    for c in &mut all {
        if let Some(body) = c["body"].as_str() {
            let compact: String = body.chars().take(512).collect();
            c["body_truncated"] = json!(compact.len() < body.len());
            c["body"] = json!(compact);
        }
    }
    Ok(json!(all))
}

pub(super) fn dispatch(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    match field(r, "op")? {
        "task_list" => list(
            db,
            r["workspace"].as_str(),
            r["cursor"].as_u64().unwrap_or(0),
            r["limit"].as_u64().unwrap_or(16),
        ),
        "comment_list" => comments(db, r),
        "task_claim" | "task_update" | "repair_update" | "repair_pickup" | "comment_add" => {
            let wid = field(r, "workspace")?;
            ws(db, wid)?;
            lifecycle::ensure_open(db, wid)?;
            if r["op"] == "repair_update" {
                validation::validate_update(r)?;
            } else if r["op"] == "repair_pickup" {
                ident(field(r, "operation_id")?)?;
            } else if r["op"] == "comment_add" {
                validate_comment(r)?;
            } else {
                validate(r)?;
            }
            if sync::is_client(db)? {
                sql(db.execute(
                    "INSERT OR IGNORE INTO coordination_outbox VALUES(?1,?2,NULL)",
                    params![field(r, "operation_id")?, r.to_string()],
                ))?;
                return Ok(
                    json!({"ok":true,"confirmed":false,"state":"queued","operation_id":r["operation_id"],"advisory":true,"reason":"The authority has not acknowledged this task declaration. Inspect task_list commands after delivery."}),
                );
            }
            transactional(db, field(r, "operation_id")?, r, &device(db)?)
        }
        "coordination_pending" => {
            if !sync::is_client(db)? {
                return Err("client_required".into());
            }
            queue_presence(state, db)?;
            let mut q=sql(db.prepare("SELECT id,request FROM coordination_outbox WHERE receipt IS NULL ORDER BY rowid LIMIT 16"))?;
            let rows=sql(q.query_map([],|r|Ok(json!({"operation_id":r.get::<_,String>(0)?,"request":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null)}))))?;
            Ok(
                json!({"ok":true,"commands":rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?,"binding":config(db)?}),
            )
        }
        "coordination_remote" => {
            let c = config(db)?.ok_or("authority_required")?;
            let actor = field(r, "device")?;
            if c["role"] != "authority"
                || !c["peers"]
                    .as_array()
                    .is_some_and(|p| p.iter().any(|v| v == actor))
            {
                return Err("authenticated_binding_mismatch".into());
            }
            transactional(db, field(r, "operation_id")?, &r["request"], actor)
        }
        "coordination_receipt" => {
            if !sync::is_client(db)? {
                return Err("client_required".into());
            }
            let id = field(r, "command_id")?;
            let receipt = &r["receipt"];
            let c = config(db)?.ok_or("client_required")?;
            if receipt["device"] != c["device"]
                || receipt["project"] != c["project"]
                || receipt["authority"] != c["authority"]
                || receipt["epoch"] != c["epoch"]
                || receipt["operation_id"] != id
                || !receipt["result"].is_object()
            {
                return Err("coordination_receipt_mismatch".into());
            }
            let old: Option<(String, Option<String>)> = sql(db
                .query_row(
                    "SELECT request,receipt FROM coordination_outbox WHERE id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional())?;
            let (raw, prior) = old.ok_or("operation_not_found")?;
            if receipt["request_digest"]
                != digest(&serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string())?)
            {
                return Err("coordination_receipt_mismatch".into());
            }
            let encoded = receipt.to_string();
            if prior.is_some_and(|s| s != encoded) {
                return Err("coordination_receipt_conflict".into());
            }
            sql(db.execute(
                "UPDATE coordination_outbox SET receipt=?2 WHERE id=?1",
                params![id, receipt.to_string()],
            ))?;
            Ok(json!({"ok":true,"operation_id":id,"acknowledged":true}))
        }
        "coordination_export" => {
            if sync::is_client(db)? {
                return Err("authority_required".into());
            }
            // A complete bounded cache; fail visibly instead of hiding additional active claims.
            let mut all = Vec::new();
            let mut cursor = 0;
            loop {
                let page = server_list(db, None, cursor, 32)?;
                all.extend(page["claims"].as_array().unwrap().iter().cloned());
                if all.len() > 256 {
                    return Err(
                        "coordination_export_bound: narrow the workload or release inactive claims"
                            .into(),
                    );
                }
                if page["has_more"] != true {
                    break;
                }
                cursor = page["next_cursor"].as_u64().unwrap();
            }
            let mut q=sql(db.prepare("SELECT id,workspace,intent,head FROM proposals WHERE state IN ('integrated','already_included') ORDER BY rowid DESC LIMIT 32"))?;
            let rows = sql(q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            }))?;
            let mut commits = Vec::new();
            for row in rows {
                let (id, workspace, message, head) = sql(row)?;
                commits.push(json!({"commit_id":id,"workspace":workspace,"message":message,"head":head,"validation":proposal_status(db,&id)?["validation"],"origin":sync::proposal_origin(db,&id)?}));
            }
            Ok(
                json!({"ok":true,"claims":all,"commits":commits,"comments":recent_comments(db)?,"repairs":validation::export(db)?,"repo_health":validation::health(db)?,"server_time":now(),"confirmed":true,"advisory":true,"binding":config(db)?}),
            )
        }
        "coordination_import" => {
            let c = config(db)?.ok_or("client_required")?;
            let data = &r["data"];
            if c["role"] != "client"
                || data["binding"]["project"] != c["project"]
                || data["binding"]["authority"] != c["authority"]
                || data["binding"]["epoch"] != c["epoch"]
                || data["claims"].as_array().is_none_or(|a| a.len() > 256)
                || data.to_string().len() > 512 * 1024
                || data["confirmed"] != true
                || data["server_time"].as_i64().is_none()
            {
                return Err("coordination_binding_mismatch".into());
            }
            sql(db.execute("INSERT INTO coordination_cache VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET fetched=excluded.fetched,data=excluded.data",params![now(),data.to_string()]))?;
            Ok(json!({"ok":true,"cached":true,"server_time":data["server_time"]}))
        }
        _ => Err("unsupported_operation".into()),
    }
}

fn queue_presence(state: &Path, db: &Connection) -> R<()> {
    let pending:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM coordination_outbox WHERE receipt IS NULL AND json_extract(request,'$.op')='workspace_report')",[],|r|r.get(0)))?;
    if pending {
        return Ok(());
    }
    let prior: Option<String> = sql(db
        .query_row(
            "SELECT value FROM meta WHERE key='workspace_presence'",
            [],
            |r| r.get(0),
        )
        .optional())?;
    let prior: Value = prior
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or(json!({}));
    if now().saturating_sub(prior["sent"].as_i64().unwrap_or(0)) < 60 {
        return Ok(());
    }
    let cursor = prior["cursor"].as_u64().unwrap_or(0);
    let page = lifecycle::inventory_local(
        state,
        db,
        &json!({"cursor":cursor,"limit":16,"inspect_files":false}),
    )?;
    let summaries: Vec<_> = page["workspaces"]
        .as_array()
        .ok_or("invalid_inventory")?
        .iter()
        .map(|w| {
            let mut item = serde_json::Map::new();
            for key in [
                "workspace",
                "generation",
                "has_unshared_changes",
                "changes_since_save",
                "workspace_state",
                "workspace_mode",
                "session_active",
                "last_activity",
                "inspection_available",
            ] {
                item.insert(key.into(), w[key].clone());
            }
            Value::Object(item)
        })
        .collect();
    let report =
        json!({"cursor":cursor,"total":page["total"],"observed_at":now(),"workspaces":summaries});
    let id = format!("presence-{}", digest(&report));
    let request = json!({"op":"workspace_report","operation_id":id,"report":report});
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    let result = (|| {
        sql(db.execute(
            "INSERT INTO coordination_outbox VALUES(?1,?2,NULL)",
            params![id, request.to_string()],
        ))?;
        event(
            db,
            "workspace_report_queued",
            &json!({"operation_id":id,"request":request}),
        )?;
        let progress = json!({"sent":now(),"cursor":if page["has_more"]==true {page["next_cursor"].clone()}else{json!(0)}});
        sql(db.execute("INSERT INTO meta(key,value) VALUES('workspace_presence',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[progress.to_string()]))?;
        Ok(())
    })();
    match result {
        Ok(()) => sql(db.execute_batch("COMMIT"))?,
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    Ok(())
}
pub(super) fn workspace_reports(db: &Connection, cursor: u64, limit: u64) -> R<Value> {
    let mut q=sql(db.prepare("SELECT device,received,data FROM workspace_reports ORDER BY device,cursor LIMIT ?1 OFFSET ?2"))?;
    let rows = sql(q.query_map(params![limit + 1, cursor], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
        ))
    }))?;
    let mut reports = Vec::new();
    for row in rows {
        let (device, received, data) = sql(row)?;
        reports.push(json!({"device":device,"received_at":received,"stale":now().saturating_sub(received)>120,"origin":"agent_reported","server_verified_files":false,"report":serde_json::from_str::<Value>(&data).map_err(|e|e.to_string())?}));
    }
    let more = reports.len() > limit as usize;
    reports.truncate(limit as usize);
    Ok(json!({"reports":reports,"next_cursor":cursor+reports.len() as u64,"has_more":more}))
}

#[cfg(test)]
mod comment_tests {
    use super::*;
    #[test]
    fn mentions_include_recent_cache_entries_beyond_the_first_page() {
        let db = Connection::open_in_memory().unwrap();
        init_db(&db).unwrap();
        db.execute("INSERT INTO meta VALUES('sync_config',?1)",[json!({"project":"p","authority":"a","epoch":1,"device":"d","role":"client","peers":[]}).to_string()]).unwrap();
        let comments:Vec<_>=(1..=64).map(|i|json!({"cursor":i,"workspace":"sender","mentions":if i==64 {json!(["recipient"])}else{json!([])},"body":"A recent diagnostic tip"})).collect();
        db.execute(
            "INSERT INTO coordination_cache VALUES(1,0,?1)",
            [json!({"comments":comments}).to_string()],
        )
        .unwrap();
        let notices = comment_notices(&db, "recipient").unwrap();
        assert_eq!(notices.as_array().unwrap().len(), 1);
        assert_eq!(notices[0]["cursor"], 64);
        assert_eq!(comment_notices(&db, "someone-else").unwrap(), json!([]));
    }
}
