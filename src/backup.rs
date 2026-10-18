//! Explicit local-bare-repository simulation. This is not a GitHub backup.
//! Callers serialize flush with other coordinator mutations (the engine lock).
use crate::git::Git;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
type ProposalMap = BTreeMap<String, String>;
const PROPOSALS: &str = "refs/heads/wipstash/proposals/";
type R<T> = Result<T, String>;
const ROOT: &str = "refs/heads/wipstash/integration";
const META: &str = "refs/heads/wipstash/metadata";
fn sql<T>(x: rusqlite::Result<T>) -> R<T> {
    x.map_err(|e| format!("backup_storage_error: {e}"))
}
fn schema(db: &Connection) -> R<()> {
    sql(db.execute_batch(
        "CREATE TABLE IF NOT EXISTS backup_state (
      id INTEGER PRIMARY KEY CHECK(id=1), destination TEXT NOT NULL,
      watermark INTEGER NOT NULL DEFAULT 0, root TEXT, metadata TEXT,
      pending_watermark INTEGER, pending_root TEXT, pending_metadata TEXT, error TEXT);
    ",
    ))?;
    let mut columns = sql(db.prepare("PRAGMA table_info(backup_state)"))?;
    let names = sql(columns.query_map([], |r| r.get::<_, String>(1)))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if !names.iter().any(|name| name == "queue_snapshot") {
        sql(db.execute(
            "ALTER TABLE backup_state ADD COLUMN queue_snapshot TEXT",
            [],
        ))?;
    }
    Ok(())
}
struct Record {
    destination: String,
    watermark: i64,
    root: Option<String>,
    metadata: Option<String>,
    pending_watermark: Option<i64>,
    pending_root: Option<String>,
    pending_metadata: Option<String>,
    error: Option<String>,
    queue_snapshot: Option<String>,
}
fn record(db: &Connection) -> R<Option<Record>> {
    sql(db.query_row("SELECT destination,watermark,root,metadata,pending_watermark,pending_root,pending_metadata,error,queue_snapshot FROM backup_state WHERE id=1",[],|r|Ok(Record {destination:r.get(0)?,watermark:r.get(1)?,root:r.get(2)?,metadata:r.get(3)?,pending_watermark:r.get(4)?,pending_root:r.get(5)?,pending_metadata:r.get(6)?,error:r.get(7)?,queue_snapshot:r.get(8)?})).optional())
}
pub fn status(db: &Connection) -> R<Value> {
    schema(db)?;
    let Some(r) = record(db)? else {
        return Ok(
            json!({"ok":true,"state":"not_configured","watermark":0,"remote_kind":"local_simulation","github_backed_up":false}),
        );
    };
    let latest: i64 = sql(
        db.query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |row| {
            row.get(0)
        }),
    )?;
    let queue_current = if let Some(snapshot) = &r.queue_snapshot {
        let snapshot: Value = serde_json::from_str(snapshot)
            .map_err(|e| format!("backup_invalid_queue_snapshot: {e}"))?;
        let proposals: ProposalMap = serde_json::from_value(snapshot["proposals"].clone())
            .map_err(|e| format!("backup_invalid_queue_snapshot: {e}"))?;
        proposal_metadata(db, &proposals)? == snapshot["metadata"]
            && recovery_metadata(db, &proposals)? == snapshot["recovery"]
    } else {
        false
    };
    let reason = r.error.clone().or_else(|| {
        if r.pending_root.is_some() {
            Some("pending_pair_not_verified".to_string())
        } else if latest > r.watermark {
            Some("local_events_not_backed_up".to_string())
        } else if !queue_current {
            Some("public_queue_snapshot_not_backed_up".to_string())
        } else {
            None
        }
    });
    Ok(
        json!({"ok":true,"state":if reason.is_some(){"blocked"}else{"complete"},
        "remote_kind":"local_simulation","github_backed_up":false,"destination":r.destination,
        "watermark":r.watermark,"latest_event_seq":latest,"integration":r.root,"metadata":r.metadata,
        "pending_watermark":r.pending_watermark,"pending_integration":r.pending_root,
        "pending_metadata":r.pending_metadata,"reason":reason}),
    )
}
fn block(db: &Connection, reason: String) -> R<Value> {
    sql(db.execute("UPDATE backup_state SET error=?1 WHERE id=1", [reason]))?;
    status(db)
}
fn fault(name: &str) {
    if std::env::var("WIPSTASH_FAULT").ok().as_deref() == Some(name) {
        std::process::exit(86);
    }
}
fn oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
// Published intent is public proposal metadata. Workspace identities, private
// checkpoints, command configuration and opaque worker evidence stay private.
fn proposal_metadata(db: &Connection, proposals: &ProposalMap) -> R<Value> {
    let exists: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='proposals')",
        [],
        |r| r.get(0),
    ))?;
    let mut records = serde_json::Map::new();
    if exists {
        let mut stmt = sql(db.prepare(
            "SELECT id,commit_oid,state,base,head,rowid,intent,details FROM proposals ORDER BY rowid",
        ))?;
        let rows = sql(stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, Option<String>>(7)?,
            ))
        }))?;
        for row in rows {
            let (id, commit, state, base, head, order, intent, details) = sql(row)?;
            if proposals.get(&id) != Some(&commit) {
                continue;
            }
            if !public_state(&state) {
                return Err("backup_invalid_proposal_state".into());
            }
            let details: Value = details
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(Value::Null);
            let saved = &details["public_queue_snapshot"];
            let evidence = if saved["evidence"].is_string() {
                saved["evidence"].as_str().unwrap()
            } else if details["checks"].as_array().is_some_and(|a| !a.is_empty()) {
                "checks_executed"
            } else if details["repaired"] == true {
                "agent_resolved_unchecked"
            } else {
                "unchecked"
            };
            let repaired = saved["repaired"] == true || details["repaired"] == true;
            let policy_sha256 = if saved["policy_sha256"].is_string() {
                saved["policy_sha256"].clone()
            } else {
                details["policy_sha256"].clone()
            };
            let origin = if table_exists(db, "sync_proposal_origins")? {
                sql(db.query_row("SELECT device,source_proposal FROM sync_proposal_origins WHERE proposal=?1",[&id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional())?
            } else {
                None
            };
            let ownership = if let Some((device, source_proposal)) = origin {
                json!({"kind":"remote_device","device":device,"source_proposal":source_proposal})
            } else if saved["ownership"].is_object() {
                saved["ownership"].clone()
            } else {
                json!({"kind":"local_authority","device":null,"source_proposal":id})
            };
            let resolution = if table_exists(db, "proposal_resolutions")? {
                sql(db.query_row("SELECT parent,root,attempt FROM proposal_resolutions WHERE proposal=?1", [&id], |r| Ok(json!({"parent":r.get::<_,String>(0)?,"root":r.get::<_,String>(1)?,"attempt":r.get::<_,i64>(2)?}))).optional())?
            } else {
                None
            };
            records.insert(id,json!({"state":state,"base":if oid(&base){Some(base)}else{None},"head":head.filter(|h|oid(h)),"queue_order":order,"intent":intent,"original_state":saved.get("original_state").or_else(||saved.get("state")).cloned().unwrap_or(json!(state)),"ownership":ownership,"evidence":evidence,"repaired":repaired,"policy_sha256":policy_sha256,"resolution":resolution}));
        }
    }
    Ok(Value::Object(records))
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
fn validate_provenance(p: &Value) -> R<()> {
    if let Some(r) = p.get("resolution").filter(|r| !r.is_null()) {
        if r.as_object().is_none_or(|o| {
            o.len() != 3
                || o.keys()
                    .any(|k| !matches!(k.as_str(), "parent" | "root" | "attempt"))
        }) || !r["parent"].as_str().is_some_and(identifier)
            || !r["root"].as_str().is_some_and(identifier)
            || !r["attempt"].as_u64().is_some_and(|n| (1..=3).contains(&n))
        {
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
        ) || (!o["device"].is_null() && !o["device"].as_str().is_some_and(identifier))
            || !o["source_proposal"].as_str().is_some_and(identifier)
            || (o["kind"] == "remote_device" && o["device"].is_null())
        {
            return Err("invalid_public_ownership".into());
        }
    }
    Ok(())
}
fn validate_metadata(value: &Value, proposals: &ProposalMap) -> R<()> {
    let Some(records) = value.get("proposal_metadata") else {
        return Ok(());
    };
    let mut orders = std::collections::BTreeSet::new();
    for (id, record) in records.as_object().ok_or("backup_invalid_queue_metadata")? {
        validate_provenance(record)?;
        if !proposals.contains_key(id)
            || !record["state"].as_str().is_some_and(public_state)
            || !record["queue_order"]
                .as_i64()
                .is_some_and(|n| n > 0 && orders.insert(n))
            || ["base", "head"]
                .iter()
                .any(|key| !record[*key].is_null() && !record[*key].as_str().is_some_and(oid))
            || record
                .get("intent")
                .is_some_and(|v| !v.as_str().is_some_and(|s| s.len() <= 4096))
            || record.as_object().is_none_or(|o| {
                o.keys().any(|k| {
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
            })
        {
            return Err("backup_invalid_queue_metadata".into());
        }
    }
    Ok(())
}
fn validate_public_events(g: &Git, manifest: &Value, proposals: &ProposalMap, root: &str) -> R<()> {
    let watermark = manifest["watermark"]
        .as_i64()
        .ok_or("backup_invalid_watermark")?;
    let mut previous = 0;
    let mut terminal = BTreeMap::<String, String>::new();
    for event in manifest["events"]
        .as_array()
        .ok_or("backup_invalid_public_events")?
    {
        if event.as_object().is_none_or(|o| {
            o.keys()
                .any(|k| !matches!(k.as_str(), "seq" | "kind" | "proposal" | "commit" | "head"))
        }) {
            return Err("backup_invalid_public_event_fields".into());
        }
        let seq = event["seq"]
            .as_i64()
            .filter(|s| *s > previous && *s <= watermark)
            .ok_or("backup_invalid_event_sequence")?;
        previous = seq;
        let kind = event["kind"].as_str().ok_or("backup_invalid_event_kind")?;
        let id = event
            .get("proposal")
            .map(|v| {
                v.as_str()
                    .filter(|id| identifier(id))
                    .ok_or("backup_invalid_event_proposal")
            })
            .transpose()?;
        match kind {
            "published" => {
                let id = id.ok_or("backup_invalid_published_proposal")?;
                if terminal.contains_key(id)
                    || proposals.get(id).map(String::as_str) != event["commit"].as_str()
                {
                    return Err("backup_inconsistent_published_event".into());
                }
            }
            "integrated" | "already_included" => {
                let head = event["head"]
                    .as_str()
                    .filter(|s| oid(s))
                    .ok_or("backup_invalid_integrated_head")?;
                if !g.ancestor(head, root)? {
                    return Err("backup_invalid_integrated_history".into());
                }
                if let Some(id) = id {
                    if terminal.insert(id.to_owned(), kind.to_owned()).is_some() {
                        return Err("backup_inconsistent_terminal_events".into());
                    }
                }
            }
            "cancelled" | "superseded" => {
                let id = id.ok_or("backup_invalid_cancelled_proposal")?;
                if terminal.insert(id.to_owned(), kind.to_owned()).is_some() {
                    return Err("backup_inconsistent_terminal_events".into());
                }
            }
            _ => return Err("backup_invalid_event_kind".into()),
        }
    }
    if let Some(records) = manifest["proposal_metadata"].as_object() {
        for (id, record) in records {
            for key in ["base", "head"] {
                if let Some(object) = record[key].as_str() {
                    if !g.ancestor(object, root)? {
                        return Err("backup_queue_object_outside_public_history".into());
                    }
                }
            }
            let state = record["state"].as_str().unwrap();
            if matches!(
                state,
                "integrated" | "already_included" | "cancelled" | "superseded"
            ) && terminal.get(id).map(String::as_str) != Some(state)
                || terminal.get(id).is_some_and(|t| t != state)
            {
                return Err("backup_inconsistent_queue_state".into());
            }
        }
    }
    Ok(())
}
fn table_exists(db: &Connection, name: &str) -> R<bool> {
    sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    ))
}
fn rows_json(db: &Connection, table: &str, columns: &[&str]) -> R<Vec<Value>> {
    if !table_exists(db, table)? {
        return Ok(vec![]);
    }
    let mut q = sql(db.prepare(&format!(
        "SELECT {} FROM {table} ORDER BY 1,2",
        columns.join(",")
    )))?;
    let rows = sql(q.query_map([], |r| {
        let mut obj = serde_json::Map::new();
        for (i, c) in columns.iter().enumerate() {
            use rusqlite::types::ValueRef;
            let v = match r.get_ref(i)? {
                ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
                ValueRef::Integer(n) => json!(n),
                _ => Value::Null,
            };
            obj.insert((*c).into(), v);
        }
        Ok(Value::Object(obj))
    }))?;
    rows.map(sql).collect()
}
fn recovery_metadata(db: &Connection, proposals: &ProposalMap) -> R<Value> {
    let policy: Option<String> = if table_exists(db, "meta")? {
        sql(db
            .query_row("SELECT value FROM meta WHERE key='policy'", [], |r| {
                r.get(0)
            })
            .optional())?
    } else {
        None
    };
    let policy: Value =
        serde_json::from_str(policy.as_deref().unwrap_or("{}")).map_err(|e| e.to_string())?;
    let binding: Option<String> = if table_exists(db, "meta")? {
        sql(db
            .query_row("SELECT value FROM meta WHERE key='sync_config'", [], |r| {
                r.get(0)
            })
            .optional())?
    } else {
        None
    };
    let binding: Value = binding
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or(Value::Null);
    let mut imports = rows_json(
        db,
        "sync_imports",
        &["device", "operation", "digest", "result"],
    )?;
    for r in &mut imports {
        let v: Value = serde_json::from_str(r["result"].as_str().ok_or("invalid_import_result")?)
            .map_err(|e| e.to_string())?;
        r["result"] = select(
            &v,
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
        );
    }
    let mut exports = rows_json(
        db,
        "sync_exports",
        &["operation", "request_digest", "manifest"],
    )?;
    for r in &mut exports {
        r["manifest"] =
            serde_json::from_str(r["manifest"].as_str().ok_or("invalid_export_manifest")?)
                .map_err(|e| e.to_string())?;
    }
    let mut observations = rows_json(
        db,
        "sync_remote_status",
        &["proposal", "revision", "digest", "receipt"],
    )?;
    for r in &mut observations {
        r["receipt"] = serde_json::from_str(r["receipt"].as_str().ok_or("invalid_receipt")?)
            .map_err(|e| e.to_string())?;
    }
    let origins = rows_json(
        db,
        "sync_proposal_origins",
        &["proposal", "device", "source_proposal"],
    )?;
    let mut budgets = vec![];
    if let Some(path) = db
        .path()
        .and_then(|p| Path::new(p).parent())
        .map(|p| p.join("repair-budget.sqlite"))
    {
        if path.exists() {
            let b = sql(Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ))?;
            budgets = rows_json(&b, "repair_budgets", &["proposal", "attempts", "seconds"])?;
            budgets.retain(|b| {
                proposals
                    .values()
                    .any(|o| Some(o.as_str()) == b["proposal"].as_str())
            });
        }
    }
    let mut replay = Value::Null;
    if let Some(path) = db
        .path()
        .and_then(|p| Path::new(p).parent())
        .map(|p| p.join("sync-replay.sqlite"))
    {
        if path.exists() {
            let b = sql(Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ))?;
            let bindings = rows_json(
                &b,
                "replication_binding",
                &["project", "authority", "epoch", "cursor", "head"],
            )?;
            if bindings.len() > 1 {
                return Err("invalid_public_replay_binding".into());
            }
            if let Some(binding) = bindings.into_iter().next() {
                let mut events = rows_json(
                    &b,
                    "replication_events",
                    &["sequence", "operation", "digest", "envelope"],
                )?;
                for r in &mut events {
                    r["envelope"] = serde_json::from_str(
                        r["envelope"]
                            .as_str()
                            .ok_or("invalid_public_replay_envelope")?,
                    )
                    .map_err(|e| e.to_string())?;
                }
                replay = json!({"binding":binding,"events":events});
            }
        }
    }
    let mut operations = Vec::new();
    for r in rows_json(db, "operations", &["id", "digest", "request", "result"])? {
        let request: Value = serde_json::from_str(r["request"].as_str().unwrap_or("{}"))
            .map_err(|e| e.to_string())?;
        if !matches!(
            request["op"].as_str(),
            Some(
                "publish"
                    | "resolution_submit"
                    | "cancel"
                    | "retry_proposal"
                    | "recovered_public_operation"
            )
        ) || r["result"].is_null()
        {
            continue;
        }
        let result: Value =
            serde_json::from_str(r["result"].as_str().ok_or("invalid_operation_result")?)
                .map_err(|e| e.to_string())?;
        if result["ok"] != true
            || !result["proposal"]
                .as_str()
                .is_some_and(|p| proposals.contains_key(p))
        {
            continue;
        }
        operations.push(json!({"id":r["id"],"digest":r["digest"],"result":select(&result,&["ok","state","proposal","commit","base","durability","replication"])}));
    }
    let mut value = json!({"version":2,"operations":operations,"replay":replay,"activation_required":true,"policy_sha256":format!("{:x}",Sha256::digest(serde_json::to_vec(&policy).map_err(|e|e.to_string())?)),"policy_required":policy.get("checks").and_then(Value::as_array).is_some_and(|a|!a.is_empty()) || policy.get("repair").is_some_and(|v|!v.is_null()),"sync_binding":binding,"origins":origins,"imports":imports,"exports":exports,"observations":observations,"repair_budgets":budgets});
    if table_exists(db, "meta")? {
        let old: Option<String> = sql(db
            .query_row(
                "SELECT value FROM meta WHERE key='public_recovery_gate'",
                [],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(old) = old {
            let old: Value = serde_json::from_str(&old).map_err(|e| e.to_string())?;
            if old["activation_required"] == true && old["version"] == 2 {
                for key in ["policy_sha256", "policy_required", "sync_binding"] {
                    value[key] = old[key].clone();
                }
            }
        }
    }
    validate_recovery(&value)?;
    Ok(value)
}
fn select(v: &Value, fields: &[&str]) -> Value {
    Value::Object(
        fields
            .iter()
            .filter_map(|k| v.get(*k).map(|v| ((*k).into(), v.clone())))
            .collect(),
    )
}
// Strict recursive public-schema validation, shared verbatim with the remote verifier.
pub(crate) fn validate_recovery(v: &Value) -> R<()> {
    fn keys(v: &Value, names: &[&str]) -> R<()> {
        if v.as_object()
            .is_none_or(|o| o.keys().any(|k| !names.contains(&k.as_str())))
        {
            return Err("invalid_public_recovery_fields".into());
        }
        Ok(())
    }
    fn id(v: &Value) -> bool {
        v.as_str().is_some_and(identifier)
    }
    fn hash(v: &Value) -> bool {
        v.as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    }
    fn positive(v: &Value) -> bool {
        v.as_i64().is_some_and(|n| n > 0)
    }
    fn task(t: &Value) -> R<()> {
        keys(
            t,
            &[
                "proposal",
                "workspace",
                "state",
                "reason",
                "base",
                "proposal_commit",
                "current_head",
                "conflict_paths",
                "checks",
                "policy_sha256",
                "attempt",
                "max_attempts",
                "lineage",
                "next_action",
                "semantic_correctness_claimed",
                "conflict_paths_total",
                "checks_total",
                "evidence_truncated",
            ],
        )?;
        if !id(&t["proposal"]) {
            return Err("invalid_resolution_proposal".into());
        }
        if !t["workspace"].is_null()
            || !matches!(t["state"].as_str(), Some("action_required" | "escalated"))
            || !matches!(
                t["reason"].as_str(),
                Some("merge_conflict" | "required_checks_failed" | "policy_evaluation_failed")
            )
            || t["semantic_correctness_claimed"] != false
            || t["max_attempts"] != 3
            || !t["attempt"].as_u64().is_some_and(|n| n <= 3)
        {
            return Err("invalid_resolution_task".into());
        }
        for key in ["base", "proposal_commit", "current_head"] {
            if !t[key].as_str().is_some_and(oid) {
                return Err("invalid_resolution_task_oid".into());
            }
        }
        if !t["policy_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            || !t["next_action"].as_str().is_some_and(|s| s.len() <= 1024)
        {
            return Err("invalid_resolution_task".into());
        }
        let paths = t["conflict_paths"]
            .as_array()
            .ok_or("invalid_resolution_paths")?;
        if paths.len() > 10000 {
            return Err("invalid_resolution_paths".into());
        }
        let mut seen = std::collections::HashSet::new();
        for p in paths {
            let p = p.as_str().ok_or("invalid_resolution_paths")?;
            if p.len() > 4096 || !seen.insert(p) {
                return Err("invalid_resolution_paths".into());
            }
            if p.is_empty()
                || p.starts_with('/')
                || p.contains('\\')
                || p.chars().any(char::is_control)
                || p.split('/')
                    .any(|s| s.is_empty() || matches!(s, "." | ".."))
            {
                return Err("invalid_resolution_paths".into());
            }
        }
        keys(&t["lineage"], &["parent", "root", "attempt"])?;
        if !id(&t["lineage"]["root"]) {
            return Err("invalid_resolution_root".into());
        }
        if !t["lineage"]["parent"].is_null() {
            if !id(&t["lineage"]["parent"]) {
                return Err("invalid_resolution_parent".into());
            }
        }
        if t["lineage"]["attempt"] != t["attempt"] {
            return Err("invalid_resolution_lineage".into());
        }
        let checks = t["checks"].as_array().ok_or("invalid_resolution_checks")?;
        if checks.len() > 64 {
            return Err("invalid_resolution_checks".into());
        }
        for c in checks {
            keys(
                c,
                &[
                    "id_sha256",
                    "required",
                    "success",
                    "exit_code",
                    "timed_out",
                    "checkout_unchanged",
                    "stdout_prefix_sha256",
                    "stderr_prefix_sha256",
                    "stdout_bytes",
                    "stderr_bytes",
                    "output_truncated",
                    "output_collection_complete",
                    "execution_is_os_sandboxed",
                ],
            )?;
            for (key, v) in c.as_object().ok_or("invalid_resolution_checks")? {
                let valid = match key.as_str() {
                    "id_sha256" | "stdout_prefix_sha256" | "stderr_prefix_sha256" => v
                        .as_str()
                        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
                    "candidate_tree" => v.as_str().is_some_and(oid),
                    "stdout_bytes" | "stderr_bytes" => v.as_u64().is_some(),
                    "exit_code" => {
                        v.is_null() || v.as_i64().is_some_and(|n| i32::try_from(n).is_ok())
                    }
                    _ => v.is_boolean(),
                };
                if !valid {
                    return Err("invalid_resolution_checks".into());
                }
            }
        }
    // Legacy tasks have no preview metadata. New tasks must supply the complete
    // triple and truthfully distinguish retained evidence from omitted evidence.
    if ["conflict_paths_total", "checks_total", "evidence_truncated"].iter().any(|k| t.get(*k).is_some()) {
        let path_total = t["conflict_paths_total"].as_u64().filter(|n| *n <= 10000).ok_or("invalid_resolution_evidence_count")?;
        let check_total = t["checks_total"].as_u64().filter(|n| *n <= 1_000_000).ok_or("invalid_resolution_evidence_count")?;
        let kept_paths = paths.len() as u64;
        let kept_checks = checks.len() as u64;
        if path_total < kept_paths || check_total < kept_checks
            || t["evidence_truncated"].as_bool() != Some(path_total > kept_paths || check_total > kept_checks) {
            return Err("invalid_resolution_evidence_count".into());
        }
    }
        if serde_json::to_vec(t).map_err(|e| e.to_string())?.len() > 8192 {
            return Err("resolution_task_too_large".into());
        }
        Ok(())
    }
    fn receipt(v: &Value) -> R<()> {
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
            if v["state"] != "quarantined" {
                return Err("invalid_resolution_task_state".into());
            }
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
                        if m["kind"] != "proposal" {
                            return Err("invalid_public_manifest_resolution".into());
                        }
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
                                && (m["receipt"]["resolution_task"].is_object()
                                    || m["payload_len"] == 0)
                        }
                        _ => false,
                    };
                    if !shape_ok {
                        return Err("invalid_public_manifest_shape".into());
                    }
                    if !m["receipt"].is_null() {
                        receipt(&m["receipt"])?;
                        if let Some(task) =
                            m["receipt"].get("resolution_task").filter(|t| !t.is_null())
                        {
                            if task["proposal"] != m["proposal"]
                                || task["base"] != m["base"]
                                || task["proposal_commit"] != m["head"]
                            {
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
fn validate_recovery_links(m: &Value, proposals: &BTreeMap<String, String>) -> R<Vec<String>> {
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
                        if let Some(o) =
                            result["remote_observation"]["resolution_task"][key].as_str()
                        {
                            objects.push(o.into());
                        }
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
                        if let Some(o) = r["receipt"]["resolution_task"][key].as_str() {
                            objects.push(o.into());
                        }
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
                        if let Some(o) = e["receipt"]["resolution_task"][key].as_str() {
                            objects.push(o.into());
                        }
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
fn export(db: &Connection, watermark: i64, root: &str, proposals: &ProposalMap) -> R<Vec<u8>> {
    let mut stmt=sql(db.prepare("SELECT seq,kind,data FROM events WHERE seq<=?1 AND kind IN ('integrated','already_included','published','cancelled','superseded') ORDER BY seq"))?;
    let rows = sql(stmt.query_map([watermark], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    }))?;
    let mut events = Vec::new();
    for row in rows {
        let (seq, kind, data) = sql(row)?;
        let data: Value =
            serde_json::from_str(&data).map_err(|e| format!("backup_invalid_event: {e}"))?;
        // An allowlist, never recursive filtering: paths, checkpoints, free text,
        // workspace identities, and arbitrary nested data cannot enter this log.
        let mut out = json!({"seq":seq,"kind":kind});
        if let Some(s) = data["proposal"].as_str().filter(|s| identifier(s)) {
            out["proposal"] = json!(s);
        }
        let key = match kind.as_str() {
            "integrated" | "already_included" => Some("head"),
            "published" => Some("commit"),
            _ => None,
        };
        if let Some(key) = key {
            if let Some(s) = data[key].as_str().filter(|s| oid(s)) {
                out[key] = json!(s);
            }
        }
        if kind == "published" {
            let id = out["proposal"]
                .as_str()
                .ok_or("backup_invalid_published_proposal")?;
            let object = out["commit"]
                .as_str()
                .ok_or("backup_invalid_published_commit")?;
            if proposals.get(id).map(String::as_str) != Some(object) {
                return Err("backup_missing_published_proposal_root".into());
            }
        }
        events.push(out);
    }
    serde_json::to_vec(&json!({"format":"wipstash-public-metadata-v2","recovery":recovery_metadata(db,proposals)?,"watermark":watermark,"integration":root,"proposals":proposals,"proposal_metadata":proposal_metadata(db,proposals)?,"events":events})).map_err(|e|e.to_string())
}
fn metadata_commit(g: &Git, bytes: &[u8], parent: Option<&String>) -> R<String> {
    let blob = String::from_utf8(g.run(&["hash-object", "-w", "--stdin"], Some(bytes))?)
        .map_err(|e| e.to_string())?
        .trim()
        .to_owned();
    let entry = format!("100644 blob {blob}\tmetadata.json\n");
    let tree = String::from_utf8(g.run(&["mktree"], Some(entry.as_bytes()))?)
        .map_err(|e| e.to_string())?
        .trim()
        .to_owned();
    g.commit(
        &tree,
        &parent.cloned().into_iter().collect::<Vec<_>>(),
        "public backup metadata\n",
    )
}
fn remote_refs(g: &Git, destination: &str) -> R<(Option<String>, Option<String>)> {
    let bytes = g.run_local_repository(
        &["ls-remote", "--refs"],
        Path::new(destination),
        &[ROOT, META],
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let (mut root, mut meta) = (None, None);
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let object = parts.next().ok_or("backup_bad_remote_ref")?;
        let name = parts.next().ok_or("backup_bad_remote_ref")?;
        if !oid(object) {
            return Err("backup_bad_remote_oid".into());
        }
        match name {
            ROOT => root = Some(object.to_owned()),
            META => meta = Some(object.to_owned()),
            _ => {}
        }
    }
    Ok((root, meta))
}
fn local_proposals(g: &Git) -> R<ProposalMap> {
    let bytes = g.run(
        &[
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "refs/wipstash/proposals/",
        ],
        None,
    )?;
    parse_proposals(&bytes, "refs/wipstash/proposals/")
}
fn parse_proposals(bytes: &[u8], prefix: &str) -> R<ProposalMap> {
    let mut map = ProposalMap::new();
    for line in std::str::from_utf8(bytes)
        .map_err(|e| e.to_string())?
        .lines()
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 2 || !oid(fields[0]) {
            return Err("backup_invalid_proposal_ref".into());
        }
        let id = fields[1]
            .strip_prefix(prefix)
            .ok_or("backup_invalid_proposal_ref")?;
        if !identifier(id) {
            return Err("backup_invalid_proposal_id".into());
        }
        map.insert(id.to_string(), fields[0].to_string());
    }
    Ok(map)
}
fn remote_proposals(g: &Git, destination: &str) -> R<ProposalMap> {
    let bytes = g.run_local_repository(
        &["ls-remote", "--refs"],
        Path::new(destination),
        &[&format!("{PROPOSALS}*")],
    )?;
    parse_proposals(&bytes, PROPOSALS)
}
fn manifest_proposals(g: &Git, metadata: Option<&String>) -> R<ProposalMap> {
    let Some(metadata) = metadata else {
        return Ok(ProposalMap::new());
    };
    let bytes = g.run(&["show", &format!("{metadata}:metadata.json")], None)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    // Older manifests had no proposal map; the next flush upgrades them.
    if value.get("proposals").is_none() {
        return Ok(ProposalMap::new());
    }
    let map: ProposalMap =
        serde_json::from_value(value["proposals"].clone()).map_err(|e| e.to_string())?;
    if map
        .iter()
        .any(|(id, object)| !identifier(id) || !oid(object))
    {
        return Err("backup_invalid_proposal_manifest".into());
    }
    Ok(map)
}
fn recognized(
    actual: &Option<String>,
    complete: &Option<String>,
    pending: &Option<String>,
) -> bool {
    actual == complete || actual == pending
}
fn flush_inner(state: &Path, db: &Connection, destination: &str) -> R<()> {
    let g = Git::open(&state.join("coordinator.git"));
    // First finish a durable pending pair, even if local events have advanced.
    loop {
        let r = record(db)?.ok_or("backup_missing_state")?;
        if r.pending_root.is_none() {
            let root = g.head("refs/wipstash/integration")?;
            let watermark: i64 =
                sql(db.query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| r.get(0)))?;
            // Restored sanitized journals may omit private event sequence numbers.
            let watermark = watermark.max(r.watermark);
            let proposals = local_proposals(&g)?;
            let previous_proposals = manifest_proposals(&g, r.metadata.as_ref())?;
            let queue = proposal_metadata(db, &proposals)?;
            let previous_queue = match r.metadata.as_ref() {
                Some(metadata) => {
                    let bytes = g.run(&["show", &format!("{metadata}:metadata.json")], None)?;
                    let manifest: Value =
                        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                    manifest
                        .get("proposal_metadata")
                        .cloned()
                        .unwrap_or(json!({}))
                }
                None => json!({}),
            };
            let recovery_current = recovery_metadata(db, &proposals)?;
            let recovery_previous = match r.metadata.as_ref() {
                Some(m) => {
                    let bytes = g.run(&["show", &format!("{m}:metadata.json")], None)?;
                    let v: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                    v["recovery"].clone()
                }
                None => Value::Null,
            };
            if recovery_current == recovery_previous
                && queue == previous_queue
                && r.root.as_ref() == Some(&root)
                && r.watermark == watermark
                && proposals == previous_proposals
            {
                let actual = remote_refs(&g, destination)?;
                if actual != (r.root, r.metadata)
                    || remote_proposals(&g, destination)? != previous_proposals
                {
                    return Err(
                        "backup_remote_diverged: completed pair no longer matches destination"
                            .into(),
                    );
                }
                sql(db.execute(
                    "UPDATE backup_state SET error=NULL,queue_snapshot=?1 WHERE id=1",
                    [
                        json!({"proposals":proposals,"metadata":queue,"recovery":recovery_current})
                            .to_string(),
                    ],
                ))?;
                return Ok(());
            }
            let meta = metadata_commit(
                &g,
                &export(db, watermark, &root, &proposals)?,
                r.metadata.as_ref(),
            )?;
            // Git pins precede the SQLite intent. A crash here leaves only harmless
            // extra pins; a crash after intent can always replay this exact pair.
            g.set_ref("refs/wipstash/backup/pending-integration", &root, None)?;
            g.set_ref("refs/wipstash/backup/pending-metadata", &meta, None)?;
            sql(db.execute("UPDATE backup_state SET pending_watermark=?1,pending_root=?2,pending_metadata=?3,error=NULL WHERE id=1",params![watermark,root,meta]))?;
            fault("backup_after_pending");
            continue;
        }
        let pending = r.pending_root.as_ref().ok_or("backup_corrupt_pending")?;
        let metadata = r
            .pending_metadata
            .as_ref()
            .ok_or("backup_corrupt_pending")?;
        let actual = remote_refs(&g, destination)?;
        if !recognized(&actual.0, &r.root, &r.pending_root)
            || !recognized(&actual.1, &r.metadata, &r.pending_metadata)
        {
            return Err(
                "backup_remote_diverged: refusing to overwrite unknown remote history".into(),
            );
        }
        let proposals = manifest_proposals(&g, Some(metadata))?;
        let previous_proposals = manifest_proposals(&g, r.metadata.as_ref())?;
        let remote_proposal_map = remote_proposals(&g, destination)?;
        for (id, object) in &remote_proposal_map {
            if Some(object) != previous_proposals.get(id) && Some(object) != proposals.get(id) {
                return Err("backup_remote_diverged: unknown proposal root".into());
            }
        }
        for (id, object) in &previous_proposals {
            if !proposals.contains_key(id) || !remote_proposal_map.contains_key(id) {
                return Err("backup_remote_diverged: missing retained proposal root".into());
            }
            if proposals.get(id) != Some(object) {
                return Err(
                    "backup_proposal_changed: published proposal roots are immutable".into(),
                );
            }
        }
        validate_metadata_history(&g, metadata)?;
        let a = format!("{pending}:{ROOT}");
        let b = format!("{metadata}:{META}");
        // Explicit reachable roots only. No --all, mirror, force, tags, local
        // checkpoint refs, or private object directory is ever transferred.
        let proposal_specs: Vec<String> = proposals
            .iter()
            .map(|(id, object)| format!("{object}:{PROPOSALS}{id}"))
            .collect();
        let receiver = if cfg!(windows) {
            "--receive-pack=git -c core.hooksPath=NUL receive-pack"
        } else {
            "--receive-pack=git -c core.hooksPath=/dev/null receive-pack"
        };
        let mut specs = vec![a.as_str(), b.as_str()];
        specs.extend(proposal_specs.iter().map(String::as_str));
        g.run_local_repository(
            &[
                "-c",
                "push.recurseSubmodules=no",
                "push",
                "--atomic",
                "--no-follow-tags",
                receiver,
            ],
            Path::new(destination),
            &specs,
        )?;
        fault("backup_after_push");
        if remote_refs(&g, destination)? != (Some(pending.clone()), Some(metadata.clone()))
            || remote_proposals(&g, destination)? != proposals
        {
            return Err(
                "backup_verification_failed: remote roots do not match pending pair".into(),
            );
        }
        let bytes = g.run(&["show", &format!("{metadata}:metadata.json")], None)?;
        let manifest: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let queue_snapshot=json!({"proposals":proposals,"metadata":manifest.get("proposal_metadata").cloned().unwrap_or(json!({})),"recovery":manifest["recovery"]}).to_string();
        sql(db.execute("UPDATE backup_state SET watermark=pending_watermark,root=pending_root,metadata=pending_metadata,pending_watermark=NULL,pending_root=NULL,pending_metadata=NULL,error=NULL,queue_snapshot=?1 WHERE id=1",[queue_snapshot]))?;
        // Loop once more to catch up events that predated this flush but followed
        // an interrupted previous flush. The caller holds the coordinator lock.
    }
}
pub fn flush(state: &Path, db: &Connection, destination: &Path) -> R<Value> {
    schema(db)?;
    // Canonicalization makes a URL, scp-style path, or nonexistent remote fail
    // before any Git transport. This function never creates a destination.
    let path = std::fs::canonicalize(destination)
        .map_err(|e| format!("backup_destination_invalid: {e}"))?;
    let destination = path
        .to_str()
        .ok_or("backup_destination_invalid: non-UTF-8 path")?;
    let bare = Git::open(&path).run(&["rev-parse", "--is-bare-repository"], None)?;
    if bare != b"true\n" {
        return Err(
            "backup_destination_invalid: requires an existing local bare repository".into(),
        );
    }
    if std::fs::canonicalize(state.join("coordinator.git")).map_err(|e| e.to_string())? == path {
        return Err(
            "backup_destination_invalid: destination must be independent of coordinator".into(),
        );
    }
    if let Some(r) = record(db)? {
        if r.destination != destination {
            return Err("backup_destination_changed: use the configured destination".into());
        }
    } else {
        sql(db.execute(
            "INSERT INTO backup_state(id,destination) VALUES(1,?1)",
            [destination],
        ))?;
    }
    match flush_inner(state, db, destination) {
        Ok(()) => status(db),
        Err(e) => block(db, e),
    }
}
/// Read-only restore preflight; it neither rewrites SQLite nor materializes files.
/// Only a paired public snapshot is represented, never private workspaces.
pub fn verify_restore(destination: &Path) -> R<Value> {
    let path = std::fs::canonicalize(destination).map_err(|e| e.to_string())?;
    let g = Git::open(&path);
    if g.run(&["rev-parse", "--is-bare-repository"], None)? != b"true\n" {
        return Err("backup_destination_invalid".into());
    }
    let root = g.head(ROOT)?;
    let meta = g.head(META)?;
    g.run(&["fsck", "--strict", "--no-reflogs", &root, &meta], None)?;
    let bytes = g.run(&["show", &format!("{meta}:metadata.json")], None)?;
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if manifest.as_object().is_none_or(|o| {
        o.keys().any(|k| {
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
        })
    }) {
        return Err("backup_invalid_manifest_fields".into());
    }
    if !matches!(
        manifest["format"].as_str(),
        Some("wipstash-public-metadata-v1" | "wipstash-public-metadata-v2")
    ) || manifest["integration"] != root
        || manifest["watermark"].as_i64().filter(|x| *x >= 0).is_none()
    {
        return Err("backup_restore_invalid_pair".into());
    }
    let proposals = manifest_proposals(&g, Some(&meta))?;
    if remote_proposals(&g, path.to_str().ok_or("backup_invalid_path")?)? != proposals {
        return Err("backup_restore_invalid_proposals".into());
    }
    if manifest["format"] == "wipstash-public-metadata-v1" && manifest.get("recovery").is_some() {
        return Err("backup_invalid_v1_recovery".into());
    }
    if manifest["format"] == "wipstash-public-metadata-v2" {
        validate_recovery(&manifest["recovery"])?;
    }
    validate_metadata(&manifest, &proposals)?;
    for object in validate_recovery_links(&manifest, &proposals)? {
        if !proposals.values().any(|o| o == &object) && !g.ancestor(&object, &root)? {
            return Err("backup_nonpublic_recovery_object".into());
        }
    }
    validate_public_events(&g, &manifest, &proposals, &root)?;
    validate_metadata_history(&g, &meta)?;

    for object in proposals.values() {
        g.run(&["cat-file", "-e", &format!("{object}^{{commit}}")], None)?;
    }
    Ok(
        json!({"ok":true,"state":"verified","integration":root,"metadata":meta,"watermark":manifest["watermark"],"proposal_count":proposals.len(),"remote_kind":"local_simulation","github_backed_up":false,"private_workspaces_restored":false}),
    )
}

fn validate_metadata_history(g: &Git, meta: &str) -> R<()> {
    // Metadata ancestors are transported too. Every historical tree must be a
    // public manifest, never a side channel for private files or opaque output.
    let lineage =
        String::from_utf8(g.run(&["rev-list", meta], None)?).map_err(|e| e.to_string())?;
    for metadata in lineage.lines() {
        if g.run(&["ls-tree", "--name-only", "-z", metadata], None)? != b"metadata.json\0" {
            return Err("backup_private_metadata_tree_entry".into());
        }
        let bytes = g.run(&["show", &format!("{metadata}:metadata.json")], None)?;
        let m: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if m.as_object().is_none_or(|o| {
            o.keys().any(|k| {
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
            })
        }) {
            return Err("backup_invalid_manifest_fields".into());
        }
        match m["format"].as_str() {
            Some("wipstash-public-metadata-v2") => validate_recovery(&m["recovery"])?,
            Some("wipstash-public-metadata-v1") if m.get("recovery").is_none() => {}
            _ => return Err("backup_invalid_metadata_lineage".into()),
        }
        let historical = manifest_proposals(g, Some(&metadata.to_string()))?;
        validate_metadata(&m, &historical)?;
        for object in validate_recovery_links(&m, &historical)? {
            if !historical.values().any(|o| o == &object)
                && !g.ancestor(
                    &object,
                    m["integration"]
                        .as_str()
                        .ok_or("backup_invalid_metadata_lineage")?,
                )?
            {
                return Err("backup_nonpublic_recovery_object".into());
            }
        }
        validate_public_events(
            g,
            &m,
            &historical,
            m["integration"]
                .as_str()
                .ok_or("backup_invalid_metadata_lineage")?,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        dir: PathBuf,
        state: PathBuf,
        remote: PathBuf,
        db: Connection,
        g: Git,
        root: String,
        private: String,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "wipstash-backup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            let state = dir.join("state");
            fs::create_dir(&state).unwrap();
            let g = Git::init(&state.join("coordinator.git")).unwrap();
            let root = g
                .commit(&g.empty_tree().unwrap(), &[], "public initial")
                .unwrap();
            g.set_ref("refs/wipstash/integration", &root, None).unwrap();
            let private = String::from_utf8(
                g.run(
                    &["hash-object", "-w", "--stdin"],
                    Some(b"private checkpoint secret blob"),
                )
                .unwrap(),
            )
            .unwrap()
            .trim()
            .to_owned();
            let remote = dir.join("remote.git");
            Git::init(&remote).unwrap();
            let db = Connection::open(state.join("test.sqlite")).unwrap();
            db.execute_batch("CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,data TEXT NOT NULL)").unwrap();
            db.execute(
                "INSERT INTO events(kind,data) VALUES('checkpoint',?1)",
                [json!({"workspace":"/private/local/path","checkpoint":private}).to_string()],
            )
            .unwrap();
            db.execute("INSERT INTO events(kind,data) VALUES('integrated',?1)",[json!({"proposal":"p1","head":root,"workspace":"/private/local/path","intent":"secret intent","checkpoint":private}).to_string()]).unwrap();
            Self {
                dir,
                state,
                remote,
                db,
                g,
                root,
                private,
            }
        }
        fn advance(&self) -> String {
            let root = self
                .g
                .commit(
                    &self.g.empty_tree().unwrap(),
                    &[self.g.head("refs/wipstash/integration").unwrap()],
                    "public next",
                )
                .unwrap();
            self.g
                .set_ref("refs/wipstash/integration", &root, None)
                .unwrap();
            self.db
                .execute(
                    "INSERT INTO events(kind,data) VALUES('integrated',?1)",
                    [json!({"proposal":"p2","head":root}).to_string()],
                )
                .unwrap();
            root
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    #[test]
    fn resolution_receipts_allow_only_sanitized_bounded_tasks() {
        let task = serde_json::json!({"proposal":"p","workspace":null,"state":"action_required","reason":"merge_conflict","base":"a".repeat(40),"proposal_commit":"b".repeat(40),"current_head":"c".repeat(40),"conflict_paths":["file.rs"],"checks":[{"id_sha256":"d".repeat(64),"success":false}],"policy_sha256":"e".repeat(64),"attempt":0,"max_attempts":3,"lineage":{"parent":null,"root":"p","attempt":0},"next_action":"Open isolated checkout","semantic_correctness_claimed":false});
        let receipt = serde_json::json!({"recipient":"device","authority_proposal":"remote-p","revision":1,"state":"quarantined","integration_head":null,"evidence":"unchecked","repaired":false,"resolution_task":task});
        let mut recovery = serde_json::json!({"version":2,"activation_required":true,"policy_sha256":"a".repeat(64),"policy_required":false,"sync_binding":null,"origins":[],"imports":[],"exports":[],"observations":[{"proposal":"p","revision":1,"digest":"f".repeat(64),"receipt":receipt}],"repair_budgets":[],"operations":[]});
        validate_recovery(&recovery).unwrap();
        let mut preview = recovery.clone();
        let t = &mut preview["observations"][0]["receipt"]["resolution_task"];
        t["conflict_paths_total"] = serde_json::json!(10000);
        t["checks_total"] = serde_json::json!(100);
        t["evidence_truncated"] = serde_json::json!(true);
        validate_recovery(&preview).unwrap();
        preview["observations"][0]["receipt"]["resolution_task"]["evidence_truncated"] = serde_json::json!(false);
        assert!(validate_recovery(&preview).is_err());
        preview["observations"][0]["receipt"]["resolution_task"]["conflict_paths_total"] = serde_json::json!(0);
        assert!(validate_recovery(&preview).is_err());

        for field in ["spawn_error", "stdout", "argv", "candidate_tree"] {
            let mut invalid = recovery.clone();
            invalid["observations"][0]["receipt"]["resolution_task"]["checks"][0][field] =
                serde_json::json!("PRIVATE_CANARY");
            assert!(validate_recovery(&invalid).is_err(), "accepted {field}");
        }
        recovery["observations"][0]["receipt"]["resolution_task"]["workspace"] =
            serde_json::json!("PRIVATE_OWNER");
        assert!(validate_recovery(&recovery).is_err());
        for attempt in [0, 4] {
            assert!(validate_provenance(
                &serde_json::json!({"resolution":{"parent":"p","root":"p","attempt":attempt}})
            )
            .is_err());
        }
    }

    #[test]
    fn queue_metadata_is_sanitized_and_state_only_changes_are_flushed() {
        let f = Fixture::new();
        let proposal =
            f.g.commit(
                &f.g.empty_tree().unwrap(),
                std::slice::from_ref(&f.root),
                "public",
            )
            .unwrap();
        f.g.set_ref("refs/wipstash/proposals/queued", &proposal, None)
            .unwrap();
        f.db.execute_batch("CREATE TABLE proposals(id TEXT,commit_oid TEXT,state TEXT,base TEXT,head TEXT,intent TEXT,details TEXT)").unwrap();
        f.db.execute("INSERT INTO proposals VALUES('queued',?1,'coordinator_accepted',?2,NULL,'secret intent',NULL)",params![proposal,f.root]).unwrap();
        let a = flush(&f.state, &f.db, &f.remote).unwrap();
        f.db.execute("UPDATE proposals SET state='quarantined'", [])
            .unwrap();
        let stale = status(&f.db).unwrap();
        assert_eq!(stale["state"], "blocked");
        assert_eq!(stale["reason"], "public_queue_snapshot_not_backed_up");
        let b = flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(status(&f.db).unwrap()["state"], "complete");
        assert_ne!(a["metadata"], b["metadata"]);
        assert_eq!(a["watermark"], b["watermark"]);
        let bytes = Git::open(&f.remote)
            .run(
                &[
                    "show",
                    &format!("{}:metadata.json", b["metadata"].as_str().unwrap()),
                ],
                None,
            )
            .unwrap();
        let manifest: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            manifest["proposal_metadata"]["queued"]["state"],
            "quarantined"
        );
        assert_eq!(
            manifest["proposal_metadata"]["queued"]["intent"],
            "secret intent"
        );
        verify_restore(&f.remote).unwrap();
        let mut invalid = manifest.clone();
        invalid["proposal_metadata"]["queued"]["state"] = json!("integrated");
        assert!(validate_public_events(
            &Git::open(&f.remote),
            &invalid,
            &manifest_proposals(
                &Git::open(&f.remote),
                Some(&b["metadata"].as_str().unwrap().to_owned())
            )
            .unwrap(),
            &f.root
        )
        .is_err());
    }
    #[test]
    fn accepts_idempotent_offline_republication_of_same_public_root() {
        let f = Fixture::new();
        let mut proposals = ProposalMap::new();
        proposals.insert("p".into(), f.root.clone());
        let manifest = json!({"watermark":3,"events":[
            {"seq":1,"kind":"published","proposal":"p","commit":f.root},
            {"seq":2,"kind":"published","proposal":"p","commit":f.root},
            {"seq":3,"kind":"integrated","proposal":"p","head":f.root}
        ]});
        validate_public_events(&f.g, &manifest, &proposals, &f.root).unwrap();
    }
    #[test]
    fn rejects_invalid_public_event_sequence_and_terminal_reversal() {
        let f = Fixture::new();
        for events in [
            json!([{"seq":2,"kind":"integrated","head":f.root},{"seq":1,"kind":"integrated","head":f.root}]),
            json!([{"seq":1,"kind":"cancelled","proposal":"p"},{"seq":2,"kind":"integrated","proposal":"p","head":f.root}]),
        ] {
            assert!(validate_public_events(
                &f.g,
                &json!({"watermark":2,"events":events}),
                &ProposalMap::new(),
                &f.root
            )
            .is_err());
        }
    }
    #[test]
    fn roundtrip_sanitizes_and_never_transfers_private_objects() {
        let f = Fixture::new();
        assert_eq!(status(&f.db).unwrap()["state"], "not_configured");
        let result = flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(result["state"], "complete");
        assert_eq!(result["watermark"], 2);
        assert_eq!(result["github_backed_up"], false);
        let remote = Git::open(&f.remote);
        assert_eq!(remote.head(ROOT).unwrap(), f.root);
        assert!(remote.run(&["cat-file", "-e", &f.private], None).is_err());
        let content = remote
            .run(&["show", &format!("{META}:metadata.json")], None)
            .unwrap();
        let text = String::from_utf8(content).unwrap();
        for private in ["checkpoint", "workspace", "/private", "secret intent"] {
            assert!(!text.contains(private), "{text}");
        }
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["events"].as_array().unwrap().len(), 1);
        let meta = remote.head(META).unwrap();
        assert_eq!(
            remote
                .run(&["rev-list", "--parents", "-n", "1", &meta], None)
                .unwrap(),
            format!("{meta}\n").as_bytes()
        );
        assert_eq!(verify_restore(&f.remote).unwrap()["watermark"], 2);
        assert_eq!(flush(&f.state, &f.db, &f.remote).unwrap()["metadata"], meta);
        let next = f.advance();
        assert_eq!(status(&f.db).unwrap()["state"], "blocked");
        let result = flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(result["integration"], next);
        let next_meta = result["metadata"].as_str().unwrap();
        assert_eq!(
            remote
                .run(&["rev-list", "--parents", "-n", "1", next_meta], None)
                .unwrap(),
            format!("{next_meta} {meta}\n").as_bytes()
        );
    }
    #[test]
    fn replays_exact_pair_after_push_before_watermark_crash() {
        let f = Fixture::new();
        let result = flush(&f.state, &f.db, &f.remote).unwrap();
        f.db.execute("UPDATE backup_state SET pending_watermark=watermark,pending_root=root,pending_metadata=metadata,watermark=0,root=NULL,metadata=NULL,error='simulated interrupted verification'",[]).unwrap();
        assert_eq!(status(&f.db).unwrap()["state"], "blocked");
        let replay = flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(replay["state"], "complete");
        assert_eq!(replay["metadata"], result["metadata"]);
        assert_eq!(replay["watermark"], 2);
    }
    #[test]
    fn refuses_foreign_remote_and_preserves_pending_pair() {
        let f = Fixture::new();
        let remote = Git::open(&f.remote);
        let foreign = remote
            .commit(&remote.empty_tree().unwrap(), &[], "foreign")
            .unwrap();
        remote.set_ref(ROOT, &foreign, None).unwrap();
        let result = flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(result["state"], "blocked");
        assert_eq!(result["watermark"], 0);
        assert!(result["reason"].as_str().unwrap().contains("diverged"));
        assert_eq!(remote.head(ROOT).unwrap(), foreign);
        let pending = result["pending_metadata"].clone();
        let replay = flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(replay["pending_metadata"], pending);
    }
    #[test]
    fn detects_remote_change_without_new_local_events() {
        let f = Fixture::new();
        flush(&f.state, &f.db, &f.remote).unwrap();
        let remote = Git::open(&f.remote);
        let foreign = remote
            .commit(&remote.empty_tree().unwrap(), &[], "foreign")
            .unwrap();
        remote.set_ref(ROOT, &foreign, None).unwrap();
        let result = flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(result["state"], "blocked");
        assert_eq!(result["watermark"], 2);
        assert_eq!(remote.head(ROOT).unwrap(), foreign);
    }
    #[test]
    fn rejects_missing_nonbare_and_self_destination() {
        let f = Fixture::new();
        assert!(flush(&f.state, &f.db, &f.dir.join("absent")).is_err());
        assert!(flush(&f.state, &f.db, &f.dir).is_err());
        assert!(flush(&f.state, &f.db, &f.state.join("coordinator.git")).is_err());
        assert_eq!(status(&f.db).unwrap()["state"], "not_configured");
    }
    #[test]
    fn rejects_mismatched_restore_pair() {
        let f = Fixture::new();
        flush(&f.state, &f.db, &f.remote).unwrap();
        let remote = Git::open(&f.remote);
        let foreign = remote
            .commit(
                &remote.empty_tree().unwrap(),
                std::slice::from_ref(&f.root),
                "newer",
            )
            .unwrap();
        remote.set_ref(ROOT, &foreign, None).unwrap();
        assert!(verify_restore(&f.remote)
            .unwrap_err()
            .contains("invalid_pair"));
    }
    #[test]
    fn preserves_accepted_unintegrated_proposal_and_checks_restore_refs() {
        let f = Fixture::new();
        let proposal =
            f.g.commit(
                &f.g.empty_tree().unwrap(),
                std::slice::from_ref(&f.root),
                "unintegrated public proposal",
            )
            .unwrap();
        f.g.set_ref("refs/wipstash/proposals/accepted", &proposal, None)
            .unwrap();
        f.db.execute(
            "INSERT INTO events(kind,data) VALUES('published',?1)",
            [json!({"proposal":"accepted","commit":proposal}).to_string()],
        )
        .unwrap();
        let result = flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(result["state"], "complete");
        let remote = Git::open(&f.remote);
        assert_eq!(
            remote.head(&format!("{PROPOSALS}accepted")).unwrap(),
            proposal
        );
        assert!(!remote.ancestor(&proposal, &f.root).unwrap());
        assert_eq!(verify_restore(&f.remote).unwrap()["proposal_count"], 1);
        assert!(remote.run(&["cat-file", "-e", &f.private], None).is_err());
        remote
            .run(&["update-ref", "-d", &format!("{PROPOSALS}accepted")], None)
            .unwrap();
        assert!(verify_restore(&f.remote).is_err());
        assert_eq!(
            flush(&f.state, &f.db, &f.remote).unwrap()["state"],
            "blocked"
        );
    }
}
