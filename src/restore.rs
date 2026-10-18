//! Recover only the paired public backup into a new standalone local authority.
use crate::{backup, git::Git};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};
type R<T> = Result<T, String>;
const REASON: &str = "public recovery is fenced pending explicit policy and authority activation; private workspaces and checkpoints are not restored";
fn sql<T>(v: rusqlite::Result<T>) -> R<T> {
    v.map_err(|e| format!("restore_storage_error: {e}"))
}
fn ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
#[derive(Default)]
struct Proposal {
    commit: String,
    state: String,
    head: Option<String>,
}

/// Recovery is explicitly operator-mediated. This is no proof of remote fencing.
pub fn recovery_status(db: &Connection) -> R<Value> {
    let saved: Option<String> = sql(db
        .query_row(
            "SELECT value FROM meta WHERE key='public_recovery_gate'",
            [],
            |r| r.get(0),
        )
        .optional())?;
    let Some(saved) = saved else {
        return Ok(json!({"ok":true,"activation_required":false,"state":"not_recovered"}));
    };
    let gate: Value = serde_json::from_str(&saved).map_err(|e| e.to_string())?;
    Ok(
        json!({"ok":true,"state":if gate["activation_required"]==true{"fenced"}else{"activated"},"version":gate["version"],"activation_required":gate["activation_required"],"policy_sha256":gate["policy_sha256"],"policy_required":gate["policy_required"],"sync_binding":gate["sync_binding"],"authenticated_migration":false,"fencing":"operator_assertion_only"}),
    )
}
pub fn activate(db: &Connection, request: &Value) -> R<Value> {
    use sha2::{Digest, Sha256};
    let saved: Option<String> = sql(db
        .query_row(
            "SELECT value FROM meta WHERE key='public_recovery_gate'",
            [],
            |r| r.get(0),
        )
        .optional())?;
    let mut gate: Value = serde_json::from_str(&saved.ok_or("public_recovery_not_pending")?)
        .map_err(|e| e.to_string())?;
    if gate["activation_required"] != true {
        return recovery_status(db);
    }
    if gate["version"] != 2 {
        return Err(
            "legacy_recovery_requires_review_and_republishing: v1 cannot restore queue eligibility"
                .into(),
        );
    }
    if request["confirm_old_authority_stopped"] != true
        || request["confirm_public_recovery_reviewed"] != true
    {
        return Err("public_recovery_confirmation_required: explicitly confirm old authority stopped and public recovery reviewed".into());
    }
    if request.get("sync_binding") != Some(&gate["sync_binding"]) {
        return Err("public_recovery_binding_mismatch: provide the exact original sync_binding (null for standalone)".into());
    }
    let policy: Option<String> = sql(db
        .query_row("SELECT value FROM meta WHERE key='policy'", [], |r| {
            r.get(0)
        })
        .optional())?;
    let policy: Value =
        serde_json::from_str(policy.as_deref().unwrap_or("{}")).map_err(|e| e.to_string())?;
    let hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&policy).map_err(|e| e.to_string())?)
    );
    if gate["policy_sha256"] != hash {
        return Err(
            "public_recovery_policy_mismatch: configure the original policy before activation"
                .into(),
        );
    }
    let existing: Option<String> = sql(db
        .query_row("SELECT value FROM meta WHERE key='sync_config'", [], |r| {
            r.get(0)
        })
        .optional())?;
    if let Some(existing) = existing {
        if serde_json::from_str::<Value>(&existing).map_err(|e| e.to_string())?
            != gate["sync_binding"]
        {
            return Err("public_recovery_binding_mismatch".into());
        }
    }
    let tx = sql(db.unchecked_transaction())?;
    let mut q = sql(tx.prepare(
        "SELECT id,base,details FROM proposals WHERE state='recovery_quarantined' ORDER BY rowid",
    ))?;
    let rows = sql(q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
        ))
    }))?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| e.to_string())?;
    drop(q);
    let mut activated = 0;
    for (id, base, details) in rows {
        let mut details: Value = details
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null);
        let snapshot = &details["public_queue_snapshot"];
        let original = snapshot
            .get("original_state")
            .unwrap_or(&snapshot["state"])
            .as_str()
            .unwrap_or("");
        if matches!(original, "coordinator_accepted" | "quarantined")
            && oid(&base)
            && snapshot["intent"].is_string()
        {
            // Public recovery preserves disposition and retry lineage, but not
            // opaque evaluation details. Explicit activation requeues unresolved
            // work so the current policy regenerates complete task evidence.
            details["eligibility_restored"] = json!(true);
            details["operator_activated"] = json!(true);
            details["fresh_evaluation_pending"] = json!(true);
            sql(tx.execute(
                "UPDATE proposals SET state='coordinator_accepted',details=?2 WHERE id=?1",
                params![id, details.to_string()],
            ))?;
            activated += 1;
        }
    }
    if !gate["sync_binding"].is_null() {
        sql(tx.execute("INSERT INTO meta(key,value) VALUES('sync_config',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[gate["sync_binding"].to_string()]))?;
    }
    gate["activation_required"] = json!(false);
    gate["activation"] = json!({"old_authority_stopped":true,"public_recovery_reviewed":true,"fencing":"operator_assertion_only","authenticated_migration":false});
    sql(tx.execute(
        "UPDATE meta SET value=?1 WHERE key='public_recovery_gate'",
        [gate.to_string()],
    ))?;
    sql(tx.commit())?;
    let mut result = recovery_status(db)?;
    result["activated_proposals"] = json!(activated);
    Ok(result)
}

pub fn restore(state: &Path, db: &Connection, destination: &Path) -> R<Value> {
    let repo = state.join("coordinator.git");
    if state.join("repair-budget.sqlite").exists() || state.join("sync-replay.sqlite").exists() {
        return Err("restore_requires_empty_state: auxiliary recovery database exists".into());
    }
    if fs::symlink_metadata(&repo).is_ok() {
        return Err("restore_requires_empty_state: coordinator repository already exists".into());
    }
    for table in [
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
    ] {
        let count: i64 =
            sql(db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)))?;
        if count != 0 {
            return Err(format!(
                "restore_requires_empty_state: {table} is not empty"
            ));
        }
    }
    // A configured source is state too, even if no project authority was created.
    let exists: i64 = sql(db.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='backup_state'",
        [],
        |r| r.get(0),
    ))?;
    if exists != 0
        && sql(db.query_row("SELECT COUNT(*) FROM backup_state", [], |r| {
            r.get::<_, i64>(0)
        }))? != 0
    {
        return Err("restore_requires_empty_state: backup already configured".into());
    }
    let source =
        fs::canonicalize(destination).map_err(|e| format!("restore_source_invalid: {e}"))?;
    let source_text = source
        .to_str()
        .ok_or("restore_source_invalid: non-UTF-8 path")?;
    let verified = backup::verify_restore(&source)?;
    let root = verified["integration"]
        .as_str()
        .ok_or("restore_invalid_root")?;
    let metadata = verified["metadata"]
        .as_str()
        .ok_or("restore_invalid_metadata")?;
    let watermark = verified["watermark"]
        .as_i64()
        .ok_or("restore_invalid_watermark")?;
    let remote = Git::open(&source);
    let bytes = remote.run(&["show", &format!("{metadata}:metadata.json")], None)?;
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let map: BTreeMap<String, String> = match manifest.get("proposals") {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|e| format!("restore_invalid_proposals: {e}"))?,
        None => BTreeMap::new(),
    };
    let v2 = manifest["format"] == "wipstash-public-metadata-v2";
    let mut proposals = BTreeMap::<String, Proposal>::new();
    for (id, commit) in &map {
        if !ident(id) || !oid(commit) {
            return Err("restore_invalid_proposal".into());
        }
        proposals.insert(
            id.clone(),
            Proposal {
                commit: commit.clone(),
                state: "recovery_quarantined".into(),
                head: None,
            },
        );
    }
    let mut events = Vec::new();
    let mut previous = 0;
    for e in manifest["events"]
        .as_array()
        .ok_or("restore_invalid_events")?
    {
        let seq = e["seq"]
            .as_i64()
            .filter(|s| *s > previous && *s <= watermark)
            .ok_or("restore_invalid_event_sequence")?;
        previous = seq;
        let kind = e["kind"]
            .as_str()
            .filter(|k| {
                matches!(
                    *k,
                    "published" | "integrated" | "already_included" | "cancelled" | "superseded"
                )
            })
            .ok_or("restore_invalid_public_event")?;
        let id = match e.get("proposal") {
            Some(v) => Some(
                v.as_str()
                    .filter(|s| ident(s))
                    .ok_or("restore_invalid_event_proposal")?,
            ),
            None => None,
        };
        let mut data = json!({});
        if let Some(id) = id {
            data["proposal"] = json!(id);
        }
        let object_key = match kind {
            "published" => Some("commit"),
            "integrated" | "already_included" => Some("head"),
            _ => None,
        };
        if let Some(key) = object_key {
            let value = e[key]
                .as_str()
                .filter(|s| oid(s))
                .ok_or("restore_invalid_event_object")?;
            data[key] = json!(value);
        }
        if kind == "published" {
            let id = id.ok_or("restore_invalid_published_proposal")?;
            if map.get(id).map(String::as_str) != data["commit"].as_str() {
                return Err("restore_missing_published_root".into());
            }
        }
        if let Some(id) = id {
            let p = proposals.entry(id.to_string()).or_insert_with(|| Proposal {
                state: "recovery_quarantined".into(),
                ..Default::default()
            });
            match kind {
                "integrated" | "already_included" => {
                    if p.state != "recovery_quarantined" {
                        return Err("restore_inconsistent_terminal_events".into());
                    }
                    p.state = kind.into();
                    p.head = data["head"].as_str().map(str::to_owned);
                }
                "cancelled" | "superseded" => {
                    if p.state != "recovery_quarantined" {
                        return Err("restore_inconsistent_terminal_events".into());
                    }
                    p.state = kind.into();
                }
                "published" => {
                    if p.state != "recovery_quarantined" {
                        return Err("restore_inconsistent_publish_order".into());
                    }
                }
                _ => unreachable!(),
            }
        }
        events.push((seq, kind.to_string(), data));
    }
    let stage = state.join("restore-staging.git");
    // Never replace an existing staging directory or ambiguous interrupted state.
    fs::create_dir(&stage).map_err(|e| format!("restore_staging_unavailable: {e}"))?;
    let mut installed = false;
    let result = (|| -> R<Value> {
        let git = Git::init(&stage)?;
        let mut specs = vec![
            format!("{root}:refs/wipstash/integration"),
            format!("{metadata}:refs/wipstash/backup/metadata"),
        ];
        specs.extend(
            map.iter()
                .map(|(id, object)| format!("{object}:refs/wipstash/proposals/{id}")),
        );
        git.run_local_repository(
            &[
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--recurse-submodules=no",
            ],
            &source,
            &specs.iter().map(String::as_str).collect::<Vec<_>>(),
        )?;
        git.run(&["cat-file", "-e", &format!("{root}^{{commit}}")], None)?;
        git.run(&["fsck", "--strict", "--no-reflogs"], None)?;
        for (_, kind, data) in &events {
            if matches!(kind.as_str(), "integrated" | "already_included")
                && !git.ancestor(data["head"].as_str().unwrap(), root)?
            {
                return Err("restore_invalid_integrated_history".into());
            }
        }
        // Check again after transport: no silently mixed source generations.
        let after = backup::verify_restore(&source)?;
        if after != verified {
            return Err("restore_source_changed: retry from a stable snapshot".into());
        }
        let tx = sql(db.unchecked_transaction())?;
        for (seq, kind, data) in &events {
            sql(tx.execute(
                "INSERT INTO events(seq,kind,data) VALUES(?1,?2,?3)",
                params![seq, kind, data.to_string()],
            ))?;
        }
        // Preserve holes left by excluded private events; future event IDs are newer.
        sql(tx.execute("DELETE FROM sqlite_sequence WHERE name='events'", []))?;
        sql(tx.execute(
            "INSERT INTO sqlite_sequence(name,seq) VALUES('events',?1)",
            [watermark],
        ))?;
        let mut ordered: Vec<_> = proposals.iter().collect();
        ordered.sort_by_key(|(id, _)| {
            manifest["proposal_metadata"][*id]["queue_order"]
                .as_i64()
                .unwrap_or(i64::MAX)
        });
        for (id, p) in ordered {
            let snapshot = manifest
                .get("proposal_metadata")
                .and_then(|m| m.get(id))
                .cloned()
                .unwrap_or(Value::Null);
            // Historical queue metadata is retained for review, never as authority
            // to execute recovered work or run commands from the old coordinator.
            let details = json!({"recovered_public_only":true,"repaired":snapshot["repaired"]==true,"reason":REASON,"eligibility_restored":false,"intent_restored":v2,"ownership_restored":v2,"public_queue_snapshot":snapshot}).to_string();
            sql(tx.execute("INSERT INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state,head,details) VALUES(?1,'','',?2,?6,?7,?3,?4,?5)",params![id,p.commit,p.state,p.head,details,snapshot["base"].as_str().unwrap_or(""),if v2 {snapshot["intent"].as_str().unwrap_or("")}else{""}]))?;
            if let Some(lineage) = snapshot.get("resolution").filter(|v| !v.is_null()) {
                sql(tx.execute_batch("CREATE TABLE IF NOT EXISTS proposal_resolutions(proposal TEXT PRIMARY KEY,parent TEXT NOT NULL,root TEXT NOT NULL,attempt INTEGER NOT NULL)"))?;
                sql(tx.execute(
                    "INSERT INTO proposal_resolutions VALUES(?1,?2,?3,?4)",
                    params![
                        id,
                        lineage["parent"].as_str(),
                        lineage["root"].as_str(),
                        lineage["attempt"].as_i64()
                    ],
                ))?;
            }
        }
        let gate = if v2 {
            manifest["recovery"].clone()
        } else {
            json!({"version":1,"activation_required":true,"policy_required":true,"policy_sha256":null,"sync_binding":null})
        };
        sql(tx.execute(
            "INSERT INTO meta(key,value) VALUES('public_recovery_gate',?1)",
            [gate.to_string()],
        ))?;
        if v2 {
            sql(tx.execute_batch("CREATE TABLE IF NOT EXISTS sync_exports(operation TEXT PRIMARY KEY,request_digest TEXT NOT NULL,manifest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sync_proposal_origins(proposal TEXT PRIMARY KEY,device TEXT NOT NULL,source_proposal TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sync_remote_status(proposal TEXT PRIMARY KEY,revision INTEGER NOT NULL,digest TEXT NOT NULL,receipt TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sync_imports(device TEXT NOT NULL,operation TEXT NOT NULL,digest TEXT NOT NULL,result TEXT NOT NULL,PRIMARY KEY(device,operation));"))?;
            for r in gate["operations"].as_array().unwrap() {
                sql(tx.execute("INSERT INTO operations(id,digest,request,result) VALUES(?1,?2,'{\"op\":\"recovered_public_operation\"}',?3)",params![r["id"].as_str(),r["digest"].as_str(),r["result"].to_string()]))?;
            }
            for r in gate["origins"].as_array().unwrap() {
                sql(tx.execute(
                    "INSERT INTO sync_proposal_origins VALUES(?1,?2,?3)",
                    params![
                        r["proposal"].as_str(),
                        r["device"].as_str(),
                        r["source_proposal"].as_str()
                    ],
                ))?;
            }
            for r in gate["imports"].as_array().unwrap() {
                sql(tx.execute(
                    "INSERT INTO sync_imports VALUES(?1,?2,?3,?4)",
                    params![
                        r["device"].as_str(),
                        r["operation"].as_str(),
                        r["digest"].as_str(),
                        r["result"].to_string()
                    ],
                ))?;
            }
            for r in gate["exports"].as_array().unwrap() {
                sql(tx.execute(
                    "INSERT INTO sync_exports VALUES(?1,?2,?3)",
                    params![
                        r["operation"].as_str(),
                        r["request_digest"].as_str(),
                        r["manifest"].to_string()
                    ],
                ))?;
            }
            for r in gate["observations"].as_array().unwrap() {
                sql(tx.execute(
                    "INSERT INTO sync_remote_status VALUES(?1,?2,?3,?4)",
                    params![
                        r["proposal"].as_str(),
                        r["revision"].as_i64(),
                        r["digest"].as_str(),
                        r["receipt"].to_string()
                    ],
                ))?;
            }
            if let Some(replay) = gate.get("replay").filter(|v| !v.is_null()) {
                let mut rdb = sql(Connection::open(state.join("sync-replay.sqlite")))?;
                let rtx = sql(rdb.transaction())?;
                sql(rtx.execute_batch("CREATE TABLE replication_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1),project TEXT NOT NULL,authority TEXT NOT NULL,epoch INTEGER NOT NULL,cursor INTEGER NOT NULL,head TEXT);CREATE TABLE replication_events(sequence INTEGER PRIMARY KEY,operation TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,envelope TEXT NOT NULL);"))?;
                let b = &replay["binding"];
                sql(rtx.execute(
                    "INSERT INTO replication_binding VALUES(1,?1,?2,?3,?4,?5)",
                    params![
                        b["project"].as_str(),
                        b["authority"].as_str(),
                        b["epoch"].as_i64(),
                        b["cursor"].as_i64(),
                        b["head"].as_str()
                    ],
                ))?;
                for r in replay["events"].as_array().unwrap() {
                    sql(rtx.execute(
                        "INSERT INTO replication_events VALUES(?1,?2,?3,?4)",
                        params![
                            r["sequence"].as_i64(),
                            r["operation"].as_str(),
                            r["digest"].as_str(),
                            r["envelope"].to_string()
                        ],
                    ))?;
                }
                sql(rtx.commit())?;
            }
            let mut budget = sql(Connection::open(state.join("repair-budget.sqlite")))?;
            let btx = sql(budget.transaction())?;
            sql(btx.execute_batch("CREATE TABLE repair_budgets(proposal TEXT PRIMARY KEY,attempts INTEGER NOT NULL,seconds INTEGER NOT NULL)"))?;
            for r in gate["repair_budgets"].as_array().unwrap() {
                sql(btx.execute(
                    "INSERT INTO repair_budgets VALUES(?1,?2,?3)",
                    params![
                        r["proposal"].as_str(),
                        r["attempts"].as_i64(),
                        r["seconds"].as_i64()
                    ],
                ))?;
            }
            sql(btx.commit())?;
        }
        sql(tx.execute_batch("CREATE TABLE IF NOT EXISTS backup_state(id INTEGER PRIMARY KEY CHECK(id=1),destination TEXT NOT NULL,watermark INTEGER NOT NULL DEFAULT 0,root TEXT,metadata TEXT,pending_watermark INTEGER,pending_root TEXT,pending_metadata TEXT,error TEXT)"))?;
        sql(tx.execute("INSERT INTO backup_state(id,destination,watermark,root,metadata) VALUES(1,?1,?2,?3,?4)",params![source_text,watermark,root,metadata]))?;
        sql(tx.execute(
            "INSERT INTO meta(key,value) VALUES('authority','local-single-authority-v1')",
            [],
        ))?;
        sql(tx.execute("INSERT INTO meta(key,value) VALUES('public_restore',?1)",[json!({"integration":root,"metadata":metadata,"watermark":watermark,"warning":REASON}).to_string()]))?;
        fs::rename(&stage, &repo).map_err(|e| format!("restore_install_failed: {e}"))?;
        installed = true;
        sql(tx.commit())?;
        let unresolved = proposals
            .values()
            .filter(|p| p.state == "recovery_quarantined")
            .count();
        Ok(
            json!({"ok":true,"state":"restored","integration":root,"metadata":metadata,"watermark":watermark,"proposal_count":proposals.len(),"pending_count":unresolved,"unresolved_count":unresolved,"authority":"local-single-authority-v1","remote_kind":"local_simulation","github_backed_up":false,"private_workspaces_restored":false,"private_checkpoints_restored":false,"intent_restored":v2,"ownership_restored":v2,"activation_required":true,"authenticated_migration":false,"warning":format!("Recovered public snapshot only. Private workspace records and checkpoints are absent; {REASON}. This is a new standalone local authority, not a network authority or zero-loss recovery.")}),
        )
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(if installed { &repo } else { &stage });
        let _ = fs::remove_file(state.join("repair-budget.sqlite"));
        let _ = fs::remove_file(state.join("sync-replay.sqlite"));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        dir: PathBuf,
        state: PathBuf,
        source: PathBuf,
        remote: PathBuf,
        db: Connection,
        proposal: String,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "wipstash-restore-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            let input = dir.join("input");
            fs::create_dir(&input).unwrap();
            fs::write(input.join("hello"), b"public source\n").unwrap();
            let source = dir.join("source");
            crate::engine::execute(&source, json!({"op":"init","source":input})).unwrap();
            let source_db = Connection::open(source.join("state.sqlite")).unwrap();
            let git = Git::open(&source.join("coordinator.git"));
            let root = git.head("refs/wipstash/integration").unwrap();
            let proposal = git
                .commit(&git.empty_tree().unwrap(), &[root], "proposal pending")
                .unwrap();
            git.set_ref("refs/wipstash/proposals/pending", &proposal, None)
                .unwrap();
            source_db
                .execute(
                    "INSERT INTO events(kind,data) VALUES('published',?1)",
                    [
                        json!({"proposal":"pending","commit":proposal,"intent":"private intent"})
                            .to_string(),
                    ],
                )
                .unwrap();
            source_db
                .execute(
                    "INSERT INTO events(kind,data) VALUES('checkpoint','{}')",
                    [],
                )
                .unwrap();
            let remote = dir.join("remote.git");
            Git::init(&remote).unwrap();
            backup::flush(&source, &source_db, &remote).unwrap();
            let state = dir.join("restored");
            assert!(crate::engine::execute(&state, json!({"op":"status"})).is_err());
            let db = Connection::open(state.join("state.sqlite")).unwrap();
            Self {
                dir,
                state,
                source,
                remote,
                db,
                proposal,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    #[test]
    fn v2_conserves_public_identity_receipts_dedup_budget_and_policy_gate() {
        use sha2::{Digest, Sha256};
        let f = Fixture::new();
        let db = Connection::open(f.source.join("state.sqlite")).unwrap();
        let git = Git::open(&f.source.join("coordinator.git"));
        let base = git.head("refs/wipstash/integration").unwrap();
        let intent = "Accepted public intent: preserve the greeting";
        db.execute("INSERT INTO proposals VALUES('pending','PRIVATE_WORKSPACE_CANARY','PRIVATE_CHECKPOINT_CANARY',?1,?2,?3,'quarantined',NULL,'PRIVATE_OUTPUT_CANARY')",params![f.proposal,base,intent]).unwrap();
        let binding = json!({"project":"public-project","authority":"public-authority","epoch":7,"device":"public-authority","role":"authority","peers":["public-client"]});
        let policy = json!({"checks":[{"id":"public-check","argv":["/PRIVATE_PATH_CANARY/check","PRIVATE_CREDENTIAL_CANARY"],"timeout_seconds":1}]});
        db.execute(
            "INSERT INTO meta VALUES('sync_config',?1)",
            [binding.to_string()],
        )
        .unwrap();
        db.execute("INSERT INTO meta VALUES('policy',?1)", [policy.to_string()])
            .unwrap();
        db.execute_batch("CREATE TABLE sync_proposal_origins(proposal TEXT PRIMARY KEY,device TEXT,source_proposal TEXT);
            CREATE TABLE sync_imports(device TEXT,operation TEXT,digest TEXT,result TEXT,PRIMARY KEY(device,operation));
            CREATE TABLE sync_exports(operation TEXT PRIMARY KEY,request_digest TEXT,manifest TEXT);
            CREATE TABLE sync_remote_status(proposal TEXT PRIMARY KEY,revision INTEGER,digest TEXT,receipt TEXT);").unwrap();
        db.execute(
            "INSERT INTO sync_proposal_origins VALUES('pending','public-client','public-source')",
            [],
        )
        .unwrap();
        let digest = "a".repeat(64);
        let import_manifest = json!({"version":1,"project":"public-project","authority":"public-authority","epoch":7,"device":"public-client","operation":"lost-ack","kind":"proposal","head":f.proposal,"base":base,"proposal":"public-source","intent":intent,"envelope":null,"payload_len":0,"payload_sha256":format!("{:x}",Sha256::digest(b""))});
        let import_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&import_manifest).unwrap())
        );
        let import_dir = f.dir.join("public-lost-ack-artifact");
        fs::create_dir(&import_dir).unwrap();
        fs::write(
            import_dir.join("manifest.json"),
            import_manifest.to_string(),
        )
        .unwrap();
        fs::write(import_dir.join("objects.json"), b"").unwrap();
        let result = json!({"ok":true,"state":"coordinator_accepted","proposal":"pending","source_proposal":"public-source","head":f.proposal,"duplicate":false,"authenticated":false,"opaque":"PRIVATE_OUTPUT_CANARY"});
        db.execute(
            "INSERT INTO sync_imports VALUES('public-client','lost-ack',?1,?2)",
            params![import_digest, result.to_string()],
        )
        .unwrap();
        let receipt = json!({"recipient":"public-client","authority_proposal":"pending","revision":4,"state":"coordinator_accepted","integration_head":null,"evidence":"unchecked","repaired":false});
        let export = json!({"version":1,"project":"public-project","authority":"public-authority","epoch":7,"device":"public-authority","operation":"receipt-4","kind":"receipt","head":f.proposal,"base":base,"proposal":"public-source","intent":null,"envelope":null,"receipt":receipt,"payload_len":0,"payload_sha256":format!("{:x}",Sha256::digest(b""))});
        db.execute(
            "INSERT INTO sync_exports VALUES('receipt-4',?1,?2)",
            params![digest, export.to_string()],
        )
        .unwrap();
        db.execute(
            "INSERT INTO sync_remote_status VALUES('pending',4,?1,?2)",
            params![digest, receipt.to_string()],
        )
        .unwrap();
        let operation = json!({"op":"publish","workspace":"PRIVATE_WORKSPACE_CANARY","checkpoint":"PRIVATE_CHECKPOINT_CANARY","operation_id":"public-publish","intent":intent});
        let odigest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&operation).unwrap())
        );
        db.execute("INSERT INTO operations VALUES('public-publish',?1,?2,?3)",params![odigest,operation.to_string(),json!({"ok":true,"state":"coordinator_accepted","proposal":"pending","commit":f.proposal,"base":base,"durability":"coordinator_saved","replication":"not_configured"}).to_string()]).unwrap();
        let budget = Connection::open(f.source.join("repair-budget.sqlite")).unwrap();
        budget.execute_batch("CREATE TABLE repair_budgets(proposal TEXT PRIMARY KEY,attempts INTEGER,seconds INTEGER)").unwrap();
        budget
            .execute("INSERT INTO repair_budgets VALUES(?1,3,180)", [&f.proposal])
            .unwrap();
        let before = backup::flush(&f.source, &db, &f.remote).unwrap();
        assert_eq!(before["state"], "complete", "{before}");
        let bytes = Git::open(&f.remote)
            .run(
                &["show", "refs/heads/wipstash/metadata:metadata.json"],
                None,
            )
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for canary in [
            "PRIVATE_WORKSPACE_CANARY",
            "PRIVATE_CHECKPOINT_CANARY",
            "PRIVATE_OUTPUT_CANARY",
            "PRIVATE_PATH_CANARY",
            "PRIVATE_CREDENTIAL_CANARY",
        ] {
            assert!(!text.contains(canary), "leaked {canary}");
        }
        assert!(text.contains(intent));
        let restored = restore(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(restored["activation_required"], true);
        assert_eq!(restored["authenticated_migration"], false);
        let (b, i, w, c, state): (String, String, String, String, String) =
            f.db.query_row(
                "SELECT base,intent,workspace,checkpoint,state FROM proposals WHERE id='pending'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            (b, i, w, c, state),
            (
                base.clone(),
                intent.into(),
                "".into(),
                "".into(),
                "recovery_quarantined".into()
            )
        );
        let gate: String =
            f.db.query_row(
                "SELECT value FROM meta WHERE key='public_recovery_gate'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let gate: Value = serde_json::from_str(&gate).unwrap();
        assert_eq!(
            gate["policy_sha256"],
            format!("{:x}", Sha256::digest(serde_json::to_vec(&policy).unwrap()))
        );
        assert_eq!(gate["policy_required"], true);
        assert_eq!(gate["sync_binding"], binding);
        assert_eq!(
            f.db.query_row(
                "SELECT COUNT(*) FROM meta WHERE key IN ('policy','sync_config')",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let imported: String =
            f.db.query_row(
                "SELECT result FROM sync_imports WHERE operation='lost-ack'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&imported).unwrap()["proposal"],
            "pending"
        );
        let saved: String =
            f.db.query_row(
                "SELECT manifest FROM sync_exports WHERE operation='receipt-4'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&saved).unwrap(), export);
        let restored_budget = Connection::open(f.state.join("repair-budget.sqlite")).unwrap();
        assert_eq!(
            restored_budget
                .query_row("SELECT attempts,seconds FROM repair_budgets", [], |r| Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?
                )))
                .unwrap(),
            (3, 180)
        );
        // Lost local publish acknowledgement returns the original public receipt,
        // without replaying a now-absent private workspace request.
        assert!(crate::engine::execute(&f.state, operation.clone())
            .unwrap_err()
            .contains("activation_required"));
        let again = backup::flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(again["state"], "complete", "{again}");
        let bytes = Git::open(&f.remote)
            .run(
                &["show", "refs/heads/wipstash/metadata:metadata.json"],
                None,
            )
            .unwrap();
        let again: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(again["recovery"]["policy_sha256"], gate["policy_sha256"]);
        assert_eq!(again["recovery"]["sync_binding"], binding);
        // Budget-only mutation must invalidate completion without an event.
        restored_budget
            .execute("UPDATE repair_budgets SET attempts=4", [])
            .unwrap();
        assert_eq!(backup::status(&f.db).unwrap()["state"], "blocked");
        let request = json!({"op":"recovery_activate","confirm_old_authority_stopped":true,"confirm_public_recovery_reviewed":true,"sync_binding":binding});
        assert!(activate(&f.db, &json!({}))
            .unwrap_err()
            .contains("confirmation_required"));
        assert!(activate(&f.db, &request)
            .unwrap_err()
            .contains("policy_mismatch"));
        let configured = crate::engine::execute(
            &f.state,
            json!({"op":"configure","operation_id":"restore-policy","policy":policy}),
        )
        .unwrap();
        assert_eq!(configured["ok"], true);
        let mut wrong = request.clone();
        wrong["sync_binding"]["epoch"] = json!(8);
        assert!(activate(&f.db, &wrong)
            .unwrap_err()
            .contains("binding_mismatch"));
        let activated = crate::engine::execute(&f.state, request.clone()).unwrap();
        let replay = crate::engine::execute(&f.state, operation).unwrap();
        assert_eq!(replay["proposal"], "pending");
        assert_eq!(activated["activation_required"], false);
        assert_eq!(activated["fencing"], "operator_assertion_only");
        assert_eq!(activated["activated_proposals"], 1);
        let duplicate = crate::engine::execute(
            &f.state,
            json!({"op":"sync_import","source":import_dir,"confirm_trusted_source":true}),
        )
        .unwrap();
        assert_eq!(duplicate["duplicate"], true, "{duplicate}");
        assert_eq!(duplicate["proposal"], "pending");
        assert_eq!(
            f.db.query_row("SELECT COUNT(*) FROM sync_imports", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            f.db.query_row("SELECT COUNT(*) FROM proposals", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );

        assert_eq!(
            f.db.query_row("SELECT state FROM proposals WHERE id='pending'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
            "coordinator_accepted"
        );
        assert_eq!(
            activate(&f.db, &request).unwrap()["activation_required"],
            false
        );
        // A restored quarantine must be evaluated again before an agent receives
        // a task. A missing check executable reliably fails without launching it.
        let integrated = crate::engine::execute(&f.state, json!({"op":"integrate"})).unwrap();
        assert_eq!(integrated["outcomes"][0]["state"], "quarantined");
        let task = &integrated["outcomes"][0]["resolution_task"];
        assert_eq!(task["current_head"], base);
        assert!(task["policy_sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64));
        let destination = f.dir.join("restored-resolution-receipt");
        let receipt = crate::engine::execute(&f.state, json!({"op":"sync_export","kind":"receipt","proposal":"pending","operation_id":"fresh-restored-task","destination":destination})).unwrap();
        assert_eq!(receipt["ok"], true);
        let manifest: Value =
            serde_json::from_slice(&fs::read(destination.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["receipt"]["resolution_task"]["proposal"],
            "public-source"
        );
        assert_eq!(manifest["receipt"]["resolution_task"]["current_head"], base);
        assert_eq!(manifest["receipt"]["resolution_task"]["attempt"], 0);
        assert!(!manifest.to_string().contains("PRIVATE_PATH_CANARY"));
    }
    #[test]
    fn repeated_fenced_recovery_preserves_fifo_and_original_disposition() {
        let f = Fixture::new();
        let db = Connection::open(f.source.join("state.sqlite")).unwrap();
        let git = Git::open(&f.source.join("coordinator.git"));
        let base = git.head("refs/wipstash/integration").unwrap();
        db.execute("INSERT INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state) VALUES('pending','','',?1,?2,'first public intent','coordinator_accepted')",params![f.proposal,base]).unwrap();
        for (id, state) in [
            ("z-second", "coordinator_accepted"),
            ("a-third", "quarantined"),
        ] {
            let commit = git
                .commit(
                    &git.empty_tree().unwrap(),
                    std::slice::from_ref(&base),
                    &format!("proposal {id}"),
                )
                .unwrap();
            git.set_ref(&format!("refs/wipstash/proposals/{id}"), &commit, None)
                .unwrap();
            db.execute("INSERT INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state) VALUES(?1,'','',?2,?3,'public intent',?4)",params![id,commit,base,state]).unwrap();
        }
        assert_eq!(
            backup::flush(&f.source, &db, &f.remote).unwrap()["state"],
            "complete"
        );
        restore(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(
            backup::flush(&f.state, &f.db, &f.remote).unwrap()["state"],
            "complete"
        );
        let second = f.dir.join("second-restored");
        let _ = crate::engine::execute(&second, json!({"op":"status"}));
        let second_db = Connection::open(second.join("state.sqlite")).unwrap();
        restore(&second, &second_db, &f.remote).unwrap();
        let activated=activate(&second_db,&json!({"confirm_old_authority_stopped":true,"confirm_public_recovery_reviewed":true,"sync_binding":null})).unwrap();
        assert_eq!(activated["activated_proposals"], 3);
        let mut q = second_db
            .prepare("SELECT id,state FROM proposals ORDER BY rowid")
            .unwrap();
        let order = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            order,
            vec![
                ("pending".into(), "coordinator_accepted".into()),
                ("z-second".into(), "coordinator_accepted".into()),
                ("a-third".into(), "coordinator_accepted".into())
            ]
        );
    }
    #[test]
    fn restores_public_head_replay_journal_without_resetting_cursor() {
        use crate::replication::{
            Admission, Authority, Envelope, Event, Id, PeerIdentity, ReplayStore,
        };
        let f = Fixture::new();
        let db = Connection::open(f.source.join("state.sqlite")).unwrap();
        let root = Git::open(&f.source.join("coordinator.git"))
            .head("refs/wipstash/integration")
            .unwrap();
        let binding = json!({"project":"p","authority":"a","epoch":1,"device":"c","role":"client","peers":["a"]});
        db.execute(
            "INSERT INTO meta VALUES('sync_config',?1)",
            [binding.to_string()],
        )
        .unwrap();
        let authority = Authority {
            project: Id::try_from("p".to_string()).unwrap(),
            authority: Id::try_from("a".to_string()).unwrap(),
            epoch: 1,
        };
        let peer = PeerIdentity {
            project: Id::try_from("p".to_string()).unwrap(),
            authority: Id::try_from("a".to_string()).unwrap(),
            device: Id::try_from("a".to_string()).unwrap(),
            may_replicate: true,
        };
        let event = Envelope {
            version: 1,
            project: Id::try_from("p".to_string()).unwrap(),
            authority: Id::try_from("a".to_string()).unwrap(),
            device: Id::try_from("a".to_string()).unwrap(),
            epoch: 1,
            sequence: 1,
            operation: Id::try_from("head-one".to_string()).unwrap(),
            event: Event::HeadAdvanced { head: root.clone() },
        };
        let encoded = serde_json::to_vec(&event).unwrap();
        let mut journal = ReplayStore::open(
            Connection::open(f.source.join("sync-replay.sqlite")).unwrap(),
            authority.clone(),
        )
        .unwrap();
        assert_eq!(
            journal.receive(&peer, &encoded).unwrap(),
            Admission::Applied
        );
        assert_eq!(
            backup::flush(&f.source, &db, &f.remote).unwrap()["state"],
            "complete"
        );
        restore(&f.state, &f.db, &f.remote).unwrap();
        let mut restored = ReplayStore::open(
            Connection::open(f.state.join("sync-replay.sqlite")).unwrap(),
            authority,
        )
        .unwrap();
        assert_eq!(restored.cursor().unwrap(), 1);
        assert_eq!(restored.cached_head().unwrap(), Some(root));
        assert_eq!(
            restored.receive(&peer, &encoded).unwrap(),
            Admission::Duplicate
        );
        assert_eq!(recovery_status(&f.db).unwrap()["activation_required"], true);
    }
    #[test]
    fn legacy_v1_restores_but_cannot_silently_activate() {
        let f = Fixture::new();
        let remote = Git::open(&f.remote);
        let bytes = remote
            .run(
                &["show", "refs/heads/wipstash/metadata:metadata.json"],
                None,
            )
            .unwrap();
        let mut m: Value = serde_json::from_slice(&bytes).unwrap();
        m["format"] = json!("wipstash-public-metadata-v1");
        m.as_object_mut().unwrap().remove("recovery");
        let blob = String::from_utf8(
            remote
                .run(
                    &["hash-object", "-w", "--stdin"],
                    Some(m.to_string().as_bytes()),
                )
                .unwrap(),
        )
        .unwrap();
        let tree = String::from_utf8(
            remote
                .run(
                    &["mktree"],
                    Some(format!("100644 blob {}\tmetadata.json\n", blob.trim()).as_bytes()),
                )
                .unwrap(),
        )
        .unwrap();
        let commit = remote
            .commit(tree.trim(), &[], "legacy public metadata")
            .unwrap();
        remote
            .set_ref("refs/heads/wipstash/metadata", &commit, None)
            .unwrap();
        let restored = restore(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(restored["intent_restored"], false);
        assert_eq!(recovery_status(&f.db).unwrap()["activation_required"], true);
        assert!(activate(&f.db,&json!({"confirm_old_authority_stopped":true,"confirm_public_recovery_reviewed":true,"sync_binding":null})).unwrap_err().contains("legacy_recovery"));
    }
    #[test]
    fn restores_already_included_as_terminal_disposition() {
        let f = Fixture::new();
        let db = Connection::open(f.source.join("state.sqlite")).unwrap();
        let git = Git::open(&f.source.join("coordinator.git"));
        let head = git.head("refs/wipstash/integration").unwrap();
        db.execute("INSERT INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state,head) VALUES('pending','','',?1,?2,'','already_included',?2)",params![f.proposal,head]).unwrap();
        db.execute(
            "INSERT INTO events(kind,data) VALUES('already_included',?1)",
            [json!({"proposal":"pending","head":head}).to_string()],
        )
        .unwrap();
        db.execute("UPDATE proposals SET details=?1 WHERE id='pending'",[json!({"checks":[{"stdout":"PRIVATE_CHECK_OUTPUT_CANARY"}],"repaired":true,"policy_sha256":"b".repeat(64)}).to_string()]).unwrap();
        backup::flush(&f.source, &db, &f.remote).unwrap();
        let result = restore(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(result["unresolved_count"], 0);
        let state: String =
            f.db.query_row("SELECT state FROM proposals WHERE id='pending'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(state, "already_included");
        let observed = crate::engine::execute(
            &f.state,
            json!({"op":"proposal_status","proposal":"pending"}),
        )
        .unwrap();
        assert_eq!(observed["evidence"], "checks_executed");
        assert_eq!(observed["details"]["repaired"], true);
        assert_eq!(
            observed["details"]["public_queue_snapshot"]["policy_sha256"],
            "b".repeat(64)
        );
        assert!(!observed.to_string().contains("PRIVATE_CHECK_OUTPUT_CANARY"));
    }
    #[test]
    fn restores_superseded_proposals_without_reactivating_them() {
        let f = Fixture::new();
        let db = Connection::open(f.source.join("state.sqlite")).unwrap();
        db.execute("INSERT INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state) VALUES('pending','','',?1,'','','superseded')",[&f.proposal]).unwrap();
        db.execute(
            "INSERT INTO events(kind,data) VALUES('superseded',?1)",
            [json!({"proposal":"pending"}).to_string()],
        )
        .unwrap();
        backup::flush(&f.source, &db, &f.remote).unwrap();
        restore(&f.state, &f.db, &f.remote).unwrap();
        let state: String =
            f.db.query_row("SELECT state FROM proposals WHERE id='pending'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(state, "superseded");
    }
    #[test]
    fn preserves_resolution_lineage_without_private_sessions() {
        let f = Fixture::new();
        let db = Connection::open(f.source.join("state.sqlite")).unwrap();
        let base = Git::open(&f.source.join("coordinator.git"))
            .head("refs/wipstash/integration")
            .unwrap();
        db.execute("INSERT INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state) VALUES('pending','PRIVATE_OWNER','PRIVATE_CHECKPOINT',?1,?2,'public retry intent','quarantined')",params![f.proposal,base]).unwrap();
        db.execute_batch("CREATE TABLE IF NOT EXISTS proposal_resolutions(proposal TEXT PRIMARY KEY,parent TEXT NOT NULL,root TEXT NOT NULL,attempt INTEGER NOT NULL)").unwrap();
        db.execute(
            "INSERT INTO proposal_resolutions VALUES('pending','original','original',3)",
            [],
        )
        .unwrap();
        backup::flush(&f.source, &db, &f.remote).unwrap();
        restore(&f.state, &f.db, &f.remote).unwrap();
        let lineage: (String, String, i64) =
            f.db.query_row(
                "SELECT parent,root,attempt FROM proposal_resolutions WHERE proposal='pending'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(lineage, ("original".into(), "original".into(), 3));
        assert!(recovery_status(&f.db).unwrap()["activation_required"] == true);
        let details: String =
            f.db.query_row(
                "SELECT details FROM proposals WHERE id='pending'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!details.contains("PRIVATE_OWNER"));
        assert!(!details.contains("PRIVATE_CHECKPOINT"));
        activate(&f.db, &json!({"confirm_old_authority_stopped":true,"confirm_public_recovery_reviewed":true,"sync_binding":null})).unwrap();
        let state: String =
            f.db.query_row("SELECT state FROM proposals WHERE id='pending'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(state, "coordinator_accepted");
        let attempt: i64 =
            f.db.query_row(
                "SELECT attempt FROM proposal_resolutions WHERE proposal='pending'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            attempt, 3,
            "Recovery activation must not refund resolution attempts"
        );
    }
    #[test]
    fn preserves_queue_snapshot_without_enabling_execution() {
        let f = Fixture::new();
        let db = Connection::open(f.source.join("state.sqlite")).unwrap();
        db.execute("INSERT INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state) VALUES('pending','secret-workspace','private-checkpoint',?1,'','secret-intent','coordinator_accepted')",[&f.proposal]).unwrap();
        backup::flush(&f.source, &db, &f.remote).unwrap();
        restore(&f.state, &f.db, &f.remote).unwrap();
        let (state, details): (String, String) =
            f.db.query_row(
                "SELECT state,details FROM proposals WHERE id='pending'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "recovery_quarantined");
        let details: Value = serde_json::from_str(&details).unwrap();
        assert_eq!(
            details["public_queue_snapshot"]["state"],
            "coordinator_accepted"
        );
        assert_eq!(details["eligibility_restored"], false);
        assert_eq!(details["public_queue_snapshot"]["intent"], "secret-intent");
        assert!(!details.to_string().contains("secret-workspace"));
        assert!(!details.to_string().contains("private-checkpoint"));
    }
    #[test]
    fn restores_public_roots_and_quarantines_unknown_work() {
        let f = Fixture::new();
        let result = restore(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(result["unresolved_count"], 1);
        assert_eq!(result["watermark"], 3);
        let git = Git::open(&f.state.join("coordinator.git"));
        assert_eq!(
            git.head("refs/wipstash/proposals/pending").unwrap(),
            f.proposal
        );
        assert_eq!(
            git.head("refs/wipstash/backup/metadata").unwrap(),
            result["metadata"].as_str().unwrap()
        );
        assert_eq!(
            f.db.query_row("SELECT state FROM proposals WHERE id='pending'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
            "recovery_quarantined"
        );
        assert_eq!(
            f.db.query_row("SELECT COUNT(*) FROM workspaces", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            f.db.query_row("SELECT COUNT(*) FROM checkpoints", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let data: String =
            f.db.query_row("SELECT data FROM events", [], |r| r.get(0))
                .unwrap();
        assert!(!data.contains("private intent"));
        f.db.execute(
            "INSERT INTO events(kind,data) VALUES('local_test','{}')",
            [],
        )
        .unwrap();
        assert_eq!(f.db.last_insert_rowid(), 4);
        let head = git.head("refs/wipstash/integration").unwrap();
        assert!(crate::engine::execute(&f.state, json!({"op":"integrate"}))
            .unwrap_err()
            .contains("activation_required"));
        assert_eq!(git.head("refs/wipstash/integration").unwrap(), head);
        for op in [
            "init",
            "restore",
            "sync_configure",
            "sync_import",
            "sync_export",
            "sync_reexport",
            "sync_export_current_head",
            "publish",
            "integrate",
            "retry_proposal",
            "cancel",
            "backup_flush",
            "backup_tick",
        ] {
            let result = crate::engine::execute(&f.state, json!({"op":op}));
            assert!(
                result
                    .unwrap_err()
                    .contains("public_recovery_activation_required"),
                "unfenced {op}"
            );
        }
        assert_eq!(
            crate::engine::execute(&f.state, json!({"op":"recovery_status"})).unwrap()
                ["activation_required"],
            true
        );
        assert_eq!(
            crate::engine::execute(&f.state, json!({"op":"status"})).unwrap()["ok"],
            true
        );
    }
    #[test]
    fn source_baseline_supports_unchanged_flush_and_existing_state_is_rejected() {
        let f = Fixture::new();
        let result = restore(&f.state, &f.db, &f.remote).unwrap();
        let flushed = backup::flush(&f.state, &f.db, &f.remote).unwrap();
        assert_eq!(flushed["integration"], result["integration"]);
        assert_eq!(flushed["state"], "complete");
        assert!(restore(&f.state, &f.db, &f.remote)
            .unwrap_err()
            .contains("empty_state"));
        assert!(restore(
            &f.source,
            &Connection::open(f.source.join("state.sqlite")).unwrap(),
            &f.remote
        )
        .is_err());
    }
    #[test]
    fn invalid_source_leaves_state_empty() {
        let f = Fixture::new();
        let git = Git::open(&f.remote);
        git.run(
            &["update-ref", "-d", "refs/heads/wipstash/proposals/pending"],
            None,
        )
        .unwrap();
        assert!(restore(&f.state, &f.db, &f.remote).is_err());
        assert!(!f.state.join("coordinator.git").exists());
        assert_eq!(
            f.db.query_row("SELECT COUNT(*) FROM meta", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn transaction_failure_removes_staged_repository_and_rows() {
        let f = Fixture::new();
        f.db.execute_batch("CREATE TRIGGER reject_restore BEFORE INSERT ON meta BEGIN SELECT RAISE(ABORT,'injected failure'); END").unwrap();
        assert!(restore(&f.state, &f.db, &f.remote).is_err());
        assert!(!f.state.join("coordinator.git").exists());
        assert!(!f.state.join("restore-staging.git").exists());
        assert_eq!(
            f.db.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
