use super::*;
use std::time::Instant;

pub(super) struct StateOwner(PathBuf);
impl StateOwner {
    pub fn install(state: &Path, r: &Value) -> R<Self> {
        let path = state.join("state-lock-owner.json");
        let record = json!({"pid":std::process::id(),"operation":r["op"],"workspace":r["workspace"],"operation_id":r["operation_id"],"acquired_at_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_millis()});
        io(fs::write(&path, record.to_string()))?;
        Ok(Self(path))
    }
}
impl Drop for StateOwner {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub(super) fn observed_owner(state: &Path) -> Value {
    fs::read(state.join("state-lock-owner.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .unwrap_or(Value::Null)
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct PreparedCapture {
    pub workspace: String,
    pub path: PathBuf,
    pub base: String,
    pub checkpoint: Option<String>,
    pub generation: i64,
    pub tree: String,
    pub hygiene: Value,
}

pub(super) fn prepare_capture(state: &Path, r: &Value) -> R<Option<PreparedCapture>> {
    if !matches!(r["op"].as_str(), Some("commit" | "checkpoint")) {
        return Ok(None);
    }
    if !state.join("state.sqlite").exists() {
        return Ok(None);
    }
    let db = sql(Connection::open(state.join("state.sqlite")))?;
    sql(db.busy_timeout(std::time::Duration::from_secs(5)))?;
    if !db
        .query_row(
            "SELECT value='2' FROM meta WHERE key='observation_schema'",
            [],
            |r| r.get::<_, bool>(0),
        )
        .unwrap_or(false)
    {
        return Ok(None);
    }
    let wid = field(r, "workspace")?;
    let id = field(r, "operation_id")?;
    ident(id)?;
    let recorded: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1)",
        [id],
        |r| r.get(0),
    ))?;
    if recorded {
        return Ok(None);
    }
    if r["op"] == "commit"
        && r["intent"]
            .as_str()
            .is_none_or(|s| s.trim().is_empty() || s.len() > 4096)
    {
        return Ok(None);
    }
    let prior: Option<(String, Option<String>)> = sql(db
        .query_row(
            "SELECT digest,result FROM capture_intents WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    if let Some((bound, result)) = prior {
        if bound != digest(r) {
            return Err("idempotency_mismatch: capture identity changed".into());
        }
        return result.map(|s|serde_json::from_str(&s).map(Some).map_err(|e|e.to_string())).unwrap_or_else(||Err("commit_interrupted: capture did not finish; live files were not recaptured. Inspect files and choose a deliberate new Commit.".into()));
    }
    let w = ws(&db, wid)?;
    if generation(r, &w).is_err()
        || lifecycle::ensure_open(&db, wid).is_err()
        || ensure_writer_idle(&db, wid).is_err()
    {
        return Ok(None);
    }
    let recovering:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM adoptions WHERE workspace=?1 AND state IN ('applying','applied'))",[wid],|r|r.get(0)))?;
    if recovering {
        return Ok(None);
    }
    sql(db.execute(
        "INSERT INTO capture_intents VALUES(?1,?2,?3,NULL)",
        params![id, digest(r), r.to_string()],
    ))?;
    fault("capture_after_intent");
    let git = local(state, wid);
    let tree = capture_tree(state, &git, &w.path, r)?;
    if r.get("staged_tree").is_none() && tree != git.capture(&w.path)? {
        return Err("snapshot_unstable: files changed during capture".into());
    }
    git.set_ref(
        &format!("refs/wipstash/prepared-captures/{}", digest(r)),
        &tree,
        None,
    )?;
    let hygiene = experience::hygiene(&git, &tree, &w.path)?;
    let capture = PreparedCapture {
        workspace: wid.into(),
        path: w.path,
        base: w.base,
        checkpoint: w.checkpoint,
        generation: w.generation,
        tree,
        hygiene,
    };
    sql(db.execute(
        "UPDATE capture_intents SET result=?2 WHERE id=?1",
        params![
            id,
            serde_json::to_string(&capture).map_err(|e| e.to_string())?
        ],
    ))?;
    fault("capture_after_ready");
    Ok(Some(capture))
}

pub(super) fn capture_tree(state: &Path, git: &Git, path: &Path, request: &Value) -> R<String> {
    if let Some(tree) = request.get("staged_tree") {
        let tree = tree.as_str().ok_or("invalid_staged_tree")?;
        git.verified_object("tree", tree)?;
        let review = tempfile::tempdir_in(state).map_err(|e| e.to_string())?;
        git.materialize(tree, review.path())?;
        return Ok(tree.into());
    }
    git.capture(path)
}

pub(super) fn workspace_fence(state: &Path, r: &Value) -> R<Option<fs::File>> {
    if !matches!(
        r["op"].as_str(),
        Some(
            "status"
                | "updates"
                | "open"
                | "checkpoint"
                | "commit"
                | "publish"
                | "adopt"
                | "resolve_adoption"
                | "command_run"
                | "command_recover"
                | "workspace_close"
                | "workspace_reopen"
        )
    ) {
        return Ok(None);
    }
    let Some(wid) = r["workspace"].as_str() else {
        return Ok(None);
    };
    ident(wid)?;
    io(fs::create_dir_all(state.join("workspace-fences")))?;
    let file = io(OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("workspace-fences").join(format!("{wid}.lock"))))?;
    fs2::FileExt::lock_exclusive(&file).map_err(|e| e.to_string())?;
    Ok(Some(file))
}

pub(super) fn coordination_fence(state: &Path) -> R<fs::File> {
    let file = io(OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("coordination.lock")))?;
    fs2::FileExt::lock_exclusive(&file).map_err(|e| e.to_string())?;
    Ok(file)
}

pub(super) fn latest(db: &Connection) -> R<Option<String>> {
    sql(db
        .query_row(
            "SELECT value FROM meta WHERE key IN ('sync_cached_head','validation_head') ORDER BY CASE key WHEN 'sync_cached_head' THEN 0 ELSE 1 END LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional())
}

pub(super) fn workspace_summary(db: &Connection, wid: &str) -> R<Value> {
    let w = ws(db, wid)?;
    let head = latest(db)?;
    let last_shared = shared_commit::shared_baseline(db, wid, &w.base, w.generation + 1)?
        .map(|(_, h)| h)
        .unwrap_or(w.base.clone());
    let phase: String = sql(db.query_row(
        "SELECT COALESCE((SELECT state FROM workspace_lifecycle WHERE workspace=?1),'open')",
        [wid],
        |r| r.get(0),
    ))?;
    let mut v = json!({"ok":true,"workspace":wid,"path":w.path,"generation":w.generation,"adopted":w.base,"local_base":w.base,"latest":head,"shared_head":head,
        "dirty":null,"has_unshared_changes":null,"changes_since_save":null,"inspection_available":false,"inspection_reason":"Live files were not scanned; request inspect_files=true for a workspace inspection.",
        "workspace_state":phase,"files_changed":false,"last_shared_head":last_shared,"workspace_behind_shared":head.as_ref().map(|h|h!=&w.base),"shared_changes_available":head.as_ref().map(|h|h!=&last_shared),"local_test_scope":"local workspace only; server checks validate the combined shared head",
        "coordination":coordination::list(db,None,0,16)?,"resolution_tasks":resolution::tasks(db,&json!({"workspace":wid}))?["tasks"],
        "next_action":feedback::action(Some("updates"),"Read incoming work before choosing a task. Merge at coherent milestones or when incoming changes affect your work; successful Commits do not require a Merge between them.",json!({"workspace":wid}))});
    for (key, value) in recent_proposals(db, wid)?.as_object().unwrap() {
        v[key] = value.clone();
    }
    Ok(v)
}

pub(super) fn try_execute(state: &Path, r: &Value) -> Option<R<Value>> {
    let op = r["op"].as_str()?;
    let short_write = matches!(
        op,
        "task_claim"
            | "task_update"
            | "repair_update"
            | "repair_pickup"
            | "comment_add"
            | "coordination_remote"
            | "coordination_receipt"
            | "coordination_import"
    );
    let read = matches!(
        op,
        "updates"
            | "diff"
            | "task_list"
            | "repair_list"
            | "validation_status"
            | "comment_list"
            | "proposal_status"
            | "operation_status"
            | "resolution_tasks"
            | "conflict_status"
            | "coordination_export"
    ) || op == "status"
        || (op == "workspace_inventory" && r["inspect_files"] == false);
    if !short_write && !read {
        return None;
    }
    if !state.join("state.sqlite").exists() {
        return None;
    }
    let db = match Connection::open_with_flags(
        state.join("state.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    ) {
        Ok(db) => db,
        Err(_) => return None,
    };
    if !db
        .query_row(
            "SELECT value='2' FROM meta WHERE key='observation_schema'",
            [],
            |r| r.get::<_, bool>(0),
        )
        .unwrap_or(false)
    {
        return None;
    }
    let pending_recovery=db.query_row("SELECT EXISTS(SELECT 1 FROM promotions WHERE state='intent') OR EXISTS(SELECT 1 FROM adoptions WHERE state IN ('applying','applied')) OR EXISTS(SELECT 1 FROM operations WHERE result IS NULL AND json_extract(request,'$.op') IN ('commit','command_run'))",[],|r|r.get::<_,bool>(0)).unwrap_or(false);
    if pending_recovery {
        if let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(state.join("state.lock"))
        {
            if fs2::FileExt::try_lock_exclusive(&file).is_ok() {
                let _ = fs2::FileExt::unlock(&file);
                return None;
            }
        }
    }
    Some((|| {
        let started = Instant::now();
        sql(db.busy_timeout(std::time::Duration::from_secs(5)))?;
        let _coordination = if short_write {
            Some(coordination_fence(state)?)
        } else {
            None
        };
        let _workspace = if op == "updates" || (op == "status" && r["inspect_files"] != false) {
            workspace_fence(state, r)?
        } else {
            None
        };
        let wait = started.elapsed().as_millis();
        let dispatch = Instant::now();
        if short_write {
            if let Some(id) = r["operation_id"].as_str() {
                let replay: Option<(String, Option<String>)> = sql(db
                    .query_row(
                        "SELECT digest,result FROM operations WHERE id=?1",
                        [id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional())?;
                if let Some((bound, Some(result))) = replay {
                    if bound != digest(r) {
                        return Err(
                            "idempotency_mismatch: operation ID already binds a different request"
                                .into(),
                        );
                    }
                    return serde_json::from_str(&result).map_err(|e| e.to_string());
                }
            }
        }
        let mut v = if short_write {
            fast_mutation(state, &db, r)?
        } else {
            sql(db.execute_batch("BEGIN"))?;
            let result = match op {
                "status" => {
                    if let Some(wid) = r["workspace"].as_str() {
                        if r["inspect_files"] != false {
                            status(state, &db, r)
                        } else {
                            workspace_summary(&db, wid)
                        }
                    } else {
                        Ok(
                            json!({"ok":true,"head":latest(&db)?,"workspaces":sql(db.query_row("SELECT COUNT(*) FROM workspaces",[],|r|r.get::<_,u64>(0)))?}),
                        )
                    }
                }
                "diff" => public_diff(state, &db, r),
                "updates" => {
                    let wid = field(r, "workspace")?;
                    let w = ws(&db, wid)?;
                    let git = local(state, wid);
                    let online = coordinator(state).repo.exists();
                    let target = if online {
                        match latest(&db)? {
                            Some(head) => head,
                            None => coordinator(state).head(HEAD)?,
                        }
                    } else {
                        git.head(HEAD)?
                    };
                    if online {
                        transfer(&coordinator(state), &git, &target, HEAD)?;
                    }
                    Ok(
                        json!({"ok":true,"workspace":wid,"adopted":w.base,"latest":target,"local_base":w.base,"shared_head":target,"generation":w.generation,"files_changed":false,"incoming":experience::incoming(state,&db,wid,r["cursor"].as_u64().unwrap_or(0),r["limit"].as_u64().unwrap_or(16))?,"coordination":coordination::list(&db,None,0,16)?,"coordinator_online":online && !sync::is_client(&db)?,"cached":!online || sync::is_client(&db)?,"remote_contact_unverified":sync::is_client(&db)?}),
                    )
                }
                "task_list" | "comment_list" | "coordination_export" => {
                    coordination::dispatch(state, &db, r)
                }
                "repair_list" | "validation_status" => validation::dispatch(state, &db, r),
                "workspace_inventory" => lifecycle::inventory(state, &db, r),
                "proposal_status" => proposal_status(&db, field(r, "proposal")?),
                "operation_status" => operation_record(&db, r),
                "resolution_tasks" => resolution::tasks(&db, r),
                "conflict_status" => {
                    conflicts::describe(&db, field(r, "candidate")?, field(r, "workspace")?)
                        .map(|v| json!({"ok":true,"conflict":v}))
                }
                _ => unreachable!(),
            };
            let result = result.map(|v| feedback::complete(&db, r, v));
            let result = result.and_then(|mut v| {
                if op != "operation_status" && !op.starts_with("coordination_") {
                    validation::decorate(&db, r, &mut v)?;
                }
                Ok(v)
            });
            sql(db.execute_batch("COMMIT"))?;
            result?
        };
        if op != "operation_status" && !op.starts_with("coordination_") {
            if r["include_timings"] == true {
                v["lock_owner_observation"] = observed_owner(state);
            }
            validation::timing(
                &db,
                r,
                wait,
                dispatch.elapsed().as_millis(),
                started.elapsed().as_millis(),
                &mut v,
            )?;
            v["timing"]["state_lock_bypassed"] = json!(true);
            v["observation_scope"] = json!("committed_database_state");
            if short_write {
                if let Some(id) = r["operation_id"].as_str() {
                    finish(&db, id, &v)?;
                }
            }
        }
        Ok(v)
    })())
}

fn public_diff(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let base = field(r, "base")?;
    let head = field(r, "head")?;
    let path = field(r, "path")?;
    crate::git::allowed_path(path)?;
    for oid in [base, head] {
        if oid.len() != 40 || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid_request: exact public commit IDs required".into());
        }
    }
    let git = coordinator(state);
    let current = latest(db)?
        .or_else(|| git.head(HEAD).ok())
        .ok_or("shared_head_unavailable")?;
    if !git.ancestor(base, &current)? || !git.ancestor(head, &current)? {
        return Err("invalid_request: diff versions must belong to shared history".into());
    }
    let raw = git.run(
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--unified=3",
            base,
            head,
            "--",
            path,
        ],
        None,
    )?;
    let text = String::from_utf8_lossy(&raw);
    let mut end = text.len().min(16_384);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(
        json!({"ok":true,"base":base,"head":head,"path":path,"diff":&text[..end],"truncated":end<text.len(),"binary":text.starts_with("Binary files") || text.contains("\nBinary files"),"files_changed":false}),
    )
}

fn operation_record(db: &Connection, r: &Value) -> R<Value> {
    if r.get("include_record").is_some_and(|v| !v.is_boolean()) {
        return Err("invalid_request: include_record must be boolean".into());
    }
    let record: Option<(String, Option<String>)> = sql(db
        .query_row(
            "SELECT request,result FROM operations WHERE id=?1",
            [field(r, "operation_id")?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    let Some((request, result)) = record else {
        let capture: Option<(String, bool)> = sql(db
            .query_row(
                "SELECT request,result IS NOT NULL FROM capture_intents WHERE id=?1",
                [field(r, "operation_id")?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        let (request, ready) =
            capture.ok_or("operation_not_found: no journaled operation has this ID")?;
        return Ok(
            json!({"ok":true,"operation_id":r["operation_id"],"recorded":true,"state":"pending","stage":"capture_preparation","capture_ready":ready,"request":serde_json::from_str::<Value>(&request).map_err(|e|e.to_string())?,"result":null}),
        );
    };
    let result: Option<Value> = result
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| e.to_string())?;
    if r["include_record"] == true {
        Ok(
            json!({"ok":true,"operation_id":r["operation_id"],"request":serde_json::from_str::<Value>(&request).map_err(|e|e.to_string())?,"recorded":true,"state":if result.is_some(){"completed"}else{"pending"},"result":result}),
        )
    } else {
        Ok(result.unwrap_or(json!({"ok":true,"state":"pending"})))
    }
}

pub(super) fn check_capture_identity(db: &Connection, id: &str, r: &Value) -> R<()> {
    let bound: Option<String> = sql(db
        .query_row(
            "SELECT digest FROM capture_intents WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .optional())?;
    if bound.is_some_and(|s| s != digest(r)) {
        return Err("idempotency_mismatch: operation ID already binds a capture request".into());
    }
    Ok(())
}

fn fast_mutation(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let op = field(r, "op")?;
    if matches!(op, "coordination_receipt" | "coordination_import") {
        return coordination::dispatch(state, db, r);
    }
    let id = field(r, "operation_id")?;
    ident(id)?;
    check_capture_identity(db, id, r)?;
    if let Some((bound, result)) = sql(db
        .query_row(
            "SELECT digest,result FROM operations WHERE id=?1",
            [id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .optional())?
    {
        if bound != digest(r) {
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
            params![id, digest(r), r.to_string()],
        ))?;
    }
    let mut result = coordination::dispatch(state, db, r).unwrap_or_else(|e| feedback::error(&e));
    if op != "coordination_remote" {
        validation::decorate(db, r, &mut result)?;
    }
    finish(db, id, &result)?;
    Ok(result)
}
