use super::*;

fn snapshot_request(request: &Value) -> Value {
    let mut value = json!({"op":"checkpoint","workspace":request["workspace"],
        "expected_generation":request["expected_generation"],
        "operation_id":format!("commit-snapshot-{}", digest(request)),
        "commit_operation":request["operation_id"]});
    if let Some(tree) = request.get("staged_tree") {
        value["staged_tree"] = tree.clone();
    }
    value
}

pub(super) fn saved_snapshot(db: &Connection, request: &Value) -> R<Option<Value>> {
    let snapshot = snapshot_request(request);
    let record: Option<(String, Option<String>)> = sql(db
        .query_row(
            "SELECT digest,result FROM operations WHERE id=?1",
            [field(&snapshot, "operation_id")?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    match record {
        Some((bound, _)) if bound != digest(&snapshot) => {
            Err("idempotency_mismatch: commit snapshot identity already used".into())
        }
        Some((_, Some(result))) => serde_json::from_str(&result)
            .map(Some)
            .map_err(|e| e.to_string()),
        _ => Ok(None),
    }
}

fn save_snapshot(
    state: &Path,
    db: &Connection,
    request: &Value,
    prepared: Option<&observation::PreparedCapture>,
) -> R<Value> {
    if let Some(result) = saved_snapshot(db, request)? {
        return Ok(result);
    }
    let snapshot = snapshot_request(request);
    sql(db.execute(
        "INSERT OR IGNORE INTO operations(id,digest,request) VALUES(?1,?2,?3)",
        params![
            snapshot["operation_id"].as_str(),
            digest(&snapshot),
            snapshot.to_string()
        ],
    ))?;
    checkpoint(state, db, &snapshot, prepared)
}

pub(super) fn shared_baseline(
    db: &Connection,
    wid: &str,
    base: &str,
    before_generation: i64,
) -> R<Option<(String, String)>> {
    sql(db.query_row(
        "SELECT c.tree,COALESCE(json_extract(s.receipt,'$.integration_head'),p.head) FROM proposals p JOIN checkpoints c ON c.id=p.checkpoint LEFT JOIN sync_remote_status s ON s.proposal=p.id WHERE c.workspace=?1 AND c.base=?2 AND c.generation<?3 AND COALESCE(json_extract(s.receipt,'$.state'),p.state) IN ('integrated','already_included') AND COALESCE(json_extract(s.receipt,'$.integration_head'),p.head) IS NOT NULL ORDER BY c.generation DESC,p.rowid DESC LIMIT 1",
        params![wid,base,before_generation], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional())
}

fn merge_delta(git: &Git, before_tree: &str, after_tree: &str, onto: &str) -> R<crate::git::Merge> {
    let base = git.commit(before_tree, &[], "local commit comparison base")?;
    let public = git.commit(
        &git.tree(onto)?,
        std::slice::from_ref(&base),
        "shared commit comparison",
    )?;
    let edited = git.commit(after_tree, &[base], "local commit comparison")?;
    git.merge(&public, &edited)
}

pub(super) fn adoption_merge(
    db: &Connection,
    wid: &str,
    w: &Workspace,
    git: &Git,
    private: &str,
    target: &str,
) -> R<crate::git::Merge> {
    if let Some((before, _)) = shared_baseline(db, wid, &w.base, w.generation + 1)? {
        merge_delta(git, &before, &git.tree(private)?, target)
    } else {
        git.merge(private, target)
    }
}

fn prepare_export(
    state: &Path,
    db: &Connection,
    request: &Value,
    saved: &Value,
) -> R<(String, String)> {
    let id = field(request, "operation_id")?;
    let checkpoint = field(saved, "checkpoint")?;
    let prepared: Option<(String, String, String)> = sql(db
        .query_row(
            "SELECT checkpoint,tree,base FROM commit_preparations WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional())?;
    if let Some((bound, tree, base)) = prepared {
        if bound != checkpoint {
            return Err("idempotency_mismatch: commit preparation snapshot changed".into());
        }
        return Ok((tree, base));
    }
    let wid = field(request, "workspace")?;
    let (mut tree, mut base, generation): (String, String, i64) = sql(db.query_row(
        "SELECT tree,base,generation FROM checkpoints WHERE id=?1 AND workspace=?2",
        params![checkpoint, wid],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ))?;
    if let Some((before, shared_head)) = shared_baseline(db, wid, &base, generation)? {
        let git = local(state, wid);
        if !git.repo.join("objects").exists() {
            return Err("incomplete_state: private object store missing".into());
        }
        if coordinator(state).repo.exists() {
            transfer(
                &coordinator(state),
                &git,
                &shared_head,
                &format!("refs/wipstash/commit-bases/{id}"),
            )?;
        } else {
            git.verified_object("commit", &shared_head)?;
        }
        let merged = merge_delta(&git, &before, &tree, &shared_head)?;
        if !merged.clean {
            conflicts::record(
                db,
                &git,
                conflicts::Capture {
                    operation: id,
                    workspace: wid,
                    origin: "commit_baseline",
                    base: &before,
                    local: field(saved, "commit")?,
                    target: &shared_head,
                    merge: &merged,
                    generation,
                },
            )?;
            return Err("commit_baseline_conflict: the previous shared result differs from the local snapshot; deliberately adopt and reconcile shared updates before a new commit".into());
        }
        tree = merged.tree;
        base = shared_head;
    }
    sql(db.execute(
        "INSERT INTO commit_preparations(id,checkpoint,tree,base) VALUES(?1,?2,?3,?4)",
        params![id, checkpoint, tree, base],
    ))?;
    Ok((tree, base))
}

fn submit_snapshot(state: &Path, db: &Connection, request: &Value, saved: &Value) -> R<Value> {
    if saved["ok"] != true {
        return Err("commit_snapshot_failed: no shared submission was made".into());
    }
    let workspace = field(request, "workspace")?;
    ensure_writer_idle(db, workspace)?;
    let resolution: Option<(String, String)> = sql(db
        .query_row(
            "SELECT owner,proposal FROM resolution_sessions WHERE workspace=?1 AND state='open'",
            [workspace],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    let mut submission = json!({"workspace":workspace,"checkpoint":saved["checkpoint"],
        "operation_id":request["operation_id"],"intent":request["intent"]});
    let mut result = if let Some((owner, proposal)) = resolution {
        submission["workspace"] = json!(owner);
        submission["proposal"] = json!(proposal);
        submission["resolution_workspace"] = json!(workspace);
        submission["expected_head"] = request["expected_head"].clone();
        submission["resolved_conflicts"] = request["resolved_conflicts"].clone();
        resolution::submit(state, db, &submission)?
    } else {
        let (tree, base) = prepare_export(state, db, request, saved)?;
        let generation = saved["generation"]
            .as_i64()
            .ok_or("invalid_snapshot_generation")?;
        publish_snapshot(state, db, &submission, &tree, &base, generation)?
    };
    result["workspace"] = json!(workspace);
    result["generation"] = saved["generation"].clone();
    result["shared"] = json!(false);
    result["submitted"] = json!(true);
    conflicts::submitted(db, workspace, field(request, "operation_id")?)?;
    finish(db, field(request, "operation_id")?, &result)?;
    Ok(result)
}

pub(super) fn commit(
    state: &Path,
    db: &Connection,
    request: &Value,
    prepared: Option<&observation::PreparedCapture>,
) -> R<Value> {
    let preflight_start = std::time::Instant::now();
    let intent = field(request, "intent")?;
    if intent.trim().is_empty() || intent.len() > 4096 {
        return Err(
            "invalid_request: commit requires a nonempty intent of at most 4096 bytes".into(),
        );
    }
    resolution::preflight(db, request)?;
    conflicts::preflight(state, db, request)?;
    let preflight_ms = preflight_start.elapsed().as_millis();
    let capture_start = std::time::Instant::now();
    let saved = save_snapshot(state, db, request, prepared)?;
    let capture_ms = capture_start.elapsed().as_millis();
    fault("commit_after_snapshot");
    let submit_start = std::time::Instant::now();
    let mut result = submit_snapshot(state, db, request, &saved)?;
    let submission_ms = submit_start.elapsed().as_millis();
    fault("commit_after_submit");
    let share_start = std::time::Instant::now();
    if !sync::is_client(db)? && coordinator(state).repo.exists() {
        if let Err(error) = integrate(
            state,
            db,
            &json!({"max_proposals":1,"only_proposal":result["proposal"]}),
        ) {
            result["integration_error"] = error_response(&error)["error"].clone();
        }
    }
    let sharing_ms = share_start.elapsed().as_millis();
    let observed = proposal_status(db, field(&result, "proposal")?)?;
    result["timing"] = json!({"preflight_ms":preflight_ms,"capture_ms":capture_ms,"submission_ms":submission_ms,"sharing_ms":sharing_ms,"merge_ms":observed["details"]["merge_duration_ms"]});
    for key in [
        "state",
        "head",
        "validation",
        "evidence",
        "resolution_task",
        "next_action",
    ] {
        if let Some(value) = observed.get(key) {
            result[key] = value.clone();
        }
    }
    result["shared"] = json!(matches!(
        result["state"].as_str(),
        Some("integrated" | "already_included")
    ));
    if result["state"] == "local_queued" {
        result["state"] = json!("queued_offline");
    }
    Ok(result)
}

pub(super) fn recover_submissions(state: &Path, db: &Connection) -> R<()> {
    if crate::restore::recovery_status(db)?["activation_required"] == true {
        return Ok(());
    }
    let mut statement = sql(db.prepare("SELECT id,request FROM operations WHERE result IS NULL AND json_extract(request,'$.op')='commit'"))?;
    let pending = sql(statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }))?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|e| e.to_string())?;
    for (id, request) in pending {
        let request: Value = serde_json::from_str(&request).map_err(|e| e.to_string())?;
        let result = match saved_snapshot(db, &request)? {
            Some(saved) => submit_snapshot(state, db, &request, &saved)
                .unwrap_or_else(|error|error_response(&error)),
            None => error_response("commit_interrupted: no durable snapshot was completed; live files were not recaptured or submitted"),
        };
        finish(db, &id, &result)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Project {
        _temp: tempfile::TempDir,
        root: PathBuf,
    }
    impl Project {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            fs::create_dir(root.join("source")).unwrap();
            fs::write(root.join("source/file"), "initial\n").unwrap();
            let project = Self { _temp: temp, root };
            project.call(json!({"op":"init","source":project.root.join("source")}));
            for actor in ["alice", "bob"] {
                project.call(json!({"op":"open","workspace":actor,"path":project.root.join(actor),"operation_id":format!("open-{actor}")}));
            }
            project
        }
        fn call(&self, request: Value) -> Value {
            execute(&self.root.join("state"), request).unwrap()
        }
        fn commit(&self, actor: &str, id: &str, generation: u64) -> Value {
            self.call(json!({"op":"commit","workspace":actor,"intent":"Change the fixture","expected_generation":generation,"operation_id":id}))
        }
        fn public(&self, path: &str) -> Vec<u8> {
            coordinator(&self.root.join("state"))
                .run(&["show", &format!("{HEAD}:{path}")], None)
                .unwrap()
        }
    }
    #[test]
    fn one_commit_shares_without_worker_or_adopting_other_workspaces() {
        let p = Project::new();
        fs::write(p.root.join("alice/file"), "shared\n").unwrap();
        let result = p.commit("alice", "share", 0);
        assert_eq!(result["ok"], true);
        assert_eq!(result["shared"], true);
        assert_eq!(result["state"], "integrated");
        assert_eq!(result["generation"], 1);
        assert_eq!(result["validation"]["state"], "unchecked");
        assert_eq!(p.public("file"), b"shared\n");
        assert_eq!(fs::read(p.root.join("bob/file")).unwrap(), b"initial\n");
        fs::write(p.root.join("alice/file"), "new private work\n").unwrap();
        assert_eq!(p.commit("alice", "share", 0), result);
        assert_eq!(p.public("file"), b"shared\n");
        assert!(execute(&p.root.join("state"),json!({"op":"commit","workspace":"alice","intent":"Changed request","expected_generation":0,"operation_id":"share"})).unwrap_err().starts_with("idempotency_mismatch"));
    }
    #[test]
    fn conflicts_are_explicit_and_resolution_uses_the_same_commit_tool() {
        let p = Project::new();
        fs::write(p.root.join("alice/file"), "alice\n").unwrap();
        fs::write(p.root.join("bob/file"), "bob\n").unwrap();
        assert_eq!(p.commit("alice", "alice-change", 0)["shared"], true);
        let blocked = p.commit("bob", "bob-change", 0);
        assert_eq!(blocked["shared"], false);
        assert_eq!(blocked["state"], "quarantined");
        let opened = p.call(json!({"op":"resolution_open","workspace":"bob","proposal":"bob-change","resolution_workspace":"fix","path":p.root.join("fix"),"operation_id":"open-fix"}));
        assert_eq!(opened["ok"], true, "{opened}");
        fs::write(p.root.join("fix/file"), "alice and bob\n").unwrap();
        let resolved = p.call(json!({"op":"commit","workspace":"fix","intent":"Combine both greetings","expected_generation":0,"expected_head":opened["resolution_head"],"resolved_conflicts":opened["conflict_paths"],"operation_id":"resolve"}));
        assert_eq!(resolved["shared"], true, "{resolved}");
        assert_eq!(resolved["resolution_of"], "bob-change");
        assert_eq!(p.public("file"), b"alice and bob\n");
        assert_eq!(fs::read(p.root.join("bob/file")).unwrap(), b"bob\n");
    }
    #[test]
    fn check_failures_are_reported_after_sharing_without_rewriting_the_commit_outcome() {
        let p = Project::new();
        let executable = std::env::current_exe().unwrap();
        p.call(json!({"op":"configure","operation_id":"checks","policy":{"checks":[{"id":"reject","argv":[executable,"--invalid-test-runner-option"],"required":true,"timeout_seconds":5}]}}));
        fs::write(p.root.join("alice/file"), "candidate\n").unwrap();
        let result = p.commit("alice", "rejected", 0);
        assert_eq!(result["state"], "integrated", "{result}");
        assert_eq!(result["shared"], true);
        assert_eq!(result["validation"]["state"], "pending");
        assert_eq!(p.public("file"), b"candidate\n");
        assert_eq!(
            validation_tick(&p.root.join("state")).unwrap()["validation"]["state"],
            "failed"
        );
        assert_eq!(
            p.call(json!({"op":"proposal_status","proposal":"rejected"}))["validation"]["state"],
            "failed"
        );
        assert_eq!(p.commit("alice", "rejected", 0), result);
    }
    #[test]
    fn stale_generation_does_not_submit_and_invalid_intent_does_not_capture() {
        let p = Project::new();
        let invalid = p.call(json!({"op":"commit","workspace":"alice","intent":" ","expected_generation":0,"operation_id":"bad-intent"}));
        assert_eq!(invalid["ok"], false);
        assert_eq!(
            p.call(json!({"op":"status","workspace":"alice"}))["generation"],
            0
        );
        let stale = p.commit("alice", "stale", 7);
        assert_eq!(stale["ok"], false);
        assert_eq!(stale["error"]["code"], "generation_mismatch");
        let db = Connection::open(p.root.join("state/state.sqlite")).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM proposals", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn missing_coordinator_queues_honestly_without_losing_saved_work() {
        let p = Project::new();
        fs::rename(
            p.root.join("state/coordinator.git"),
            p.root.join("offline.git"),
        )
        .unwrap();
        fs::write(p.root.join("alice/file"), "offline work\n").unwrap();
        let result = p.commit("alice", "offline", 0);
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["shared"], false);
        assert_eq!(result["state"], "queued_offline");
        assert_eq!(result["generation"], 1);
    }
}
