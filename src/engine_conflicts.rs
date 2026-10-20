use super::*;

pub(super) fn schema(db: &Connection) -> R<()> {
    sql(db.execute_batch("CREATE TABLE IF NOT EXISTS workspace_conflicts(id TEXT PRIMARY KEY,operation_id TEXT UNIQUE NOT NULL,workspace TEXT NOT NULL,origin TEXT NOT NULL,base TEXT NOT NULL,local_commit TEXT NOT NULL,target TEXT NOT NULL,tree TEXT NOT NULL,paths TEXT NOT NULL,details TEXT NOT NULL,generation INTEGER NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS conflict_reviews(workspace TEXT PRIMARY KEY,conflict TEXT NOT NULL,owner TEXT NOT NULL,state TEXT NOT NULL,submitted_commit TEXT);
CREATE TABLE IF NOT EXISTS conflict_openings(operation_id TEXT PRIMARY KEY,path TEXT NOT NULL,response TEXT);
CREATE TABLE IF NOT EXISTS workspace_lifecycle(workspace TEXT PRIMARY KEY,state TEXT NOT NULL,closed_at INTEGER,reason TEXT NOT NULL);") )?;
    Ok(())
}
pub(super) struct Capture<'a> {
    pub operation: &'a str,
    pub workspace: &'a str,
    pub origin: &'a str,
    pub base: &'a str,
    pub local: &'a str,
    pub target: &'a str,
    pub merge: &'a crate::git::Merge,
    pub generation: i64,
}
pub(super) fn record(db: &Connection, git: &Git, c: Capture<'_>) -> R<String> {
    let id = if c.origin == "merge" {
        c.operation.to_owned()
    } else {
        format!("baseline-{}", digest(&json!(c.operation)))
    };
    let pinned = git.commit(
        &c.merge.tree,
        &[c.local.to_owned(), c.target.to_owned()],
        &format!("private conflict review {id}"),
    )?;
    git.set_ref(&format!("refs/wipstash/conflicts/{id}"), &pinned, None)?;
    let details = experience::conflict_details(git, c.base, c.local, c.target, &c.merge.conflicts)?;
    sql(db.execute("INSERT OR IGNORE INTO workspace_conflicts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'open')",params![id,c.operation,c.workspace,c.origin,c.base,c.local,c.target,c.merge.tree,serde_json::to_string(&c.merge.conflicts).unwrap(),serde_json::to_string(&details).unwrap(),c.generation]))?;
    Ok(id)
}
pub(super) fn describe(db: &Connection, id: &str, owner: &str) -> R<Value> {
    let value=sql(db.query_row("SELECT workspace,origin,base,local_commit,target,tree,paths,details,generation,state FROM workspace_conflicts WHERE id=?1",[id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?,r.get::<_,i64>(8)?,r.get::<_,String>(9)?))))?;
    if value.0 != owner {
        return Err("conflict_owner_mismatch".into());
    }
    Ok(
        json!({"id":id,"workspace":owner,"origin":value.1,"sides":{"base":value.2,"local":value.3,"shared":value.4},"proposed_tree":value.5,"paths":serde_json::from_str::<Value>(&value.7).map_err(|e|e.to_string())?,"conflict_paths":serde_json::from_str::<Value>(&value.6).map_err(|e|e.to_string())?,"generation":value.8,"state":value.9,"files_changed":false,"next_action":{"op":"resolution_open","arguments":{"workspace":owner,"candidate":id}}}),
    )
}
pub(super) fn for_operation(db: &Connection, operation: &str) -> R<Option<Value>> {
    let row: Option<(String, String)> = sql(db
        .query_row(
            "SELECT id,workspace FROM workspace_conflicts WHERE operation_id=?1",
            [operation],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    row.map(|(id, w)| describe(db, &id, &w)).transpose()
}
fn validate_new_path(state: &Path, db: &Connection, requested: &Path) -> R<PathBuf> {
    if !requested.is_absolute() || requested.file_name().is_none() {
        return Err("invalid_root".into());
    }
    let parent = io(requested.parent().ok_or("invalid_root")?.canonicalize())?;
    let path = parent.join(requested.file_name().unwrap());
    let state = io(state.canonicalize())?;
    if path.starts_with(&state) || state.starts_with(&path) {
        return Err("path_collision: review overlaps state".into());
    }
    if let Ok(m) = fs::symlink_metadata(&path) {
        if !m.is_dir() || m.file_type().is_symlink() || io(fs::read_dir(&path))?.next().is_some() {
            return Err("path_collision: review must be empty".into());
        }
    }
    let mut q = sql(
        db.prepare("SELECT path FROM workspaces UNION ALL SELECT path FROM resolution_sessions")
    )?;
    for p in sql(q.query_map([], |r| r.get::<_, String>(0)))? {
        let p = PathBuf::from(sql(p)?);
        if path.starts_with(&p) || p.starts_with(&path) {
            return Err("path_collision: review overlaps another workspace".into());
        }
    }
    Ok(path)
}
pub(super) fn open(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let owner = field(r, "workspace")?;
    lifecycle::ensure_open(db, owner)?;
    ensure_writer_idle(db, owner)?;
    let id = field(r, "candidate")?;
    let wid = field(r, "resolution_workspace")?;
    ident(wid)?;
    let operation = field(r, "operation_id")?;
    let opening: Option<(String, Option<String>)> = sql(db
        .query_row(
            "SELECT path,response FROM conflict_openings WHERE operation_id=?1",
            [operation],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    if let Some((_, Some(response))) = &opening {
        return serde_json::from_str(response).map_err(|e| e.to_string());
    }
    let conflict = describe(db, id, owner)?;
    if conflict["state"] != "open" {
        return Err("conflict_already_resolved".into());
    }
    let w = ws(db, owner)?;
    if conflict["generation"] != w.generation
        || local(state, owner).capture(&w.path)?
            != local(state, owner).tree(field(&conflict["sides"], "local")?)?
    {
        return Err("stale_conflict: original workspace changed; preserve both versions and request a fresh Merge".into());
    }
    let exists: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspaces WHERE id=?1)",
        [wid],
        |r| r.get(0),
    ))?;
    if exists {
        return Err("workspace_exists".into());
    }
    let path = if let Some((path, _)) = &opening {
        PathBuf::from(path)
    } else {
        let path = validate_new_path(state, db, Path::new(field(r, "path")?))?;
        sql(db.execute(
            "INSERT INTO conflict_openings VALUES(?1,?2,NULL)",
            params![operation, path.to_string_lossy()],
        ))?;
        path
    };
    fault("conflict_review_after_intent");
    let target = field(&conflict["sides"], "shared")?;
    let git = Git::init(&state.join("locals").join(wid).join("objects.git"))?;
    let source = local(state, owner);
    let pin = source.head(&format!("refs/wipstash/conflicts/{id}"))?;
    transfer(
        &source,
        &git,
        &pin,
        &format!("refs/wipstash/conflicts/{id}"),
    )?;
    transfer(&source, &git, target, HEAD)?;
    let root = state.join("reviews").join(field(r, "operation_id")?);
    io(fs::create_dir_all(&root))?;
    let mut sides = serde_json::Map::new();
    for label in ["base", "local", "shared"] {
        let side = root.join(label);
        materialize_once(&git, field(&conflict["sides"], label)?, &side)?;
        sides.insert(label.into(), json!(side));
    }
    materialize_once(&git, field(&conflict, "proposed_tree")?, &path)?;
    fault("conflict_review_after_materialize");
    let initial = git.commit(
        field(&conflict, "proposed_tree")?,
        &[target.to_owned()],
        "prepared workspace conflict review",
    )?;
    git.set_ref(&format!("refs/wipstash/reviews/{wid}"), &initial, None)?;
    let response = json!({"ok":true,"state":"open","workspace":wid,"resolution_workspace":wid,"path":path,"generation":0,"resolution_head":target,"current_head":target,"candidate":id,"conflict":conflict,"conflict_paths":conflict["conflict_paths"],"side_paths":sides,"result_path":path,"files_changed_in_original_workspace":false,"completion":if conflict["origin"]=="merge"{"resolve_merge"}else{"commit"}});
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    let inserted = (|| {
        sql(db.execute(
            "INSERT INTO workspaces(id,path,base,checkpoint) VALUES(?1,?2,?3,?4)",
            params![wid, path.to_string_lossy(), target, initial],
        ))?;
        sql(db.execute(
            "INSERT INTO conflict_reviews VALUES(?1,?2,?3,'open',NULL)",
            params![wid, id, owner],
        ))?;
        sql(db.execute(
            "UPDATE conflict_openings SET response=?2 WHERE operation_id=?1",
            params![operation, response.to_string()],
        ))?;
        event(
            db,
            "conflict_review_opened",
            &json!({"workspace":wid,"owner":owner,"candidate":id}),
        )?;
        Ok(())
    })();
    match inserted {
        Ok(()) => sql(db.execute_batch("COMMIT"))?,
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    fault("conflict_review_after_register");
    Ok(response)
}
fn materialize_once(git: &Git, tree: &str, path: &Path) -> R<()> {
    if path.exists() {
        if git.capture(path)? == git.tree(tree)? {
            return Ok(());
        }
        if io(fs::read_dir(path))?.next().is_some() {
            return Err(format!("review_recovery_required: preserve partial or edited review at {} and inspect before opening a fresh review",path.display()));
        }
    } else {
        io(fs::create_dir_all(path))?;
    }
    git.materialize(tree, path)
}

pub(super) fn preflight(state: &Path, db: &Connection, r: &Value) -> R<()> {
    let wid = field(r, "workspace")?;
    let review: Option<(String, String, String)> = sql(db
        .query_row(
            "SELECT conflict,owner,state FROM conflict_reviews WHERE workspace=?1",
            [wid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional())?;
    if let Some((id, owner, phase)) = review {
        if phase == "completed" {
            return Ok(());
        }
        if phase == "submitted" {
            let done:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM conflict_reviews c JOIN proposals p ON p.id=c.submitted_commit WHERE c.workspace=?1 AND p.state IN ('integrated','already_included'))",[wid],|r|r.get(0)))?;
            if done {
                sql(db.execute(
                    "UPDATE conflict_reviews SET state='completed' WHERE workspace=?1",
                    [wid],
                ))?;
                return Ok(());
            }
            return Err("resolution_pending: inspect the submitted resolution commit".into());
        }
        let conflict = describe(db, &id, &owner)?;
        if conflict["origin"] == "merge" {
            return Err("merge_resolution_requires_acceptance: use resolve_merge on the original workspace with resolution_workspace before sharing".into());
        }
        if r["expected_head"] != conflict["sides"]["shared"] {
            return Err(
                "stale_resolution: expected_head must match this review's resolution_head".into(),
            );
        }
        attest(r, &conflict["conflict_paths"])?;
        markers(&local(state, wid), &ws(db, wid)?.path, &conflict)?;
    }
    Ok(())
}
pub(super) fn attest(r: &Value, paths: &Value) -> R<()> {
    let expected: Vec<String> = serde_json::from_value(paths.clone()).map_err(|e| e.to_string())?;
    let supplied: Vec<String> = serde_json::from_value(r["resolved_conflicts"].clone())
        .map_err(|_| "resolution_attestation_required")?;
    let a: std::collections::BTreeSet<_> = expected.iter().collect();
    let b: std::collections::BTreeSet<_> = supplied.iter().collect();
    if a != b || supplied.len() != b.len() {
        return Err("resolution_attestation_required: review every returned conflict path".into());
    }
    Ok(())
}
pub(super) fn markers(git: &Git, root: &Path, conflict: &Value) -> R<()> {
    let tree = git.capture(root)?;
    let paths: Vec<String> =
        serde_json::from_value(conflict["conflict_paths"].clone()).map_err(|e| e.to_string())?;
    for path in paths {
        let initial = resolution::public_file(git, field(conflict, "proposed_tree")?, &path)?
            .unwrap_or_default();
        let resolved = resolution::public_file(git, &tree, &path)?.unwrap_or_default();
        if initial.contains(&0) || resolved.contains(&0) {
            continue;
        }
        for line in initial.split_inclusive(|b| *b == b'\n') {
            if !(line.starts_with(b"<<<<<<< ") || line.starts_with(b">>>>>>> "))
                || !resolved.windows(line.len()).any(|w| w == line)
            {
                continue;
            }
            let mut existing = false;
            for side in ["base", "local", "shared"] {
                let bytes = resolution::public_file(git, field(&conflict["sides"], side)?, &path)?
                    .unwrap_or_default();
                if bytes.windows(line.len()).any(|w| w == line) {
                    existing = true;
                }
            }
            if !existing {
                return Err("unresolved_conflict_markers: prepared result still contains generated conflict markers".into());
            }
        }
    }
    if git.capture(root)? != tree {
        return Err("snapshot_unstable".into());
    }
    Ok(())
}
pub(super) fn submitted(db: &Connection, wid: &str, commit: &str) -> R<()> {
    sql(db.execute("UPDATE conflict_reviews SET state='submitted',submitted_commit=?2 WHERE workspace=?1 AND state='open'",params![wid,commit]))?;
    Ok(())
}
pub(super) fn review_tree(
    state: &Path,
    db: &Connection,
    r: &Value,
) -> R<Option<(String, PathBuf)>> {
    let Some(wid) = r["resolution_workspace"].as_str() else {
        return Ok(None);
    };
    let owner = field(r, "workspace")?;
    let candidate = field(r, "candidate")?;
    let matches:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM conflict_reviews WHERE workspace=?1 AND owner=?2 AND conflict=?3 AND state='open')",params![wid,owner,candidate],|r|r.get(0)))?;
    if !matches {
        return Err("resolution_owner_mismatch".into());
    }
    let c = describe(db, candidate, owner)?;
    if r["target"] != c["sides"]["shared"] {
        return Err("stale_resolution".into());
    }
    attest(r, &c["conflict_paths"])?;
    let original = ws(db, owner)?;
    let source = local(state, owner);
    if source.capture(&original.path)? != source.tree(field(&c["sides"], "local")?)? {
        return Err("stale_conflict: original files changed after review opened".into());
    }
    lifecycle::ensure_open(db, wid)?;
    ensure_writer_idle(db, wid)?;
    let review = ws(db, wid)?;
    let before = local(state, wid).capture(&review.path)?;
    markers(&local(state, wid), &review.path, &c)?;
    let tree = local(state, wid).capture(&review.path)?;
    if tree != before {
        return Err("snapshot_unstable".into());
    }
    let commit = local(state, wid).commit(
        &tree,
        &[field(&c["sides"], "shared")?.to_owned()],
        "reviewed private Merge result",
    )?;
    transfer(
        &local(state, wid),
        &source,
        &commit,
        &format!("refs/wipstash/reviews/{}", field(r, "operation_id")?),
    )?;
    Ok(Some((tree, review.path)))
}
pub(super) fn complete(db: &Connection, id: &str) -> R<()> {
    sql(db.execute(
        "UPDATE workspace_conflicts SET state='resolved' WHERE id=?1",
        [id],
    ))?;
    sql(db.execute(
        "UPDATE conflict_reviews SET state='completed' WHERE conflict=?1",
        [id],
    ))?;
    Ok(())
}

pub(super) fn apply(
    state: &Path,
    db: &Connection,
    r: &Value,
    w: &Workspace,
    git: &Git,
    tree: &str,
) -> R<Value> {
    let id = field(r, "operation_id")?;
    let wid = field(r, "workspace")?;
    let target = field(r, "target")?;
    let old = git.capture(&w.path)?;
    let local = git.commit(
        &old,
        &[w.checkpoint.clone().unwrap_or(w.base.clone())],
        "before reviewed Merge",
    )?;
    let commit = git.commit(tree, &[local, target.into()], "accepted prepared Merge")?;
    git.set_ref(&format!("refs/wipstash/adoptions/{id}"), &commit, None)?;
    let root = state.join("transactions").join(id);
    io(fs::create_dir_all(&root))?;
    let oldstage = root.join("old");
    let stage = root.join("new");
    let backup = root.join("backup");
    io(fs::create_dir(&oldstage))?;
    io(fs::create_dir(&stage))?;
    git.materialize(&old, &oldstage)?;
    git.materialize(tree, &stage)?;
    let oldfiles = adoption::files(&oldstage)?;
    let newfiles = adoption::files(&stage)?;
    sql(db.execute(
        "INSERT INTO adoptions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'applying',?11)",
        params![
            id,
            wid,
            w.base,
            target,
            commit,
            tree,
            serde_json::to_string(&oldfiles).unwrap(),
            serde_json::to_string(&newfiles).unwrap(),
            stage.to_string_lossy(),
            backup.to_string_lossy(),
            w.generation
        ],
    ))?;
    fault("review_after_intent");
    if let Err(e) =
        adoption::apply_captured(&w.path, &oldstage, &stage, &backup, &oldfiles, &newfiles)
    {
        adoption::rollback(&w.path, &backup, &oldfiles, &newfiles)
            .map_err(|e| format!("recovery_required: {e}"))?;
        sql(db.execute("UPDATE adoptions SET state='rolled_back' WHERE id=?1", [id]))?;
        return Err(e);
    }
    sql(db.execute("UPDATE adoptions SET state='applied' WHERE id=?1", [id]))?;
    fault("review_after_apply");
    finalize_adoption(db, id)
}

pub(super) fn reconcile_completed(db: &Connection) -> R<()> {
    sql(db.execute_batch("UPDATE workspace_conflicts SET state='resolved' WHERE id IN (SELECT c.conflict FROM conflict_reviews c JOIN proposals p ON p.id=c.submitted_commit LEFT JOIN sync_remote_status s ON s.proposal=p.id WHERE c.state='submitted' AND COALESCE(json_extract(s.receipt,'$.state'),p.state) IN ('integrated','already_included'));
UPDATE conflict_reviews SET state='completed' WHERE conflict IN (SELECT id FROM workspace_conflicts WHERE state='resolved');
UPDATE resolution_sessions SET state='completed' WHERE state='submitted' AND EXISTS(SELECT 1 FROM proposals p JOIN checkpoints c ON c.id=p.checkpoint LEFT JOIN sync_remote_status s ON s.proposal=p.id WHERE c.workspace=resolution_sessions.workspace AND COALESCE(json_extract(s.receipt,'$.state'),p.state) IN ('integrated','already_included'));"))?;
    Ok(())
}
