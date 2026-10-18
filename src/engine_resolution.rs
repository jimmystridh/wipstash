//! Deliberate agent handback. All inputs are public proposal/history objects;
//! private workspaces are never adopted, reset, or exported by this workflow.
use super::*;
const MAX_ATTEMPTS: i64 = 3;

pub(super) fn schema(db: &Connection) -> R<()> {
    sql(db.execute_batch("CREATE TABLE IF NOT EXISTS proposal_resolutions(proposal TEXT PRIMARY KEY,parent TEXT NOT NULL,root TEXT NOT NULL,attempt INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS resolution_sessions(id TEXT PRIMARY KEY,proposal TEXT NOT NULL,owner TEXT NOT NULL,workspace TEXT UNIQUE NOT NULL,path TEXT UNIQUE NOT NULL,head TEXT NOT NULL,tree TEXT NOT NULL,conflicts TEXT NOT NULL,state TEXT NOT NULL);"))
}
pub(super) fn lineage(db: &Connection, proposal: &str) -> R<Value> {
    let row: Option<(String,String,i64)> = sql(db.query_row("SELECT parent,root,attempt FROM proposal_resolutions WHERE proposal=?1", [proposal], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())?;
    Ok(match row { Some((parent,root,attempt)) => json!({"parent":parent,"root":root,"attempt":attempt}), None => json!({"parent":null,"root":proposal,"attempt":0}) })
}
pub(super) fn task(db: &Connection, proposal: &str) -> R<Option<Value>> {
    let (wid,base,commit,phase,details):(String,String,String,String,Option<String>) = sql(db.query_row("SELECT workspace,base,commit_oid,state,details FROM proposals WHERE id=?1",[proposal],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))))?;
    if phase == "superseded" || phase == "cancelled" { return Ok(None); }
    if let Some(remote) = sync::observed_status(db,proposal)? {
        return Ok(remote.get("resolution_task").filter(|v| !v.is_null()).cloned().map(|mut t| { t["proposal"] = json!(proposal); t["workspace"] = json!(wid); t }));
    }
    if phase != "quarantined" { return Ok(None); }
    let details: Value = details.and_then(|s|serde_json::from_str(&s).ok()).unwrap_or(json!({}));
    let lineage = lineage(db,proposal)?;
    let attempt = lineage["attempt"].as_i64().unwrap_or(0);
    Ok(Some(json!({"proposal":proposal,"workspace":wid,"state":if attempt >= MAX_ATTEMPTS {"escalated"} else {"action_required"},"reason":if details["evaluation_error"].is_string() {"policy_evaluation_failed"} else if details["conflicted"] == true && details["repaired"] != true {"merge_conflict"} else {"required_checks_failed"},"diagnosis":details["evaluation_error"],"base":base,"proposal_commit":commit,"current_head":details["head"],"input_tree":details["input_tree"],"candidate_tree":details["candidate_tree"],"sides":{"base":base,"current":details["head"],"proposal":commit},"checkout_basis":"Fresh merge of latest available public head and public proposal; previous repair output is evidence only","conflict_paths":details.get("conflict_paths").cloned().unwrap_or(json!([])),"checks":details.get("checks").cloned().unwrap_or(json!([])),"policy_sha256":details["policy_sha256"],"attempt":attempt,"max_attempts":MAX_ATTEMPTS,"lineage":lineage,"next_action":if attempt >= MAX_ATTEMPTS {"Review and publish a deliberately new proposal if further work is authorized."} else {"Use resolution_open for an isolated checkout, checkpoint the explicit fix, then resolution_submit. Original workspace is unchanged."},"semantic_correctness_claimed":false})))
}
pub(super) fn tasks(db: &Connection, r: &Value) -> R<Value> {
    let wid = field(r,"workspace")?;
    ws(db,wid)?;
    let mut s = sql(db.prepare("SELECT id FROM proposals WHERE workspace=?1 ORDER BY rowid"))?;
    let ids = sql(s.query_map([wid],|r|r.get::<_,String>(0)))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
    let mut tasks=Vec::new();
    for id in ids { if let Some(t) = task(db,&id)? { tasks.push(t); } }
    Ok(json!({"ok":true,"workspace":wid,"tasks":tasks}))
}
fn owned(db: &Connection, r: &Value) -> R<Value> {
    let proposal=field(r,"proposal")?;
    let wid=field(r,"workspace")?;
    ws(db,wid)?;
    let owner:String = sql(db.query_row("SELECT workspace FROM proposals WHERE id=?1",[proposal],|r|r.get(0)))?;
    if owner != wid || sync::proposal_origin(db,proposal)?.is_some() { return Err("resolution_owner_mismatch: only the submitting local workspace can resolve its proposal".into()); }
    let task=task(db,proposal)?.ok_or("resolution_not_required: proposal has no open resolution task")?;
    if task["state"] == "escalated" { return Err("resolution_attempts_exhausted: three submitted revisions failed; explicit escalation is required".into()); }
    Ok(task)
}

fn latest_public_head(state: &Path, db: &Connection, task: &Value) -> R<String> {
    let public=coordinator(state);
    let cached=public.head(HEAD)?;
    if !sync::is_client(db)? { return Ok(cached); }
    let observed=field(task,"current_head")?;
    if public.ancestor(&cached,observed)? { return Ok(observed.into()); }
    if public.ancestor(observed,&cached)? { return Ok(cached); }
    Err("inconsistent_authority_history: receipt and cached head diverge; synchronize authority history before resolving".into())
}
// Missing paths (deletions/renames) are distinct from corruption or Git failure.
fn public_file(git: &Git, tree: &str, path: &str) -> R<Option<Vec<u8>>> {
    let listing=git.run(&["ls-tree","-r","-z","--full-tree",tree],None)?;
    for item in listing.split(|b| *b==0).filter(|s| !s.is_empty()) {
        let tab=item.iter().position(|b|*b==b'\t').ok_or("invalid_public_tree")?;
        if &item[tab+1..] != path.as_bytes() { continue; }
        let header=std::str::from_utf8(&item[..tab]).map_err(|e|e.to_string())?;
        let fields:Vec<_>=header.split(' ').collect();
        if fields.len()!=3 || fields[1]!="blob" { return Err("invalid_public_tree".into()); }
        return git.run(&["cat-file","blob",fields[2]],None).map(Some);
    }
    Ok(None)
}

pub(super) fn open(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let task=owned(db,r)?;
    let id=field(r,"operation_id")?;
    let owner=field(r,"workspace")?;
    let proposal=field(r,"proposal")?;
    let wid=field(r,"resolution_workspace")?;
    ident(wid)?;
    if wid==owner { return Err("resolution_isolation_required".into()); }
    let existing:Option<(String,String,String,String,String)> = sql(db.query_row("SELECT path,head,tree,conflicts,state FROM resolution_sessions WHERE id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional())?;
    let (path,head,tree,conflicts,phase) = if let Some(saved)=existing { saved } else {
        let occupied:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM workspaces WHERE id=?1)",[wid],|r|r.get(0)))?;
        if occupied { return Err("workspace_exists".into()); }
        let requested=PathBuf::from(field(r,"path")?);
        if !requested.is_absolute() || requested.file_name().is_none() { return Err("invalid_root".into()); }
        let parent=io(requested.parent().ok_or("invalid_root")?.canonicalize())?;
        let path=parent.join(requested.file_name().unwrap());
        let state_abs=io(state.canonicalize())?;
        if path.starts_with(&state_abs) || state_abs.starts_with(&path) { return Err("invalid_root: workspace overlaps state".into()); }
        if let Ok(meta)=fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() || !meta.is_dir() || io(fs::read_dir(&path))?.next().is_some() { return Err("path_collision: resolution checkout must be empty".into()); }
        }
        let mut paths=sql(db.prepare("SELECT path FROM workspaces UNION ALL SELECT path FROM resolution_sessions"))?;
        for p in sql(paths.query_map([],|r|r.get::<_,String>(0)))? {
            let p=PathBuf::from(sql(p)?);
            if path.starts_with(&p) || p.starts_with(&path) { return Err("path_collision: resolution checkout overlaps another workspace".into()); }
        }
        let public=coordinator(state);
        let head=latest_public_head(state,db,&task)?;
        let git=Git::init(&state.join("locals").join(wid).join("objects.git"))?;
        transfer(&public,&git,&head,HEAD)?;
        let commit=field(&task,"proposal_commit")?;
        // A client's proposal may not be present in its public authority cache.
        let source=if sync::is_client(db)? {local(state,owner)} else {coordinator(state)};
        transfer(&source,&git,commit,&format!("refs/wipstash/proposals/{proposal}"))?;
        let merge=git.merge(&head,commit)?;
        let conflicts=serde_json::to_string(&merge.conflicts).map_err(|e|e.to_string())?;
        // Pin the initial tree durably, without making private ancestry public.
        let initial=git.commit(&merge.tree,std::slice::from_ref(&head),&format!("resolution checkout {id}"))?;
        git.set_ref(&format!("refs/wipstash/resolutions/{id}"),&initial,None)?;
        sql(db.execute("INSERT INTO resolution_sessions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'preparing')",params![id,proposal,owner,wid,path.to_string_lossy(),head,merge.tree,conflicts]))?;
        fault("resolution_open_after_intent");
        (path.to_string_lossy().into_owned(),head,merge.tree,conflicts,"preparing".into())
    };
    let root=PathBuf::from(&path);
    let git=local(state,wid);
    if phase == "preparing" {
        // A crash after rename is recognizable without overwriting later user edits.
        let installed=if root.exists() && io(fs::read_dir(&root))?.next().is_some() {
            if git.capture(&root)? != tree { return Err("resolution_recovery_required: checkout changed after interrupted creation; preserve it and use a new checkout".into()); }
            true
        } else {false};
        if !installed {
            // create_new file writes inside materialize never replace a destination
            // appearing after preflight. A partial crash is preserved for inspection.
            if !root.exists() { io(fs::create_dir(&root))?; }
            git.materialize(&tree,&root)?;
        }
        fault("resolution_open_after_materialize");
        // Public side snapshots give model-agnostic tools byte-exact base/ours/theirs
        // inputs, including binary conflicts, without exposing private checkpoints.
        let inputs=state.join("resolution-inputs").join(id);
        let mut side_paths=serde_json::Map::new();
        for (label,oid) in [("base",field(&task,"base")?), ("current",head.as_str()), ("proposal",field(&task,"proposal_commit")?)] {
            let side=inputs.join(label);
            if !side.exists() { io(fs::create_dir_all(&side))?; git.materialize(oid,&side)?; }
            else if git.capture(&side)? != git.tree(oid)? { return Err("resolution_recovery_required: public input snapshot changed".into()); }
            side_paths.insert(label.into(),json!(side));
        }
        let initial=git.head(&format!("refs/wipstash/resolutions/{id}"))?;
        sql(db.execute_batch("BEGIN IMMEDIATE"))?;
        sql(db.execute("INSERT INTO workspaces(id,path,base,checkpoint) VALUES(?1,?2,?3,?4)",params![wid,path,head,initial]))?;
        sql(db.execute("UPDATE resolution_sessions SET state='open' WHERE id=?1",[id]))?;
        let result=json!({"ok":true,"state":"open","resolution_workspace":wid,"path":path,"generation":0,"current_head":head,"conflict_paths":serde_json::from_str::<Value>(&conflicts).map_err(|e|e.to_string())?,"task":task,"side_paths":side_paths,"sides":{"base":task["base"],"current":head,"proposal":task["proposal_commit"]},"cached":sync::is_client(db)?,"files_changed_in_original_workspace":false});
        finish(db,id,&result)?;
        event(db,"resolution_opened",&json!({"proposal":proposal,"resolution_workspace":wid,"head":head}))?;
        sql(db.execute_batch("COMMIT"))?;
        return Ok(result);
    }
    Err("resolution_session_not_openable".into())
}

pub(super) fn submit(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let task=owned(db,r)?;
    let owner=field(r,"workspace")?;
    let proposal=field(r,"proposal")?;
    let wid=field(r,"resolution_workspace")?;
    let cp=field(r,"checkpoint")?;
    let id=field(r,"operation_id")?;
    ensure_writer_idle(db,wid)?;
    let w=ws(db,wid)?;
    let (session,original,session_owner,head,conflicts,phase):(String,String,String,String,String,String)=sql(db.query_row("SELECT id,proposal,owner,head,conflicts,state FROM resolution_sessions WHERE workspace=?1",[wid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))))?;
    if original!=proposal || session_owner!=owner || phase!="open" { return Err("resolution_owner_mismatch: checkout does not belong to this open task".into()); }
    if field(r,"expected_head")? != head || w.base != head || latest_public_head(state,db,&task)? != head { return Err("stale_resolution: authority tip advanced; open a fresh isolated checkout and use new operation IDs".into()); }
    let expected:Vec<String>=serde_json::from_str(&conflicts).map_err(|e|e.to_string())?;
    let resolved:Vec<String>=serde_json::from_value(r.get("resolved_conflicts").cloned().unwrap_or(json!([]))).map_err(|_|"invalid_request: resolved_conflicts must be a string array")?;
    let expected_set:std::collections::BTreeSet<_>=expected.iter().collect();
    let resolved_set:std::collections::BTreeSet<_>=resolved.iter().collect();
    if expected_set!=resolved_set || resolved.len()!=resolved_set.len() { return Err("resolution_attestation_required: resolved_conflicts must name exactly the checkout conflict paths".into()); }
    let (tree,cp_commit,base):(String,String,String)=sql(db.query_row("SELECT tree,commit_oid,base FROM checkpoints WHERE id=?1 AND workspace=?2",params![cp,wid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))))?;
    let git=local(state,wid);
    if base!=head || w.checkpoint.as_deref()!=Some(cp_commit.as_str()) || git.capture(&w.path)? != tree || git.capture(&w.path)? != tree { return Err("stale_resolution_checkpoint: checkpoint must match the live isolated checkout".into()); }
    // Reject exact Git-generated marker lines that were absent from all input
    // sides. Ordinary marker-like source text is allowed; binary decisions rely
    // on the explicit conflict-path attestation and current policy checks.
    let input_tree:String=sql(db.query_row("SELECT tree FROM resolution_sessions WHERE id=?1",[&session],|r|r.get(0)))?;
    for path in &expected {
        let initial=public_file(&git,&input_tree,path)?.unwrap_or_default();
        let resolved=public_file(&git,&tree,path)?.unwrap_or_default();
        for line in initial.split_inclusive(|b| *b==b'\n') {
            if !(line.starts_with(b"<<<<<<< ") || line.starts_with(b">>>>>>> ")) { continue; }
            if !resolved.windows(line.len()).any(|w|w==line) { continue; }
            let mut preexisting=false;
            for side in [field(&task,"base")?,head.as_str(),field(&task,"proposal_commit")?] {
                let bytes=public_file(&git,side,path)?.unwrap_or_default();
                if bytes.windows(line.len()).any(|w|w==line) { preexisting=true; }
            }
            if !preexisting { return Err("unresolved_conflict_markers: checkout still contains generated merge markers".into()); }
        }
    }
    let attempt=task["attempt"].as_i64().ok_or("invalid_resolution_task")?+1;
    if attempt>MAX_ATTEMPTS { return Err("resolution_attempts_exhausted".into()); }
    let root=task["lineage"]["root"].as_str().unwrap_or(proposal);
    let intent:String=sql(db.query_row("SELECT intent FROM proposals WHERE id=?1",[proposal],|r|r.get(0)))?;
    let commit=git.commit(&tree,std::slice::from_ref(&head),&format!("proposal {id}"))?;
    // Store the sanitized export on the ORIGINAL owner, so routing and ownership
    // survive client sync. Never transfer checkpoint ancestry.
    let owner_git=local(state,owner);
    transfer(&git,&owner_git,&commit,&format!("refs/wipstash/exports/{id}"))?;
    let online=!sync::is_client(db)?;
    if online { transfer(&owner_git,&coordinator(state),&commit,&format!("refs/wipstash/proposals/{id}"))?; }
    fault("resolution_submit_after_pin");
    let phase=if online {"coordinator_accepted"} else {"local_queued"};
    let result=json!({"ok":true,"proposal":id,"resolution_of":proposal,"state":if online {"coordinator_accepted"} else {"queued_offline"},"commit":commit,"base":head,"attempt":attempt,"checks_pending":true,"remote_contact_unverified":!online});
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    sql(db.execute("INSERT INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,owner,cp,commit,head,intent,phase]))?;
    sql(db.execute("INSERT INTO proposal_resolutions VALUES(?1,?2,?3,?4)",params![id,proposal,root,attempt]))?;
    sql(db.execute("UPDATE proposals SET state='superseded' WHERE id=?1",[proposal]))?;
    sql(db.execute("UPDATE resolution_sessions SET state='submitted' WHERE id=?1",[session]))?;
    finish(db,id,&result)?;
    event(db,"superseded",&json!({"proposal":proposal}))?;
    event(db,"resolution_submitted",&json!({"proposal":id,"resolution_of":proposal,"attempt":attempt}))?;
    sql(db.execute_batch("COMMIT"))?;
    fault("resolution_submit_after_commit");
    Ok(result)
}
