use super::*;

pub(super) fn changes(git: &Git, before: &str, after: &str) -> R<Vec<Value>> {
    let raw = git.run(
        &[
            "diff-tree",
            "-r",
            "--no-commit-id",
            "--name-status",
            "-z",
            "-M",
            before,
            after,
            "--",
        ],
        None,
    )?;
    let mut fields = raw.split(|b| *b == 0).filter(|s| !s.is_empty());
    let mut result = Vec::new();
    while let Some(status) = fields.next() {
        let status = std::str::from_utf8(status).map_err(|e| e.to_string())?;
        let path =
            std::str::from_utf8(fields.next().ok_or("invalid_diff")?).map_err(|e| e.to_string())?;
        crate::git::allowed_path(path)?;
        let mut change = json!({"path":path,"kind":match status.as_bytes().first(){Some(b'A')=>"added",Some(b'D')=>"deleted",Some(b'R')=>"renamed",Some(b'T')=>"type_changed",_=>"edited"}});
        if status.starts_with('R') || status.starts_with('C') {
            let next = std::str::from_utf8(fields.next().ok_or("invalid_diff")?)
                .map_err(|e| e.to_string())?;
            crate::git::allowed_path(next)?;
            change["old_path"] = json!(path);
            change["path"] = json!(next);
        }
        result.push(change);
    }
    Ok(result)
}
fn tree_files(git: &Git, tree: &str) -> R<Vec<String>> {
    git.run(&["ls-tree", "-r", "--name-only", "-z", tree], None)?
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8(p.to_vec()).map_err(|e| e.to_string()))
        .collect()
}
fn generated(path: &str) -> bool {
    path.ends_with(".pyc")
        || path.ends_with(".pyo")
        || path.split('/').any(|part| {
            matches!(
                part,
                "__pycache__"
                    | "node_modules"
                    | ".pytest_cache"
                    | ".mypy_cache"
                    | ".DS_Store"
                    | ".venv"
                    | "coverage"
            )
        })
}
pub(super) fn hygiene(git: &Git, tree: &str, root: &Path) -> R<Value> {
    let captured: std::collections::BTreeSet<_> = tree_files(git, tree)?.into_iter().collect();
    let mut found = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_owned()];
    let mut scanned = 0;
    while let Some(directory) = stack.pop() {
        for item in io(fs::read_dir(directory))? {
            let item = io(item)?;
            scanned += 1;
            if scanned > 10_000 {
                break;
            }
            let path = item.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let kind = io(item.file_type())?;
            if kind.is_symlink() {
                continue;
            }
            if generated(&relative) {
                found.insert(relative.clone());
            }
            let name = item.file_name();
            let name = name.to_string_lossy();
            if kind.is_dir()
                && !matches!(
                    name.as_ref(),
                    ".git"
                        | ".agent"
                        | ".agents"
                        | ".codex"
                        | ".claude"
                        | ".ssh"
                        | ".aws"
                        | "credentials"
                        | "node_modules"
                        | ".venv"
                        | "target"
                        | "build"
                )
            {
                stack.push(path);
            }
        }
        if scanned > 10_000 {
            break;
        }
    }
    found.extend(captured.iter().filter(|p| generated(p)).cloned());
    let included: Vec<_> = found
        .iter()
        .filter(|p| captured.contains(*p))
        .take(100)
        .collect();
    let excluded: Vec<_> = found
        .iter()
        .filter(|p| !captured.contains(*p))
        .take(100)
        .collect();
    Ok(
        json!({"generated_files":found.iter().take(100).collect::<Vec<_>>(),"generated_files_total":found.len(),
        "included_in_save":included,"excluded_from_save":excluded,"truncated":found.len()>100 || scanned>10_000,
        "files_changed":false,"advisory":true}),
    )
}
pub(super) fn workspace_state(state: &Path, db: &Connection, wid: &str) -> R<Value> {
    let w = ws(db, wid)?;
    let git = local(state, wid);
    let lifecycle: String = sql(db.query_row(
        "SELECT COALESCE((SELECT state FROM workspace_lifecycle WHERE workspace=?1),'open')",
        [wid],
        |r| r.get(0),
    ))?;
    if ensure_writer_idle(db, wid).is_err() {
        return Ok(
            json!({"has_unshared_changes":null,"changes_since_save":null,"workspace_state":lifecycle,"inspection_available":false}),
        );
    }
    let live = git.capture(&w.path)?;
    let saved = git.tree(w.checkpoint.as_deref().unwrap_or(&w.base))?;
    let baseline = shared_commit::shared_baseline(db, wid, &w.base, w.generation + 1)?
        .map(|v| v.0)
        .unwrap_or(git.tree(&w.base)?);
    let pending:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM proposals p JOIN checkpoints c ON c.id=p.checkpoint WHERE c.workspace=?1 AND p.state!='superseded' AND COALESCE((SELECT json_extract(s.receipt,'$.state') FROM sync_remote_status s WHERE s.proposal=p.id),p.state) IN ('local_queued','coordinator_accepted','quarantined'))",[wid],|r|r.get(0)))?;
    let latest = coordinator(state).head(HEAD).ok();
    if let Some(head) = &latest {
        transfer(&coordinator(state), &git, head, "refs/wipstash/status-head")?;
    }
    let cache_behind = shared_commit::shared_baseline(db, wid, &w.base, w.generation + 1)?
        .is_some_and(|(_, shared)| {
            latest
                .as_ref()
                .is_some_and(|head| !git.ancestor(&shared, head).unwrap_or(false))
        });
    let incoming = if cache_behind {
        None
    } else {
        latest
            .as_ref()
            .map(|head| git.tree(head).map(|t| t != baseline))
            .transpose()?
    };
    let resolution: Option<String> = sql(db.query_row(
        "SELECT CASE WHEN s.state='submitted' AND EXISTS(SELECT 1 FROM proposals p JOIN checkpoints c ON c.id=p.checkpoint WHERE c.workspace=s.workspace AND p.state IN ('integrated','already_included')) THEN 'completed' ELSE s.state END FROM resolution_sessions s WHERE s.workspace=?1",
        [wid], |r|r.get(0)).optional())?;
    let review: Option<String> = sql(db.query_row(
        "SELECT CASE WHEN c.state='submitted' AND p.state IN ('integrated','already_included') THEN 'completed' ELSE c.state END FROM conflict_reviews c LEFT JOIN proposals p ON p.id=c.submitted_commit WHERE c.workspace=?1",
        [wid], |r|r.get(0)).optional())?;
    let local_changes = changes(&git, &baseline, &live)?;
    Ok(
        json!({"has_unshared_changes":live!=baseline || pending,"changes_since_save":live!=saved,"shared_changes_available":incoming,"head_cache_behind_receipt":cache_behind,"local_changes":local_changes.iter().take(200).collect::<Vec<_>>(),"local_changes_total":local_changes.len(),"local_changes_truncated":local_changes.len()>200,"workspace_state":lifecycle,"workspace_mode":if resolution.as_deref()==Some("open"){"commit_resolution"}else if review.as_deref()==Some("open"){"conflict_review"}else if resolution.as_deref()==Some("submitted") || review.as_deref()==Some("submitted"){"resolution_pending"}else{"ordinary"},"hygiene":hygiene(&git,&live,&w.path)?,"inspection_available":true}),
    )
}
pub(super) fn incoming(
    state: &Path,
    db: &Connection,
    wid: &str,
    cursor: u64,
    limit: u64,
) -> R<Value> {
    if !(1..=32).contains(&limit) || cursor > i64::MAX as u64 {
        return Err("invalid_page".into());
    }
    let w = ws(db, wid)?;
    let git = local(state, wid);
    let target = git.head(HEAD)?;
    let comparison = shared_commit::shared_baseline(db, wid, &w.base, w.generation + 1)?
        .map(|v| v.0)
        .unwrap_or(git.tree(&w.base)?);
    if shared_commit::shared_baseline(db, wid, &w.base, w.generation + 1)?
        .is_some_and(|(_, head)| !git.ancestor(&head, &target).unwrap_or(false))
    {
        return Ok(
            json!({"base":w.base,"target":target,"changes":[],"commits":[],"shared_changes_available":null,"head_cache_behind_receipt":true,"inspection_available":false,"reason":"Cached shared history precedes an acknowledged Commit; wait for transport catch-up.","files_changed":false}),
        );
    }
    let all = changes(&git, &comparison, &target)?;
    let revision_range = format!("^{}", w.base);
    let missing: std::collections::HashSet<String> =
        String::from_utf8(git.run(&["rev-list", &target, &revision_range], None)?)
            .map_err(|e| e.to_string())?
            .lines()
            .map(str::to_owned)
            .collect();
    let mut statement=sql(db.prepare("SELECT id,workspace,intent,head FROM proposals WHERE head IS NOT NULL AND state IN ('integrated','already_included') ORDER BY rowid"))?;
    let rows = sql(statement.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    }))?;
    let mut commits = Vec::new();
    for row in rows {
        let (id, owner, message, head) = sql(row)?;
        if owner != wid && head != w.base && missing.contains(&head) {
            commits.push(json!({"commit_id":id,"workspace":owner,"message":message,"head":head,"validation":proposal_status(db,&id)?["validation"]}));
        }
    }
    if sync::is_client(db)? {
        let cache: Option<String> = sql(db
            .query_row("SELECT data FROM coordination_cache WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional())?;
        if let Some(cache) = cache {
            let cache: Value = serde_json::from_str(&cache).map_err(|e| e.to_string())?;
            for summary in cache["commits"].as_array().into_iter().flatten() {
                let Some(head) = summary["head"]
                    .as_str()
                    .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                else {
                    continue;
                };
                let source_id = if summary["origin"]["device"] == coordination::device(db)? {
                    summary["origin"]["source_proposal"].as_str()
                } else {
                    summary["commit_id"].as_str()
                };
                let own: bool = sql(db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM proposals WHERE id=?1 AND workspace=?2)",
                    params![source_id, wid],
                    |r| r.get(0),
                ))?;
                if !own
                    && head != w.base
                    && missing.contains(head)
                    && !commits
                        .iter()
                        .any(|c| c["commit_id"] == summary["commit_id"])
                {
                    let mut summary = summary.clone();
                    summary["from_authority_cache"] = json!(true);
                    summary["server_time"] = cache["server_time"].clone();
                    commits.push(summary);
                }
            }
        }
    }
    let start = (cursor as usize).min(commits.len());
    let end = (start + limit as usize).min(commits.len());
    Ok(
        json!({"base":w.base,"target":target,"changes":all.iter().take(200).collect::<Vec<_>>(),"changes_total":all.len(),"changes_truncated":all.len()>200,"commits":&commits[start..end],"commits_total":commits.len(),"next_cursor":end,"has_more":end<commits.len(),"shared_changes_available":!all.is_empty(),"files_changed":false,"authority_contact_verified":!sync::is_client(db)?}),
    )
}
pub(super) fn outcome(db: &Connection, r: &Value, v: &mut Value) {
    if r["op"] != "commit" {
        return;
    }
    let Some(wid) = r["workspace"].as_str() else {
        return;
    };
    let Ok(w) = ws(db, wid) else { return };
    let saved = shared_commit::saved_snapshot(db, r).ok().flatten();
    let submission: Option<(String, String)> = db
        .query_row(
            "SELECT id,state FROM proposals WHERE id=?1",
            [r["operation_id"].as_str().unwrap_or("")],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()
        .flatten();
    let preserved = saved.as_ref().is_some_and(|s| s["ok"] == true);
    v["saved_locally"] = json!(preserved);
    if let Some(saved) = &saved {
        v["hygiene"] = saved["hygiene"].clone();
    }
    v["submitted"] = json!(submission.is_some());
    v["shared"] = json!(submission
        .as_ref()
        .is_some_and(|(_, s)| matches!(s.as_str(), "integrated" | "already_included")));
    v["generation"] = json!(w.generation);
    v["generation_before"] = r["expected_generation"].clone();
    v["generation_after"] = json!(w.generation);
    v["generation_reason"] = json!(if preserved {
        "Commit preserved the requested files before sharing was attempted"
    } else {
        "No new files were saved by this request"
    });
    v["files_changed"] = json!(false);
    v["stage"] = json!(if v["shared"] == true {
        "shared"
    } else if submission.is_some() {
        "submitted"
    } else if preserved {
        "preparing_shared_change"
    } else {
        "preflight"
    });
    v["outcome_certain"] = json!(true);
}
pub(super) fn templates() -> Value {
    json!({"ok":true,"templates":{"python":["__pycache__/","*.py[cod]",".pytest_cache/",".mypy_cache/",".venv/"],"node":["node_modules/","coverage/",".cache/"],"python-node":["__pycache__/","*.py[cod]",".pytest_cache/",".mypy_cache/",".venv/","node_modules/","coverage/",".cache/"]},"applied_automatically":false})
}
pub(super) fn initial_tree(
    git: &Git,
    state: &Path,
    source: &Path,
    r: &Value,
) -> R<(String, Value)> {
    let tree = git.capture(source)?;
    let Some(template) = r.get("ignore_template") else {
        return Ok((tree, json!({"applied":false})));
    };
    let template = template.as_str().ok_or("invalid_ignore_template")?;
    let presets = templates();
    let rules = presets["templates"][template]
        .as_array()
        .ok_or("invalid_ignore_template")?;
    let stage = state.join(format!("init-ignore-{}", digest(r)));
    io(fs::create_dir(&stage))?;
    let result = (|| {
        git.materialize(&tree, &stage)?;
        let file = stage.join(".gitignore");
        let mut content = if file.exists() {
            io(fs::read_to_string(&file))?
        } else {
            String::new()
        };
        content.push('\n');
        for rule in rules {
            content.push_str(rule.as_str().unwrap());
            content.push('\n');
        }
        io(fs::write(file, content))?;
        let selected = git.capture(&stage)?;
        let excluded: Vec<_> = changes(git, &tree, &selected)?
            .into_iter()
            .filter(|c| c["kind"] == "deleted")
            .collect();
        Ok((
            selected,
            json!({"applied":true,"template":template,"excluded":excluded,"source_directory_changed":false}),
        ))
    })();
    let cleanup = fs::remove_dir_all(&stage);
    if result.is_ok() {
        io(cleanup)?;
    }
    result
}
pub(super) fn conflict_details(
    git: &Git,
    base: &str,
    local: &str,
    shared: &str,
    paths: &[String],
) -> R<Vec<Value>> {
    let local_changes = changes(git, base, local)?;
    let shared_changes = changes(git, base, shared)?;
    let mut result = Vec::new();
    for path in paths {
        let find = |changes: &[Value]| {
            changes
                .iter()
                .find(|c| c["path"] == *path || c["old_path"] == *path)
                .cloned()
        };
        let binary = |tree: &str| -> R<bool> {
            let listing = git.run(&["ls-tree", "-r", "-z", tree, "--", path], None)?;
            for entry in listing.split(|b| *b == 0).filter(|e| !e.is_empty()) {
                let head = entry.split(|b| *b == b'\t').next().ok_or("invalid_tree")?;
                let parts: Vec<_> = head.split(|b| *b == b' ').collect();
                if parts.len() == 3 {
                    let id = std::str::from_utf8(parts[2]).map_err(|e| e.to_string())?;
                    if git.verified_object("blob", id)?.contains(&0) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        };
        result.push(json!({"path":path,"local":find(&local_changes),"shared":find(&shared_changes),"binary":binary(local)? || binary(shared)?}));
    }
    Ok(result)
}
