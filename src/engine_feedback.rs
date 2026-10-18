//! Read-only, advisory feedback. Never changes publication, policy, or adoption.
//! Evidence describes one immutable candidate, not correctness of live files.
use super::*;

pub(super) const PROPOSAL_LIMIT: i64 = 10;

pub(super) fn policy_counts(db: &Connection) -> (Option<usize>, Option<usize>) {
    if sync::is_client(db).unwrap_or(true) {
        return (None, None);
    }
    let policy: Option<String> = match db
        .query_row("SELECT value FROM meta WHERE key='policy'", [], |r| {
            r.get(0)
        })
        .optional()
    {
        Ok(policy) => policy,
        Err(_) => return (None, None),
    };
    let policy: Value = match policy {
        None => json!({}),
        Some(s) => match serde_json::from_str(&s) {
            Ok(value) => value,
            Err(_) => return (None, None),
        },
    };
    if !policy.is_object() {
        return (None, None);
    }
    let Some(checks) = policy.get("checks") else {
        return (Some(0), Some(0));
    };
    let Some(checks) = checks.as_array() else {
        return (None, None);
    };
    (
        Some(checks.len()),
        Some(checks.iter().filter(|c| c["required"] != false).count()),
    )
}

pub(super) fn action(op: Option<&str>, reason: &str, arguments: Value) -> Value {
    json!({"op":op,"reason":reason,"arguments":arguments,"requires_explicit_request":true})
}

pub(super) fn unchecked(scope: &str, reason: &str, tree: Option<&str>) -> Value {
    json!({"state":"unchecked","scope":scope,"reason":reason,"candidate_tree":tree,
        "checks_total":0,"checks_passed":0,"checks_failed":0,"semantic_correctness_claimed":false})
}

// `checks_executed` is deliberately not an input. Neither an accepted merge nor
// a remote evidence label establishes affirmative, snapshot-bound check results.
pub(super) fn validation(
    details: Option<&Value>,
    phase: &str,
    configured: Option<usize>,
    proposal_commit: Option<&str>,
    remote: bool,
) -> Value {
    let scope = if remote {
        "remote_receipt"
    } else {
        "integration_candidate"
    };
    let mut result = unchecked(scope, "no_snapshot_bound_check_results", None);
    if matches!(
        phase,
        "coordinator_accepted" | "local_queued" | "queued_offline" | "pending"
    ) {
        if configured != Some(0) {
            result["state"] = json!("pending");
            result["reason"] = json!(if configured.is_none() {
                "authority_policy_unknown"
            } else {
                "configured_checks_not_yet_evaluated"
            });
        }
        return result;
    }
    if remote {
        result["reason"] = json!("remote_receipt_has_no_complete_check_evidence");
        return result;
    }
    let Some(d) = details else {
        return result;
    };
    result["candidate_tree"] = d.get("candidate_tree").cloned().unwrap_or(Value::Null);
    if d["evaluation_error"].is_string() {
        result["state"] = json!("failed");
        result["reason"] = json!("policy_evaluation_failed");
        return result;
    }
    let Some(checks) = d["checks"].as_array().filter(|a| !a.is_empty()) else {
        return result;
    };
    let tree = d["candidate_tree"].as_str().filter(|s| !s.is_empty());
    let proposal_matches = proposal_commit.is_some_and(|p| d["proposal"] == p);
    let configured_checks = d["policy"]["checks"].as_array();
    let complete = configured_checks.is_some_and(|expected| {
        expected.len() == checks.len()
            && checks.iter().all(|c| {
                c["id"].is_string() && expected.iter().filter(|e| e["id"] == c["id"]).count() == 1
            })
            && expected.iter().all(|e| {
                e["id"].is_string() && checks.iter().filter(|c| c["id"] == e["id"]).count() == 1
            })
    });
    let passed = checks
        .iter()
        .filter(|check| {
            check["success"] == true
                && check["checkout_unchanged"] == true
                && tree.is_some_and(|t| check["candidate_tree"] == t)
                && proposal_matches
        })
        .count();
    let failed = checks
        .iter()
        .filter(|check| {
            check["success"] == false
                || check["checkout_unchanged"] == false
                || (tree.is_some()
                    && check["candidate_tree"].is_string()
                    && check["candidate_tree"].as_str() != tree)
        })
        .count();
    result["checks_total"] = json!(checks.len());
    result["checks_passed"] = json!(passed);
    result["checks_failed"] = json!(failed);
    if failed > 0 {
        result["state"] = json!("failed");
        result["reason"] = json!("check_failed_or_snapshot_changed");
    } else if complete && passed == checks.len() {
        result["state"] = json!("passed");
        result["reason"] = json!("all_recorded_checks_passed_on_candidate");
    } else {
        result["reason"] = json!("incomplete_or_unbound_check_evidence");
    }
    result
}

pub(super) fn proposal_action(id: &str, phase: &str, task: Option<&Value>) -> Value {
    match phase {
        "quarantined" if task.is_some_and(|t| t["state"] == "escalated") =>
            action(None, "Resolution attempt limit reached; review before deliberately publishing new work.", json!({"proposal":id})),
        "quarantined" => action(Some("resolution_open"), "Inspect the resolution task, then explicitly open a separate checkout to fix it.", json!({"proposal":id})),
        "coordinator_accepted" | "local_queued" | "queued_offline" =>
            action(Some("proposal_status"), "Proposal is queued. Observe its result; integration and adoption are separate actions.", json!({"proposal":id})),
        "integrated" | "already_included" =>
            action(Some("updates"), "Read available public updates before deciding whether to adopt them.", json!({})),
        _ => action(None, "No automatic publication or adoption is needed.", json!({"proposal":id})),
    }
}

pub(super) fn proposal_action_for_store(
    db: &Connection,
    id: &str,
    phase: &str,
    task: Option<&Value>,
) -> Value {
    match sync::proposal_origin(db, id) {
        Ok(None) => proposal_action(id, phase, task),
        Ok(Some(_)) => action(None,
            "This proposal belongs to a submitting peer. Deliver an explicit receipt through the configured sync workflow; do not open or adopt a synthetic authority workspace.",
            json!({"proposal":id})),
        Err(_) => action(None,
            "Proposal ownership could not be verified. Inspect sync state before choosing a workspace action.",
            json!({"proposal":id})),
    }
}

pub(super) fn error(error: &str) -> Value {
    let code = error.split(':').next().unwrap_or("internal_error");
    let (op, hint, fresh) = match code {
        "generation_mismatch" => (Some("status"), "Read the current workspace generation and inspect changes before retrying with a new operation ID.", true),
        "writer_recovery_required" | "writer_confirmation_required" => (Some("status"), "Never retry the uncertain command. Stop and verify unmanaged writers first. Only then explicitly acknowledge command_recover with its own new operation ID.", false),
        "stale_resolution" => (Some("resolution_tasks"), "Preserve the isolated checkout for comparison. Read the task and open a fresh isolated checkout with new operation IDs; never substitute a newer expected_head.", true),
        "stale_resolution_checkpoint" | "unresolved_conflict_markers" => (Some("status"), "Inspect and fix the isolated checkout, then checkpoint its current generation and submit using new operation IDs.", true),
        "resolution_attestation_required" => (Some("resolution_tasks"), "Review every conflict path, then explicitly attest the exact set using a new operation ID.", true),
        "adoption_conflict" => (Some("status"), "Live files are unchanged. Preserve private edits and resolve deliberately before requesting another adoption.", true),
        "adoption_rolled_back" => (Some("status"), "Inspect restored files and current generation before retrying with a new operation ID.", true),
        "snapshot_unstable" => (Some("status"), "Stop concurrent writers and inspect the workspace before a new capture with a new operation ID.", true),
        "idempotency_mismatch" => (Some("operation_status"), "Inspect the original operation before deciding what to do. Replay only the identical request; a deliberately new action requires its own operation ID.", false),
        "checkpoint_not_found" => (Some("status"), "Read the workspace checkpoint ID. Select an existing checkpoint or deliberately create one before retrying.", true),
        "resolution_submit_required" => (Some("resolution_tasks"), "Publish this isolated checkout only through its owner's resolution_submit workflow.", true),
        "stale_head" | "coordinator_unreachable" => (Some("updates"), "Read available public updates and review the intended target before retrying.", true),
        "public_recovery_activation_required" | "recovery_required" => (Some("recovery_status"), "Inspect recovery state and preserve files before taking any explicit recovery action.", false),
        "resolution_attempts_exhausted" => (Some("resolution_tasks"), "The resolution budget is exhausted. Review the task before deciding whether new work is authorized.", true),
        "operation_not_found" => (Some("status"), "No operation with this ID is journaled. Verify the state directory and operation ID before deciding whether to submit the request.", false),
        _ => (Some("operation_status"), "The outcome may be uncertain. Inspect the original operation ID before retrying; do not create a new operation ID until its outcome is established.", false),
    };
    json!({"ok":false,"error":{"code":code,"message":error},
        "validation":unchecked("request","request_failed_without_new_validation",None),
        "recovery":{"action":op,"reason":hint,"retry_with_new_operation_id":fresh},
        "next_action":action(op,hint,json!({}))})
}

pub(super) fn checkpoint_context(db: &Connection, wid: &str, w: &Workspace) -> Value {
    let checkpoint: Option<(String, i64)> = db.query_row(
        "SELECT id,generation FROM checkpoints WHERE workspace=?1 AND commit_oid=?2 ORDER BY generation DESC,id LIMIT 1",
        params![wid,w.checkpoint], |r| Ok((r.get(0)?,r.get(1)?)),
    ).optional().ok().flatten();
    json!({"checkpoint":checkpoint.as_ref().map(|v|&v.0),
        "checkpoint_generation":checkpoint.as_ref().map(|v|v.1)})
}

// Local response decoration only. Do not add these fields in resolution::task:
// its unchanged allowlisted representation also feeds public receipt creation.
fn task_feedback(db: &Connection, task: &mut Value) {
    let Some(id) = task["proposal"].as_str().map(str::to_owned) else {
        return;
    };
    let mut next = proposal_action_for_store(db, &id, "quarantined", Some(task));
    if let Some(workspace) = task["workspace"].as_str() {
        next["arguments"]["workspace"] = json!(workspace);
    }
    task["next_action_hint"] = next;
    // Compatibility: task.current_head is historical quarantine evidence.
    task["captured_head"] = task["current_head"].clone();
    task["current_head_scope"] = json!("captured_at_quarantine");
    let evidence: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT commit_oid,details FROM proposals WHERE id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()
        .flatten();
    let (commit, details) = evidence.unwrap_or_default();
    let details: Option<Value> = details.and_then(|s| serde_json::from_str(&s).ok());
    task["validation"] = validation(
        details.as_ref(),
        "quarantined",
        policy_counts(db).0,
        Some(&commit),
        sync::is_client(db).unwrap_or(true),
    );
}

// Called before the original result is durably journaled, including recovery.
// Also called at ordinary return boundaries; additions are idempotent. Stored
// replay and operation_status bypass this function and stay byte-for-byte equal.
pub(super) fn complete(db: &Connection, r: &Value, mut v: Value) -> Value {
    let op = r["op"].as_str().unwrap_or("");
    if !matches!(
        op,
        "init"
            | "open"
            | "status"
            | "updates"
            | "checkpoint"
            | "publish"
            | "integrate"
            | "adopt"
            | "proposal_status"
            | "retry_proposal"
            | "cancel"
            | "command_run"
            | "command_recover"
            | "configure"
            | "resolve_adoption"
            | "resolution_open"
            | "resolution_submit"
            | "resolution_tasks"
    ) {
        return v;
    }
    if op == "resolution_open" && v["ok"] == true {
        v["resolution_head"] = v["current_head"].clone();
        v["current_head_scope"] = json!("resolution_checkout_basis");
    }
    let (configured, required) = policy_counts(db);
    v["checks_configured"] = json!(configured);
    v["required_checks_configured"] = json!(required);
    let wid = if matches!(op, "resolution_submit" | "resolution_open") {
        r["resolution_workspace"].as_str()
    } else {
        r["workspace"].as_str()
    };
    if let Some((wid, w)) = wid.and_then(|id| ws(db, id).ok().map(|w| (id, w))) {
        v["current_generation"] = json!(w.generation);
        v["current_generation_workspace"] = json!(wid);
        let context = checkpoint_context(db, wid, &w);
        if v.get("checkpoint").is_none() {
            v["checkpoint"] = context["checkpoint"].clone();
        }
        if v.get("checkpoint_generation").is_none() {
            v["checkpoint_generation"] = context["checkpoint_generation"].clone();
        }
    }
    if v["ok"] == false {
        let code = if v["writer_recovery_required"] == true || v["state"] == "uncertain" {
            "writer_recovery_required"
        } else {
            v["error"]["code"].as_str().unwrap_or("internal_error")
        };
        let message = v["error"]["message"].as_str().unwrap_or(code);
        let feedback = error(&format!("{code}: {message}"));
        v["recovery"] = feedback["recovery"].clone();
        v["next_action"] = feedback["next_action"].clone();
        let action = v["next_action"]["op"].as_str();
        let arguments = if action == Some("operation_status") {
            json!({"operation_id":r["operation_id"]})
        } else if action == Some("resolution_tasks") {
            json!({"workspace":r["workspace"]})
        } else if matches!(action, Some("status" | "updates")) && wid.is_some() {
            json!({"workspace":wid})
        } else {
            json!({})
        };
        v["next_action"]["arguments"] = arguments;
    }
    if v.get("validation").is_none() {
        v["validation"] = if matches!(op, "publish" | "resolution_submit" | "retry_proposal")
            && v["ok"] == true
        {
            validation(
                None,
                v["state"].as_str().unwrap_or(""),
                configured,
                None,
                false,
            )
        } else {
            unchecked(
                if op == "checkpoint" {
                    "private_checkpoint"
                } else if wid.is_some() {
                    "private_workspace"
                } else {
                    "response"
                },
                "this_operation_did_not_validate_live_files",
                v["tree"].as_str(),
            )
        };
    }
    if v.get("next_action").is_none() {
        let proposal = v["proposal"].as_str();
        v["next_action"] = if let Some(id) = proposal {
            proposal_action_for_store(
                db,
                id,
                v["state"].as_str().unwrap_or(""),
                v.get("resolution_task"),
            )
        } else if v["writer_recovery_required"] == true {
            action(Some("status"),"Stop and verify unmanaged writers before explicitly acknowledging command_recover.",json!({"workspace":wid}))
        } else if matches!(
            op,
            "checkpoint"
                | "open"
                | "resolution_open"
                | "adopt"
                | "resolve_adoption"
                | "command_recover"
        ) {
            action(Some("status"),"Inspect this workspace before the next explicit action. Checkpointing never publishes or adopts.",json!({"workspace":wid}))
        } else {
            action(
                None,
                "Choose the next explicit action after reviewing this state.",
                json!({}),
            )
        };
    }
    for key in ["resolution_task", "task"] {
        if v[key].is_object() {
            task_feedback(db, &mut v[key]);
        }
    }
    for key in ["resolution_tasks", "tasks"] {
        if let Some(tasks) = v.get_mut(key).and_then(Value::as_array_mut) {
            for task in tasks {
                task_feedback(db, task);
            }
        }
    }
    if let Some(outcomes) = v.get_mut("outcomes").and_then(Value::as_array_mut) {
        for outcome in outcomes {
            if outcome["resolution_task"].is_object() {
                task_feedback(db, &mut outcome["resolution_task"]);
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence() -> Value {
        json!({"proposal":"proposal-commit","candidate_tree":"candidate-tree","accepted":true,
            "policy":{"checks":[{"id":"unit"}]},"checks":[{"id":"unit","success":true,
            "candidate_tree":"candidate-tree","checkout_unchanged":true}]})
    }
    fn classify(d: &Value) -> Value {
        validation(
            Some(d),
            "integrated",
            Some(1),
            Some("proposal-commit"),
            false,
        )
    }
    #[test]
    fn validation_requires_affirmative_complete_snapshot_evidence() {
        let d = evidence();
        assert_eq!(classify(&d)["state"], "passed");
        for field in ["success", "checkout_unchanged", "candidate_tree"] {
            let mut missing = d.clone();
            missing["checks"][0].as_object_mut().unwrap().remove(field);
            assert_eq!(classify(&missing)["state"], "unchecked", "{field}");
        }
        let mut wrong = d.clone();
        wrong["proposal"] = json!("another-proposal");
        assert_eq!(classify(&wrong)["state"], "unchecked");
        let mut incomplete = d.clone();
        incomplete["policy"]["checks"] = json!([{"id":"unit"},{"id":"missing"}]);
        assert_eq!(classify(&incomplete)["state"], "unchecked");
        let mut unbound = d.clone();
        unbound["checks"][0]["candidate_tree"] = json!("different-tree");
        assert_eq!(classify(&unbound)["state"], "failed");
        assert_eq!(
            classify(&json!({"accepted":true,"evidence":"checks_executed"}))["state"],
            "unchecked"
        );
    }
    #[test]
    fn optional_failed_checks_are_failed_even_when_integration_is_accepted() {
        let mut d = evidence();
        d["policy"]["checks"][0]["required"] = json!(false);
        d["checks"][0]["required"] = json!(false);
        d["checks"][0]["success"] = json!(false);
        assert_eq!(classify(&d)["state"], "failed");
        assert_eq!(classify(&d)["checks_failed"], 1);
    }
    #[test]
    fn pending_and_remote_evidence_do_not_overstate_validation() {
        assert_eq!(
            validation(None, "coordinator_accepted", Some(0), None, false)["state"],
            "unchecked"
        );
        assert_eq!(
            validation(None, "coordinator_accepted", Some(1), None, false)["state"],
            "pending"
        );
        assert_eq!(
            validation(None, "local_queued", None, None, true)["state"],
            "pending"
        );
        assert_eq!(
            validation(
                Some(&evidence()),
                "integrated",
                None,
                Some("proposal-commit"),
                true
            )["state"],
            "unchecked"
        );
        assert_eq!(
            classify(&json!({"evaluation_error":"invalid policy"}))["state"],
            "failed"
        );
    }
    #[test]
    fn recovery_hints_preserve_generation_and_resolution_fences() {
        let stale = error("stale_resolution: changed head");
        assert_eq!(stale["recovery"]["action"], "resolution_tasks");
        assert!(stale["recovery"]["reason"]
            .as_str()
            .unwrap()
            .contains("never substitute"));
        assert_eq!(
            error("generation_mismatch: current 7")["next_action"]["op"],
            "status"
        );
        assert_eq!(
            error("idempotency_mismatch: changed request")["next_action"]["op"],
            "operation_status"
        );
        assert_eq!(
            error("idempotency_mismatch: changed request")["recovery"]
                ["retry_with_new_operation_id"],
            false
        );
        let uncertain = error("storage_error: lost durable write outcome");
        assert_eq!(uncertain["next_action"]["op"], "operation_status");
        assert_eq!(uncertain["recovery"]["retry_with_new_operation_id"], false);
    }

    #[test]
    fn client_current_policy_is_unknown_not_an_empty_policy() {
        let db = Connection::open_in_memory().unwrap();
        init_db(&db).unwrap();
        assert_eq!(policy_counts(&db), (Some(0), Some(0)));
        db.execute("INSERT INTO meta VALUES('sync_config',?1)",[json!({"project":"p","authority":"a","epoch":1,"device":"d","role":"client","peers":[]}).to_string()]).unwrap();
        assert_eq!(policy_counts(&db), (None, None));
        let result = complete(&db, &json!({"op":"status"}), json!({"ok":true}));
        assert_eq!(result["checks_configured"], Value::Null);
        assert_eq!(result["required_checks_configured"], Value::Null);
        assert_eq!(result["validation"]["state"], "unchecked");
    }
    #[test]
    fn uncertain_command_without_error_requires_writer_recovery_not_replay() {
        let db = Connection::open_in_memory().unwrap();
        init_db(&db).unwrap();
        let result = complete(
            &db,
            &json!({"op":"command_run","workspace":"actor","operation_id":"uncertain-command"}),
            json!({"ok":false,"state":"uncertain","writer_recovery_required":true,
                "execution":{"output_collection_complete":false}}),
        );
        assert_eq!(result["next_action"]["op"], "status");
        assert_eq!(result["next_action"]["arguments"]["workspace"], "actor");
        assert_eq!(result["recovery"]["retry_with_new_operation_id"], false);
        assert!(result["recovery"]["reason"]
            .as_str()
            .unwrap()
            .contains("Never retry"));
        assert!(result["recovery"]["reason"]
            .as_str()
            .unwrap()
            .contains("command_recover"));
        assert_eq!(result["validation"]["state"], "unchecked");
    }
    #[test]
    fn imported_proposal_actions_stay_with_submitting_peer() {
        let db = Connection::open_in_memory().unwrap();
        init_db(&db).unwrap();
        db.execute("INSERT INTO meta VALUES('sync_config',?1)",[json!({"project":"p","authority":"a","epoch":1,"device":"a","role":"authority","peers":["d"]}).to_string()]).unwrap();
        db.execute_batch("CREATE TABLE sync_proposal_origins(proposal TEXT PRIMARY KEY,device TEXT NOT NULL,source_proposal TEXT NOT NULL); INSERT INTO sync_proposal_origins VALUES('remote-p','d','original-p');").unwrap();
        for phase in ["quarantined", "integrated", "coordinator_accepted"] {
            let next = proposal_action_for_store(&db, "remote-p", phase, None);
            assert_eq!(next["op"], Value::Null);
            assert!(next["reason"].as_str().unwrap().contains("submitting peer"));
            assert!(next["arguments"].get("workspace").is_none());
        }
        assert_eq!(
            proposal_action_for_store(&db, "local-p", "quarantined", None)["op"],
            "resolution_open"
        );
    }
    #[test]
    fn historical_validation_uses_recorded_policy_not_current_configuration() {
        let prior = evidence();
        for current_count in [Some(0), Some(1), Some(3), None] {
            let result = validation(
                Some(&prior),
                "integrated",
                current_count,
                Some("proposal-commit"),
                false,
            );
            assert_eq!(result["state"], "passed");
            assert_eq!(result["checks_total"], 1);
            assert_eq!(result["candidate_tree"], "candidate-tree");
        }
        assert_eq!(
            validation(
                Some(&prior),
                "coordinator_accepted",
                Some(3),
                Some("proposal-commit"),
                false
            )["state"],
            "pending"
        );
    }
}
