use serde_json::{json, Value};

pub fn request(mut value: Value) -> Result<Value, String> {
    let op = value["op"].as_str().unwrap_or("").to_owned();
    value["op"] = json!(match op.as_str() {
        "clone" => "open",
        "get_latest" => "updates",
        "merge" => "adopt",
        "resolve_merge" => "resolve_adoption",
        "commit_status" => "proposal_status",
        "retry_commit" => "retry_proposal",
        other => other,
    });
    if let Some(object) = value.as_object_mut() {
        for (public, stored) in [("message", "intent"), ("commit_id", "proposal")] {
            if let Some(field) = object.remove(public) {
                if object.contains_key(stored) {
                    return Err(format!("invalid_request: use only {public}"));
                }
                object.insert(stored.into(), field);
            }
        }
    }
    Ok(value)
}

pub fn removed_request(value: &Value) -> bool {
    matches!(
        value["op"].as_str(),
        Some(
            "open"
                | "updates"
                | "adopt"
                | "resolve_adoption"
                | "proposal_status"
                | "checkpoint"
                | "publish"
                | "integrate"
                | "resolution_submit"
                | "retry_proposal"
        )
    ) || matches!(
        value["op"].as_str(),
        Some(
            "audit_ingest"
                | "audit_ack"
                | "audit_batch"
                | "audit_transport"
                | "coordination_remote"
                | "coordination_pending"
                | "coordination_receipt"
                | "coordination_import"
                | "coordination_export"
        )
    ) || value.get("intent").is_some()
        || value.get("proposal").is_some()
}

pub(crate) fn public_operation(value: &str) -> &str {
    match value {
        "open" => "clone",
        "updates" => "get_latest",
        "adopt" => "merge",
        "resolve_adoption" => "resolve_merge",
        "proposal_status" => "commit_status",
        "retry_proposal" => "retry_commit",
        other => other,
    }
}

fn guidance(value: &str) -> String {
    value
        .replace("resolve_adoption", "resolve_merge")
        .replace("proposal_status", "commit_status")
        .replace("adoption", "merge")
        .replace("Adoption", "Merge")
        .replace("adopt", "merge")
        .replace("Adopt", "Merge")
        .replace("commit_snapshot_failed", "commit_save_failed")
        .replace("snapshot_unstable", "files_changed_during_commit")
        .replace("no_snapshot_bound_check_results", "no_commit_check_results")
        .replace("snapshots", "commits")
        .replace("snapshot", "commit")
        .replace("Snapshot", "Commit")
        .replace("quarantined", "blocked")
        .replace("quarantine", "blocked state")
        .replace("proposal", "commit")
        .replace("Proposal", "Commit")
}

pub fn response(value: Value) -> Value {
    present(value, false)
}

fn present(value: Value, error: bool) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(|v| present(v, false)).collect()),
        Value::Object(fields) => {
            let mut output = serde_json::Map::new();
            for (key, value) in fields {
                if matches!(
                    key.as_str(),
                    "checkpoint"
                        | "checkpoint_commit"
                        | "checkpoint_generation"
                        | "current_head_scope"
                ) {
                    continue;
                }
                let name = match key.as_str() {
                    "intent" => "message",
                    "proposal" => "commit_id",
                    "proposals" => "commits",
                    "proposals_total" => "commits_total",
                    "proposals_truncated" => "commits_truncated",
                    "adopted" => "merged_base",
                    "resolution_of" => "resolves_commit",
                    "proposal_commit" => "source_commit",
                    "authority_proposal" => "authority_commit_id",
                    "source_proposal" => "source_commit_id",
                    other => other,
                };
                let translated = match (&*key, &value) {
                    ("op", Value::String(text)) => json!(public_operation(text)),
                    ("state" | "status", Value::String(text)) if text == "quarantined" => {
                        json!("blocked")
                    }
                    ("state" | "status", Value::String(text)) if text == "recovery_quarantined" => {
                        json!("recovery_blocked")
                    }
                    ("reason" | "next_action" | "checkout_basis", Value::String(text)) => {
                        json!(guidance(text))
                    }
                    ("code", Value::String(text)) if error => json!(guidance(text)),
                    ("message", Value::String(text)) if error => {
                        if let Some((code, detail)) = text.split_once(':') {
                            json!(format!("{}:{detail}", guidance(code)))
                        } else {
                            value
                        }
                    }
                    _ => present(value, key == "error"),
                };
                output.insert(name.into(), translated);
            }
            Value::Object(output)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requests_use_git_terms_without_changing_user_text() {
        let text = "Adopt snapshot quarantine: exact user message";
        assert_eq!(
            request(json!({"op":"commit","message":text})).unwrap(),
            json!({"op":"commit","intent":text})
        );
        assert_eq!(request(json!({"op":"clone"})).unwrap()["op"], "open");
        assert_eq!(
            response(json!({"request":{"op":"open"}}))["request"]["op"],
            "clone"
        );
        assert!(removed_request(&json!({"op":"open"})));
        assert_eq!(request(json!({"op":"merge"})).unwrap()["op"], "adopt");
        assert_eq!(
            request(json!({"op":"get_latest"})).unwrap()["op"],
            "updates"
        );
        assert!(removed_request(&json!({"op":"adopt"})));
        assert!(removed_request(&json!({"op":"commit","intent":"old"})));
    }
    #[test]
    fn responses_hide_private_details_and_preserve_messages_and_paths() {
        let value = response(
            json!({"intent":"snapshot quarantine","checkpoint":"private","state":"quarantined","proposal":"c1","adopted":"abc","path":"/quarantine/snapshot","next_action":{"op":"updates","reason":"Read updates before adoption."},"error":{"code":"adoption_conflict","message":"snapshot is quarantined"}}),
        );
        assert_eq!(value["message"], "snapshot quarantine");
        assert_eq!(value["path"], "/quarantine/snapshot");
        assert_eq!(value["state"], "blocked");
        assert_eq!(value["commit_id"], "c1");
        assert_eq!(value["next_action"]["op"], "get_latest");
        assert!(value.get("checkpoint").is_none());
        assert_eq!(value["error"]["code"], "merge_conflict");
        assert_eq!(value["error"]["message"], "snapshot is quarantined");
    }
}
