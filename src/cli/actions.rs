use super::{args::*, context::Context, Result};
use serde_json::{json, Value};

fn lease(op: &str, action: &str, fields: &Lease, repair: bool) -> Value {
    let mut value = json!({"op":op,"action":action,"expected_revision":fields.revision});
    value[if repair { "incident_id" } else { "claim_id" }] = json!(fields.id);
    if let Some(seconds) = fields.lease {
        value["lease_seconds"] = json!(seconds);
    }
    value
}
fn page(op: &str, p: &Page) -> Value {
    json!({"op":op,"cursor":p.cursor,"limit":p.limit})
}

pub fn request(command: &Command, context: &Context) -> Result<Option<(Value, bool)>> {
    let pair = match command {
        Command::GetLatest => (json!({"op":"get_latest"}), false),
        Command::Merge { target } => {
            let mut r = context.generation_request("merge")?;
            r["target"] = json!(target);
            (r, true)
        }
        Command::CommitStatus { commit_id } => {
            (json!({"op":"commit_status","commit_id":commit_id}), false)
        }
        Command::Check { head, timings } => {
            let mut r = json!({"op":"validation_status","include_timings":timings});
            if let Some(h) = head {
                r["head"] = json!(h);
            }
            (r, false)
        }
        Command::Task { command } => match command {
            Task::List { page: p } => (page("task_list", p), false),
            Task::Claim {
                id,
                title,
                acceptance,
                paths,
                lease,
            } => (
                json!({"op":"task_claim","task_id":id,"title":title,"acceptance_criteria":acceptance,"paths":paths,"lease_seconds":lease}),
                true,
            ),
            Task::Renew(l) => (lease("task_update", "renew", l, false), true),
            Task::Complete(l) => (lease("task_update", "complete", l, false), true),
            Task::Release(l) => (lease("task_update", "release", l, false), true),
        },
        Command::Repair { command } => match command {
            Repair::List { page: p } => (page("repair_list", p), false),
            Repair::Acknowledge(l) => (lease("repair_update", "acknowledge", l, true), true),
            Repair::Claim(l) => (lease("repair_update", "claim", l, true), true),
            Repair::Renew(l) => (lease("repair_update", "renew", l, true), true),
            Repair::Release(l) => (lease("repair_update", "release", l, true), true),
        },
        Command::Comment { command } => match command {
            Comment::Add {
                subject_type,
                subject_id,
                message,
                mentions,
            } => (
                json!({"op":"comment_add","subject_type":subject_type,"subject_id":subject_id,"body":message,"mentions":mentions}),
                true,
            ),
            Comment::List {
                subject_type,
                subject_id,
                page: p,
            } => {
                let mut r = page("comment_list", p);
                if let Some(v) = subject_type {
                    r["subject_type"] = json!(v);
                }
                if let Some(v) = subject_id {
                    r["subject_id"] = json!(v);
                }
                (r, false)
            }
        },
        Command::Conflict {
            command: Conflict::List,
        } => (json!({"op":"resolution_tasks"}), false),
        Command::Conflict {
            command: Conflict::Show { candidate },
        } => (json!({"op":"conflict_status","candidate":candidate}), false),
        Command::Workspace { command } => match command {
            Workspace::List { page: p } => (page("workspace_inventory", p), false),
            Workspace::Close {
                writers_stopped,
                reason,
            } => {
                let mut r = context.generation_request("workspace_close")?;
                r["confirm_writers_stopped"] = json!(writers_stopped);
                r["reason"] = json!(reason);
                (r, true)
            }
            Workspace::Reopen => (context.generation_request("workspace_reopen")?, true),
        },
        Command::Audit { command } => match command {
            Audit::Status => (json!({"op":"audit_status"}), false),
            Audit::Log { page: p } => (page("audit_log", p), false),
            Audit::Verify => (json!({"op":"audit_verify"}), false),
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    Ok(Some(pair))
}
