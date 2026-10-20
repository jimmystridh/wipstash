mod actions;
mod args;
mod context;
mod remote;
mod staging;

use args::*;
use clap::Parser;
use context::{Context, Repository};
use serde_json::{json, Value};
use std::{
    fmt::Display,
    fs,
    io::{BufRead, Read},
    path::Path,
};

type Result<T> = std::result::Result<T, String>;
fn fail(error: impl Display) -> String {
    error.to_string()
}
fn id(prefix: &str) -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("OS randomness unavailable");
    format!(
        "{prefix}-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
fn execute(state: &Path, value: Value) -> Value {
    crate::request(state, value)
}
fn error(message: &str) -> Value {
    crate::vocabulary::response(crate::engine::error_response(message))
}

fn internal(arguments: &[String]) -> Option<i32> {
    if arguments.get(1).map(String::as_str) != Some("--state") {
        return None;
    }
    if arguments.len() != 5 && arguments.len() != 4 {
        eprintln!("Invalid internal engine arguments");
        return Some(2);
    }
    let state = Path::new(&arguments[2]);
    let dispatch = |text: &str| -> Value {
        match serde_json::from_str(text) {
            Ok(value) => context::raw(state, value),
            Err(e) => error(&format!("invalid_request: {e}")),
        }
    };
    match arguments[3].as_str() {
        "stdin" => {
            for line in std::io::stdin().lock().lines() {
                match line {
                    Ok(line) => println!("{}", dispatch(&line)),
                    Err(_) => return Some(1),
                }
            }
            Some(0)
        }
        "audit-record" => {
            let mut bytes = Vec::new();
            let result = std::io::stdin()
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes);
            let value = if result.is_err() || bytes.len() > 16 * 1024 * 1024 {
                error("audit_payload_bound")
            } else {
                match serde_json::from_slice::<Value>(&bytes) {
                    Ok(record) => context::raw(state, json!({"op":"audit_record","record":record})),
                    Err(e) => error(&fail(e)),
                }
            };
            println!("{value}");
            Some(if value["ok"] == true { 0 } else { 1 })
        }
        "mcp" => {
            eprintln!("MCP support has been removed; use wip commands.");
            Some(2)
        }
        text => {
            let v = dispatch(text);
            println!("{v}");
            Some(if v["ok"] == true { 0 } else { 1 })
        }
    }
}

pub async fn main() -> i32 {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.get(1).map(String::as_str) == Some("--pairing") {
        return match wipstash_transport::pairing_cli::run(&arguments[2..]).await {
            Ok(true) => 0,
            Ok(false) => 2,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        };
    }
    if let Some(code) = internal(&arguments) {
        return code;
    }
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = e.exit_code();
            if arguments.iter().any(|s| s == "--json") && e.use_stderr() {
                println!("{}", error(&format!("invalid_arguments: {e}")));
            } else {
                let _ = e.print();
            }
            return code;
        }
    };
    let json_output = cli.json;
    let result = run(cli).await.unwrap_or_else(|e| error(&e));
    let code = if result["state"] == "blocked" || result["error"]["code"] == "merge_conflict" {
        4
    } else if result["ok"] == false {
        1
    } else if result["pending"] == true
        || result["shared"] == false && result["submitted"] == true
        || result["confirmed"] == false
    {
        3
    } else {
        0
    };
    if json_output {
        println!("{result}");
    } else {
        print_human(&result);
    }
    code
}

fn print_human(value: &Value) {
    if value["ok"] == false {
        eprintln!(
            "{}",
            value["error"]["message"]
                .as_str()
                .or(value["error"]["code"].as_str())
                .unwrap_or("Operation failed")
        );
    } else if value["shared"] == true {
        println!(
            "Shared: {}",
            value["head"].as_str().unwrap_or("confirmed by server")
        );
    } else if value["pending"] == true || value["shared"] == false && value["submitted"] == true {
        println!(
            "Saved locally; delivery pending. Commit: {}",
            value["commit_id"]
                .as_str()
                .unwrap_or("see retained operations")
        );
    } else if let Some(patch) = value["patch"].as_str() {
        print!("{patch}");
        return;
    } else if value.get("path").is_some() && value.get("workspace").is_some() {
        println!(
            "{}\nWorkspace: {}",
            value["path"].as_str().unwrap_or(""),
            value["workspace"].as_str().unwrap_or("")
        );
    } else {
        println!("{}", serde_json::to_string_pretty(value).unwrap());
        return;
    }
    if value["validation"].is_object() {
        println!(
            "Checks: {}",
            value["validation"]["state"].as_str().unwrap_or("unknown")
        );
    }
    if value["state"] == "blocked" || value["ok"] == false {
        eprintln!("Use --json for conflict and recovery details.");
    }
}

async fn run(cli: Cli) -> Result<Value> {
    std::env::set_current_dir(&cli.directory).map_err(fail)?;
    let cwd = std::env::current_dir()
        .map_err(fail)?
        .canonicalize()
        .map_err(fail)?;
    match &cli.command {
        Command::Init { path } => return context::local_init(path),
        Command::Clone {
            source,
            path,
            profile,
        } => return remote::clone(source, path, profile.as_deref()).await,
        Command::Attach {
            state,
            workspace,
            profile,
        } => {
            return Context::install(Repository {
                version: 1,
                root: cwd,
                state: context::absolute(state)?,
                workspace: workspace.clone(),
                profile: profile.clone(),
            })
        }
        Command::Remote { command } => {
            return match command {
                Remote::Add {
                    name,
                    config,
                    default,
                } => remote::add(name, config, *default),
                Remote::List => remote::list(),
                Remote::Guide => remote::native(&["help".into()]).await,
                Remote::Native(values) => remote::native(values).await,
            }
        }
        Command::Admin {
            operation,
            params,
            state: Some(state),
        } => {
            let mut request = read_value(params)?;
            if !request.is_object() {
                return Err("parameters_must_be_an_object".into());
            }
            request["op"] = json!(operation);
            return Ok(execute(&context::absolute(state)?, request));
        }
        _ => {}
    }
    let context = Context::discover(&cwd)?;
    let local_only = cli.offline
        || matches!(
            cli.command,
            Command::Add { .. }
                | Command::Restore { .. }
                | Command::Diff { .. }
                | Command::Audit {
                    command: Audit::Collect { .. } | Audit::Import { .. } | Audit::Record { .. }
                }
        );
    let mut contact_error = None;
    if !local_only
        && context.repo.profile.is_some()
        && !matches!(cli.command, Command::Commit { .. } | Command::Sync)
        && !direct_coordination(&cli.command)
    {
        if let Err(e) = remote::refresh(&context).await {
            contact_error = Some(e);
        }
    }
    let mut result = match &cli.command {
        Command::Add { paths } => staging::add(&context, &context.relative_paths(paths, &cwd)?)?,
        Command::Restore { paths, .. } => {
            staging::restore(&context, &context.relative_paths(paths, &cwd)?)?
        }
        Command::Status { quick } => staging::status(&context, *quick)?,
        Command::Diff {
            staged,
            base,
            head,
            path,
        } => diff(
            &context,
            *staged,
            base.as_deref(),
            head.as_deref(),
            path.as_deref(),
        )?,
        Command::Log { limit } => log(&context, *limit)?,
        Command::Commit { .. } => commit(&context, &cli.command, cli.offline).await?,
        Command::Sync => {
            if cli.offline {
                json!({"ok":true,"pending":true,"reason":"offline_requested"})
            } else {
                match remote::sync(&context).await {
                    Ok(v) => v,
                    Err(e) => json!({"ok":true,"pending":true,"delivery_error":e}),
                }
            }
        }
        Command::Operation { command } => operation(&context, command, cli.offline).await?,
        Command::Conflict {
            command:
                Conflict::Open {
                    path,
                    commit,
                    candidate,
                },
        } => open_resolution(&context, path, commit.as_deref(), candidate.as_deref())?,
        Command::Conflict {
            command:
                Conflict::Resolve {
                    resolution,
                    candidate,
                    target,
                    paths,
                },
        } => {
            staging::require_empty(&context)?;
            let review = Context::discover(resolution)?;
            let mut request = context.generation_request("resolve_merge")?;
            request["resolution_workspace"] = json!(review.repo.workspace);
            request["candidate"] = json!(candidate);
            request["target"] = json!(target);
            request["resolved_conflicts"] = json!(paths);
            context.mutation(request)?
        }
        Command::Audit {
            command: Audit::Log { page },
        } if context.repo.profile.is_some() && !cli.offline => {
            remote::workstation(context.repo.profile.as_ref().unwrap())?
                .audit_log(page.cursor, page.limit)
                .await
                .map_err(fail)?
        }
        Command::Check { head, timings } if context.repo.profile.is_some() && !cli.offline => {
            remote::workstation(context.repo.profile.as_ref().unwrap())?
                .validation_status(head.as_deref(), *timings)
                .await
                .map_err(fail)?
        }
        Command::Audit {
            command: Audit::Record { file },
        } => context.call(json!({"op":"audit_record","record":context::read_json(file)?})),
        Command::Audit {
            command: Audit::Import { file },
        } => import_audit(&context, file)?,
        Command::Audit {
            command: Audit::Collect { collector },
        } => collect_audit(&context, collector)?,
        Command::Request { operation, params }
        | Command::Admin {
            operation, params, ..
        } => {
            let mut request = read_value(params)?;
            if !request.is_object() {
                return Err("parameters_must_be_an_object".into());
            }
            request["op"] = json!(operation);
            if matches!(cli.command, Command::Request { .. })
                && crate::vocabulary::removed_request(&request)
            {
                return Err(
                    "removed_workflow: use add and commit, or trusted operator admin commands"
                        .into(),
                );
            }
            execute_request(&context, request, !read_operation(operation), cli.offline).await?
        }
        _ => {
            if matches!(cli.command, Command::Merge { .. }) {
                staging::require_empty(&context)?;
            }
            let (request, mutating) =
                actions::request(&cli.command, &context)?.ok_or("unsupported_command")?;
            execute_request(&context, request, mutating, cli.offline).await?
        }
    };
    if !local_only
        && context.repo.profile.is_some()
        && contact_error.is_none()
        && result.get("notices").is_none()
    {
        let observation = context
            .call(json!({"op":"status","workspace":context.repo.workspace,"inspect_files":false}));
        for field in ["notices", "comment_notices"] {
            if let Some(value) = observation.get(field) {
                result[field] = value.clone();
            }
        }
    }
    if let Some(profile) = context.repo.profile.as_deref().filter(|_| {
        !local_only
            && contact_error.is_none()
            && !matches!(cli.command, Command::Operation { .. } | Command::Sync)
            && result.get("notices").is_some()
    }) {
        let station = remote::workstation(profile)?;
        if context.has_pending_coordination()? && station.flush_coordination().await.is_ok() {
            let fresh=context.call(json!({"op":"status","workspace":context.repo.workspace,"inspect_files":false,"accept_repairs":false}));
            for field in ["notices", "comment_notices", "repo_health", "coordination"] {
                if let Some(value) = fresh.get(field) {
                    result[field] = value.clone();
                }
            }
            if let Command::Repair {
                command: Repair::List { page },
            } = &cli.command
            {
                let latest=context.call(json!({"op":"repair_list","workspace":context.repo.workspace,"accept_repairs":false,"cursor":page.cursor,"limit":page.limit}));
                result["repairs"] = latest["repairs"].clone();
            }
        }
    }
    if let Some(e) = contact_error {
        result["remote_refresh_error"] = json!(e);
        result["remote_contact_verified"] = json!(false);
    }
    let action = match &cli.command {
        Command::Add { .. } => "add",
        Command::Restore { .. } => "unstage",
        Command::Commit { .. } => "commit",
        Command::Merge { .. } => "merge",
        Command::Sync => "sync",
        _ => "cli_action",
    };
    let record = json!({"event_id":id("cli"),"agent":std::env::var("WIP_AGENT").unwrap_or_else(|_|"cli".into()),"session_id":context.repo.workspace,"workspace":context.repo.workspace,"action":action,"phase":if result["ok"]==true{"completed"}else{"failed"},"payload":{"command":action,"result":result}});
    let audit = context.call(json!({"op":"audit_record","record":record}));
    if audit["ok"] != true {
        result["audit_error"] = audit["error"].clone();
    }
    if let Some(profile) = context.repo.profile.as_deref().filter(|_| {
        !local_only
            && result.get("remote_refresh_error").is_none()
            && result.get("delivery_error").is_none()
    }) {
        let station = remote::workstation(profile)?;
        match tokio::time::timeout(std::time::Duration::from_secs(60), station.flush_audit()).await
        {
            Ok(Ok(delivered)) => {
                result["audit_delivery"] = json!({"synced":delivered["synced"],"pending":delivered["pending"],"scope":"wip_actions"});
            }
            _ => {
                result["audit_delivery"] =
                    json!({"synced":false,"pending":true,"scope":"wip_actions"});
            }
        }
    }
    if matches!(
        cli.command,
        Command::Audit {
            command: Audit::Status
        }
    ) {
        result["native_activity"] = json!({"required":false,"collection":result["collection"]});
        result["scope"] = json!("wip_actions");
        result["complete"] = result["audit_delivery"]["synced"]
            .as_bool()
            .map(Value::Bool)
            .unwrap_or_else(|| result["synced"].clone());
    }
    Ok(result)
}

fn direct_coordination(command: &Command) -> bool {
    matches!(
        command,
        Command::Task {
            command: Task::Claim { .. } | Task::Renew(_) | Task::Complete(_) | Task::Release(_)
        } | Command::Repair {
            command: Repair::Acknowledge(_)
                | Repair::Claim(_)
                | Repair::Renew(_)
                | Repair::Release(_)
        } | Command::Comment {
            command: Comment::Add { .. }
        }
    )
}

fn read_operation(op: &str) -> bool {
    matches!(
        op,
        "status"
            | "get_latest"
            | "commit_status"
            | "operation_status"
            | "task_list"
            | "repair_list"
            | "comment_list"
            | "conflict_status"
            | "resolution_tasks"
            | "workspace_inventory"
            | "validation_status"
            | "audit_status"
            | "audit_log"
            | "audit_verify"
            | "ignore_templates"
            | "diff"
            | "events"
            | "sync_status"
            | "recovery_status"
    )
}

async fn execute_request(
    context: &Context,
    mut request: Value,
    mutation: bool,
    offline: bool,
) -> Result<Value> {
    if request.get("workspace").is_none() {
        request["workspace"] = json!(context.repo.workspace);
    }
    if mutation && request["op"] == "workspace_close" && !offline {
        if let Some(profile) = context.repo.profile.as_deref() {
            let delivered = remote::workstation(profile)?
                .flush_audit()
                .await
                .map_err(fail)?;
            if delivered["synced"] != true {
                return Err(
                    "workspace_pending_delivery: sync retained audit evidence before archiving"
                        .into(),
                );
            }
        }
    }
    let coordination = matches!(
        request["op"].as_str(),
        Some("task_claim" | "task_update" | "repair_update" | "comment_add")
    );
    let mut result = if mutation {
        context.mutation(request)?
    } else {
        context.call(request)
    };
    if mutation && result["ok"] == true && context.repo.profile.is_some() {
        if offline {
            result["pending"] = json!(result["confirmed"] == false || result["submitted"] == true);
        } else {
            let delivery = if coordination {
                remote::workstation(context.repo.profile.as_deref().unwrap())?
                    .flush_coordination()
                    .await
                    .map_err(fail)
            } else {
                remote::sync(context).await
            };
            match delivery {
                Ok(delivery) => {
                    if let Some(operation) = result["operation_id"].as_str() {
                        if let Some(confirmed) = context.confirmed_operation(operation)? {
                            result = confirmed;
                        }
                    }
                    result["delivery"] = delivery;
                }
                Err(e) => {
                    result["delivery_error"] = json!(e);
                    result["pending"] = json!(true);
                }
            }
        }
    }
    Ok(result)
}

async fn commit(context: &Context, command: &Command, offline: bool) -> Result<Value> {
    let Command::Commit {
        message,
        all,
        allow_empty,
        operation_id,
        expected_head,
        resolved_conflicts,
    } = command
    else {
        unreachable!()
    };
    if operation_id.as_ref().is_some_and(|v| {
        v.is_empty()
            || v.len() > 100
            || !v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return Err("invalid_operation_id".into());
    }
    let prior = operation_id.as_ref().map(|id| {
        context
            .repo
            .state
            .join("cli-operations")
            .join(format!("{id}.json"))
    });
    let request = if prior.as_ref().is_some_and(|p| p.exists()) {
        let retained = context::read_json(prior.as_ref().unwrap())?;
        if retained["op"] != "commit"
            || retained["message"] != *message
            || retained["workspace"] != context.repo.workspace
        {
            return Err("idempotency_mismatch".into());
        }
        retained
    } else {
        if *all {
            staging::add(context, &[".".into()])?;
        }
        let index = staging::index(context)?;
        if index.tree == index.base_tree && !allow_empty {
            return Err("nothing_staged: use wip add PATH or wip commit --all".into());
        }
        let mut request = json!({"op":"commit","workspace":context.repo.workspace,"message":message,"expected_generation":index.generation,"staged_tree":index.tree,"operation_id":operation_id.clone().unwrap_or_else(||id("commit"))});
        if let Some(head) = expected_head {
            request["expected_head"] = json!(head);
        }
        if let Some(paths) = resolved_conflicts {
            request["resolved_conflicts"] = json!(paths);
        }
        let review = context.repo.root.join(".wip/resolution.json");
        if review.exists() {
            let details = context::read_json(&review)?;
            if details["used"] != true {
                if details["completion"] == "resolve_merge" {
                    return Err("private_merge_review: use wip conflict resolve from the original workspace".into());
                }
                if resolved_conflicts.is_none() {
                    return Err(format!("resolution_attestation_required: review these paths and pass --resolved-conflicts: {}",details["conflict_paths"]));
                }
                if request.get("expected_head").is_none() {
                    request["expected_head"] = details["resolution_head"].clone();
                }
            }
        }
        request
    };
    let mut result = context.mutation(request.clone())?;
    clear_saved_index(context, &request, &result)?;
    let commit_id = request["operation_id"].clone();
    if result["submitted"] == true || result.get("commit_id").is_some() {
        if !offline && (context.repo.profile.is_some() || result["shared"] != true) {
            if let Err(e) = remote::sync(context).await {
                result["delivery_error"] = json!(e);
            }
        }
        let observed = context.call(json!({"op":"commit_status","commit_id":commit_id}));
        if observed["ok"] == true {
            for field in [
                "state",
                "shared",
                "head",
                "validation",
                "repo_health",
                "resolution_task",
                "next_action",
                "notices",
            ] {
                if let Some(value) = observed.get(field) {
                    result[field] = value.clone();
                }
            }
        }
        result["pending"] = json!(result["shared"] != true && result["state"] != "blocked");
        let review = context.repo.root.join(".wip/resolution.json");
        if result["shared"] == true && review.exists() {
            let mut details = context::read_json(&review)?;
            details["used"] = json!(true);
            context::write_json(&review, &details)?;
        }
    }
    Ok(result)
}

fn clear_saved_index(context: &Context, request: &Value, result: &Value) -> Result<()> {
    if result["saved_locally"] == true || result["submitted"] == true {
        if let Ok(index) = staging::index(context) {
            if request["expected_generation"] == index.generation
                && request["staged_tree"] == index.tree
            {
                staging::clear(context)?;
            }
        } else if context.workspace()?.0
            == request["expected_generation"]
                .as_u64()
                .unwrap_or(u64::MAX)
                .saturating_add(1)
        {
            staging::clear(context)?;
        }
    }
    Ok(())
}

async fn operation(context: &Context, command: &Operation, offline: bool) -> Result<Value> {
    let (id, retry) = match command {
        Operation::List { page } => {
            let directory = context.repo.state.join("cli-operations");
            let mut records = Vec::new();
            if directory.exists() {
                for entry in fs::read_dir(directory).map_err(fail)? {
                    let entry = entry.map_err(fail)?;
                    let path = entry.path();
                    if path.extension().is_none_or(|s| s != "json") {
                        continue;
                    }
                    let request = context::read_json(&path)?;
                    if request["workspace"] != context.repo.workspace {
                        continue;
                    }
                    let modified = entry
                        .metadata()
                        .map_err(fail)?
                        .modified()
                        .map_err(fail)?
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(fail)?
                        .as_secs();
                    records.push(json!({"operation_id":request["operation_id"],"op":request["op"],"recorded_at":modified}));
                }
            }
            records.sort_by_key(|v| std::cmp::Reverse(v["recorded_at"].as_u64().unwrap_or(0)));
            let start = (page.cursor as usize).min(records.len());
            let end = (start + page.limit as usize).min(records.len());
            return Ok(
                json!({"ok":true,"operations":&records[start..end],"next_cursor":end,"has_more":end<records.len()}),
            );
        }
        Operation::Show { id } => (id, false),
        Operation::Retry { id } => (id, true),
    };
    if id.is_empty()
        || id.len() > 100
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid_operation_id".into());
    }
    if !retry {
        return Ok(
            context.call(json!({"op":"operation_status","operation_id":id,"include_record":true}))
        );
    }
    let path = context
        .repo
        .state
        .join("cli-operations")
        .join(format!("{id}.json"));
    let request = if path.exists() {
        context::read_json(&path)?
    } else {
        let record =
            context.call(json!({"op":"operation_status","operation_id":id,"include_record":true}));
        if !record["request"].is_object() {
            return Err("operation_not_found: no exact retained request is available".into());
        }
        record["request"].clone()
    };
    if request["workspace"] != context.repo.workspace {
        return Err("operation_workspace_mismatch".into());
    }
    let original = context.mutation(request.clone())?;
    clear_saved_index(context, &request, &original)?;
    if !offline {
        let _ = remote::sync(context).await;
    }
    let mut result =
        context.call(json!({"op":"operation_status","operation_id":id,"include_record":true}));
    result["retained_request"] = request.clone();
    if request["op"] == "commit" && original["submitted"] == true {
        let current = context.call(json!({"op":"commit_status","commit_id":id}));
        result["current"] = current.clone();
        result["shared"] = current["shared"].clone();
        result["recorded_operation_state"] = result["state"].clone();
        result["state"] = current["state"].clone();
        result["commit_id"] = json!(id);
        result["head"] = current["head"].clone();
        result["pending"] = json!(current["shared"] != true && current["state"] != "blocked");
    }
    Ok(result)
}

fn read_value(value: &str) -> Result<Value> {
    if value == "-" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(fail)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("input_too_large".into());
        }
        serde_json::from_slice(&bytes).map_err(fail)
    } else if let Some(path) = value.strip_prefix('@') {
        context::read_json(Path::new(path))
    } else {
        serde_json::from_str(value).map_err(fail)
    }
}

fn diff(
    context: &Context,
    staged: bool,
    base: Option<&str>,
    head: Option<&str>,
    path: Option<&str>,
) -> Result<Value> {
    if base.is_some() || head.is_some() {
        return Ok(context.call(json!({"op":"diff","base":base.ok_or("base_required")?,"head":head.ok_or("head_required")?,"path":path.ok_or("path_required")?})));
    }
    let index = staging::index(context)?;
    let (base, head) = if staged {
        (index.base_tree, index.tree)
    } else {
        (index.tree, context.git().capture(&context.repo.root)?)
    };
    let mut args = vec![
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        &base,
        &head,
        "--",
    ];
    if let Some(path) = path {
        args.push(path);
    }
    let bytes = context.git().run(&args, None)?;
    Ok(json!({"ok":true,"patch":String::from_utf8_lossy(&bytes),"base_tree":base,"head_tree":head}))
}
fn log(context: &Context, limit: u32) -> Result<Value> {
    let git = crate::git::Git::open(&context.repo.state.join("coordinator.git"));
    let bytes = git.run(
        &[
            "log",
            "--format=%H%x00%ct%x00%s",
            &format!("--max-count={limit}"),
            "refs/wipstash/integration",
            "--",
        ],
        None,
    )?;
    let commits = String::from_utf8_lossy(&bytes)
        .lines()
        .map(|line| {
            let mut p = line.splitn(3, '\0');
            json!({"head":p.next(),"timestamp":p.next(),"message":p.next()})
        })
        .collect::<Vec<_>>();
    Ok(json!({"ok":true,"commits":commits}))
}
fn open_resolution(
    context: &Context,
    path: &Path,
    commit: Option<&str>,
    candidate: Option<&str>,
) -> Result<Value> {
    let root = context::absolute(path)?;
    let workspace = id("resolution");
    let mut request = json!({"op":"resolution_open","workspace":context.repo.workspace,"resolution_workspace":workspace,"path":root});
    if let Some(v) = commit {
        request["commit_id"] = json!(v);
    }
    if let Some(v) = candidate {
        request["candidate"] = json!(v);
    }
    let result = context.mutation(request)?;
    if result["ok"] == true {
        Context::install(Repository {
            version: 1,
            root: root.clone(),
            state: context.repo.state.clone(),
            workspace,
            profile: context.repo.profile.clone(),
        })?;
        context::write_json(&root.join(".wip/resolution.json"), &result)?;
    }
    Ok(result)
}
fn import_audit(context: &Context, file: &Path) -> Result<Value> {
    let reader = std::io::BufReader::new(fs::File::open(file).map_err(fail)?);
    let mut imported = 0;
    for line in reader.lines() {
        let line = line.map_err(fail)?;
        if line.len() > 16 * 1024 * 1024 {
            return Err("audit_record_too_large".into());
        }
        if line.trim().is_empty() {
            continue;
        }
        let record: Value = serde_json::from_str(&line).map_err(fail)?;
        let result = context.call(json!({"op":"audit_record","record":record}));
        if result["ok"] != true {
            return Ok(result);
        }
        imported += 1;
    }
    Ok(json!({"ok":true,"imported":imported,"delivery":"pending_until_sync"}))
}
fn collect_audit(context: &Context, collector: &Path) -> Result<Value> {
    let result = std::process::Command::new("uv")
        .args(["run", "--no-project", "--python", "3.12", "python"])
        .arg(collector)
        .arg("--binary")
        .arg(std::env::current_exe().map_err(fail)?)
        .arg("--state")
        .arg(&context.repo.state)
        .arg("--once")
        .output()
        .map_err(fail)?;
    if !result.status.success() {
        return Err(format!(
            "native_collection_failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    serde_json::from_slice(&result.stdout).map_err(fail)
}
