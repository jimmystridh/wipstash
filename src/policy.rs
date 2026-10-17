//! Repair defaults to fail-closed OS confinement. Checks remain trusted commands.
//! Explicit trusted_unsandboxed repair is unsafe and for development fixtures only.
use crate::git::Git;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
const OUTPUT_LIMIT: usize = 8192; // Each stream; 16 KiB total retained.
pub struct Evaluation {
    pub tree: String,
    pub accepted: bool,
    pub repaired: bool,
    pub details: Value,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
struct Checkout(PathBuf);
impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn checkout(state: &Path, git: &Git, tree: &str) -> Result<Checkout, String> {
    let parent = state.join("candidates");
    fs::create_dir_all(&parent).map_err(error)?;
    let path = parent.join(format!(
        "run-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(error)?
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).map_err(error)?;
    let guard = Checkout(fs::canonicalize(path).map_err(error)?);
    git.materialize(tree, &guard.0)?;
    Ok(guard)
}
// Unlike Git capture, fingerprint includes ignored/excluded files and directories.
fn fingerprint(root: &Path) -> Result<String, String> {
    fn walk(root: &Path, path: &Path, h: &mut Sha256) -> Result<(), String> {
        let mut entries = fs::read_dir(path)
            .map_err(error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(error)?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let meta = fs::symlink_metadata(&p).map_err(error)?;
            if meta.file_type().is_symlink() {
                return Err("candidate contains symlink".into());
            }
            let name = p
                .strip_prefix(root)
                .map_err(error)?
                .to_str()
                .ok_or("candidate contains non-UTF8 path")?
                .as_bytes()
                .to_vec();
            h.update((name.len() as u64).to_be_bytes());
            h.update(name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                h.update(meta.permissions().mode().to_be_bytes());
            }
            if meta.is_dir() {
                h.update(b"dir");
                walk(root, &p, h)?;
            } else if meta.is_file() {
                h.update(b"file");
                h.update(meta.len().to_be_bytes());
                let mut f = fs::File::open(p).map_err(error)?;
                let mut buf = [0; 8192];
                loop {
                    let n = f.read(&mut buf).map_err(error)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
            } else {
                return Err("candidate contains special file".into());
            }
        }
        Ok(())
    }
    let mut h = Sha256::new();
    walk(root, root, &mut h)?;
    Ok(format!("{:x}", h.finalize()))
}
fn argv(spec: &Value) -> Result<Vec<String>, String> {
    let a = spec
        .get("argv")
        .and_then(Value::as_array)
        .ok_or("policy command requires argv array")?;
    if a.is_empty() {
        return Err("policy argv cannot be empty".into());
    }
    a.iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.contains('\0'))
                .map(str::to_owned)
                .ok_or_else(|| "policy argv must contain strings without NUL".into())
        })
        .collect()
}
fn timeout(spec: &Value) -> Result<u64, String> {
    match spec.get("timeout_seconds") {
        None => Ok(60),
        Some(v) => v
            .as_u64()
            .filter(|n| *n > 0 && *n <= 600)
            .ok_or_else(|| "timeout_seconds must be 1..600".into()),
    }
}
/// Validate a command before persisting configuration or starting any work.
pub fn validate_command(spec: &Value) -> Result<(), String> {
    let args = argv(spec)?;
    if args[0].trim().is_empty() {
        return Err("policy executable cannot be empty".into());
    }
    timeout(spec)?;
    Ok(())
}
pub fn validate_policy(policy: &Value) -> Result<(), String> {
    let object = policy.as_object().ok_or("policy must be an object")?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "checks" | "repair"))
    {
        return Err("unknown policy field".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    if let Some(checks) = policy.get("checks") {
        for check in checks.as_array().ok_or("policy checks must be an array")? {
            validate_command(check)?;
            let id = check
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty() && !id.contains('\0'))
                .ok_or("check requires nonempty string id")?;
            if !ids.insert(id) {
                return Err("duplicate check id".into());
            }
            if check.get("required").is_some_and(|v| !v.is_boolean()) {
                return Err("required must be boolean".into());
            }
            if check
                .as_object()
                .unwrap()
                .keys()
                .any(|key| !matches!(key.as_str(), "id" | "argv" | "timeout_seconds" | "required"))
            {
                return Err("unknown check field".into());
            }
        }
    }
    if let Some(repair) = policy.get("repair").filter(|v| !v.is_null()) {
        validate_command(repair)?;
        if repair.as_object().unwrap().keys().any(|key| {
            !matches!(
                key.as_str(),
                "argv"
                    | "timeout_seconds"
                    | "max_attempts"
                    | "execution_profile"
                    | "sandbox_disabled"
            )
        }) {
            return Err("unknown repair field".into());
        }
        if repair
            .get("execution_profile")
            .is_some_and(|v| !matches!(v.as_str(), Some("confined" | "trusted_unsandboxed")))
        {
            return Err("execution_profile must be confined or trusted_unsandboxed".into());
        }
        if repair
            .get("sandbox_disabled")
            .is_some_and(|v| !v.is_boolean())
        {
            return Err("sandbox_disabled must be boolean".into());
        }
        if repair.get("execution_profile").and_then(Value::as_str) != Some("trusted_unsandboxed")
            && timeout(repair)? > 120
        {
            return Err("confined repair timeout_seconds must be 1..120".into());
        }
        if repair
            .get("max_attempts")
            .is_some_and(|v| !v.as_u64().is_some_and(|n| (1..=2).contains(&n)))
        {
            return Err("max_attempts must be 1..2".into());
        }
    }
    Ok(())
}
// Reserve before launching a worker. Interrupted reservations are intentionally
// charged in full; neither restart, a new head nor policy edits refund them.
fn reserve_repair(
    state: &Path,
    proposal: &str,
    attempts: u64,
    seconds: u64,
) -> Result<Option<u64>, String> {
    let mut db = rusqlite::Connection::open(state.join("repair-budget.sqlite")).map_err(error)?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS repair_budgets(proposal TEXT PRIMARY KEY, attempts INTEGER NOT NULL, seconds INTEGER NOT NULL);").map_err(error)?;
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(error)?;
    tx.execute(
        "INSERT OR IGNORE INTO repair_budgets VALUES(?1,0,0)",
        [proposal],
    )
    .map_err(error)?;
    let (used, allocated): (u64, u64) = tx
        .query_row(
            "SELECT attempts,seconds FROM repair_budgets WHERE proposal=?1",
            [proposal],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(error)?;
    if used >= attempts || allocated.saturating_add(seconds) > 600 {
        return Ok(None);
    }
    tx.execute(
        "UPDATE repair_budgets SET attempts=attempts+1,seconds=seconds+?2 WHERE proposal=?1",
        rusqlite::params![proposal, seconds],
    )
    .map_err(error)?;
    tx.commit().map_err(error)?;
    Ok(Some(used + 1))
}
fn collect(mut pipe: impl Read) -> (String, u64, bool) {
    let mut kept = Vec::new();
    let mut total = 0u64;
    let mut buf = [0u8; 8192];
    let mut read_ok = true;
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total = total.saturating_add(n as u64);
                let take = n.min(OUTPUT_LIMIT - kept.len());
                kept.extend_from_slice(&buf[..take]);
            }
            Err(_) => {
                read_ok = false;
                break;
            }
        }
    }
    (hash(&kept), total, read_ok)
}
/// Resolve only the explicit trusted runtime path; never inherit a caller PATH.
fn command_executable(argument: &str, cwd: &Path) -> Result<PathBuf, String> {
    let path = Path::new(argument);
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    #[cfg(unix)]
    {
        if argument.contains('/') {
            return Ok(cwd.join(path));
        }
        for directory in ["/usr/bin", "/bin"] {
            let candidate = Path::new(directory).join(path);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Err("policy executable not found in /usr/bin:/bin".into())
    }
    #[cfg(not(unix))]
    {
        Err("policy executable must be an absolute native executable path on this platform".into())
    }
}
pub(crate) fn run(
    spec: &Value,
    cwd: &Path,
    head: &str,
    proposal: &str,
    tree: &str,
    deadline: Instant,
) -> Result<Value, String> {
    run_with_conflicts(spec, cwd, head, proposal, tree, deadline, None)
}
fn run_with_conflicts(
    spec: &Value,
    cwd: &Path,
    head: &str,
    proposal: &str,
    tree: &str,
    deadline: Instant,
    conflicts: Option<&[String]>,
) -> Result<Value, String> {
    validate_command(spec)?;
    let args = argv(spec)?;
    let seconds = timeout(spec)?;
    if Instant::now() >= deadline {
        return Ok(
            json!({"success":false,"timed_out":true,"reason":"evaluation_budget_exhausted"}),
        );
    }
    let cwd = fs::canonicalize(cwd).map_err(error)?;
    let mut environment: Vec<(std::ffi::OsString, std::ffi::OsString)> = vec![
        ("LANG".into(), "C".into()),
        ("LC_ALL".into(), "C".into()),
        ("HOME".into(), cwd.as_os_str().into()),
        ("TMPDIR".into(), cwd.as_os_str().into()),
        ("WIPSTASH_HEAD".into(), head.into()),
        ("WIPSTASH_PROPOSAL".into(), proposal.into()),
        ("WIPSTASH_CANDIDATE_TREE".into(), tree.into()),
    ];
    #[cfg(unix)]
    environment.push(("PATH".into(), "/usr/bin:/bin".into()));
    #[cfg(windows)]
    {
        // Runtime initialization may need SystemRoot; no credentials or arbitrary
        // caller variables are inherited. Windows commands require absolute paths.
        if let Some(root) = std::env::var_os("SystemRoot") {
            environment.push(("SystemRoot".into(), root.clone()));
            environment.push((
                "PATH".into(),
                Path::new(&root).join("System32").into_os_string(),
            ));
        }
        environment.push(("TEMP".into(), cwd.as_os_str().into()));
        environment.push(("TMP".into(), cwd.as_os_str().into()));
        environment.push(("USERPROFILE".into(), cwd.as_os_str().into()));
    }
    if let Some(paths) = conflicts {
        environment.push((
            "WIPSTASH_CONFLICT_PATHS".into(),
            serde_json::to_string(paths).map_err(error)?.into(),
        ));
        environment.push((
            "WIPSTASH_RESOLUTION_FILE".into(),
            cwd.join(".wipstash-resolution.json").into_os_string(),
        ));
    }
    let launch = wipstash_platform::Launch {
        executable: command_executable(&args[0], &cwd)?,
        arguments: args[1..].iter().map(Into::into).collect(),
        directory: cwd,
        environment,
        purpose: wipstash_platform::Purpose::CooperativeCommand,
    };
    let mut child = match wipstash_platform::ManagedProcess::spawn_piped(&launch) {
        Ok(c) => c,
        Err(e) => {
            return Ok(json!({"success":false,"spawn_error":e.to_string(),
                "argv_hash":hash(&serde_json::to_vec(&args).map_err(error)?)}))
        }
    };
    let (out, err) = child.take_output().ok_or("missing output pipes")?;
    let (out_tx, out_rx) = std::sync::mpsc::channel();
    let (err_tx, err_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = out_tx.send(collect(out));
    });
    std::thread::spawn(move || {
        let _ = err_tx.send(collect(err));
    });
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(seconds));
    let outcome = child.finish(remaining).map_err(error)?;
    let (exit_code, timed_out) = match outcome.completion {
        wipstash_platform::Completion::Exited { code } => (code, false),
        wipstash_platform::Completion::TimedOut => (None, true),
    };
    let drain = match outcome.drain {
        wipstash_platform::DrainEvidence::WindowsJobEmpty => "windows_job_empty",
        wipstash_platform::DrainEvidence::CooperativeOnly => "cooperative_only",
    };
    // Do not wait indefinitely if an unsandboxed worker escapes its process group.
    let stdout = out_rx
        .recv_timeout(Duration::from_millis(200))
        .unwrap_or_else(|_| (hash(b""), 0, false));
    let stderr = err_rx
        .recv_timeout(Duration::from_millis(200))
        .unwrap_or_else(|_| (hash(b""), 0, false));
    Ok(
        json!({"success":exit_code == Some(0)&&!timed_out&&stdout.2&&stderr.2,"exit_code":exit_code,"process_drain":drain,"execution_is_os_sandboxed":false,"timed_out":timed_out,"argv_hash":hash(&serde_json::to_vec(&args).map_err(error)?),"stdout_prefix_sha256":stdout.0,"stderr_prefix_sha256":stderr.0,"stdout_bytes":stdout.1,"stderr_bytes":stderr.1,"output_collection_complete":stdout.2&&stderr.2,"output_truncated":stdout.1>OUTPUT_LIMIT as u64||stderr.1>OUTPUT_LIMIT as u64,"retained_output_limit_bytes":16384}),
    )
}
/// Only this boundary may choose the explicitly unsafe development profile.
#[allow(clippy::too_many_arguments)]
fn run_repair(
    spec: &Value,
    cwd: &Path,
    head: &str,
    proposal: &str,
    tree: &str,
    deadline: Instant,
    conflicts: &[String],
) -> Result<Value, String> {
    let profile = spec
        .get("execution_profile")
        .and_then(Value::as_str)
        .unwrap_or("confined");
    if spec.get("sandbox_disabled") == Some(&json!(true)) {
        return Ok(
            json!({"success":false,"unavailable":true,"reason":"sandbox_disabled_by_policy",
            "execution_profile":profile,"execution_is_os_sandboxed":false,"worker_started":false}),
        );
    }
    if profile == "trusted_unsandboxed" {
        let mut record =
            run_with_conflicts(spec, cwd, head, proposal, tree, deadline, Some(conflicts))?;
        record["execution_profile"] = json!(profile);
        record["execution_backend"] = json!("unsafe_development_bare_process");
        record["execution_is_os_sandboxed"] = json!(false);
        record["unsafe_development_only"] = json!(true);
        return Ok(record);
    }
    let args = argv(spec)?;
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(timeout(spec)?));
    if remaining.is_zero() {
        return Ok(
            json!({"success":false,"timed_out":true,"reason":"evaluation_budget_exhausted"}),
        );
    }
    let request = wipstash_repair_runner::Request {
        candidate: cwd.to_path_buf(),
        executable: args[0].clone().into(),
        args: args[1..].to_vec(),
        timeout: remaining,
        output_limit: OUTPUT_LIMIT * 2,
        bindings: Some(wipstash_repair_runner::Bindings {
            head: head.into(),
            proposal: proposal.into(),
            candidate_tree: tree.into(),
            conflict_paths_json: serde_json::to_string(conflicts).map_err(error)?,
        }),
    };
    let mut record = json!({"success":false,"execution_profile":"confined","execution_backend":if cfg!(target_os = "linux") { "linux_bubblewrap" } else { "unavailable" },
        "execution_is_os_sandboxed":false,"argv_hash":hash(&serde_json::to_vec(&args).map_err(error)?),
        "sandbox_candidate_path":"/workspace","sandbox_resolution_file":"/workspace/.wipstash-resolution.json",
        "provenance_bindings":{"WIPSTASH_HEAD":head,"WIPSTASH_PROPOSAL":proposal,"WIPSTASH_CANDIDATE_TREE":tree,"WIPSTASH_CONFLICT_PATHS":conflicts},
        "retained_output_limit_bytes":OUTPUT_LIMIT*2});
    match wipstash_repair_runner::run(&request) {
        Ok(out) => {
            record["success"] = json!(true);
            record["execution_is_os_sandboxed"] = json!(true);
            record["exit_code"] = json!(0);
            record["stdout_prefix_sha256"] = json!(hash(&out.stdout));
            record["stderr_prefix_sha256"] = json!(hash(&out.stderr));
            record["stdout_bytes"] = json!(out.stdout.len());
            record["stderr_bytes"] = json!(out.stderr.len());
            record["output_collection_complete"] = json!(true);
        }
        Err(wipstash_repair_runner::Error::TimedOut) => {
            record["timed_out"] = json!(true);
            record["reason"] = json!("confined_repair_timeout");
        }
        Err(wipstash_repair_runner::Error::OutputLimit) => {
            record["reason"] = json!("confined_repair_output_limit");
        }
        Err(wipstash_repair_runner::Error::Failed { code, stderr }) => {
            record["exit_code"] = json!(code);
            record["reason"] = json!("sandbox_or_worker_failed");
            record["stderr_prefix_sha256"] = json!(hash(&stderr));
            // Never claim a nonzero bwrap exit proves its worker was launched.
            record["confinement_verified"] = json!(false);
        }
        Err(e) => {
            record["unavailable"] = json!(true);
            record["reason"] = json!("confined_repair_unavailable");
            record["error"] = json!(e.to_string());
        }
    }
    Ok(record)
}
fn validate_report(
    path: &Path,
    head: &str,
    proposal: &str,
    tree: &str,
    conflicts: &[String],
) -> Result<Value, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "missing resolution report".to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 65536 {
        return Err("invalid resolution report file".into());
    }
    let report: Value = serde_json::from_slice(&fs::read(path).map_err(error)?).map_err(error)?;
    if report["head"] != head || report["proposal"] != proposal || report["input_tree"] != tree {
        return Err("resolution report input mismatch".into());
    }
    let paths = report["resolved_paths"]
        .as_array()
        .ok_or("resolution report requires resolved_paths")?;
    let actual: std::collections::BTreeSet<&str> = paths
        .iter()
        .map(|p| p.as_str().ok_or("resolved_paths must contain strings"))
        .collect::<Result<_, _>>()?;
    let expected: std::collections::BTreeSet<&str> = conflicts.iter().map(String::as_str).collect();
    if expected.is_empty()
        || expected.len() != conflicts.len()
        || actual.len() != paths.len()
        || actual != expected
    {
        return Err(
            "resolution report must cover exactly every conflict path without duplicates".into(),
        );
    }
    Ok(report)
}
fn conflict_paths_changed(
    git: &Git,
    before: &str,
    after: &str,
    paths: &[String],
) -> Result<bool, String> {
    fn object(git: &Git, tree: &str, path: &str) -> Result<Option<String>, String> {
        let spec = format!(":(literal){path}");
        let bytes = git.run(&["ls-tree", "-z", tree, "--", &spec], None)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let header = bytes
            .split(|b| *b == b'\t')
            .next()
            .ok_or("invalid tree entry")?;
        let oid = std::str::from_utf8(header)
            .map_err(error)?
            .split(' ')
            .nth(2)
            .ok_or("invalid tree entry")?;
        Ok(Some(oid.to_owned()))
    }
    if paths.is_empty() {
        return Ok(false);
    }
    for path in paths {
        if object(git, before, path)? == object(git, after, path)? {
            return Ok(false);
        }
    }
    Ok(true)
}
// Immutable candidate inputs are deliberately explicit at this boundary.
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    state: &Path,
    git: &Git,
    head: &str,
    proposal: &str,
    tree: &str,
    conflicted: bool,
    conflict_paths: &[String],
    policy: &Value,
) -> Result<Evaluation, String> {
    validate_policy(policy)?;
    let empty = Vec::new();
    let checks = match policy.get("checks") {
        None => &empty,
        Some(v) => v.as_array().ok_or("policy checks must be an array")?,
    };
    // Validate the complete policy before executing anything.
    for check in checks {
        argv(check)?;
        timeout(check)?;
        if check.get("id").and_then(Value::as_str).is_none() {
            return Err("check requires string id".into());
        }
        if check.get("required").is_some_and(|v| !v.is_boolean()) {
            return Err("required must be boolean".into());
        }
    }
    let repair = policy.get("repair").filter(|v| !v.is_null());
    let attempts = if let Some(r) = repair {
        argv(r)?;
        timeout(r)?;
        match r.get("max_attempts") {
            None => 2,
            Some(v) => v
                .as_u64()
                .filter(|n| *n > 0 && *n <= 2)
                .ok_or("max_attempts must be 1..2")?,
        }
    } else {
        0
    };
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut current = tree.to_owned();
    let mut repaired = false;
    let mut records = Vec::new();
    let mut accepted = !conflicted;
    let mut budget_exhausted = false;
    if conflicted {
        if let Some(worker) = repair {
            for _ in 0..attempts {
                let Some(attempt) = reserve_repair(state, proposal, attempts, timeout(worker)?)?
                else {
                    budget_exhausted = true;
                    break;
                };
                let dir = checkout(state, git, tree)?;
                let report_path = dir.0.join(".wipstash-resolution.json");
                if report_path.exists() {
                    return Err("reserved resolution report path exists in candidate".into());
                }
                let mut record = run_repair(
                    worker,
                    &dir.0,
                    head,
                    proposal,
                    tree,
                    deadline,
                    conflict_paths,
                )?;
                let report = validate_report(&report_path, head, proposal, tree, conflict_paths);
                if report_path.is_file() || report_path.is_symlink() {
                    fs::remove_file(&report_path).map_err(error)?;
                }
                record["resolution_report_valid"] = json!(report.is_ok());
                if let Err(e) = &report {
                    record["resolution_report_error"] = json!(e);
                }
                if let Ok(value) = &report {
                    record["resolution_report"] = value.clone();
                }
                let captured = git.capture(&dir.0);
                record["attempt"] = json!(attempt);
                record["input_tree"] = json!(tree);
                match captured {
                    Ok(after) => {
                        record["output_tree"] = json!(after);
                        if record["success"] == true
                            && report.is_ok()
                            && after != tree
                            && conflict_paths_changed(git, tree, &after, conflict_paths)?
                        {
                            current = after;
                            repaired = true;
                            accepted = true;
                        } else {
                            record["unresolved"] = json!(true);
                        }
                    }
                    Err(e) => {
                        record["capture_error"] = json!(e);
                    }
                }
                records.push(record);
                if repaired || Instant::now() >= deadline {
                    break;
                }
            }
        }
    }
    let mut check_records = Vec::new();
    if accepted {
        for check in checks {
            let dir = checkout(state, git, &current)?;
            let before = fingerprint(&dir.0)?;
            let mut record = run(check, &dir.0, head, proposal, &current, deadline)?;
            let after = fingerprint(&dir.0);
            let unchanged = after.as_ref().is_ok_and(|s| s == &before);
            let captured = git.capture(&dir.0);
            let exact = captured.as_ref().is_ok_and(|s| s == &current);
            let required = check
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            record["id"] = check["id"].clone();
            record["required"] = json!(required);
            record["candidate_tree"] = json!(current);
            record["checkout_unchanged"] = json!(unchanged && exact);
            record["before_sha256"] = json!(before);
            record["after_sha256"] = json!(after.ok());
            if !unchanged || !exact || (required && record["success"] != true) {
                accepted = false;
            }
            check_records.push(record);
        }
    }
    // The aggregate is true only when every executed repair succeeded through
    // the confined backend and there were no trusted, unsandboxed checks.
    let all_execution_sandboxed = !records.is_empty()
        && check_records.is_empty()
        && records
            .iter()
            .all(|r| r["execution_is_os_sandboxed"] == true);
    Ok(Evaluation {
        tree: current.clone(),
        accepted,
        repaired,
        details: json!({"head":head,"proposal":proposal,"input_tree":tree,"candidate_tree":current,"conflicted":conflicted,"conflict_paths":conflict_paths,"policy_sha256":hash(&serde_json::to_vec(policy).map_err(error)?),"policy":policy,"repair_attempts":records,"repair_budget_durable":true,"repair_budget_exhausted":budget_exhausted,"repair_budget_scope":"public_proposal_commit","repair_budget_seconds_reservation_limit":600,"checks":check_records,"accepted":accepted,"repaired":repaired,"resolution_authority":if repaired {"configured_worker_report_and_changed_conflict_paths"}else{"none"},"repair_status":if repaired&&checks.is_empty(){"agent_resolved_unchecked"}else if repaired{"agent_resolved_checked"}else{"not_repaired"},"semantic_correctness_claimed":false,"execution_is_os_sandboxed":all_execution_sandboxed,"repair_execution_profile":repair.and_then(|r|r.get("execution_profile").and_then(Value::as_str)).unwrap_or("confined"),"checks_execution_profile":"trusted_unsandboxed"}),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn fixture() -> (Checkout, Git, String) {
        let p = std::env::temp_dir().join(format!(
            "wipstash-policy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        let g = Git::init(&p.join("repo")).unwrap();
        let src = p.join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("file"), b"original\n").unwrap();
        let t = g.capture(&src).unwrap();
        (Checkout(p), g, t)
    }
    #[test]
    fn rejects_invalid_policy_before_work() {
        for policy in [
            json!({"checks":[{"id":"","argv":["/bin/true"]}]}),
            json!({"checks":[{"id":"a","argv":[""]}]}),
            json!({"checks":[{"id":"a","argv":["/bin/true"]},{"id":"a","argv":["/bin/true"]}]}),
            json!({"repair":{"execution_profile":"trusted_unsandboxed","argv":["/bin/true"],"max_attempts":3}}),
            json!({"check":[]}),
        ] {
            assert!(validate_policy(&policy).is_err(), "{policy}");
        }
    }
    #[test]
    fn default_confined_denial_never_starts_worker() {
        let (d, g, t) = fixture();
        let marker = d.0.join("must-not-exist");
        let e=evaluate(&d.0,&g,"head","proposal",&t,true,&["file".into()],
            &json!({"repair":{"argv":["/bin/sh","-c",format!("touch {}",marker.display())],"sandbox_disabled":true,"max_attempts":1}})).unwrap();
        assert!(!e.accepted && !e.repaired && !marker.exists());
        let attempt = &e.details["repair_attempts"][0];
        assert_eq!(attempt["execution_profile"], "confined");
        assert_eq!(attempt["unavailable"], true);
        assert_eq!(attempt["worker_started"], false);
        assert_eq!(e.details["repair_budget_durable"], true);
        assert!(e.details["checks"].as_array().unwrap().is_empty());
        assert_eq!(reserve_repair(&d.0, "proposal", 1, 60).unwrap(), None);
    }
    #[test]
    fn profile_validation_is_explicit() {
        for repair in [
            json!({"argv":["/bin/true"],"execution_profile":"automatic_fallback"}),
            json!({"argv":["/bin/true"],"sandbox_disabled":"false"}),
            json!({"argv":["/bin/true"],"timeout_seconds":121}),
        ] {
            assert!(validate_policy(&json!({"repair":repair})).is_err());
        }
        assert!(validate_policy(&json!({"repair":{"argv":["/bin/true"],"execution_profile":"trusted_unsandboxed","timeout_seconds":121}})).is_ok());
    }
    #[test]
    fn durable_reservations_survive_reopen_and_changed_policy() {
        let (d, g, t) = fixture();
        assert_eq!(reserve_repair(&d.0, "p", 2, 60).unwrap(), Some(1));
        // This reservation has no completion record, simulating interruption.
        let e = evaluate(
            &d.0,
            &g,
            "new-head",
            "p",
            &t,
            true,
            &["file".into()],
            &json!({"repair":{"execution_profile":"trusted_unsandboxed","argv":["/bin/true"]}}),
        )
        .unwrap();
        assert_eq!(e.details["repair_attempts"].as_array().unwrap().len(), 1);
        let e = evaluate(
            &d.0,
            &g,
            "another-head",
            "p",
            &t,
            true,
            &["file".into()],
            &json!({"repair":{"execution_profile":"trusted_unsandboxed","argv":["/bin/false"]}}),
        )
        .unwrap();
        assert!(!e.accepted);
        assert_eq!(e.details["repair_attempts"].as_array().unwrap().len(), 0);
        assert_eq!(e.details["repair_budget_exhausted"], true);
        assert_eq!(reserve_repair(&d.0, "other", 2, 600).unwrap(), Some(1));
        assert_eq!(reserve_repair(&d.0, "other", 2, 1).unwrap(), None);
    }
    #[test]
    fn defaults_quarantine_conflicts() {
        let (d, g, t) = fixture();
        assert!(
            evaluate(&d.0, &g, "h", "p", &t, false, &[], &json!({}))
                .unwrap()
                .accepted
        );
        assert!(
            !evaluate(&d.0, &g, "h", "p", &t, true, &["file".into()], &json!({}))
                .unwrap()
                .accepted
        );
    }
    #[test]
    fn required_and_advisory() {
        let (d, g, t) = fixture();
        for required in [true, false] {
            let e=evaluate(&d.0,&g,"h","p",&t,false,&[],&json!({"checks":[{"id":"fail","argv":["/bin/sh","-c","exit 4"],"required":required}]})).unwrap();
            assert_eq!(e.accepted, !required);
            assert_eq!(e.details["checks"][0]["exit_code"], 4);
        }
    }
    #[test]
    fn rejects_mutating_checks_even_ignored_artifacts() {
        let (d, g, t) = fixture();
        for command in [
            "echo changed > file",
            "mkdir target; echo artifact > target/out",
        ] {
            let e=evaluate(&d.0,&g,"h","p",&t,false,&[],&json!({"checks":[{"id":"mutator","argv":["/bin/sh","-c",command],"required":false}]})).unwrap();
            assert!(!e.accepted);
        }
    }
    fn manifest_script(change: &str) -> String {
        format!(
            r#"{}; printf '{{"head":"%s","proposal":"%s","input_tree":"%s","resolved_paths":%s}}' "$WIPSTASH_HEAD" "$WIPSTASH_PROPOSAL" "$WIPSTASH_CANDIDATE_TREE" "$WIPSTASH_CONFLICT_PATHS" > "$WIPSTASH_RESOLUTION_FILE""#,
            change
        )
    }
    #[test]
    fn configured_simulated_repair_provenance() {
        let (d, g, t) = fixture();
        let e=evaluate(&d.0,&g,"head-id","proposal-id",&t,true,&["file".into()],&json!({"repair":{"execution_profile":"trusted_unsandboxed","argv":["/bin/sh","-c",manifest_script("echo resolved > file")],"max_attempts":2},"checks":[{"id":"resolved","argv":["/bin/sh","-c","grep -q resolved file"]}]})).unwrap();
        assert!(e.accepted && e.repaired);
        assert_eq!(
            e.details["repair_attempts"][0]["unsafe_development_only"],
            true
        );
        assert_eq!(
            e.details["repair_attempts"][0]["execution_is_os_sandboxed"],
            false
        );
        assert_ne!(e.tree, t);
        assert_eq!(e.details["checks"][0]["candidate_tree"], e.tree);
        assert_eq!(e.details["semantic_correctness_claimed"], false);
    }
    #[test]
    fn unrelated_change_with_valid_report_is_rejected() {
        let (d, g, t) = fixture();
        let e = evaluate(
            &d.0,
            &g,
            "h",
            "p",
            &t,
            true,
            &["file".into()],
            &json!({"repair":{"execution_profile":"trusted_unsandboxed","argv":["/bin/sh","-c",manifest_script("echo unrelated > other")]}}),
        )
        .unwrap();
        assert!(!e.accepted && !e.repaired);
    }
    #[test]
    fn report_rejects_wrong_inputs_and_path_coverage() {
        let (d, _g, t) = fixture();
        let path = d.0.join("report");
        for paths in [
            json!([]),
            json!(["file", "extra"]),
            json!(["file", "file"]),
            json!(["other"]),
        ] {
            fs::write(
                &path,
                serde_json::to_vec(
                    &json!({"head":"h","proposal":"p","input_tree":t,"resolved_paths":paths}),
                )
                .unwrap(),
            )
            .unwrap();
            assert!(validate_report(&path, "h", "p", &t, &["file".into()]).is_err());
        }
        fs::write(
            &path,
            serde_json::to_vec(
                &json!({"head":"wrong","proposal":"p","input_tree":t,"resolved_paths":["file"]}),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(validate_report(&path, "h", "p", &t, &["file".into()]).is_err());
    }
    #[test]
    fn missing_report_is_rejected() {
        let (d, g, t) = fixture();
        let e = evaluate(
            &d.0,
            &g,
            "h",
            "p",
            &t,
            true,
            &["file".into()],
            &json!({"repair":{"execution_profile":"trusted_unsandboxed","argv":["/bin/sh","-c","echo resolved > file"]}}),
        )
        .unwrap();
        assert!(!e.accepted && !e.repaired);
    }
    #[test]
    fn unchecked_repair_labeled_and_report_excluded() {
        let (d, g, t) = fixture();
        let e = evaluate(
            &d.0,
            &g,
            "h",
            "p",
            &t,
            true,
            &["file".into()],
            &json!({"repair":{"execution_profile":"trusted_unsandboxed","argv":["/bin/sh","-c",manifest_script("echo resolved > file")]}}),
        )
        .unwrap();
        assert!(e.accepted && e.repaired);
        assert_eq!(e.details["repair_status"], "agent_resolved_unchecked");
        assert!(
            !String::from_utf8(g.run(&["ls-tree", "-r", &e.tree], None).unwrap())
                .unwrap()
                .contains(".wipstash-resolution.json")
        );
    }
    #[test]
    fn unchanged_worker_is_not_resolution() {
        let (d, g, t) = fixture();
        let e = evaluate(
            &d.0,
            &g,
            "h",
            "p",
            &t,
            true,
            &["file".into()],
            &json!({"repair":{"execution_profile":"trusted_unsandboxed","argv":["/bin/true"]}}),
        )
        .unwrap();
        assert!(!e.accepted && !e.repaired);
        assert_eq!(e.details["repair_attempts"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn output_is_bounded_and_hashed() {
        let (d, g, t) = fixture();
        let e = evaluate(
            &d.0,
            &g,
            "h",
            "p",
            &t,
            false,
            &[],
            &json!({"checks":[{"id":"loud","argv":["/bin/sh","-c","head -c 20000 /dev/zero"]}]}),
        )
        .unwrap();
        assert!(e.accepted);
        assert_eq!(e.details["checks"][0]["stdout_bytes"], 20000);
        assert_eq!(e.details["checks"][0]["output_truncated"], true);
        assert!(e.details["checks"][0].get("stdout").is_none());
    }
    #[test]
    fn timeout_is_failure() {
        let (d, g, t) = fixture();
        let e=evaluate(&d.0,&g,"h","p",&t,false,&[],&json!({"checks":[{"id":"timeout","argv":["/bin/sh","-c","sleep 30"],"timeout_seconds":1}]})).unwrap();
        assert!(!e.accepted);
        assert_eq!(e.details["checks"][0]["timed_out"], true);
    }
}

#[cfg(test)]
mod command_contract_tests {
    use super::*;
    #[test]
    fn capture_hashes_only_bounded_prefix() {
        let bytes = vec![b'x'; OUTPUT_LIMIT + 4096];
        let (digest, total, complete) = collect(std::io::Cursor::new(&bytes));
        assert_eq!(digest, hash(&bytes[..OUTPUT_LIMIT]));
        assert_eq!(total, bytes.len() as u64);
        assert!(complete);
    }
    #[test]
    fn expired_budget_does_not_launch() {
        let record = run(
            &json!({"argv":["must-not-run"]}),
            Path::new("missing"),
            "head",
            "proposal",
            "tree",
            Instant::now(),
        )
        .unwrap();
        assert_eq!(record["success"], false);
        assert_eq!(record["reason"], "evaluation_budget_exhausted");
    }
    #[cfg(unix)]
    #[test]
    fn resolution_never_uses_inherited_path() {
        let cwd = Path::new("/candidate");
        assert_eq!(
            command_executable("./tool", cwd).unwrap(),
            cwd.join("./tool")
        );
        assert_eq!(
            command_executable("/explicit/tool", cwd).unwrap(),
            Path::new("/explicit/tool")
        );
        assert!(command_executable("wipstash-nonexistent-test-tool", cwd).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn windows_requires_absolute_executable() {
        assert!(command_executable("cmd.exe", Path::new(r"C:\candidate")).is_err());
        assert!(
            command_executable(r"C:\Windows\System32\cmd.exe", Path::new(r"C:\candidate")).is_ok()
        );
    }
    #[cfg(windows)]
    #[test]
    fn native_windows_policy_capture() {
        let root = std::env::var_os("SystemRoot").unwrap();
        let executable = Path::new(&root).join("System32").join("cmd.exe");
        let record = run(
            &json!({"argv":[executable, "/D", "/C", "echo policy-output& exit 0"]}),
            &std::env::temp_dir(),
            "head",
            "proposal",
            "tree",
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(record["success"], true);
        assert_eq!(record["process_drain"], "windows_job_empty");
        assert_eq!(record["execution_is_os_sandboxed"], false);
        assert!(record["stdout_bytes"].as_u64().unwrap() > 0);
    }
}
