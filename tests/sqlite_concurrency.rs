//! Native-CI regression for serialized CLI writes with repeated SQLite WAL reopen.
//! No retries, journal changes, or subprocess execution outside native CI.
use serde_json::{json, Value};
use std::{fs, path::Path, process::{Command, Stdio}, sync::{Arc, Barrier}, time::{Duration, Instant}};

fn request(state: &Path, request: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wipstash"))
        .args(["--state", state.to_str().unwrap(), &request.to_string()])
        .env("WIPSTASH_SQLITE_DIAGNOSTICS", "1")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(45) {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("owned CLI exceeded deadline: {}", String::from_utf8_lossy(&output.stderr));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "request={request}; stdout={}; stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], true, "{result}");
    result
}

#[test]
fn native_concurrent_cli_wal_reopen_preserves_all_writes() {
    if std::env::var("GITHUB_ACTIONS").ok().as_deref() != Some("true") {
        eprintln!("native CI only: concurrent CLI WAL-reopen regression not executed");
        return;
    }
    let root = std::env::temp_dir().join(format!("wsql-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&root).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let source = root.join("source");
    let state = root.join("state");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("public.txt"), b"synthetic public input\n").unwrap();
    request(&state, json!({"op":"init","source":source}));
    let barrier = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4).map(|actor| {
        let state = state.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            for iteration in 0..12 {
                request(&state, json!({"op":"configure","policy":{"checks":[]},"operation_id":format!("reopen-{actor}-{iteration}")}));
            }
        })
    }).collect();
    let joins: Vec<_> = handles.into_iter().map(|handle| handle.join()).collect();
    assert!(joins.iter().all(|result| result.is_ok()), "one or more owned workers failed; all workers joined");
    let db = rusqlite::Connection::open(state.join("state.sqlite")).unwrap();
    assert_eq!(db.query_row("PRAGMA integrity_check", [], |r| r.get::<_,String>(0)).unwrap(), "ok");
    assert_eq!(db.query_row("SELECT COUNT(*) FROM operations WHERE result IS NOT NULL", [], |r| r.get::<_,i64>(0)).unwrap(), 48);
    assert_eq!(db.query_row("SELECT COUNT(*) FROM events WHERE kind='policy_changed'", [], |r| r.get::<_,i64>(0)).unwrap(), 48);
    assert_eq!(db.query_row("PRAGMA journal_mode", [], |r| r.get::<_,String>(0)).unwrap(), "wal");
    drop(db);
    fs::remove_dir_all(root).unwrap();
}
