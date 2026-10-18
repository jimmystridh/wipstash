mod adoption;
mod backup;
mod client;
mod client_journal;
mod engine;
mod git;
mod policy;
mod replication;
mod restore;
mod transfer;
use serde_json::{json, Value};
use std::{io::BufRead, path::PathBuf};
fn request(state: &std::path::Path, s: &str) -> Value {
    match serde_json::from_str::<Value>(s)
        .map_err(|e| e.to_string())
        .and_then(|v| engine::execute(state, v))
    {
        Ok(v) => v,
        Err(e) => engine::error_response(&e),
    }
}
fn worker_startup(state: &std::path::Path) -> Result<(), String> {
    let recovery = engine::execute(state, json!({"op":"recovery_status"}))?;
    if recovery["activation_required"] == true {
        return Err("public_recovery_activation_required: explicitly activate the reviewed recovery before starting the worker".into());
    }
    Ok(())
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("client-journal") {
        if args.len() != 3 {
            eprintln!("usage: wipstash client-journal ABS_PRIVATE_DIRECTORY");
            std::process::exit(2);
        }
        if let Err(error) = client_journal::serve(
            std::path::Path::new(&args[2]),
            std::io::stdin().lock(),
            std::io::stdout().lock(),
        ) {
            eprintln!("client_journal: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("remote") {
        // Resolve a fixed companion executable, never a PATH-selected helper.
        let outcome = std::env::current_exe().and_then(|path| {
            let parent = path
                .parent()
                .ok_or_else(|| std::io::Error::other("missing_executable_directory"))?;
            let name = if cfg!(windows) {
                "wipstash-transport.exe"
            } else {
                "wipstash-transport"
            };
            std::process::Command::new(parent.join(name))
                .args(&args[2..])
                .status()
        });
        match outcome {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(_) => {
                eprintln!("remote_helper_unavailable: install wipstash-transport beside wipstash");
                std::process::exit(1);
            }
        }
    }

    if args.len() < 4 || args[1] != "--state" {
        eprintln!("usage: wipstash --state DIR '<JSON>' | daemon | worker | stdin | mcp");
        std::process::exit(2);
    }
    let state = PathBuf::from(&args[2]);
    if args[3] == "mcp" {
        if let Err(e) = client::serve(std::io::stdin().lock(), std::io::stdout().lock(), |v| {
            request(&state, &v.to_string())
        }) {
            eprintln!("mcp_io: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args[3] == "worker" {
        if let Err(e) = worker_startup(&state) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        std::fs::create_dir_all(&state).unwrap();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(state.join("daemon.lock"))
            .unwrap();
        if fs2::FileExt::try_lock_exclusive(&lock).is_err() {
            eprintln!("daemon_busy");
            std::process::exit(1)
        }
        let mut next_backup = std::time::Instant::now();
        let mut backoff = 1u64;
        loop {
            if let Err(e) = engine::execute(&state, json!({"op":"integrate","max_proposals":1})) {
                eprintln!("{e}");
            }
            if std::time::Instant::now() >= next_backup {
                let result = engine::execute(&state, json!({"op":"backup_tick"}));
                let blocked = result
                    .as_ref()
                    .map(|v| v["state"] == "blocked")
                    .unwrap_or(true);
                if blocked {
                    eprintln!("local backup paused: {result:?}");
                }
                backoff = if blocked { (backoff * 2).min(60) } else { 1 };
                next_backup = std::time::Instant::now() + std::time::Duration::from_secs(backoff);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    if args[3] == "daemon" {
        if let Err(e) = daemon(&state) {
            eprintln!("{e}");
            std::process::exit(1)
        }
        return;
    }
    if args[3] == "stdin" {
        for s in std::io::stdin().lock().lines().map_while(Result::ok) {
            println!("{}", request(&state, &s));
        }
        return;
    }
    let result = request(&state, &args[3]);
    println!("{result}");
    if result.get("ok") == Some(&Value::Bool(false)) {
        std::process::exit(1)
    }
}
#[cfg(unix)]
fn daemon(state: &std::path::Path) -> Result<(), String> {
    use std::io::{BufReader, Read, Write};
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    std::fs::create_dir_all(state).map_err(|e| e.to_string())?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("daemon.lock"))
        .map_err(|e| e.to_string())?;
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| "daemon_busy".to_string())?;
    let socket = state.join("daemon.sock");
    if socket.exists() {
        std::fs::remove_file(&socket).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();
                let mut line = String::new();
                if BufReader::new(&stream)
                    .take(1024 * 1024)
                    .read_line(&mut line)
                    .is_ok()
                {
                    let r = request(state, &line);
                    let _ = writeln!(stream, "{r}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        };
        let _ = engine::execute(state, json!({"op":"integrate"}));
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
#[cfg(not(unix))]
fn daemon(_: &std::path::Path) -> Result<(), String> {
    Err("unsupported_platform: daemon currently Unix-only".into())
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    #[test]
    fn worker_refuses_unactivated_public_recovery_at_startup() {
        let root = std::env::temp_dir().join(format!(
            "wipstash-worker-startup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.txt"), "source").unwrap();
        let state = root.join("state");
        engine::execute(&state, json!({"op":"init","source":source})).unwrap();
        worker_startup(&state).unwrap();
        let db = rusqlite::Connection::open(state.join("state.sqlite")).unwrap();
        db.execute(
            "INSERT INTO meta(key,value) VALUES('public_recovery_gate',?1)",
            [json!({"version":2,"activation_required":true}).to_string()],
        )
        .unwrap();
        let rejected = worker_startup(&state).unwrap_err();
        assert!(rejected.starts_with("public_recovery_activation_required"));
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
}
