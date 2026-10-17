//! Explicit public-snapshot enqueue and independently supervised replication worker.
use fs2::FileExt;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wipstash_backup::{Github, GithubConfig, Outbox, Remote, Result};

const HELP: &str = "wipstash-backup --config /absolute/config.json COMMAND\nCommands:\n  enqueue --public-source /absolute/sanitized-public.git\n  status\n  worker [--watch] [--max-attempts 1..1000]\n  restore --destination /absolute/new-public.git\nEnqueue is local only. Worker/restore use the configured GitHub repository and OS credential helper.\n";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    outbox: PathBuf,
    github: GithubConfig,
    #[serde(default)]
    public_source: Option<PathBuf>,
}
fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("absolute_path_without_parent_components_required".into());
    }
    Ok(())
}
fn config(path: &Path) -> Result<Config> {
    absolute(path)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "config_unavailable")?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "config_unavailable")?;
    if bytes.len() > 65536 {
        return Err("config_too_large".into());
    }
    let c: Config = serde_json::from_slice(&bytes).map_err(|_| "invalid_config")?;
    absolute(&c.outbox)?;
    c.github.validate()?;
    if let Some(source) = &c.public_source {
        absolute(source)?;
        if source.starts_with(&c.outbox) {
            return Err("public_source_must_be_separate_from_outbox".into());
        }
    }
    Ok(c)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
fn storage<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(|_| "worker_storage_error".into())
}
struct Retry {
    db: Connection,
}
impl Retry {
    fn open(dir: &Path) -> Result<Self> {
        let db = storage(Connection::open(dir.join("worker.sqlite")))?;
        storage(db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS retry(id INTEGER PRIMARY KEY CHECK(id=1), failures INTEGER NOT NULL, not_before INTEGER NOT NULL); INSERT OR IGNORE INTO retry VALUES(1,0,0);"))?;
        Ok(Self { db })
    }
    fn state(&self) -> Result<(u32, i64)> {
        storage(self.db.query_row(
            "SELECT failures,not_before FROM retry WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))
    }
    fn failed(&self, time: i64) -> Result<()> {
        let failures = self.state()?.0.saturating_add(1).min(30);
        let delay = (5u64.saturating_mul(1u64 << failures.saturating_sub(1))).min(300);
        storage(self.db.execute(
            "UPDATE retry SET failures=?1,not_before=?2 WHERE id=1",
            rusqlite::params![failures, time.saturating_add(delay as i64)],
        ))?;
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        storage(
            self.db
                .execute("UPDATE retry SET failures=0,not_before=0 WHERE id=1", []),
        )?;
        Ok(())
    }
}
/// One scheduler tick: inspect only the explicitly configured public export,
/// enqueue its verified snapshot idempotently, then replicate one durable job.
fn worker_tick(c: &Config, out: &mut Outbox, remote: &mut impl Remote) -> Result<bool> {
    if let Some(source) = &c.public_source {
        out.enqueue(source)?;
    }
    out.drain_one(remote)
}
fn worker(c: &Config, out: &mut Outbox, watch: bool, max: usize) -> Result<()> {
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(c.outbox.join("service.lock"))
        .map_err(|_| "worker_lock_failed")?;
    lock.try_lock_exclusive()
        .map_err(|_| "worker_already_running")?;
    let retry = Retry::open(&c.outbox)?;
    let mut remote = Github::new(c.github.clone())?;
    let mut attempts = 0;
    loop {
        let remaining = retry.state()?.1.saturating_sub(now()).max(0) as u64;
        // Clamp clock rollback effects. Backoff survives service restarts.
        if remaining > 0 {
            std::thread::sleep(Duration::from_secs(remaining.min(300)));
        }
        attempts += 1;
        let failed = match worker_tick(c, out, &mut remote) {
            Ok(processed) => {
                retry.clear()?;
                if !processed {
                    if !watch {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_secs(5));
                }
                if watch {
                    attempts = 0;
                }
                false
            }
            Err(e) => {
                retry.failed(now())?;
                eprintln!("{}", json!({"ok":false,"error":e,"retry":retry.state()?}));
                true
            }
        };
        if attempts >= max {
            if failed || out.status()?.pending > 0 {
                return Err("worker_attempt_budget_exhausted".into());
            }
            if !watch {
                return Ok(());
            }
        }
    }
}

fn run(args: &[String]) -> Result<serde_json::Value> {
    if args.len() < 3 || args[0] != "--config" {
        return Err("usage_error_use_help".into());
    }
    // Parse the complete command before opening storage or making any network call.
    let command = &args[2];
    let rest = &args[3..];
    let mut watch = false;
    let mut max = 8;
    let mut path = None;
    match command.as_str() {
        "status" if rest.is_empty() => {}
        "enqueue" | "restore" => {
            let flag = if command == "enqueue" {
                "--public-source"
            } else {
                "--destination"
            };
            if rest.len() != 2 || rest[0] != flag {
                return Err("usage_error_use_help".into());
            }
            let p = PathBuf::from(&rest[1]);
            absolute(&p)?;
            path = Some(p);
        }
        "worker" => {
            let mut i = 0;
            let mut max_seen = false;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--watch" if !watch => watch = true,
                    "--max-attempts" if !max_seen => {
                        i += 1;
                        max_seen = true;
                        max = rest
                            .get(i)
                            .ok_or("missing_attempt_limit")?
                            .parse::<usize>()
                            .map_err(|_| "invalid_attempt_limit")?;
                        if !(1..=1000).contains(&max) {
                            return Err("invalid_attempt_limit".into());
                        }
                    }
                    _ => return Err("usage_error_use_help".into()),
                }
                i += 1;
            }
        }
        _ => return Err("usage_error_use_help".into()),
    }
    let c = config(Path::new(&args[1]))?;
    // Even restore checks the pinned destination binding of this configured outbox.
    let mut out = Outbox::open(&c.outbox, c.github.clone())?;
    match command.as_str() {
        "enqueue" => {
            let snapshot = out.enqueue(path.as_ref().unwrap())?;
            let status = out.status()?;
            let replication =
                if status.pending == 0 && status.verified_watermark >= snapshot.watermark {
                    "verified"
                } else {
                    "pending_verification"
                };
            Ok(json!({"ok":true,"enqueued":snapshot,"replication":replication,"status":status}))
        }
        "status" => {
            let retry = Retry::open(&c.outbox)?.state()?;
            Ok(
                json!({"ok":true,"github":c.github.url()?,"namespace":c.github.namespace,"public_source":c.public_source,"status":out.status()?,"retry":{"failures":retry.0,"not_before_unix":retry.1}}),
            )
        }
        "worker" => {
            worker(&c, &mut out, watch, max)?;
            Ok(json!({"ok":true,"status":out.status()?}))
        }
        "restore" => {
            let mut remote = Github::new(c.github.clone())?;
            Ok(
                json!({"ok":true,"restored":wipstash_backup::restore(&mut remote,&c.github,path.as_ref().unwrap())?,"activation_required":true}),
            )
        }
        _ => unreachable!(),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] || args.as_slice() == ["-h"] {
        print!("{HELP}");
        return;
    }
    match run(&args) {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("{}", json!({"ok":false,"error":e}));
            std::process::exit(1);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Vec<String>) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        fs::write(&p,serde_json::to_vec(&json!({"outbox":d.path().join("outbox"),"github":{"owner":"fixture","repository":"public","namespace":"wipstash","credential_helper":"libsecret"}})).unwrap()).unwrap();
        let args = vec!["--config".into(), p.to_str().unwrap().into()];
        (d, args)
    }
    #[test]
    fn status_and_empty_worker_are_local_and_restartable() {
        let (_d, mut a) = fixture();
        a.push("status".into());
        assert_eq!(run(&a).unwrap()["status"]["pending"], 0);
        a[2] = "worker".into();
        assert_eq!(run(&a).unwrap()["status"]["verified_watermark"], 0);
        a[2] = "status".into();
        assert_eq!(run(&a).unwrap()["status"]["pending"], 0);
    }
    #[test]
    fn retry_is_durable_and_capped() {
        let d = tempfile::tempdir().unwrap();
        let r = Retry::open(d.path()).unwrap();
        r.failed(100).unwrap();
        assert_eq!(r.state().unwrap(), (1, 105));
        drop(r);
        let r = Retry::open(d.path()).unwrap();
        for _ in 0..40 {
            r.failed(100).unwrap();
        }
        assert_eq!(r.state().unwrap(), (30, 400));
        r.clear().unwrap();
        assert_eq!(r.state().unwrap(), (0, 0));
    }
    #[test]
    fn invalid_options_and_relative_paths_fail_before_side_effects() {
        let (d, mut a) = fixture();
        a.extend(["worker".into(), "--max-attempts".into(), "0".into()]);
        assert!(run(&a).is_err());
        assert!(!d.path().join("outbox").exists());
        a.truncate(2);
        a.extend([
            "enqueue".into(),
            "--public-source".into(),
            "private.git".into(),
        ]);
        assert!(run(&a).is_err());
        assert!(!d.path().join("outbox").exists());
        assert!(absolute(Path::new("/tmp/../private")).is_err());
    }
    #[test]
    fn configured_source_requires_absolute_separate_public_path() {
        let (d, a) = fixture();
        let p = Path::new(&a[1]);
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
        v["public_source"] = json!("relative.git");
        fs::write(p, v.to_string()).unwrap();
        assert!(config(p).is_err());
        v["public_source"] = json!(d.path().join("outbox/public.git"));
        fs::write(p, v.to_string()).unwrap();
        assert!(config(p).is_err());
        v["public_source"] = json!(d.path().join("public.git"));
        fs::write(p, v.to_string()).unwrap();
        assert_eq!(
            config(p).unwrap().public_source,
            Some(d.path().join("public.git"))
        );
    }
    #[test]
    fn destination_is_pinned_and_credentials_cannot_be_inline() {
        let (_d, mut a) = fixture();
        a.push("status".into());
        run(&a).unwrap();
        let p = Path::new(&a[1]);
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
        v["github"]["repository"] = json!("other");
        fs::write(p, v.to_string()).unwrap();
        assert_eq!(run(&a).unwrap_err(), "backup_destination_changed");
        v["github"]["credential_helper"] = json!("store");
        fs::write(p, v.to_string()).unwrap();
        assert!(config(p).is_err());
        v["github"]["credential_helper"] = json!("libsecret");
        v["github"]["token"] = json!("fixture-not-a-token");
        fs::write(p, v.to_string()).unwrap();
        assert!(config(p).is_err());
    }
    #[test]
    fn explicit_public_snapshot_enqueue_survives_restart() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        fn git(path: &Path, args: &[&str], input: &[u8]) -> String {
            let mut child = Command::new("git")
                .arg("--git-dir")
                .arg(path)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
                .env("GIT_COMMITTER_NAME", "fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(result.status.success());
            String::from_utf8(result.stdout).unwrap().trim().to_owned()
        }
        let (d, mut a) = fixture();
        let source = d.path().join("public.git");
        git(&source, &["init", "--bare", "--template="], b"");
        let tree = git(&source, &["mktree"], b"");
        let root = git(&source, &["commit-tree", &tree], b"public fixture\n");
        let m = json!({"format":"wipstash-public-metadata-v1","integration":root,"watermark":0,"proposals":{},"proposal_metadata":{},"events":[]});
        let blob = git(
            &source,
            &["hash-object", "-w", "--stdin"],
            m.to_string().as_bytes(),
        );
        let tree = git(
            &source,
            &["mktree"],
            format!("100644 blob {blob}\tmetadata.json\n").as_bytes(),
        );
        let meta = git(&source, &["commit-tree", &tree], b"public metadata\n");
        git(
            &source,
            &["update-ref", "refs/heads/wipstash/integration", &root],
            b"",
        );
        git(
            &source,
            &["update-ref", "refs/heads/wipstash/metadata", &meta],
            b"",
        );
        let private = git(
            &source,
            &["hash-object", "-w", "--stdin"],
            b"PRIVATE_UNREACHABLE_SENTINEL",
        );
        a.extend([
            "enqueue".into(),
            "--public-source".into(),
            source.to_str().unwrap().into(),
        ]);
        assert_eq!(run(&a).unwrap()["replication"], "pending_verification");
        assert!(run(&a).is_ok()); // Idempotent snapshot, no duplicate job.
        a.truncate(2);
        a.push("status".into());
        let status = run(&a).unwrap();
        assert_eq!(status["status"]["pending"], 1);
        assert_eq!(status["status"]["verified_watermark"], 0);
        let result = Command::new("git")
            .arg("--git-dir")
            .arg(d.path().join("outbox/public.git"))
            .args(["cat-file", "-e", &private])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!result.success());
        // Advance only the designated sanitized public output. A scheduler tick
        // enqueues the new snapshot before the fake offline transport fails.
        let mut c = config(Path::new(&a[1])).unwrap();
        c.public_source = Some(source.clone());
        let next = json!({"format":"wipstash-public-metadata-v1","integration":root,"watermark":1,"proposals":{},"proposal_metadata":{},"events":[]});
        let blob = git(
            &source,
            &["hash-object", "-w", "--stdin"],
            next.to_string().as_bytes(),
        );
        let tree = git(
            &source,
            &["mktree"],
            format!("100644 blob {blob}\tmetadata.json\n").as_bytes(),
        );
        let next_meta = git(
            &source,
            &["commit-tree", &tree, "-p", &meta],
            b"advanced public metadata\n",
        );
        git(
            &source,
            &["update-ref", "refs/heads/wipstash/metadata", &next_meta],
            b"",
        );
        struct Offline;
        impl Remote for Offline {
            fn refs(&mut self, _: &Path, _: &str) -> Result<wipstash_backup::Refs> {
                Err("fixture_offline".into())
            }
            fn push(
                &mut self,
                _: &Path,
                _: &wipstash_backup::Refs,
                _: &wipstash_backup::Refs,
            ) -> Result<()> {
                panic!("unexpected push")
            }
            fn fetch(&mut self, _: &Path, _: &wipstash_backup::Refs) -> Result<()> {
                panic!("unexpected fetch")
            }
        }
        let mut out = Outbox::open(&c.outbox, c.github.clone()).unwrap();
        assert_eq!(
            worker_tick(&c, &mut out, &mut Offline).unwrap_err(),
            "fixture_offline"
        );
        assert_eq!(out.status().unwrap().pending, 2);
        assert_eq!(
            worker_tick(&c, &mut out, &mut Offline).unwrap_err(),
            "fixture_offline"
        );
        assert_eq!(out.status().unwrap().pending, 2); // Unchanged snapshots deduplicate.
    }
}
