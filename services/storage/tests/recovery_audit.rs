use rusqlite::Connection;
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, SystemTime},
};
use wipstash_storage::*;
fn command(repo: &Path, args: &[&str], input: &[u8]) -> String {
    let mut c = Command::new("git");
    c.arg("--git-dir")
        .arg(repo)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().into()
}
fn fixture() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("coordinator.git");
    assert!(Command::new("git")
        .args(["init", "--bare"])
        .arg(&repo)
        .output()
        .unwrap()
        .status
        .success());
    File::create(d.path().join("state.lock")).unwrap();
    let db = Connection::open(d.path().join("state.sqlite")).unwrap();
    db.execute_batch(" CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);\n CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY,path TEXT UNIQUE NOT NULL,base TEXT NOT NULL,checkpoint TEXT,generation INTEGER NOT NULL DEFAULT 0);\n CREATE TABLE IF NOT EXISTS checkpoints(id TEXT PRIMARY KEY,workspace TEXT NOT NULL REFERENCES workspaces(id),commit_oid TEXT NOT NULL,tree TEXT NOT NULL,base TEXT NOT NULL,generation INTEGER NOT NULL);\n CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,checkpoint TEXT NOT NULL,commit_oid TEXT NOT NULL,base TEXT NOT NULL,intent TEXT NOT NULL,state TEXT NOT NULL,head TEXT,details TEXT);\n CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,digest TEXT NOT NULL,request TEXT NOT NULL,result TEXT);\n CREATE TABLE IF NOT EXISTS candidates(id TEXT PRIMARY KEY,head TEXT NOT NULL,proposal TEXT NOT NULL,tree TEXT NOT NULL,policy_hash TEXT NOT NULL,evidence TEXT NOT NULL,state TEXT NOT NULL);\n CREATE TABLE IF NOT EXISTS promotions(id TEXT PRIMARY KEY,proposal TEXT NOT NULL,old TEXT NOT NULL,new TEXT NOT NULL,state TEXT NOT NULL);\n CREATE TABLE IF NOT EXISTS adoptions(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,old_base TEXT NOT NULL,target TEXT NOT NULL,commit_oid TEXT NOT NULL,tree TEXT NOT NULL,old_files TEXT NOT NULL,new_files TEXT NOT NULL,stage TEXT NOT NULL,backup TEXT NOT NULL,state TEXT NOT NULL,generation INTEGER NOT NULL);\n CREATE TABLE IF NOT EXISTS adoption_conflicts(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,target TEXT NOT NULL,base TEXT NOT NULL,generation INTEGER NOT NULL,state TEXT NOT NULL);\n CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,workspace TEXT NOT NULL REFERENCES workspaces(id),state TEXT NOT NULL,generation INTEGER NOT NULL);\n CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,data TEXT NOT NULL);\n PRAGMA user_version=1;").unwrap();
    d
}
fn blob(d: &Path, bytes: &[u8]) -> String {
    command(
        &d.join("coordinator.git"),
        &["hash-object", "-w", "--stdin"],
        bytes,
    )
}
fn age(d: &Path, oid: &str) {
    let p = d
        .join("coordinator.git/objects")
        .join(&oid[..2])
        .join(&oid[2..]);
    let file = File::open(p).unwrap();
    file.set_times(
        std::fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(172800)),
    )
    .unwrap();
}

fn rooted() -> tempfile::TempDir {
    let d = fixture();
    let live = blob(d.path(), b"live root");
    command(
        &d.path().join("coordinator.git"),
        &["update-ref", "refs/wipstash/live", &live],
        b"",
    );
    d
}
#[test]
fn missing_events_table_fails_closed() {
    let d = rooted();
    let db = Connection::open(d.path().join("state.sqlite")).unwrap();
    db.execute("DROP TABLE events", []).unwrap();
    assert!(
        plan(d.path(), "coordinator.git", 86400).is_err(),
        "missing core journal table accepted"
    );
}
#[test]
fn index_only_object_fails_closed_or_is_preserved() {
    let d = rooted();
    let oid = blob(d.path(), b"index-only recovery bytes");
    age(d.path(), &oid);
    command(
        &d.path().join("coordinator.git"),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("100644,{oid},recovery"),
        ],
        b"",
    );
    if let Ok(p) = plan(d.path(), "coordinator.git", 86400) {
        assert!(
            !p.candidates.iter().any(|c| c.oid == oid),
            "index-only recovery object offered for deletion"
        );
    }
}
#[test]
fn malformed_packed_refs_fails_closed() {
    let d = rooted();
    fs::write(
        d.path().join("coordinator.git/packed-refs"),
        b"unknown damaged encoding\n",
    )
    .unwrap();
    assert!(
        plan(d.path(), "coordinator.git", 86400).is_err(),
        "ambiguous packed-refs accepted"
    );
}
#[test]
fn escaped_json_pin_is_preserved_or_rejected() {
    let d = rooted();
    let oid = blob(d.path(), b"escaped replay recovery bytes");
    age(d.path(), &oid);
    let encoded = oid
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect::<String>();
    let db = Connection::open(d.path().join("state.sqlite")).unwrap();
    db.execute(
        "INSERT INTO operations VALUES('replay','digest',?1,NULL)",
        [format!("{{\"tree\":\"{encoded}\"}}")],
    )
    .unwrap();
    if let Ok(p) = plan(d.path(), "coordinator.git", 86400) {
        assert!(
            !p.candidates.iter().any(|c| c.oid == oid),
            "valid JSON-escaped recovery pin offered for deletion"
        );
    }
}
#[test]
fn quota_entry_overflow_and_overlap_refused() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("child")).unwrap();
    assert!(usage(&[d.path().to_owned(), d.path().join("child")], 100).is_err());
    assert!(admit(
        &[d.path().to_owned()],
        Budget {
            max_bytes: u64::MAX,
            max_entries: u64::MAX,
            reserve_bytes: 0
        },
        0,
        u64::MAX
    )
    .is_err());
}

#[test]
fn separate_replay_journal_pin_is_preserved_or_rejected() {
    let d = rooted();
    let oid = blob(d.path(), b"admitted but ref not installed yet");
    age(d.path(), &oid);
    let db = Connection::open(d.path().join("sync-replay.sqlite")).unwrap();
    db.execute_batch("CREATE TABLE replication_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1),project TEXT NOT NULL,authority TEXT NOT NULL,epoch INTEGER NOT NULL,cursor INTEGER NOT NULL,head TEXT); CREATE TABLE replication_events(sequence INTEGER PRIMARY KEY,operation TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,envelope TEXT NOT NULL);").unwrap();
    db.execute(
        "INSERT INTO replication_binding VALUES(1,'p','a',1,1,?1)",
        [&oid],
    )
    .unwrap();
    db.execute(
        "INSERT INTO replication_events VALUES(1,'op','digest',?1)",
        [format!("{{\"head\":\"{oid}\"}}")],
    )
    .unwrap();
    if let Ok(p) = plan(d.path(), "coordinator.git", 86400) {
        assert!(
            !p.candidates.iter().any(|c| c.oid == oid),
            "separate replay journal recovery object offered for deletion"
        );
    }
}
#[test]
fn uncertain_command_refuses_collection() {
    let d = rooted();
    let db = Connection::open(d.path().join("state.sqlite")).unwrap();
    let root = blob(d.path(), b"live root");
    db.execute(
        "INSERT INTO workspaces VALUES('w','/unused',?1,NULL,1)",
        [root],
    )
    .unwrap();
    db.execute(
        "INSERT INTO commands VALUES('potential-live-writer','w','uncertain',1)",
        [],
    )
    .unwrap();
    assert!(
        plan(d.path(), "coordinator.git", 86400).is_err(),
        "uncertain command writer accepted"
    );
}

#[test]
fn missing_json_recovery_root_refuses_collection() {
    let d = rooted();
    let db = Connection::open(d.path().join("state.sqlite")).unwrap();
    db.execute(
        "INSERT INTO operations VALUES('missing','digest',?1,NULL)",
        [r#"{"tree":"1111111111111111111111111111111111111111"}"#],
    )
    .unwrap();
    assert!(
        plan(d.path(), "coordinator.git", 86400).is_err(),
        "missing JSON recovery root silently dropped"
    );
}
#[test]
fn malformed_retained_export_refuses_collection() {
    let d = rooted();
    let db = Connection::open(d.path().join("state.sqlite")).unwrap();
    db.execute_batch("CREATE TABLE sync_exports(operation TEXT PRIMARY KEY,request_digest TEXT NOT NULL,manifest TEXT NOT NULL)").unwrap();
    db.execute(
        "INSERT INTO sync_exports VALUES('export','digest','{damaged manifest')",
        [],
    )
    .unwrap();
    assert!(
        plan(d.path(), "coordinator.git", 86400).is_err(),
        "malformed retained export accepted"
    );
}
#[test]
fn freshened_object_makes_plan_stale() {
    let d = rooted();
    let oid = blob(d.path(), b"synthetic garbage");
    age(d.path(), &oid);
    let p = plan(d.path(), "coordinator.git", 86400).unwrap();
    assert!(p.candidates.iter().any(|c| c.oid == oid));
    let path = d
        .path()
        .join("coordinator.git/objects")
        .join(&oid[..2])
        .join(&oid[2..]);
    File::open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(SystemTime::now()))
        .unwrap();
    assert!(apply(d.path(), &p).is_err());
    assert!(path.exists());
}
#[test]
fn reflog_only_pin_preserved() {
    let d = rooted();
    let oid = blob(d.path(), b"synthetic reflog recovery");
    age(d.path(), &oid);
    fs::create_dir_all(d.path().join("coordinator.git/logs/refs/wipstash")).unwrap();
    fs::write(d.path().join("coordinator.git/logs/refs/wipstash/old"),format!("0000000000000000000000000000000000000000 {oid} Test <test@example.invalid> 1 +0000\told operation\n")).unwrap();
    let p = plan(d.path(), "coordinator.git", 86400).unwrap();
    assert!(!p.candidates.iter().any(|c| c.oid == oid));
}
#[test]
fn future_object_never_candidate() {
    let d = rooted();
    let oid = blob(d.path(), b"synthetic future object");
    let path = d
        .path()
        .join("coordinator.git/objects")
        .join(&oid[..2])
        .join(&oid[2..]);
    File::open(&path)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(3600)),
        )
        .unwrap();
    let p = plan(d.path(), "coordinator.git", 86400).unwrap();
    assert!(!p.candidates.iter().any(|c| c.oid == oid));
}

fn valid_replay(d: &Path, head: &str) {
    use sha2::{Digest, Sha256};
    let db = Connection::open(d.join("sync-replay.sqlite")).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE replication_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1),project TEXT NOT NULL,authority TEXT NOT NULL,epoch INTEGER NOT NULL,cursor INTEGER NOT NULL,head TEXT); CREATE TABLE replication_events(sequence INTEGER PRIMARY KEY,operation TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,envelope TEXT NOT NULL);").unwrap();
    let envelope = format!(
        r#"{{"version":1,"project":"p","device":"authority-device","authority":"a","epoch":1,"sequence":1,"operation":"op","event":{{"kind":"head_advanced","head":"{head}"}}}}"#
    );
    let digest = format!("{:x}", Sha256::digest(envelope.as_bytes()));
    db.execute(
        "INSERT INTO replication_binding VALUES(1,'p','a',1,1,?1)",
        [head],
    )
    .unwrap();
    db.execute(
        "INSERT INTO replication_events VALUES(1,'op',?1,?2)",
        [digest, envelope],
    )
    .unwrap();
}
#[test]
fn admitted_head_before_ref_install_preserves_full_graph() {
    let d = rooted();
    let oid = blob(d.path(), b"crash-window admitted file");
    let repo = d.path().join("coordinator.git");
    let tree = command(
        &repo,
        &["mktree"],
        format!("100644 blob {oid}\tfile\n").as_bytes(),
    );
    let commit = command(
        &repo,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit-tree",
            &tree,
        ],
        b"synthetic admitted head\n",
    );
    for o in [&oid, &tree, &commit] {
        age(d.path(), o);
    }
    valid_replay(d.path(), &commit);
    let p = plan(d.path(), "coordinator.git", 86400)
        .expect("valid admitted replay journal must be supported");
    for o in [&oid, &tree, &commit] {
        assert!(p.reachable.contains(o), "missing replay graph object {o}");
        assert!(!p.candidates.iter().any(|c| &c.oid == o));
    }
}
#[test]
fn replay_change_makes_plan_stale() {
    let d = rooted();
    let oid = blob(d.path(), b"admitted head one");
    valid_replay(d.path(), &oid);
    let p =
        plan(d.path(), "coordinator.git", 86400).expect("valid replay journal must be supported");
    let db = Connection::open(d.path().join("sync-replay.sqlite")).unwrap();
    db.execute("UPDATE replication_binding SET cursor=2", [])
        .unwrap();
    assert!(
        apply(d.path(), &p).is_err(),
        "changed replay must invalidate plan"
    );
}

#[test]
fn collection_never_changes_dirty_live_worktree_bytes() {
    let d = rooted();
    let live = d.path().join("dirty-worktree");
    fs::create_dir(&live).unwrap();
    let file = live.join("uncommitted.txt");
    let dirty = b"synthetic unsaved user work\0\xff";
    fs::write(&file, dirty).unwrap();
    let root = blob(d.path(), b"live root");
    let db = Connection::open(d.path().join("state.sqlite")).unwrap();
    db.execute(
        "INSERT INTO workspaces VALUES('w',?1,?2,NULL,0)",
        [live.to_str().unwrap(), &root],
    )
    .unwrap();
    drop(db);
    let garbage = blob(d.path(), b"isolated synthetic garbage only");
    age(d.path(), &garbage);
    let p = plan(d.path(), "coordinator.git", 86400).unwrap();
    assert_eq!(p.candidates.len(), 1);
    assert_eq!(p.candidates[0].oid, garbage);
    let report = apply(d.path(), &p).unwrap();
    assert_eq!(report.removed_objects, 1);
    assert_eq!(fs::read(file).unwrap(), dirty);
}
#[test]
fn changed_reference_bytes_make_plan_stale_even_if_roots_same() {
    let d = rooted();
    let root = blob(d.path(), b"live root");
    let logfile = d.path().join("coordinator.git/logs/refs/wipstash/live");
    fs::create_dir_all(logfile.parent().unwrap()).unwrap();
    fs::write(
        &logfile,
        format!("{root} {root} Test <test@example.invalid> 1 +0000\tbefore\n"),
    )
    .unwrap();
    let p = plan(d.path(), "coordinator.git", 86400).unwrap();
    fs::write(
        &logfile,
        format!("{root} {root} Test <test@example.invalid> 1 +0000\tafter\n"),
    )
    .unwrap();
    assert!(apply(d.path(), &p).unwrap_err().contains("stale"));
}
