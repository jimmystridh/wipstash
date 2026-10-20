use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use wipstash_transport::daemon::{AuthorityWorker, PeerSync, Reply, Worker};
use wipstash_transport::*;
fn engine_path() -> PathBuf {
    std::env::var_os("WIPSTASH_ENGINE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/wipstash")
        })
        .canonicalize()
        .expect("build main wipstash engine first")
}
fn run(state: &Path, v: Value) -> Value {
    let o = std::process::Command::new(engine_path())
        .arg("--state")
        .arg(state)
        .arg(v.to_string())
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(o.status.success(), "{value}");
    value
}
struct Fixture {
    _tmp: tempfile::TempDir,
    c: Config,
    alice: PathBuf,
    cert: Vec<u8>,
}
impl Fixture {
    async fn new() -> Self {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("hello.txt"), "hello\n").unwrap();
        let state = root.join("authority");
        run(&state, json!({"op":"init","source":source}));
        run(
            &state,
            json!({"op":"sync_configure","project":"demo","authority":"central","epoch":1,"device":"central-device","role":"authority","peers":["alice","bob"]}),
        );
        let staging = root.join("staging");
        std::fs::create_dir(&staging).unwrap();
        let acl = root.join("acl.json");
        let cert = b"test-only-inprocess-peer".to_vec();
        let a = Acl {
            peers: HashMap::from([(
                fingerprint(&cert),
                Peer {
                    device: "alice".into(),
                    project: "demo".into(),
                    role: "client".into(),
                    revoked: false,
                },
            )]),
        };
        std::fs::write(&acl, serde_json::to_vec(&a).unwrap()).unwrap();
        let c = Config {
            engine: engine_path(),
            state,
            staging,
            project: "demo".into(),
            authority: "central".into(),
            epoch: 1,
            device: "central-device".into(),
            acl: acl.into(),
            ca: root.join("ca"),
            certificate: root.join("certificate"),
            key: root.join("key").into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            limits: Limits::default(),
        };
        let alice = root.join("alice");
        let bob = root.join("bob");
        for (path, device) in [(&alice, "alice"), (&bob, "bob")] {
            run(
                path,
                json!({"op":"sync_configure","project":"demo","authority":"central","epoch":1,"device":device,"role":"client","peers":["central-device"]}),
            );
        }
        Self {
            _tmp: t,
            c,
            alice,
            cert,
        }
    }
    fn proposal(&self, state: &Path, name: &str) -> Artifact {
        let workspace = self.c.staging.join(format!("workspace-{name}"));
        run(
            state,
            json!({"op":"open","workspace":"work","path":workspace,"operation_id":"open"}),
        );
        std::fs::write(workspace.join("new.txt"), name).unwrap();
        run(
            state,
            json!({"op":"checkpoint","workspace":"work","expected_generation":0,"operation_id":"checkpoint"}),
        );
        run(
            state,
            json!({"op":"publish","workspace":"work","checkpoint":"checkpoint","intent":"Test network source exchange","operation_id":"proposal"}),
        );
        let d = self.c.staging.join(format!("proposal-{name}"));
        run(
            state,
            json!({"op":"sync_export","kind":"proposal","proposal":"proposal","destination":d,"operation_id":"upload"}),
        );
        Artifact {
            manifest: std::fs::read(d.join("manifest.json")).unwrap(),
            objects: std::fs::read(d.join("objects.json")).unwrap(),
        }
    }
}
struct MemoryPeer {
    service: Arc<Service>,
    cert: Vec<u8>,
    state: PathBuf,
    staging: PathBuf,
    lose_upload: Arc<AtomicBool>,
}
impl MemoryPeer {
    fn import(&self, bytes: &[u8]) -> Value {
        let a = Artifact::decode(bytes).unwrap();
        let d = tempfile::tempdir_in(&self.staging).unwrap();
        std::fs::write(d.path().join("manifest.json"), a.manifest).unwrap();
        std::fs::write(d.path().join("objects.json"), a.objects).unwrap();
        run(
            &self.state,
            json!({"op":"sync_import","source":d.path(),"confirm_trusted_source":true}),
        )
    }
}
impl PeerSync for MemoryPeer {
    fn upload<'a>(&'a self, proposal: &'a str, operation: &'a str) -> Reply<'a> {
        Box::pin(async move {
            let dir = tempfile::tempdir_in(&self.staging)?;
            let exists = run(
                &self.state,
                json!({"op":"sync_export_lookup","operation_id":operation}),
            )["exists"]
                == true;
            run(
                &self.state,
                if exists {
                    json!({"op":"sync_reexport","operation_id":operation,"destination":dir.path().join("artifact")})
                } else {
                    json!({"op":"sync_export","kind":"proposal","proposal":proposal,"operation_id":operation,"destination":dir.path().join("artifact")})
                },
            );
            let a = Artifact {
                manifest: std::fs::read(dir.path().join("artifact/manifest.json"))?,
                objects: std::fs::read(dir.path().join("artifact/objects.json"))?,
            };
            let (_, bytes) = self
                .service
                .route(&self.cert, "POST", "/v1/proposals", &a.encode()?)
                .await?;
            if self.lose_upload.swap(false, Ordering::SeqCst) {
                return Err("lost_upload_response".into());
            }
            Ok(serde_json::from_slice(&bytes)?)
        })
    }
    fn current_receipt<'a>(&'a self, proposal: &'a str) -> Reply<'a> {
        Box::pin(async move {
            let (_, bytes) = self
                .service
                .route(
                    &self.cert,
                    "POST",
                    "/v1/current-receipt",
                    &serde_json::to_vec(&json!({"proposal":proposal}))?,
                )
                .await?;
            Ok(self.import(&bytes))
        })
    }
    fn catch_up(&self) -> Reply<'_> {
        Box::pin(async move {
            let mut cursor = run(&self.state, json!({"op":"sync_status"}))["cursor"]
                .as_u64()
                .unwrap_or(0);
            loop {
                let (_, bytes) = self
                    .service
                    .route(
                        &self.cert,
                        "POST",
                        "/v1/history",
                        &serde_json::to_vec(
                            &json!({"after":cursor,"limit":128,"cursor_kind":"head_sequence"}),
                        )?,
                    )
                    .await?;
                let page: Value = serde_json::from_slice(&bytes)?;
                for head in page["exports"].as_array().unwrap() {
                    let (_, bytes) = self
                        .service
                        .route(
                            &self.cert,
                            "POST",
                            "/v1/export",
                            &serde_json::to_vec(
                                &json!({"kind":"retained","operation_id":head["operation_id"]}),
                            )?,
                        )
                        .await?;
                    self.import(&bytes);
                    cursor = head["sequence"].as_u64().unwrap();
                }
                if page["has_more"] != true {
                    break;
                }
            }
            Ok(json!({"ok":true,"cursor":cursor}))
        })
    }
}
#[tokio::test]
async fn authority_run_validates_in_background_without_holding_the_state_lock() {
    let f = Fixture::new().await;
    // The check itself reads authority state. It would deadlock if validation
    // retained the state lock while waiting for the child process.
    run(
        &f.c.state,
        json!({"op":"configure","operation_id":"async-worker-policy","policy":{"checks":[{"id":"authority-read","argv":[engine_path(),"--state",f.c.state,json!({"op":"ignore_templates"}).to_string()],"timeout_seconds":15}]}}),
    );
    let mut worker = AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
        .await
        .unwrap();
    let task = tokio::spawn(async move { worker.run().await });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let health = run(&f.c.state, json!({"op":"validation_status"}));
        if health["repo_health"]["state"] == "passed" {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{health}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn durable_worker_replays_lost_ack_and_polls_immutable_receipts() {
    let f = Fixture::new().await;
    let service = Service::new(f.c.clone()).await.unwrap();
    let mut authority =
        AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
            .await
            .unwrap();
    assert_eq!(authority.tick().await.unwrap()["exported"], true);
    assert_eq!(authority.tick().await.unwrap()["exported"], false);
    let lost = Arc::new(AtomicBool::new(false));
    let peer = || MemoryPeer {
        service: service.clone(),
        cert: f.cert.clone(),
        state: f.alice.clone(),
        staging: f.c.staging.clone(),
        lose_upload: lost.clone(),
    };
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .unwrap();
    worker.tick(0).await.unwrap(); // initial verified public head
    assert!(Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .is_err());
    f.proposal(&f.alice, "alice");
    let source = f.c.staging.join("workspace-alice/new.txt");
    std::fs::write(&source, "private post-publish edits").unwrap();
    lost.store(true, Ordering::SeqCst);
    assert_eq!(worker.tick(5).await.unwrap()["failures"], 1);
    let before: Value =
        serde_json::from_slice(&std::fs::read(f.alice.join("transport-outbox.json")).unwrap())
            .unwrap();
    drop(worker);
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .unwrap();
    worker.tick(6).await.unwrap(); // persisted backoff prevents immediate resend
    worker.tick(7).await.unwrap(); // exact retained artifact, import replay
    let after: Value =
        serde_json::from_slice(&std::fs::read(f.alice.join("transport-outbox.json")).unwrap())
            .unwrap();
    assert_eq!(
        before["entries"]["proposal"]["operation"],
        after["entries"]["proposal"]["operation"]
    );
    assert!(after["entries"]["proposal"]["authority_proposal"].is_string());
    worker.tick(12).await.unwrap(); // accepted receipt
    worker.tick(17).await.unwrap(); // same immutable receipt
    let history = run(&f.c.state, json!({"op":"sync_export_history"}));
    assert_eq!(
        history["exports"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "receipt")
            .count(),
        1
    );
    assert_eq!(authority.tick().await.unwrap()["exported"], true);
    assert_eq!(authority.tick().await.unwrap()["exported"], false);
    worker.tick(22).await.unwrap();
    let observed = run(
        &f.alice,
        json!({"op":"proposal_status","proposal":"proposal"}),
    );
    assert_eq!(observed["state"], "integrated");
    assert_eq!(
        std::fs::read_to_string(source).unwrap(),
        "private post-publish edits"
    );
    let history = run(&f.c.state, json!({"op":"sync_export_history"}));
    assert_eq!(
        history["exports"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "receipt")
            .count(),
        2
    );
}

#[tokio::test]
async fn private_checkpoints_and_cancelled_publications_never_upload() {
    let f = Fixture::new().await;
    let service = Service::new(f.c.clone()).await.unwrap();
    let mut authority =
        AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
            .await
            .unwrap();
    authority.tick().await.unwrap();
    let peer = || MemoryPeer {
        service: service.clone(),
        cert: f.cert.clone(),
        state: f.alice.clone(),
        staging: f.c.staging.clone(),
        lose_upload: Arc::new(AtomicBool::new(false)),
    };
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .unwrap();
    worker.tick(0).await.unwrap();
    let workspace = f.c.staging.join("private");
    run(
        &f.alice,
        json!({"op":"open","workspace":"private","path":workspace,"operation_id":"private-open"}),
    );
    std::fs::write(workspace.join("secret.txt"), "private work").unwrap();
    run(
        &f.alice,
        json!({"op":"checkpoint","workspace":"private","expected_generation":0,"operation_id":"private-cp"}),
    );
    assert!(run(&f.alice, json!({"op":"sync_pending"}))["proposals"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(worker.tick(5).await.unwrap()["tracked"], 0);
    run(
        &f.alice,
        json!({"op":"publish","workspace":"private","checkpoint":"private-cp","intent":"explicit","operation_id":"cancel-me"}),
    );
    run(
        &f.alice,
        json!({"op":"cancel","proposal":"cancel-me","operation_id":"cancel"}),
    );
    assert_eq!(worker.tick(10).await.unwrap()["tracked"], 0);
    drop(worker);
    let path = f.alice.join("transport-outbox.json");
    let mut journal: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    journal["binding"]["epoch"] = json!(2);
    std::fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();
    assert!(Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .is_err());
}

#[tokio::test]
async fn authority_worker_integrates_one_candidate_per_tick() {
    let f = Fixture::new().await;
    let service = Service::new(f.c.clone()).await.unwrap();
    let mut authority =
        AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
            .await
            .unwrap();
    authority.tick().await.unwrap();
    let peer = MemoryPeer {
        service,
        cert: f.cert.clone(),
        state: f.alice.clone(),
        staging: f.c.staging.clone(),
        lose_upload: Arc::new(AtomicBool::new(false)),
    };
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer)
        .await
        .unwrap();
    worker.tick(0).await.unwrap();
    f.proposal(&f.alice, "batch");
    std::fs::write(
        f.c.staging.join("workspace-batch/another.txt"),
        "independent",
    )
    .unwrap();
    run(
        &f.alice,
        json!({"op":"checkpoint","workspace":"work","expected_generation":1,"operation_id":"cp-two"}),
    );
    run(
        &f.alice,
        json!({"op":"publish","workspace":"work","checkpoint":"cp-two","intent":"second","operation_id":"proposal-two"}),
    );
    worker.tick(5).await.unwrap();
    let first = authority.tick().await.unwrap();
    let second = authority.tick().await.unwrap();
    assert_eq!(
        first["integration"]["outcomes"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        second["integration"]["outcomes"].as_array().unwrap().len(),
        1
    );
    assert_eq!(first["integration"]["outcomes"][0]["state"], "integrated");
    assert_eq!(second["integration"]["outcomes"][0]["state"], "integrated");
}

#[tokio::test]
async fn authority_quota_pauses_before_creating_head_export() {
    let f = Fixture::new().await;
    let limits = Limits {
        max_storage_bytes: 1,
        ..Limits::default()
    };
    let mut authority = AuthorityWorker::open_with_limits(
        engine_path(),
        f.c.state.clone(),
        f.c.staging.clone(),
        limits,
    )
    .await
    .unwrap();
    assert!(authority
        .tick()
        .await
        .unwrap_err()
        .to_string()
        .contains("storage_quota"));
    let history = run(&f.c.state, json!({"op":"sync_export_history"}));
    assert!(history["exports"].as_array().unwrap().is_empty());
}

struct WrongAck(MemoryPeer);
impl PeerSync for WrongAck {
    fn upload<'a>(&'a self, proposal: &'a str, operation: &'a str) -> Reply<'a> {
        Box::pin(async move {
            let mut result = self.0.upload(proposal, operation).await?;
            result["source_proposal"] = json!("wrong-source");
            Ok(result)
        })
    }
    fn current_receipt<'a>(&'a self, proposal: &'a str) -> Reply<'a> {
        self.0.current_receipt(proposal)
    }
    fn catch_up(&self) -> Reply<'_> {
        self.0.catch_up()
    }
}
#[tokio::test]
async fn identity_rejection_blocks_without_new_operation_or_retry() {
    let f = Fixture::new().await;
    let service = Service::new(f.c.clone()).await.unwrap();
    let mut authority =
        AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
            .await
            .unwrap();
    authority.tick().await.unwrap();
    let peer = WrongAck(MemoryPeer {
        service,
        cert: f.cert.clone(),
        state: f.alice.clone(),
        staging: f.c.staging.clone(),
        lose_upload: Arc::new(AtomicBool::new(false)),
    });
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer)
        .await
        .unwrap();
    worker.tick(0).await.unwrap();
    f.proposal(&f.alice, "wrong-ack");
    assert_eq!(worker.tick(5).await.unwrap()["failures"], 1);
    let path = f.alice.join("transport-outbox.json");
    let before: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        before["entries"]["proposal"]["blocked"],
        "upload_ack_identity"
    );
    assert_eq!(worker.tick(1000).await.unwrap()["failures"], 0);
    let after: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(before["entries"], after["entries"]);
}

#[tokio::test]
async fn configured_local_backup_advances_without_reenqueue_after_publication() {
    let f = Fixture::new().await;
    let destination = f._tmp.path().join("public-backup.git");
    assert!(std::process::Command::new("git")
        .args(["init", "--bare"])
        .arg(&destination)
        .output()
        .unwrap()
        .status
        .success());
    let configured = run(
        &f.c.state,
        json!({"op":"backup_flush","destination":destination,"operation_id":"configure-backup"}),
    );
    assert_eq!(configured["state"], "complete");
    let service = Service::new(f.c.clone()).await.unwrap();
    let mut authority =
        AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
            .await
            .unwrap();
    authority.tick().await.unwrap();
    let peer = MemoryPeer {
        service,
        cert: f.cert.clone(),
        state: f.alice.clone(),
        staging: f.c.staging.clone(),
        lose_upload: Arc::new(AtomicBool::new(false)),
    };
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer)
        .await
        .unwrap();
    worker.tick(0).await.unwrap();
    f.proposal(&f.alice, "automatic-backup");
    worker.tick(5).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5100)).await;
    let observed = authority.tick().await.unwrap();
    assert_eq!(observed["backup"]["state"], "complete");
    assert_eq!(observed["backup"]["integration"], observed["head"]);
    assert!(
        observed["backup"]["watermark"].as_u64().unwrap()
            > configured["watermark"].as_u64().unwrap()
    );
    let verified = run(
        &f.c.state,
        json!({"op":"backup_verify_restore","destination":destination}),
    );
    assert_eq!(verified["ok"], true);
}

#[tokio::test]
async fn local_backup_still_ticks_when_promotion_admission_is_blocked() {
    let f = Fixture::new().await;
    let destination = f._tmp.path().join("blocked-backup.git");
    assert!(std::process::Command::new("git")
        .args(["init", "--bare"])
        .arg(&destination)
        .output()
        .unwrap()
        .status
        .success());
    run(
        &f.c.state,
        json!({"op":"backup_flush","destination":destination,"operation_id":"configure-backup"}),
    );
    let workspace = f._tmp.path().join("authority-work");
    run(
        &f.c.state,
        json!({"op":"open","workspace":"local","path":workspace,"operation_id":"local-open"}),
    );
    std::fs::write(workspace.join("queued.txt"), "queued retained work").unwrap();
    run(
        &f.c.state,
        json!({"op":"checkpoint","workspace":"local","expected_generation":0,"operation_id":"local-cp"}),
    );
    run(
        &f.c.state,
        json!({"op":"publish","workspace":"local","checkpoint":"local-cp","intent":"explicit source publication","operation_id":"local-pub"}),
    );
    assert_eq!(
        run(&f.c.state, json!({"op":"backup_status"}))["state"],
        "blocked"
    );
    let mut authority = AuthorityWorker::open_with_limits(
        engine_path(),
        f.c.state.clone(),
        f.c.staging.clone(),
        Limits {
            max_storage_bytes: 1,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    assert!(authority.tick().await.is_err());
    assert_eq!(
        run(&f.c.state, json!({"op":"backup_status"}))["state"],
        "complete"
    );
    assert_eq!(
        run(
            &f.c.state,
            json!({"op":"proposal_status","proposal":"local-pub"})
        )["state"],
        "coordinator_accepted"
    );
}

#[tokio::test]
async fn backup_failure_preserves_successful_source_promotion() {
    let f = Fixture::new().await;
    let destination = f._tmp.path().join("failed-backup.git");
    assert!(std::process::Command::new("git")
        .args(["init", "--bare"])
        .arg(&destination)
        .output()
        .unwrap()
        .status
        .success());
    run(
        &f.c.state,
        json!({"op":"backup_flush","destination":destination,"operation_id":"configure-backup"}),
    );
    let workspace = f._tmp.path().join("authority-work");
    run(
        &f.c.state,
        json!({"op":"open","workspace":"local","path":workspace,"operation_id":"local-open"}),
    );
    std::fs::write(workspace.join("queued.txt"), "queued retained work").unwrap();
    run(
        &f.c.state,
        json!({"op":"checkpoint","workspace":"local","expected_generation":0,"operation_id":"local-cp"}),
    );
    run(
        &f.c.state,
        json!({"op":"publish","workspace":"local","checkpoint":"local-cp","intent":"explicit source publication","operation_id":"local-pub"}),
    );
    assert_eq!(
        run(&f.c.state, json!({"op":"backup_status"}))["state"],
        "blocked"
    );
    std::fs::rename(&destination, f._tmp.path().join("unavailable-backup.git")).unwrap();
    let mut authority =
        AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
            .await
            .unwrap();
    let result = authority.tick().await.unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["integration"]["outcomes"][0]["state"], "integrated");
    assert_eq!(result["backup"]["state"], "blocked");
    assert_eq!(
        run(
            &f.c.state,
            json!({"op":"proposal_status","proposal":"local-pub"})
        )["state"],
        "integrated"
    );
}

struct AuditRetryPeer {
    inner: MemoryPeer,
    fail: Arc<AtomicBool>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl PeerSync for AuditRetryPeer {
    fn flush_audit(&self) -> Reply<'_> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err("audit_offline".into());
            }
            Ok(json!({"ok":true,"synced":true,"pending":0}))
        })
    }
    fn upload<'a>(&'a self, proposal: &'a str, operation: &'a str) -> Reply<'a> {
        self.inner.upload(proposal, operation)
    }
    fn catch_up(&self) -> Reply<'_> {
        self.inner.catch_up()
    }
    fn current_receipt<'a>(&'a self, proposal: &'a str) -> Reply<'a> {
        self.inner.current_receipt(proposal)
    }
}
#[tokio::test]
async fn audit_backoff_survives_restart_without_blocking_source_catch_up() {
    let f = Fixture::new().await;
    let service = Service::new(f.c.clone()).await.unwrap();
    let mut authority =
        AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
            .await
            .unwrap();
    authority.tick().await.unwrap();
    let fail = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peer = || AuditRetryPeer {
        inner: MemoryPeer {
            service: service.clone(),
            cert: f.cert.clone(),
            state: f.alice.clone(),
            staging: f.c.staging.clone(),
            lose_upload: Arc::new(AtomicBool::new(false)),
        },
        fail: fail.clone(),
        calls: calls.clone(),
    };
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .unwrap();
    assert_eq!(worker.tick(0).await.unwrap()["audit_failures"], 1);
    assert!(run(&f.alice, json!({"op":"status"}))["head"].is_string());
    drop(worker);
    fail.store(false, Ordering::SeqCst);
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .unwrap();
    worker.tick(1).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let result = worker.tick(2).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(result["audit_failures"], 0);
    assert_eq!(result["audit"]["synced"], true);
}

struct CoordinationRetryPeer {
    inner: MemoryPeer,
    fail: Arc<AtomicBool>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl PeerSync for CoordinationRetryPeer {
    fn flush_coordination(&self) -> Reply<'_> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err("coordination_offline".into());
            }
            Ok(json!({"ok":true,"synced":true,"pending":0}))
        })
    }
    fn upload<'a>(&'a self, proposal: &'a str, operation: &'a str) -> Reply<'a> {
        self.inner.upload(proposal, operation)
    }
    fn catch_up(&self) -> Reply<'_> {
        self.inner.catch_up()
    }
    fn current_receipt<'a>(&'a self, proposal: &'a str) -> Reply<'a> {
        self.inner.current_receipt(proposal)
    }
}
#[tokio::test]
async fn coordination_backoff_survives_restart_without_blocking_source_catch_up() {
    let f = Fixture::new().await;
    let service = Service::new(f.c.clone()).await.unwrap();
    let mut authority =
        AuthorityWorker::open(engine_path(), f.c.state.clone(), f.c.staging.clone())
            .await
            .unwrap();
    authority.tick().await.unwrap();
    let fail = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peer = || CoordinationRetryPeer {
        inner: MemoryPeer {
            service: service.clone(),
            cert: f.cert.clone(),
            state: f.alice.clone(),
            staging: f.c.staging.clone(),
            lose_upload: Arc::new(AtomicBool::new(false)),
        },
        fail: fail.clone(),
        calls: calls.clone(),
    };
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .unwrap();
    assert_eq!(worker.tick(0).await.unwrap()["coordination_failures"], 1);
    assert!(run(&f.alice, json!({"op":"status"}))["head"].is_string());
    drop(worker);
    fail.store(false, Ordering::SeqCst);
    let mut worker = Worker::open(engine_path(), f.alice.clone(), peer())
        .await
        .unwrap();
    worker.tick(1).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let result = worker.tick(2).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(result["coordination_failures"], 0);
    assert_eq!(result["coordination"]["synced"], true);
}
