use serde_json::json;
#[cfg(unix)]
use std::io::Write;
use wipstash_transport::{
    fingerprint,
    resumable::{Binding, Store, CHUNK_MAX},
    PAYLOAD_MAX,
};
fn tempdir() -> tempfile::TempDir {
    // macOS exposes temporary storage through symlink aliases. Resolve only
    // the test fixture parent; production continues rejecting symlink roots.
    tempfile::Builder::new()
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap()
}

fn binding() -> Binding {
    Binding {
        certificate: fingerprint(b"authenticated certificate"),
        device: "alice".into(),
        project: "demo".into(),
    }
}
fn manifest(payload: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({"version":1,"kind":"proposal","device":"alice","project":"demo","authority":"central","epoch":1,"payload_len":payload.len(),"payload_sha256":fingerprint(payload)})).unwrap()
}
#[test]
fn restart_lost_ack_replay_and_final_digest() {
    let t = tempdir();
    let b = binding();
    let payload = vec![42; CHUNK_MAX + 33];
    let m = manifest(&payload);
    let store = Store::open(t.path()).unwrap();
    let initial = store.begin(&b, &m).unwrap();
    let id = initial.transfer_id;
    assert_eq!(initial.committed_offset, 0);
    assert!(store.artifact(&b, &id).is_err());
    assert!(store.complete(&b, &id, json!({"ok":true})).is_err());
    assert_eq!(
        store
            .chunk(&b, &id, 0, &payload[..CHUNK_MAX])
            .unwrap()
            .committed_offset,
        CHUNK_MAX as u64
    );
    drop(store);
    let store = Store::open(t.path()).unwrap();
    assert_eq!(
        store.begin(&b, &m).unwrap().committed_offset,
        CHUNK_MAX as u64
    );
    // Lost-ack replay is identical and has no acceptance result.
    assert!(store
        .chunk(&b, &id, 0, &payload[..CHUNK_MAX])
        .unwrap()
        .import_result
        .is_none());
    assert!(store.chunk(&b, &id, 0, b"changed").is_err());
    assert!(store.chunk(&b, &id, CHUNK_MAX as u64 + 1, b"gap").is_err());
    assert!(store
        .chunk(&b, &id, CHUNK_MAX as u64 - 1, b"overlap")
        .is_err());
    store
        .chunk(&b, &id, CHUNK_MAX as u64, &payload[CHUNK_MAX..])
        .unwrap();
    assert_eq!(store.artifact(&b, &id).unwrap().objects, payload);
    assert!(store.complete(&b, &id, serde_json::Value::Null).is_err());
    assert_eq!(store.artifact(&b, &id).unwrap().objects, payload);
    let imported = json!({"ok":true,"proposal":"core-proposal"});
    store.complete(&b, &id, imported.clone()).unwrap();
    assert!(!t.path().join(&id).join("payload").exists());
    assert!(store.chunk(&b, &id, 0, &payload[..CHUNK_MAX]).is_ok());
    assert!(store.chunk(&b, &id, 0, b"changed").is_err());
    drop(store);
    let store = Store::open(t.path()).unwrap();
    assert_eq!(
        store.status(&b, &id).unwrap().import_result,
        Some(imported.clone())
    );
    assert!(store.complete(&b, &id, imported).is_ok());
    assert!(store.complete(&b, &id, json!({"changed":true})).is_err());
}
#[test]
fn binding_paths_and_immutable_manifest() {
    let t = tempdir();
    let store = Store::open(t.path()).unwrap();
    let b = binding();
    let m = manifest(b"abc");
    let id = store.begin(&b, &m).unwrap().transfer_id;
    for other in [
        Binding {
            certificate: fingerprint(b"other cert"),
            ..b.clone()
        },
        Binding {
            device: "bob".into(),
            ..b.clone()
        },
        Binding {
            project: "other".into(),
            ..b.clone()
        },
    ] {
        assert!(store.status(&other, &id).is_err());
        assert!(store.chunk(&other, &id, 0, b"abc").is_err());
        assert!(store.artifact(&other, &id).is_err());
    }
    for id in ["../escape", "/tmp/escape", "a", &"A".repeat(64)] {
        assert!(store.status(&b, id).is_err());
    }
    let mut changed: serde_json::Value = serde_json::from_slice(&m).unwrap();
    changed["epoch"] = json!(2);
    assert_ne!(
        store
            .begin(&b, &serde_json::to_vec(&changed).unwrap())
            .unwrap()
            .transfer_id,
        id
    );
    assert!(store.chunk(&b, &id, 0, &vec![0; CHUNK_MAX + 1]).is_err());
    assert!(store.chunk(&b, &id, u64::MAX, b"x").is_err());
    assert!(store.chunk(&b, &id, 0, b"").is_err());
    changed["payload_len"] = json!(PAYLOAD_MAX + 1);
    assert!(store
        .begin(&b, &serde_json::to_vec(&changed).unwrap())
        .is_err());
}
#[cfg(unix)]
#[test]
fn journal_recovery_discards_only_unacknowledged_tail_and_rejects_corruption() {
    let t = tempdir();
    let b = binding();
    let store = Store::open(t.path()).unwrap();
    let id = store.begin(&b, &manifest(b"abcdef")).unwrap().transfer_id;
    store.chunk(&b, &id, 0, b"abc").unwrap();
    let path = t.path().join(&id).join("payload");
    // Simulates a crash after data fsync but before durable journal advancement.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    f.write_all(b"BAD").unwrap();
    f.sync_all().unwrap();
    drop(f);
    drop(store);
    let store = Store::open(t.path()).unwrap();
    assert_eq!(store.status(&b, &id).unwrap().committed_offset, 3);
    store.chunk(&b, &id, 3, b"def").unwrap();
    assert_eq!(store.artifact(&b, &id).unwrap().objects, b"abcdef");
    std::fs::write(&path, b"abcBAD").unwrap();
    assert!(store.artifact(&b, &id).is_err());
    std::fs::write(&path, b"ab").unwrap();
    assert!(store.chunk(&b, &id, 0, b"ab").is_err());
}

fn engine_path() -> std::path::PathBuf {
    std::env::var_os("WIPSTASH_ENGINE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
                "../../target/debug/wipstash{}",
                std::env::consts::EXE_SUFFIX
            ))
        })
        .canonicalize()
        .expect("build engine first")
}
fn engine(state: &std::path::Path, request: serde_json::Value) -> serde_json::Value {
    let output = std::process::Command::new(engine_path())
        .arg("--state")
        .arg(state)
        .arg(request.to_string())
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        output.status.success(),
        "request={request}; response={value}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    value
}
#[tokio::test]
async fn actual_engine_in_memory_adapter_resumes_and_imports_only_at_finish() {
    use std::{collections::HashMap, fs};
    use wipstash_transport::{Acl, Artifact, Config, Limits, Peer, Service};
    let t = tempdir();
    let root = t.path();
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("hello"), "hello").unwrap();
    let state = root.join("authority");
    let client = root.join("client");
    let staging = root.join("staging");
    fs::create_dir(&staging).unwrap();
    engine(&state, json!({"op":"init","source":source}));
    engine(
        &state,
        json!({"op":"sync_configure","project":"demo","authority":"central","epoch":1,"device":"central-device","role":"authority","peers":["alice"]}),
    );
    engine(
        &client,
        json!({"op":"sync_configure","project":"demo","authority":"central","epoch":1,"device":"alice","role":"client","peers":["central-device"]}),
    );
    let cert = b"test-only-in-memory-authenticated-certificate";
    let acl = root.join("acl.json");
    let mut peers = Acl {
        peers: HashMap::from([(
            fingerprint(cert),
            Peer {
                device: "alice".into(),
                project: "demo".into(),
                role: "client".into(),
                revoked: false,
            },
        )]),
    };
    fs::write(&acl, serde_json::to_vec(&peers).unwrap()).unwrap();
    let config = Config {
        engine: engine_path(),
        state: state.clone(),
        staging: staging.clone(),
        project: "demo".into(),
        authority: "central".into(),
        epoch: 1,
        device: "central-device".into(),
        acl: acl.clone(),
        ca: root.join("unused-ca"),
        certificate: root.join("unused-cert"),
        key: root.join("unused-key").into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        limits: Limits {
            request_burst: 10000,
            requests_per_minute: 100000,
            ..Limits::default()
        },
    };
    let service = Service::new(config.clone()).await.unwrap();
    let (_, wire) = service
        .route(
            cert,
            "POST",
            "/v1/export",
            &serde_json::to_vec(&json!({"kind":"head","operation_id":"initial"})).unwrap(),
        )
        .await
        .unwrap();
    let head = Artifact::decode(&wire).unwrap();
    let head_dir = root.join("head");
    fs::create_dir(&head_dir).unwrap();
    fs::write(head_dir.join("manifest.json"), head.manifest).unwrap();
    fs::write(head_dir.join("objects.json"), head.objects).unwrap();
    engine(
        &client,
        json!({"op":"sync_import","source":head_dir,"confirm_trusted_source":true}),
    );
    let workspace = root.join("work");
    engine(
        &client,
        json!({"op":"open","workspace":"work","path":workspace,"operation_id":"open"}),
    );
    fs::write(
        workspace.join("new.txt"),
        "resumable synthetic content\n".repeat(15000),
    )
    .unwrap();
    engine(
        &client,
        json!({"op":"checkpoint","workspace":"work","expected_generation":0,"operation_id":"checkpoint"}),
    );
    engine(
        &client,
        json!({"op":"publish","workspace":"work","checkpoint":"checkpoint","intent":"Synthetic resumable transport test","operation_id":"proposal"}),
    );
    let artifact_dir = root.join("proposal");
    engine(
        &client,
        json!({"op":"sync_export","kind":"proposal","proposal":"proposal","destination":artifact_dir,"operation_id":"export"}),
    );
    let manifest = fs::read(artifact_dir.join("manifest.json")).unwrap();
    let payload = fs::read(artifact_dir.join("objects.json")).unwrap();
    assert!(payload.len() > CHUNK_MAX);
    let (_, bytes) = service
        .route(cert, "POST", "/v1/transfers", &manifest)
        .await
        .unwrap();
    let start: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let id = start["transfer_id"].as_str().unwrap();
    let path = format!("/v1/transfers/{id}");
    let (_, ack) = service
        .route(cert, "PUT", &format!("{path}/0"), &payload[..CHUNK_MAX])
        .await
        .unwrap();
    let ack: serde_json::Value = serde_json::from_slice(&ack).unwrap();
    assert!(ack["import_result"].is_null());
    assert!(service
        .route(cert, "POST", &format!("{path}/finish"), b"")
        .await
        .is_err());
    drop(service);
    let mut quota_config = config.clone();
    quota_config.limits.max_storage_bytes = 1;
    let quota_service = Service::new(quota_config).await.unwrap();
    quota_service.route(cert, "GET", &path, b"").await.unwrap();
    quota_service
        .route(cert, "POST", "/v1/transfers", &manifest)
        .await
        .unwrap();
    quota_service
        .route(cert, "PUT", &format!("{path}/0"), &payload[..CHUNK_MAX])
        .await
        .unwrap();
    assert_eq!(
        quota_service
            .route(
                cert,
                "PUT",
                &format!("{path}/{CHUNK_MAX}"),
                &payload[CHUNK_MAX..]
                    .iter()
                    .copied()
                    .take(CHUNK_MAX)
                    .collect::<Vec<_>>()
            )
            .await
            .unwrap_err()
            .to_string(),
        "storage_quota"
    );
    drop(quota_service);
    let service = Service::new(config).await.unwrap();
    service
        .route(cert, "PUT", &format!("{path}/0"), &payload[..CHUNK_MAX])
        .await
        .unwrap();
    assert!(service
        .route(b"different cert", "GET", &path, b"")
        .await
        .is_err());
    peers.peers.get_mut(&fingerprint(cert)).unwrap().revoked = true;
    fs::write(&acl, serde_json::to_vec(&peers).unwrap()).unwrap();
    assert!(service.route(cert, "GET", &path, b"").await.is_err());
    peers.peers.get_mut(&fingerprint(cert)).unwrap().revoked = false;
    fs::write(&acl, serde_json::to_vec(&peers).unwrap()).unwrap();
    let lost_ack = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let artifact = Artifact {
        manifest,
        objects: payload,
    };
    let status = wipstash_transport::resumable::upload(&artifact, |method, path, body| {
        let service = service.clone();
        let lost_ack = lost_ack.clone();
        async move {
            let reply = service.route(cert, &method, &path, &body).await?;
            if method == "PUT" && !lost_ack.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "simulated lost acknowledgement",
                )
                .into());
            }
            Ok(reply)
        }
    })
    .await
    .unwrap();
    assert!(lost_ack.load(std::sync::atomic::Ordering::SeqCst));
    let finished = serde_json::to_vec(&status).unwrap();
    assert!(!staging.join("resumable").join(id).join("payload").exists());
    let (_, replayed) = service
        .route(cert, "POST", &format!("{path}/finish"), b"")
        .await
        .unwrap();
    assert_eq!(finished, replayed);
    let finished: serde_json::Value = serde_json::from_slice(&finished).unwrap();
    assert!(!finished["import_result"].is_null(), "{finished}");
}

#[cfg(unix)]
#[test]
fn symlinks_and_changed_journal_are_rejected() {
    use std::os::unix::fs::symlink;
    let t = tempdir();
    let b = binding();
    let real = t.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = t.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(Store::open(&link).is_err());
    let store = Store::open(&real).unwrap();
    let id = store.begin(&b, &manifest(b"abc")).unwrap().transfer_id;
    let payload = real.join(&id).join("payload");
    std::fs::remove_file(&payload).unwrap();
    let external = t.path().join("external");
    std::fs::write(&external, b"keep").unwrap();
    symlink(&external, &payload).unwrap();
    assert!(store.chunk(&b, &id, 0, b"abc").is_err());
    assert_eq!(std::fs::read(&external).unwrap(), b"keep");
    let record_path = real.join(&id).join("record.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    record["status"]["payload_len"] = json!(4);
    std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(store.status(&b, &id).is_err());
}
