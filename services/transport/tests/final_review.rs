//! Independent final-review regressions. These use direct service routing, no listener.
use serde_json::json;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use wipstash_transport::{
    fingerprint,
    resumable::{Binding, Store},
    Acl, Config, Limits, Peer, Service,
};
fn engine_path() -> PathBuf {
    std::env::var_os("WIPSTASH_ENGINE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/wipstash")
        })
        .canonicalize()
        .expect("build engine first")
}
fn engine(state: &Path, request: serde_json::Value) {
    let output = std::process::Command::new(engine_path())
        .arg("--state")
        .arg(state)
        .arg(request.to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[tokio::test]
async fn retained_transfers_cannot_cross_authority_epoch() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("hello"), "hello").unwrap();
    let state = root.join("state");
    let staging = root.join("staging");
    fs::create_dir(&staging).unwrap();
    engine(&state, json!({"op":"init","source":source}));
    engine(
        &state,
        json!({"op":"sync_configure","project":"demo","authority":"central","epoch":2,"device":"central-device","role":"authority","peers":["alice"]}),
    );
    let cert = b"test-only-authenticated-certificate";
    let acl = root.join("acl.json");
    fs::write(
        &acl,
        serde_json::to_vec(&Acl {
            peers: HashMap::from([(
                fingerprint(cert),
                Peer {
                    device: "alice".into(),
                    project: "demo".into(),
                    role: "client".into(),
                    revoked: false,
                },
            )]),
        })
        .unwrap(),
    )
    .unwrap();
    let binding = Binding {
        certificate: fingerprint(cert),
        device: "alice".into(),
        project: "demo".into(),
    };
    let store = Store::open(staging.join("resumable")).unwrap();
    let mut transfers = Vec::new();
    for (authority, epoch, completed) in [
        ("central", 1, false),
        ("central", 1, true),
        ("foreign-authority", 2, false),
        ("foreign-authority", 2, true),
    ] {
        let payload = if completed { &b"abc"[..] } else { &b"abcd"[..] };
        let manifest = serde_json::to_vec(&json!({"version":1,"kind":"proposal","device":"alice","project":"demo","authority":authority,"epoch":epoch,"payload_len":payload.len(),"payload_sha256":fingerprint(payload)})).unwrap();
        let id = store.begin(&binding, &manifest).unwrap().transfer_id;
        store.chunk(&binding, &id, 0, b"abc").unwrap();
        if completed {
            store.complete(&binding, &id, json!({"ok":true,"proposal":"old-authority-proposal","source_proposal":"source"})).unwrap();
            assert!(!staging.join("resumable").join(&id).join("payload").exists());
        }
        transfers.push((id, authority, epoch, completed));
    }
    let service = Service::new(Config {
        engine: engine_path(),
        state,
        staging,
        project: "demo".into(),
        authority: "central".into(),
        epoch: 2,
        device: "central-device".into(),
        acl: acl.into(),
        ca: root.join("unused-ca"),
        certificate: root.join("unused-cert"),
        key: root.join("unused-key").into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        limits: Limits::default(),
    })
    .await
    .unwrap();
    let mut accepted = Vec::new();
    for (id, authority, epoch, completed) in transfers {
        for (method, suffix, body) in [
            ("GET", "", &b""[..]),
            ("PUT", "/0", &b"abc"[..]),
            ("POST", "/finish", &b""[..]),
        ] {
            if service
                .route(cert, method, &format!("/v1/transfers/{id}{suffix}"), body)
                .await
                .is_ok()
            {
                accepted.push(format!(
                    "{authority}/{epoch} completed={completed}: {method} {suffix}"
                ));
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "stale-epoch transfer accepted by new authority: {accepted:?}"
    );
}
