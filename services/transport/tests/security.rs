use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use wipstash_transport::*;

fn ca() -> (Certificate, KeyPair) {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let k = KeyPair::generate().unwrap();
    (p.self_signed(&k).unwrap(), k)
}
fn leaf(ca: &Certificate, key: &KeyPair, name: &str, server: bool) -> (Certificate, KeyPair) {
    let mut p = CertificateParams::new(vec![name.into()]).unwrap();
    p.extended_key_usages = vec![if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    }];
    let k = KeyPair::generate().unwrap();
    (p.signed_by(&k, ca, key).unwrap(), k)
}
fn roots_for(c: &Certificate) -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(c.der().clone()).unwrap();
    r
}
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
    bob: PathBuf,
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
            limits: wipstash_transport::Limits {
                request_burst: 10000,
                requests_per_minute: 100000,
                ..Default::default()
            },
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
            bob,
            cert,
        }
    }
    fn import(&self, state: &Path, a: &Artifact, name: &str) -> Value {
        let d = self.c.staging.join(name);
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("manifest.json"), &a.manifest).unwrap();
        std::fs::write(d.join("objects.json"), &a.objects).unwrap();
        run(
            state,
            json!({"op":"sync_import","source":d,"confirm_trusted_source":true}),
        )
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
#[test]
fn acl_denies_unknown_wrong_project_role_and_revoked() {
    let cert = b"x";
    let peer = Peer {
        device: "alice".into(),
        project: "demo".into(),
        role: "client".into(),
        revoked: false,
    };
    let mut a = Acl {
        peers: HashMap::from([(fingerprint(cert), peer)]),
    };
    assert!(authorize(&a, cert, "demo").is_ok());
    assert!(authorize(&a, b"other", "demo").is_err());
    assert!(authorize(&a, cert, "other").is_err());
    a.peers.get_mut(&fingerprint(cert)).unwrap().role = "admin".into();
    assert!(authorize(&a, cert, "demo").is_err());
    a.peers.get_mut(&fingerprint(cert)).unwrap().role = "client".into();
    a.peers.get_mut(&fingerprint(cert)).unwrap().revoked = true;
    assert!(authorize(&a, cert, "demo").is_err());
}
#[test]
fn bounds_and_checksums() {
    assert!(Artifact::decode(&[0, 0, 0, 0]).is_err());
    assert!(Artifact::decode(&vec![0; WIRE_MAX + 1]).is_err());
    assert!(Artifact::decode(&[255, 255, 255, 255]).is_err());
    let a = Artifact {
        manifest: serde_json::to_vec(
            &json!({"version":1,"payload_len":1,"payload_sha256":fingerprint(b"a")}),
        )
        .unwrap(),
        objects: b"b".to_vec(),
    };
    assert!(a.encode().is_err());
}
#[tokio::test]
async fn actual_engine_exchange_receipts_replay_and_isolation() {
    let f = Fixture::new().await;
    let s = Service::new(f.c.clone()).await.unwrap();
    let request = serde_json::to_vec(&json!({"kind":"head","operation_id":"initial"})).unwrap();
    let (_, wire) = s
        .route(&f.cert, "POST", "/v1/export", &request)
        .await
        .unwrap();
    let head = Artifact::decode(&wire).unwrap();
    let (_, again) = s
        .route(&f.cert, "POST", "/v1/export", &request)
        .await
        .unwrap();
    assert_eq!(wire, again);
    f.import(&f.alice, &head, "alice-head");
    f.import(&f.bob, &head, "bob-head");
    let a = f.proposal(&f.alice, "alice");
    let b = f.proposal(&f.bob, "bob");
    assert!(
        s.route(&f.cert, "POST", "/v1/proposals", &b.encode().unwrap())
            .await
            .is_err(),
        "manifest identity cannot impersonate Bob"
    );
    let (_, accepted) = s
        .route(&f.cert, "POST", "/v1/proposals", &a.encode().unwrap())
        .await
        .unwrap();
    let accepted: Value = serde_json::from_slice(&accepted).unwrap();
    let authority_proposal = accepted["proposal"].as_str().unwrap();
    let (_, duplicate) = s
        .route(&f.cert, "POST", "/v1/proposals", &a.encode().unwrap())
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&duplicate).unwrap()["duplicate"],
        true
    );
    run(&f.c.state, json!({"op":"integrate"}));
    let receipt = serde_json::to_vec(
        &json!({"kind":"receipt","operation_id":"receipt-1","proposal":authority_proposal}),
    )
    .unwrap();
    let (_, r) = s
        .route(&f.cert, "POST", "/v1/export", &receipt)
        .await
        .unwrap();
    let r = Artifact::decode(&r).unwrap();
    f.import(&f.alice, &r, "receipt-import");
    assert_eq!(
        run(
            &f.alice,
            json!({"op":"proposal_status","proposal":"proposal"})
        )["state"],
        "integrated"
    );
    let mut acl: Acl = serde_json::from_slice(&std::fs::read(&f.c.acl).unwrap()).unwrap();
    acl.peers.get_mut(&fingerprint(&f.cert)).unwrap().device = "bob".into();
    std::fs::write(&f.c.acl, serde_json::to_vec(&acl).unwrap()).unwrap();
    let before_denied = run(&f.c.state, json!({"op":"sync_export_history"}));
    assert!(
        s.route(&f.cert, "POST", "/v1/export", &receipt)
            .await
            .is_err(),
        "receipt cannot be read by another device"
    );
    assert_eq!(
        before_denied,
        run(&f.c.state, json!({"op":"sync_export_history"})),
        "unauthorized request must not reserve or export another device's receipt"
    );
    let (_, history) = s.route(&f.cert, "GET", "/v1/history", &[]).await.unwrap();
    let history: Value = serde_json::from_slice(&history).unwrap();
    assert!(history["exports"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["kind"] == "head"));
    for body in [
        json!({"kind":"retained","operation_id":"../../state"}),
        json!({"kind":"head","operation_id":"x","destination":"/tmp/escape"}),
        json!({"kind":"head","operation_id":"x","op":"worker"}),
    ] {
        assert!(s
            .route(
                &f.cert,
                "POST",
                "/v1/export",
                &serde_json::to_vec(&body).unwrap()
            )
            .await
            .is_err());
    }
    assert!(s
        .route(&f.cert, "POST", "/v1/proposals/../../run", &[])
        .await
        .is_err());
    acl.peers.get_mut(&fingerprint(&f.cert)).unwrap().revoked = true;
    std::fs::write(&f.c.acl, serde_json::to_vec(&acl).unwrap()).unwrap();
    assert!(s.route(&f.cert, "GET", "/v1/history", &[]).await.is_err());
}

// The test matrix varies each trust input independently.
#[allow(clippy::too_many_arguments)]
async fn tls_request(
    f: &Fixture,
    root: &Certificate,
    server: &Certificate,
    server_key: &KeyPair,
    client_root: &Certificate,
    client_cert: &Certificate,
    client_key: &KeyPair,
    name: &str,
    pin: &str,
) -> Result<Vec<u8>> {
    let tls = Arc::new(server_tls(
        roots_for(root),
        vec![server.der().clone()],
        PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
    )?);
    let c = Client {
        tls: Arc::new(client_tls(
            roots_for(client_root),
            vec![client_cert.der().clone()],
            PrivatePkcs8KeyDer::from(client_key.serialize_der()).into(),
        )?),
        server_name: name.into(),
        authority_fingerprint: pin.into(),
    };
    let s = Service::new(f.c.clone()).await?;
    let (a, b) = tokio::io::duplex(65536);
    let server = tokio::spawn(s.serve_stream(a, tls));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        c.request_stream(b, "GET", "/v1/history", Vec::new()),
    )
    .await?;
    server.abort();
    result
}
#[tokio::test]
async fn real_mtls_http_over_memory_rejects_wrong_ca_name_pin_and_identity() {
    let f = Fixture::new().await;
    let (root, key) = ca();
    let (server, sk) = leaf(&root, &key, "localhost", true);
    let (alice, ak) = leaf(&root, &key, "alice", false);
    let (bob, bk) = leaf(&root, &key, "bob", false);
    let (wrong, wk) = ca();
    let (mallory, mk) = leaf(&wrong, &wk, "mallory", false);
    let acl = Acl {
        peers: HashMap::from([(
            fingerprint(alice.der()),
            Peer {
                device: "alice".into(),
                project: "demo".into(),
                role: "client".into(),
                revoked: false,
            },
        )]),
    };
    std::fs::write(&f.c.acl, serde_json::to_vec(&acl).unwrap()).unwrap();
    let pin = fingerprint(server.der());
    let good = tls_request(
        &f,
        &root,
        &server,
        &sk,
        &root,
        &alice,
        &ak,
        "localhost",
        &pin,
    )
    .await
    .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&good).unwrap()["ok"], true);
    assert!(tls_request(
        &f,
        &root,
        &server,
        &sk,
        &wrong,
        &alice,
        &ak,
        "localhost",
        &pin
    )
    .await
    .is_err());
    assert!(tls_request(
        &f,
        &root,
        &server,
        &sk,
        &root,
        &mallory,
        &mk,
        "localhost",
        &pin
    )
    .await
    .is_err());
    assert!(
        tls_request(&f, &root, &server, &sk, &root, &bob, &bk, "localhost", &pin)
            .await
            .is_err()
    );
    assert!(tls_request(
        &f,
        &root,
        &server,
        &sk,
        &root,
        &alice,
        &ak,
        "wrong.example",
        &pin
    )
    .await
    .is_err());
    assert!(tls_request(
        &f,
        &root,
        &server,
        &sk,
        &root,
        &alice,
        &ak,
        "localhost",
        &"0".repeat(64)
    )
    .await
    .is_err());
}

#[tokio::test]
async fn http_headers_cannot_forge_identity_and_oversize_body_is_rejected() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::ServerName;
    let f = Fixture::new().await;
    let (root, key) = ca();
    let (server, sk) = leaf(&root, &key, "localhost", true);
    let (alice, ak) = leaf(&root, &key, "alice", false);
    let acl = Acl {
        peers: HashMap::from([(
            fingerprint(alice.der()),
            Peer {
                device: "alice".into(),
                project: "demo".into(),
                role: "client".into(),
                revoked: false,
            },
        )]),
    };
    std::fs::write(&f.c.acl, serde_json::to_vec(&acl).unwrap()).unwrap();
    let s = Service::new(f.c.clone()).await.unwrap();
    let tls = Arc::new(
        server_tls(
            roots_for(&root),
            vec![server.der().clone()],
            PrivatePkcs8KeyDer::from(sk.serialize_der()).into(),
        )
        .unwrap(),
    );
    let ctls = Arc::new(
        client_tls(
            roots_for(&root),
            vec![alice.der().clone()],
            PrivatePkcs8KeyDer::from(ak.serialize_der()).into(),
        )
        .unwrap(),
    );
    let (a, b) = tokio::io::duplex(65536);
    let server_task = tokio::spawn(s.clone().serve_stream(a, tls));
    let stream = tokio_rustls::TlsConnector::from(ctls)
        .connect(ServerName::try_from("localhost").unwrap(), b)
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    // The certificate authenticates Alice despite headers asserting Bob/admin/another project.
    let req = hyper::Request::builder()
        .method("GET")
        .uri("/v1/history")
        .header("host", "localhost")
        .header("x-device", "bob")
        .header("x-project", "other")
        .header("x-role", "admin")
        .header("x-forwarded-client-cert", "bob")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let r = sender.send_request(req).await.unwrap();
    assert_eq!(r.status(), 200);
    r.into_body().collect().await.unwrap();
    let head = serde_json::to_vec(&json!({"kind":"head","operation_id":"initial"})).unwrap();
    let (_, wire) = s
        .route(alice.der(), "POST", "/v1/export", &head)
        .await
        .unwrap();
    f.import(&f.bob, &Artifact::decode(&wire).unwrap(), "bob-http-head");
    let bob = f.proposal(&f.bob, "http-bob");
    let req = hyper::Request::builder()
        .method("POST")
        .uri("/v1/proposals")
        .header("host", "localhost")
        .header("x-device", "bob")
        .header("x-forwarded-client-cert", "bob")
        .body(Full::new(Bytes::from(bob.encode().unwrap())))
        .unwrap();
    let r = sender.send_request(req).await.unwrap();
    assert_eq!(r.status(), 400);
    r.into_body().collect().await.unwrap();
    // Revocation is reloaded on an already authenticated, reused HTTP/TLS connection.
    let mut revoked = acl.clone();
    revoked
        .peers
        .get_mut(&fingerprint(alice.der()))
        .unwrap()
        .revoked = true;
    std::fs::write(&f.c.acl, serde_json::to_vec(&revoked).unwrap()).unwrap();
    let req = hyper::Request::builder()
        .method("GET")
        .uri("/v1/history")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let r = sender.send_request(req).await.unwrap();
    assert_eq!(r.status(), 400);
    r.into_body().collect().await.unwrap();
    std::fs::write(&f.c.acl, serde_json::to_vec(&acl).unwrap()).unwrap();
    let req = hyper::Request::builder()
        .method("POST")
        .uri("/v1/proposals")
        .header("host", "localhost")
        .body(Full::new(Bytes::from(vec![0; WIRE_MAX + 1])))
        .unwrap();
    let r = sender.send_request(req).await.unwrap();
    assert_eq!(r.status(), 400);
    server_task.abort();
}

#[tokio::test]
async fn plaintext_and_missing_client_certificate_fail_closed() {
    use tokio::io::AsyncWriteExt;
    let f = Fixture::new().await;
    let (root, key) = ca();
    let (server, sk) = leaf(&root, &key, "localhost", true);
    let tls = Arc::new(
        server_tls(
            roots_for(&root),
            vec![server.der().clone()],
            PrivatePkcs8KeyDer::from(sk.serialize_der()).into(),
        )
        .unwrap(),
    );
    let s = Service::new(f.c.clone()).await.unwrap();
    let (a, mut b) = tokio::io::duplex(4096);
    let st = tokio::spawn(s.clone().serve_stream(a, tls.clone()));
    b.write_all(b"GET /v1/history HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    drop(b);
    assert!(st.await.unwrap().is_err());
    let ctls = rustls::ClientConfig::builder()
        .with_root_certificates(roots_for(&root))
        .with_no_client_auth();
    let (a, b) = tokio::io::duplex(4096);
    let st = tokio::spawn(s.serve_stream(a, tls));
    let c = Client {
        tls: Arc::new(ctls),
        server_name: "localhost".into(),
        authority_fingerprint: fingerprint(server.der()),
    };
    assert!(c
        .request_stream(b, "GET", "/v1/history", vec![])
        .await
        .is_err());
    assert!(st.await.unwrap().is_err());
}

#[tokio::test]
async fn history_pages_and_replay_beyond_page_boundary() {
    let f = Fixture::new().await;
    let s = Service::new(f.c.clone()).await.unwrap();
    let first_request =
        serde_json::to_vec(&json!({"kind":"head","operation_id":"page-0"})).unwrap();
    let (_, original) = s
        .route(&f.cert, "POST", "/v1/export", &first_request)
        .await
        .unwrap();
    for n in 1..130 {
        s.route(
            &f.cert,
            "POST",
            "/v1/export",
            &serde_json::to_vec(&json!({"kind":"head","operation_id":format!("page-{n}")}))
                .unwrap(),
        )
        .await
        .unwrap();
    }
    let (_, page) = s.route(&f.cert, "GET", "/v1/history", &[]).await.unwrap();
    let page: Value = serde_json::from_slice(&page).unwrap();
    assert_eq!(page["exports"].as_array().unwrap().len(), 128);
    assert_eq!(page["next_cursor"], 128);
    assert_eq!(page["has_more"], true);
    let body = serde_json::to_vec(&json!({"after":128,"cursor_kind":"head_sequence"})).unwrap();
    let (_, next) = s
        .route(&f.cert, "POST", "/v1/history", &body)
        .await
        .unwrap();
    let next: Value = serde_json::from_slice(&next).unwrap();
    assert_eq!(next["exports"].as_array().unwrap().len(), 2);
    assert_eq!(next["exports"][0]["sequence"], 129);
    assert_eq!(next["next_cursor"], 130);
    assert_eq!(next["has_more"], false);
    let (_, replay) = s
        .route(&f.cert, "POST", "/v1/export", &first_request)
        .await
        .unwrap();
    assert_eq!(original, replay);
    for body in [
        json!({"after":131}),
        json!({"after":128,"cursor_kind":"export_row"}),
        json!({"limit":257}),
    ] {
        assert!(s
            .route(
                &f.cert,
                "POST",
                "/v1/history",
                &serde_json::to_vec(&body).unwrap()
            )
            .await
            .is_err());
    }
    // A fresh client can consume all pages contiguously without adopting into a workspace.
    let mut cursor = 0;
    loop {
        let (_, page) = s
            .route(
                &f.cert,
                "POST",
                "/v1/history",
                &serde_json::to_vec(&json!({"after":cursor,"limit":51})).unwrap(),
            )
            .await
            .unwrap();
        let page: Value = serde_json::from_slice(&page).unwrap();
        for h in page["exports"].as_array().unwrap() {
            let (_, wire) = s
                .route(
                    &f.cert,
                    "POST",
                    "/v1/export",
                    &serde_json::to_vec(
                        &json!({"kind":"retained","operation_id":h["operation_id"]}),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let imported = f.import(
                &f.alice,
                &Artifact::decode(&wire).unwrap(),
                &format!("page-import-{cursor}"),
            );
            cursor += 1;
            assert_eq!(imported["sequence"], cursor);
            assert_eq!(imported["files_changed"], false);
        }
        if page["has_more"] == false {
            break;
        }
    }
    assert_eq!(cursor, 130);
    assert_eq!(run(&f.alice, json!({"op":"sync_status"}))["cursor"], 130);
}

#[tokio::test]
async fn quota_rejection_does_not_reserve_export_or_change_history() {
    let mut f = Fixture::new().await;
    f.c.limits.max_storage_bytes = 1;
    let s = Service::new(f.c.clone()).await.unwrap();
    let before = run(&f.c.state, json!({"op":"sync_export_history"}));
    let request = serde_json::to_vec(&json!({"kind":"head","operation_id":"over-budget"})).unwrap();
    let error = s
        .route(&f.cert, "POST", "/v1/export", &request)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "storage_quota");
    assert_eq!(before, run(&f.c.state, json!({"op":"sync_export_history"})));
    assert!(
        s.route(&f.cert, "GET", "/v1/history", &[]).await.is_ok(),
        "quota pressure must not disable bounded reads"
    );
}

#[tokio::test]
async fn authenticated_peer_rate_is_bounded_without_engine_mutation() {
    let mut f = Fixture::new().await;
    f.c.limits.request_burst = 1;
    f.c.limits.requests_per_minute = 1;
    let s = Service::new(f.c.clone()).await.unwrap();
    assert!(s.route(&f.cert, "GET", "/v1/history", &[]).await.is_ok());
    let error = s
        .route(&f.cert, "GET", "/v1/history", &[])
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "rate_limited");
}
