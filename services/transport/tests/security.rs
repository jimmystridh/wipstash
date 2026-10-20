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

#[tokio::test]
async fn central_audit_reads_require_peer_identity_and_bounded_pages() {
    let fixture = Fixture::new().await;
    let service = Service::new(fixture.c.clone()).await.unwrap();
    let request = serde_json::to_vec(&json!({"cursor":0,"limit":16})).unwrap();
    let (_, bytes) = service
        .route(&fixture.cert, "GET", "/v1/audit-log", &request)
        .await
        .unwrap();
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["ok"], true);
    assert!(!result["records"].as_array().unwrap().is_empty());
    assert!(service
        .route(b"unknown", "GET", "/v1/audit-log", &request)
        .await
        .is_err());
    for limit in [0, 33] {
        assert!(service
            .route(
                &fixture.cert,
                "GET",
                "/v1/audit-log",
                &serde_json::to_vec(&json!({"cursor":0,"limit":limit})).unwrap()
            )
            .await
            .is_err());
    }
}
#[tokio::test]
async fn exact_validation_reads_are_authenticated_and_reject_invalid_queries() {
    let fixture = Fixture::new().await;
    let service = Service::new(fixture.c.clone()).await.unwrap();
    let request = serde_json::to_vec(
        &json!({"head":"0000000000000000000000000000000000000000","include_timings":true}),
    )
    .unwrap();
    let (_, bytes) = service
        .route(&fixture.cert, "GET", "/v1/validation", &request)
        .await
        .unwrap();
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["release_ready"], false);
    assert_eq!(result["validation"]["state"], "unchecked");
    assert!(result["operation_timings"].is_array());
    assert!(service
        .route(b"unknown", "GET", "/v1/validation", &request)
        .await
        .is_err());
    for request in [
        json!({"head":"invalid"}),
        json!({"include_timings":"true"}),
        json!({"op":"configure"}),
    ] {
        assert!(service
            .route(
                &fixture.cert,
                "GET",
                "/v1/validation",
                &serde_json::to_vec(&request).unwrap()
            )
            .await
            .is_err());
    }
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
    let status = run(
        &f.alice,
        json!({"op":"proposal_status","proposal":"proposal"}),
    );
    assert_eq!(status["state"], "integrated");
    assert_eq!(status["shared"], true);
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
        cloud: None,
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
        cloud: None,
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

#[tokio::test]
async fn audit_delivery_over_real_mtls_replays_lost_ack_and_preserves_device_identity() {
    let f = Fixture::new().await;
    let (root, key) = ca();
    let (server, sk) = leaf(&root, &key, "localhost", true);
    let (alice, ak) = leaf(&root, &key, "alice", false);
    std::fs::write(
        &f.c.acl,
        serde_json::to_vec(&Acl {
            peers: HashMap::from([(
                fingerprint(alice.der()),
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
    let service = Service::new(f.c.clone()).await.unwrap();
    let batch = run(&f.alice, json!({"op":"audit_batch"}))["batch"].clone();
    assert!(!batch["records"].as_array().unwrap().is_empty());
    let (_, received) = service
        .route(
            alice.der(),
            "POST",
            "/v1/audit",
            &serde_json::to_vec(&batch).unwrap(),
        )
        .await
        .unwrap();
    let first: Value = serde_json::from_slice(&received).unwrap();
    assert_eq!(first["receipt"]["binding"]["device"], "alice");
    assert!(
        run(&f.alice, json!({"op":"audit_status"}))["pending"]
            .as_u64()
            .unwrap()
            > 0
    );
    let mut spoofed = batch.clone();
    spoofed["device"] = json!("bob");
    assert!(service
        .route(
            alice.der(),
            "POST",
            "/v1/audit",
            &serde_json::to_vec(&spoofed).unwrap()
        )
        .await
        .is_err());
    assert!(service
        .route(
            b"unknown",
            "POST",
            "/v1/audit",
            &serde_json::to_vec(&batch).unwrap()
        )
        .await
        .is_err());
    let tls = Arc::new(
        server_tls(
            roots_for(&root),
            vec![server.der().clone()],
            PrivatePkcs8KeyDer::from(sk.serialize_der()).into(),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let s = service.clone();
            let t = tls.clone();
            tokio::spawn(async move {
                let _ = s.serve_stream(stream, t).await;
            });
        }
    });
    let workstation = Workstation {
        client: Client {
            tls: Arc::new(
                client_tls(
                    roots_for(&root),
                    vec![alice.der().clone()],
                    PrivatePkcs8KeyDer::from(ak.serialize_der()).into(),
                )
                .unwrap(),
            ),
            server_name: "localhost".into(),
            authority_fingerprint: fingerprint(server.der()),
            cloud: None,
        },
        address,
        engine: engine_path(),
        state: f.alice.clone(),
        staging: f.c.staging.clone(),
        project: "demo".into(),
        authority: "central".into(),
        epoch: 1,
        device: "alice".into(),
        authority_device: "central-device".into(),
    };
    let status = workstation.flush_audit().await.unwrap();
    assert_eq!(status["pending"], 0);
    assert_eq!(status["synced"], true);
    let history = run(&f.c.state, json!({"op":"audit_log","limit":32}));
    let remote: Vec<_> = history["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["binding"]["device"] == "alice")
        .collect();
    assert!(!remote.is_empty());
    assert!(remote
        .iter()
        .all(|r| r["origin"] == "agent_reported"
            && r["certificate_sha256"] == fingerprint(alice.der())));
    assert!(
        run(&f.c.state, json!({"op":"audit_verify"}))["verified"]
            .as_u64()
            .unwrap()
            > 0
    );
    server_task.abort();
    let _ = server_task.await;
    run(&f.alice, json!({"op":"status"}));
    assert!(workstation.flush_audit().await.is_err());
    assert!(
        run(&f.alice, json!({"op":"audit_status"}))["pending"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[tokio::test]
async fn task_claims_over_mtls_preserve_ownership_lost_ack_and_offline_truth() {
    let f = Fixture::new().await;
    let (root, key) = ca();
    let (server, sk) = leaf(&root, &key, "localhost", true);
    let (alice, ak) = leaf(&root, &key, "alice", false);
    std::fs::write(
        &f.c.acl,
        serde_json::to_vec(&Acl {
            peers: HashMap::from([(
                fingerprint(alice.der()),
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
    let service = Service::new(f.c.clone()).await.unwrap();
    let (_, bytes) = service
        .route(
            alice.der(),
            "POST",
            "/v1/export",
            &serde_json::to_vec(&json!({"kind":"head","operation_id":"claims-head"})).unwrap(),
        )
        .await
        .unwrap();
    f.import(&f.alice, &Artifact::decode(&bytes).unwrap(), "claims-head");
    let path = f.c.staging.join("claim-work");
    run(
        &f.alice,
        json!({"op":"open","workspace":"work","path":path,"operation_id":"claim-open"}),
    );
    let request = json!({"op":"task_claim","workspace":"work","task_id":"policy","title":"Validate policy","acceptance_criteria":"Nullable bounds and path-aware errors","paths":["src/policy.py"],"lease_seconds":300,"operation_id":"claim"});
    let queued = run(&f.alice, request.clone());
    assert_eq!(queued["confirmed"], false);
    assert_eq!(queued["state"], "queued");
    assert_eq!(
        run(&f.c.state, json!({"op":"task_list"}))["claims"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let declaration = json!({"project":"demo","authority":"central","epoch":1,"device":"alice","request":request});
    let (_, lost) = service
        .route(
            alice.der(),
            "POST",
            "/v1/coordination",
            &serde_json::to_vec(&declaration).unwrap(),
        )
        .await
        .unwrap();
    let (_, replay) = service
        .route(
            alice.der(),
            "POST",
            "/v1/coordination",
            &serde_json::to_vec(&declaration).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        lost, replay,
        "lost acknowledgement must not create another lease"
    );
    let reply: Value = serde_json::from_slice(&lost).unwrap();
    let claim = reply["receipt"]["result"]["claim_id"].clone();
    let mut spoof = declaration.clone();
    spoof["device"] = json!("bob");
    assert!(service
        .route(
            alice.der(),
            "POST",
            "/v1/coordination",
            &serde_json::to_vec(&spoof).unwrap()
        )
        .await
        .is_err());
    assert!(service
        .route(b"unknown", "GET", "/v1/coordination", &[])
        .await
        .is_err());
    let tls = Arc::new(
        server_tls(
            roots_for(&root),
            vec![server.der().clone()],
            PrivatePkcs8KeyDer::from(sk.serialize_der()).into(),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let s = service.clone();
            let t = tls.clone();
            tokio::spawn(async move {
                let _ = s.serve_stream(stream, t).await;
            });
        }
    });
    let workstation = Workstation {
        client: Client {
            tls: Arc::new(
                client_tls(
                    roots_for(&root),
                    vec![alice.der().clone()],
                    PrivatePkcs8KeyDer::from(ak.serialize_der()).into(),
                )
                .unwrap(),
            ),
            server_name: "localhost".into(),
            authority_fingerprint: fingerprint(server.der()),
            cloud: None,
        },
        address,
        engine: engine_path(),
        state: f.alice.clone(),
        staging: f.c.staging.clone(),
        project: "demo".into(),
        authority: "central".into(),
        epoch: 1,
        device: "alice".into(),
        authority_device: "central-device".into(),
    };
    assert_eq!(
        workstation.flush_coordination().await.unwrap()["delivered"],
        2
    );
    let inventory = run(&f.c.state, json!({"op":"workspace_inventory"}));
    assert_eq!(
        inventory["remote_hosts"]["reports"][0]["origin"],
        "agent_reported"
    );
    assert_eq!(
        inventory["remote_hosts"]["reports"][0]["server_verified_files"],
        false
    );
    assert_eq!(
        inventory["remote_hosts"]["reports"][0]["report"]["workspaces"][0]["workspace"],
        "work"
    );
    let listed = run(&f.alice, json!({"op":"task_list"}));
    assert_eq!(listed["claims"][0]["claim_id"], claim);
    assert_eq!(listed["remote_cache"], true);
    assert_eq!(listed["commands"][0]["state"], "acknowledged");
    run(
        &f.alice,
        json!({"op":"task_update","workspace":"work","claim_id":claim,"action":"renew","expected_revision":1,"operation_id":"renew"}),
    );
    workstation.flush_coordination().await.unwrap();
    assert_eq!(
        run(&f.c.state, json!({"op":"task_list"}))["claims"][0]["revision"],
        2
    );
    let other = f.c.staging.join("other-claim-work");
    run(
        &f.alice,
        json!({"op":"open","workspace":"other","path":other,"operation_id":"other-open"}),
    );
    run(
        &f.alice,
        json!({"op":"task_update","workspace":"other","claim_id":claim,"action":"release","expected_revision":2,"operation_id":"wrong-owner"}),
    );
    workstation.flush_coordination().await.unwrap();
    let denied = run(&f.alice, json!({"op":"task_list"}));
    assert_eq!(
        denied["commands"][0]["result"]["result"]["error"]["code"],
        "task_owner_mismatch"
    );
    assert_eq!(
        denied["commands"][0]["state"], "acknowledged",
        "a deterministic rejection is an acknowledged outcome"
    );
    // Source receipts also close the saved/unshared state without rewriting local files.
    let own_file = path.join("own.txt");
    std::fs::write(&own_file, "one\n").unwrap();
    let queued = run(
        &f.alice,
        json!({"op":"commit","workspace":"work","intent":"First remote increment","expected_generation":0,"operation_id":"remote-one"}),
    );
    assert_eq!(queued["shared"], false);
    let uploaded = workstation
        .upload("remote-one", "upload-one")
        .await
        .unwrap();
    let mut authority = wipstash_transport::daemon::AuthorityWorker::open(
        engine_path(),
        f.c.state.clone(),
        f.c.staging.clone(),
    )
    .await
    .unwrap();
    authority.tick().await.unwrap();
    workstation
        .current_receipt(uploaded["proposal"].as_str().unwrap())
        .await
        .unwrap();
    let before_head = run(&f.alice, json!({"op":"status","workspace":"work"}));
    assert_eq!(before_head["has_unshared_changes"], false);
    assert_eq!(before_head["head_cache_behind_receipt"], true);
    workstation.catch_up().await.unwrap();
    let caught_up = run(&f.alice, json!({"op":"status","workspace":"work"}));
    assert_eq!(caught_up["head_cache_behind_receipt"], false);
    std::fs::write(&own_file, "two\n").unwrap();
    run(
        &f.alice,
        json!({"op":"commit","workspace":"work","intent":"Second remote increment","expected_generation":1,"operation_id":"remote-two"}),
    );
    let uploaded = workstation
        .upload("remote-two", "upload-two")
        .await
        .unwrap();
    authority.tick().await.unwrap();
    workstation
        .current_receipt(uploaded["proposal"].as_str().unwrap())
        .await
        .unwrap();
    workstation.catch_up().await.unwrap();
    assert_eq!(
        run(&f.alice, json!({"op":"status","workspace":"work"}))["has_unshared_changes"],
        false
    );
    assert_eq!(std::fs::read(&own_file).unwrap(), b"two\n");
    let central = f.c.staging.join("central-work");
    run(
        &f.c.state,
        json!({"op":"open","workspace":"central","path":central,"operation_id":"central-open"}),
    );
    std::fs::write(central.join("incoming.txt"), "incoming\n").unwrap();
    run(
        &f.c.state,
        json!({"op":"commit","workspace":"central","intent":"Describe incoming work","expected_generation":0,"operation_id":"central-commit"}),
    );
    authority.tick().await.unwrap();
    workstation.catch_up().await.unwrap();
    workstation.flush_coordination().await.unwrap();
    let latest = run(&f.alice, json!({"op":"updates","workspace":"work"}));
    assert!(!path.join("incoming.txt").exists());
    let messages: Vec<_> = latest["incoming"]["commits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["message"].as_str().unwrap())
        .collect();
    assert_eq!(messages, vec!["Describe incoming work"]);
    // Background failures return through authenticated coordination, including
    // after the source receipt has already reached its terminal shared state.
    run(
        &f.c.state,
        json!({"op":"configure","operation_id":"async-policy","policy":{"checks":[{"id":"remote-check","argv":[engine_path(),"--invalid-worker-command"],"timeout_seconds":10}]}}),
    );
    std::fs::write(own_file.clone(), "third remote increment\n").unwrap();
    run(
        &f.alice,
        json!({"op":"commit","workspace":"work","intent":"Remote async check ownership","expected_generation":2,"operation_id":"remote-three"}),
    );
    let uploaded = workstation
        .upload("remote-three", "upload-three")
        .await
        .unwrap();
    authority.tick().await.unwrap();
    workstation
        .current_receipt(uploaded["proposal"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        run(&f.c.state, json!({"op":"validation_tick"}))["validation"]["state"],
        "failed"
    );
    workstation.flush_coordination().await.unwrap();
    let pending_offer = run(
        &f.alice,
        json!({"op":"status","workspace":"work","inspect_files":false}),
    );
    assert_eq!(
        pending_offer["notices"],
        json!([]),
        "A queued pickup does not grant a lease"
    );
    workstation.flush_coordination().await.unwrap();
    let notified = run(
        &f.alice,
        json!({"op":"status","workspace":"work","inspect_files":false}),
    );
    assert_eq!(notified["repo_health"]["state"], "failed");
    assert_eq!(notified["notices"].as_array().unwrap().len(), 1);
    assert_eq!(
        run(&f.alice, json!({"op":"status","workspace":"other"}))["notices"],
        json!([])
    );
    assert_eq!(
        run(
            &f.alice,
            json!({"op":"proposal_status","proposal":"remote-three"})
        )["validation"]["state"],
        "failed"
    );
    let notice = &notified["notices"][0];
    let ack = json!({"op":"repair_update","workspace":"work","incident_id":notice["incident_id"],"expected_revision":notice["revision"],"action":"acknowledge","operation_id":"remote-repair-ack"});
    assert_eq!(run(&f.alice, ack.clone())["confirmed"], false);
    workstation.flush_coordination().await.unwrap();
    let repairs = run(&f.alice, json!({"op":"repair_list","workspace":"work"}));
    assert_eq!(repairs["repairs"][0]["owner"]["device"], "alice");
    assert_eq!(repairs["repairs"][0]["owner"]["workspace"], "work");
    assert_eq!(repairs["repairs"][0]["revision"], 3);
    assert_eq!(
        run(&f.alice, json!({"op":"status","workspace":"work"}))["notices"],
        json!([])
    );
    // Exact local replay stays the original queued reply, never a second renewal.
    assert_eq!(run(&f.alice, ack)["confirmed"], false);
    run(
        &f.alice,
        json!({"op":"repair_update","workspace":"other","incident_id":notice["incident_id"],"expected_revision":3,"action":"renew","operation_id":"remote-wrong-repair-owner"}),
    );
    workstation.flush_coordination().await.unwrap();
    let commands = run(&f.alice, json!({"op":"repair_list","workspace":"other"}));
    assert_eq!(
        commands["commands"][0]["result"]["result"]["error"]["code"],
        "repair_owner_mismatch"
    );
    let forged = json!({"project":"demo","authority":"central","epoch":1,"device":"bob","request":{"op":"repair_update","workspace":"work","incident_id":notice["incident_id"],"expected_revision":3,"action":"renew","operation_id":"forged-repair"}});
    assert!(workstation
        .client
        .request(
            address,
            "POST",
            "/v1/coordination",
            serde_json::to_vec(&forged).unwrap()
        )
        .await
        .is_err());
    let tip = run(
        &f.alice,
        json!({"op":"comment_add","workspace":"work","subject_type":"repair","subject_id":notice["incident_id"],"body":"Inspect the child process environment.","mentions":["central"],"operation_id":"remote-repair-tip"}),
    );
    assert_eq!(tip["confirmed"], false);
    workstation.flush_coordination().await.unwrap();
    let comments = run(
        &f.c.state,
        json!({"op":"comment_list","subject_id":notice["incident_id"]}),
    );
    assert_eq!(comments["comments"][0]["device"], "alice");
    assert_eq!(comments["comments"][0]["workspace"], "work");
    let local_comments = run(
        &f.alice,
        json!({"op":"comment_list","subject_id":notice["incident_id"]}),
    );
    assert_eq!(local_comments["comments"][0]["device"], "alice");
    server_task.abort();
    let _ = server_task.await;
    run(
        &f.alice,
        json!({"op":"task_update","workspace":"work","claim_id":claim,"action":"complete","expected_revision":2,"operation_id":"offline-complete"}),
    );
    assert!(workstation.flush_coordination().await.is_err());
    let offline = run(&f.alice, json!({"op":"task_list"}));
    assert_eq!(offline["commands"][0]["state"], "queued");
    assert_eq!(
        run(&f.c.state, json!({"op":"task_list"}))["claims"][0]["state"],
        "active"
    );
    assert_eq!(std::fs::read(path.join("hello.txt")).unwrap(), b"hello\n");
}
