//! Independent, offline security-review checks. No socket listeners or vault access.
use serde_json::{json, Value};
use std::{collections::HashMap, path::PathBuf};
use wipstash_transport::{
    authorize, fingerprint, Acl, Artifact, Config, Peer, Service, MANIFEST_MAX, PAYLOAD_MAX,
};

fn config() -> Config {
    Config {
        engine: PathBuf::from("/review/nonexistent-engine"),
        state: PathBuf::from("/review/state"),
        staging: PathBuf::from("/review/staging"),
        project: "review".into(),
        authority: "authority".into(),
        epoch: 7,
        device: "authority-device".into(),
        acl: PathBuf::from("/review/acl").into(),
        ca: PathBuf::from("/review/ca"),
        certificate: PathBuf::from("/review/cert"),
        key: PathBuf::from("/review/key").into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        limits: wipstash_transport::Limits::default(),
    }
}
fn peer() -> Peer {
    Peer {
        device: "alice".into(),
        project: "review".into(),
        role: "client".into(),
        revoked: false,
    }
}
fn artifact(mut manifest: Value, objects: Vec<u8>) -> Artifact {
    manifest["version"] = json!(1);
    manifest["payload_len"] = json!(objects.len());
    manifest["payload_sha256"] = json!(fingerprint(&objects));
    Artifact {
        manifest: serde_json::to_vec(&manifest).unwrap(),
        objects,
    }
}
#[test]
fn upload_checks_each_binding_before_admission() {
    let base = json!({"kind":"proposal","project":"review","authority":"authority","epoch":7,"device":"alice"});
    assert!(artifact(base.clone(), vec![])
        .validate_upload(&peer(), &config())
        .is_ok());
    for (key, replacement) in [
        ("kind", json!("head")),
        ("project", json!("other")),
        ("authority", json!("other")),
        ("epoch", json!(6)),
        ("epoch", json!(8)),
        ("epoch", json!("7")),
        ("device", json!("bob")),
    ] {
        let mut m = base.clone();
        m[key] = replacement;
        assert!(
            artifact(m, vec![])
                .validate_upload(&peer(), &config())
                .is_err(),
            "unchecked {key}"
        );
    }
}
#[test]
fn download_never_accepts_proposals_or_other_receipts() {
    let base = json!({"kind":"receipt","project":"review","authority":"authority","epoch":7,"device":"authority-device","receipt":{"recipient":"alice"}});
    assert!(artifact(base.clone(), vec![])
        .validate_download(&peer(), &config())
        .is_ok());
    for (key, replacement) in [
        ("kind", json!("proposal")),
        ("project", json!("other")),
        ("authority", json!("other")),
        ("epoch", json!(8)),
        ("device", json!("alice")),
        ("receipt", json!({"recipient":"bob"})),
        ("receipt", Value::Null),
    ] {
        let mut m = base.clone();
        m[key] = replacement;
        assert!(
            artifact(m, vec![])
                .validate_download(&peer(), &config())
                .is_err(),
            "unchecked {key}"
        );
    }
}
#[test]
fn malformed_frames_and_resource_edges_fail_closed() {
    for n in 0..4 {
        assert!(Artifact::decode(&vec![0; n]).is_err());
    }
    for n in [0, 1, MANIFEST_MAX, MANIFEST_MAX + 1, u32::MAX as usize] {
        assert!(Artifact::decode(&(n as u32).to_be_bytes()).is_err());
    }
    let a = artifact(json!({}), vec![42; PAYLOAD_MAX]);
    assert!(Artifact::decode(&a.encode().unwrap()).is_ok());
    assert!(artifact(json!({}), vec![42; PAYLOAD_MAX + 1])
        .encode()
        .is_err());
    let mut a = artifact(json!({}), vec![]);
    a.manifest = vec![b' '; MANIFEST_MAX + 1];
    assert!(a.encode().is_err());
}
#[test]
fn certificate_mapping_is_exact_and_not_a_prefix() {
    let acl = Acl {
        peers: HashMap::from([(fingerprint(b"certificate"), peer())]),
    };
    assert!(authorize(&acl, b"certificate", "review").is_ok());
    assert!(authorize(&acl, b"certificate\0", "review").is_err());
    assert!(authorize(&acl, b"certificat", "review").is_err());
}
#[tokio::test]
async fn relative_service_paths_and_zero_epoch_fail_before_spawn() {
    for field in 0..4 {
        let mut c = config();
        match field {
            0 => c.engine = "relative".into(),
            1 => c.state = "relative".into(),
            2 => c.staging = "relative".into(),
            _ => c.acl = PathBuf::from("relative").into(),
        }
        match Service::new(c).await {
            Err(e) => assert_eq!(e.to_string(), "absolute_config_paths_required"),
            Ok(_) => panic!("accepted relative path"),
        }
    }
    let mut c = config();
    c.epoch = 0;
    match Service::new(c).await {
        Err(e) => assert_eq!(e.to_string(), "invalid_epoch"),
        Ok(_) => panic!("accepted zero epoch"),
    }
}

fn workstation() -> wipstash_transport::Workstation {
    // Configuration-only fixture. No socket, certificate, or credential access.
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let c = config();
    wipstash_transport::Workstation {
        client: wipstash_transport::Client {
            tls: std::sync::Arc::new(tls),
            server_name: "localhost".into(),
            authority_fingerprint: "0".repeat(64),
            cloud: None,
        },
        address: c.listen,
        engine: c.engine,
        state: c.state,
        staging: c.staging,
        project: c.project,
        authority: c.authority,
        epoch: c.epoch,
        device: "alice".into(),
        authority_device: c.device,
    }
}
#[tokio::test]
async fn workstation_rejects_relative_paths_and_invalid_binding_before_engine() {
    for field in 0..3 {
        let mut w = workstation();
        match field {
            0 => w.engine = "relative".into(),
            1 => w.state = "relative".into(),
            _ => w.staging = "relative".into(),
        }
        assert_eq!(
            w.upload("proposal", "operation")
                .await
                .unwrap_err()
                .to_string(),
            "absolute_config_paths_required"
        );
    }
    let mut w = workstation();
    w.epoch = 0;
    assert_eq!(
        w.catch_up().await.unwrap_err().to_string(),
        "invalid_client_binding"
    );
    let mut w = workstation();
    w.authority_device = "../other".into();
    assert_eq!(
        w.catch_up().await.unwrap_err().to_string(),
        "invalid_client_binding"
    );
}

#[tokio::test]
async fn canceled_request_closes_in_memory_tls_driver() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let key = KeyPair::generate().unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = p.self_signed(&ca_key).unwrap();
    let cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    let client = wipstash_transport::Client {
        tls: Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ),
        server_name: "localhost".into(),
        authority_fingerprint: fingerprint(cert.der()),
        cloud: None,
    };
    let (a, b) = tokio::io::duplex(4096);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(a)
            .await
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            tls.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        ready_tx.send(()).unwrap();
        // No response body: the client is canceled while waiting for it.
        tokio::time::timeout(Duration::from_secs(2), tls.read(&mut byte)).await
    });
    let request =
        tokio::spawn(async move { client.request_stream(b, "GET", "/v1/history", vec![]).await });
    ready_rx.await.unwrap();
    request.abort();
    let _ = request.await;
    let closed = server
        .await
        .unwrap()
        .expect("connection driver leaked after cancellation");
    assert!(matches!(closed, Ok(0) | Err(_)), "unexpected client data");
}

#[tokio::test]
async fn acl_file_bound_is_checked_before_parsing() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("source.txt"), b"review").unwrap();
    let mut c = config();
    c.engine = std::env::var_os("WIPSTASH_ENGINE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/wipstash")
        })
        .canonicalize()
        .unwrap();
    c.state = tmp.path().join("state");
    c.staging = tmp.path().join("staging");
    c.acl = tmp.path().join("acl.json").into();
    std::fs::create_dir(&c.staging).unwrap();
    for request in [
        json!({"op":"init","source":source}),
        json!({"op":"sync_configure","project":c.project,"authority":c.authority,"epoch":c.epoch,"device":c.device,"role":"authority","peers":["alice"]}),
    ] {
        let output = std::process::Command::new(&c.engine)
            .arg("--state")
            .arg(&c.state)
            .arg(request.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let service = Service::new(c.clone()).await.unwrap();
    let acl = std::fs::File::create(&c.acl).unwrap();
    acl.set_len(1024 * 1024 + 1).unwrap();
    assert_eq!(
        service
            .route(b"certificate", "GET", "/v1/history", &[])
            .await
            .unwrap_err()
            .to_string(),
        "artifact_file"
    );
}
