//! Synthetic duplex tests only: no listeners, real credentials, or account changes.
use super::*;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

struct TlsFixture {
    ca: Certificate,
    ca_key: KeyPair,
    leaf: Certificate,
    leaf_key: KeyPair,
}
impl TlsFixture {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&[1]));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let mut params = CertificateParams::new(vec!["enroll.test".to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        Self {
            ca,
            ca_key,
            leaf,
            leaf_key,
        }
    }
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.der().clone()).unwrap();
        roots
    }
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()).into()
    }
    fn server(&self) -> Arc<rustls::ServerConfig> {
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![self.leaf.der().clone()], self.key())
                .unwrap(),
        )
    }
    fn client(&self) -> EnrollmentClient {
        EnrollmentClient::new(
            self.roots(),
            "enroll.test".into(),
            fingerprint(self.leaf.der().as_ref()),
        )
        .unwrap()
    }
    fn service(&self) -> (tempfile::TempDir, Arc<EnrollmentService>) {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().canonicalize().unwrap().join("private");
        crate::pairing_files::ensure_private_dir(&private).unwrap();
        let store = PairingStore::open(private.join("pairing.sqlite")).unwrap();
        let issuer =
            Issuer::from_pem(&self.ca.pem(), &self.ca_key.serialize_pem(), now().unwrap()).unwrap();
        let service =
            EnrollmentService::new(store, issuer, vec![self.leaf.der().clone()], self.key())
                .unwrap();
        (dir, Arc::new(service))
    }
}

#[tokio::test]
async fn wrong_pin_sends_no_http_or_invite_bytes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct SecretProbe(Arc<AtomicUsize>);
    impl Serialize for SecretProbe {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            serializer.serialize_str("synthetic-secret-must-never-be-sent")
        }
    }
    let fixture = TlsFixture::new();
    let client =
        EnrollmentClient::new(fixture.roots(), "enroll.test".into(), "00".repeat(32)).unwrap();
    let (client_io, server_io) = tokio::io::duplex(65536);
    let tls = fixture.server();
    let observed = tokio::spawn(async move {
        let accepted = tokio_rustls::TlsAcceptor::from(tls).accept(server_io).await;
        match accepted {
            Ok(mut stream) => {
                let mut bytes = Vec::new();
                let _ = stream.read_to_end(&mut bytes).await;
                bytes
            }
            Err(error) => {
                // The client can close after pin validation while the server is
                // still finishing its handshake/session-ticket writes.
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                ));
                Vec::new()
            }
        }
    });
    let serializations = Arc::new(AtomicUsize::new(0));
    let result: Result<Value> = client
        .request_stream(client_io, ENROLL, &SecretProbe(serializations.clone()))
        .await;
    assert_eq!(result.unwrap_err().to_string(), "enrollment_pin_mismatch");
    assert_eq!(serializations.load(Ordering::SeqCst), 0);
    assert!(observed.await.unwrap().is_empty());
}

#[tokio::test]
async fn wrong_dns_is_rejected_despite_matching_pin() {
    let fixture = TlsFixture::new();
    let client = EnrollmentClient::new(
        fixture.roots(),
        "wrong.test".into(),
        fingerprint(fixture.leaf.der().as_ref()),
    )
    .unwrap();
    let (client_io, server_io) = tokio::io::duplex(65536);
    let tls = fixture.server();
    let server = tokio::spawn(async move {
        tokio_rustls::TlsAcceptor::from(tls)
            .accept(server_io)
            .await
            .is_err()
    });
    let result: Result<Value> = client
        .request_stream(client_io, ENROLL, &json!({"secret":"never-send"}))
        .await;
    assert!(result.is_err());
    assert!(server.await.unwrap());
}

#[tokio::test]
async fn matching_pin_does_not_bypass_ca_validation() {
    let fixture = TlsFixture::new();
    let unrelated = TlsFixture::new();
    let client = EnrollmentClient::new(
        unrelated.roots(),
        "enroll.test".into(),
        fingerprint(fixture.leaf.der().as_ref()),
    )
    .unwrap();
    let (client_io, server_io) = tokio::io::duplex(65536);
    let tls = fixture.server();
    let server = tokio::spawn(async move {
        let _ = tokio_rustls::TlsAcceptor::from(tls).accept(server_io).await;
    });
    let result: Result<Value> = client
        .request_stream(client_io, ENROLL, &json!({"secret":"never-send"}))
        .await;
    assert!(result.is_err());
    server.await.unwrap();
}

async fn rejected_http(
    path: &str,
    method: &str,
    content_type: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let fixture = TlsFixture::new();
    let (_directory, service) = fixture.service();
    let (client_io, server_io) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move {
        let _ = service.serve_stream(server_io).await;
    });
    let tls = tokio_rustls::TlsConnector::from(fixture.client().tls)
        .connect(ServerName::try_from("enroll.test").unwrap(), client_io)
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", "enroll.test")
                .header("content-type", content_type)
                .body(Full::new(Bytes::from(body)))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    drop(sender);
    driver.await.unwrap();
    task.await.unwrap();
    (status, body)
}

#[tokio::test]
async fn enrollment_cannot_dispatch_sync_or_administration_routes() {
    for path in [
        "/v1/proposals",
        "/v1/export",
        "/v1/transfers",
        "/v1/current-receipt",
        "/v1/devices",
        "/v1/revoke",
        "/v1/enroll?secret=do-not-echo",
    ] {
        let (status, body) = rejected_http(path, "POST", "application/json", b"{}".to_vec()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, b"{\"error\":\"enrollment_rejected\"}");
    }
}

#[tokio::test]
async fn malformed_enrollment_requests_return_only_generic_errors() {
    for (method, kind, body) in [
        ("GET", "application/json", b"{}".to_vec()),
        ("POST", "text/plain", b"{\"secret\":\"do-not-echo\"}".to_vec()),
        ("POST", "application/json", b"not-json-do-not-echo".to_vec()),
        ("POST", "application/json", b"{\"version\":1,\"invite_id\":\"x\",\"secret\":\"do-not-echo\",\"request_id\":\"r\",\"csr_der\":[1],\"role\":\"authority\"}".to_vec()),
    ] {
        let (status, body) = rejected_http(ENROLL, method, kind, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, b"{\"error\":\"enrollment_rejected\"}");
    }
}

#[tokio::test]
async fn redirects_and_unknown_response_fields_are_rejected() {
    for redirect in [false, true] {
        let fixture = TlsFixture::new();
        let client = fixture.client();
        let tls = fixture.server();
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move {
            let stream = tokio_rustls::TlsAcceptor::from(tls)
                .accept(server_io)
                .await
                .unwrap();
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(stream),
                    hyper::service::service_fn(move |_req| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(if redirect { 307 } else { 200 })
                                .header("content-type", "application/json")
                                .header("location", "https://elsewhere.test/steal")
                                .body(Full::new(Bytes::from_static(
                                    b"{\"nonce\":\"abc\",\"deadline\":42,\"extra\":true}",
                                )))
                                .unwrap(),
                        )
                    }),
                )
                .await;
        });
        let result: Result<RecoveryChallenge> = client
            .request_stream(client_io, CHALLENGE, &json!({}))
            .await;
        assert!(result.is_err());
        server.await.unwrap();
    }
}

#[test]
fn admission_and_payload_limits_are_fixed_and_fail_closed() {
    let mut admission = Admission::new();
    let ip = "127.0.0.1".parse().unwrap();
    for _ in 0..8 {
        assert!(admission.charge(ip));
    }
    assert!(!admission.charge(ip));
    assert_eq!(admission.sources.len(), 256);
    assert!(csr_bound(&[]).is_err());
    assert!(csr_bound(&vec![1; CSR_MAX + 1]).is_err());
    assert!(pin_valid(&"ab".repeat(32)));
    assert!(!pin_valid(&"AB".repeat(32)));
    assert!(!allowed_route("/v1/enroll/../proposals"));
}

#[tokio::test]
async fn retry_challenge_and_recovery_fit_admission_and_preserve_exact_grant() {
    use crate::pairing::{random_id, recovery_message, InvitePurpose};
    use crate::pairing_crypto::{generate_local_csr, sign_recovery};
    let fixture = TlsFixture::new();
    let (_dir, service) = fixture.service();
    let scope = InviteScope {
        project: "demo".into(),
        authority: "coordinator".into(),
        epoch: 1,
        authority_device: "coordinator-device".into(),
        client_device: "new-device".into(),
        purpose: InvitePurpose::New,
        enrollment_address: "127.0.0.1:7444".parse().unwrap(),
        enrollment_server_name: "enroll.test".into(),
        enrollment_leaf_pin: fingerprint(fixture.leaf.der().as_ref()),
        // Deliberately distinct: enrollment pin must never replace the sync pin.
        sync_address: "127.0.0.1:7443".parse().unwrap(),
        sync_server_name: "sync.test".into(),
        sync_leaf_pin: "ab".repeat(32),
        ca_certificate_der: fixture.ca.der().to_vec(),
        certificate_lifetime_secs: 3600,
    };
    service.store.initialize(&scope.binding()).unwrap();
    service.store.reserve_device(&scope.client_device).unwrap();
    let invite = service
        .store
        .create_invite(scope.clone(), now().unwrap() + 600, now().unwrap())
        .unwrap();
    let local = generate_local_csr().unwrap();
    let request = RedeemRequest {
        version: 1,
        invite_id: invite.invite_id.clone(),
        secret: invite.secret.clone(),
        request_id: random_id().unwrap(),
        csr_der: local.csr_der.clone(),
    };
    let client = fixture.client();
    async fn serve(
        service: Arc<EnrollmentService>,
    ) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            let _ = service.serve_stream(server).await;
        });
        (client, task)
    }
    let (stream, task) = serve(service.clone()).await;
    let first = client
        .enroll_stream(stream, &request, &scope)
        .await
        .unwrap();
    task.await.unwrap();
    let (stream, task) = serve(service.clone()).await;
    let retry = client
        .enroll_stream(stream, &request, &scope)
        .await
        .unwrap();
    task.await.unwrap();
    assert_eq!(first, retry);
    let challenge_request = RecoveryChallengeRequest {
        version: 1,
        invite_id: request.invite_id.clone(),
        request_id: request.request_id.clone(),
        csr_der: request.csr_der.clone(),
    };
    let (stream, task) = serve(service.clone()).await;
    let challenge = client
        .challenge_stream(stream, &challenge_request)
        .await
        .unwrap();
    task.await.unwrap();
    let signature = sign_recovery(
        &local.key_pem,
        &recovery_message(&challenge_request, &challenge).unwrap(),
    )
    .unwrap();
    let recovery = RecoveryRequest {
        version: 1,
        invite_id: request.invite_id,
        request_id: request.request_id,
        csr_der: request.csr_der,
        challenge,
        signature,
    };
    let (stream, task) = serve(service.clone()).await;
    let recovered = client
        .recover_stream(stream, &recovery, &scope)
        .await
        .unwrap();
    task.await.unwrap();
    assert_eq!(first, recovered);
    assert_eq!(recovered.scope.sync_leaf_pin, "ab".repeat(32));
    let (stream, task) = serve(service).await;
    assert!(client
        .recover_stream(stream, &recovery, &scope)
        .await
        .is_err());
    task.await.unwrap();
}
