//! Install as services/transport/tests/live_tls_ci.rs after review.
//! CI only: cargo test --manifest-path services/transport/Cargo.toml --test live_tls_ci
//! four_devices_live_tls_restart_and_faults -- --ignored --nocapture
//! Requires GITHUB_ACTIONS=true, WIPSTASH_LIVE_TLS_CI=1, and the built root engine.
//! Optional WIPSTASH_LIVE_TLS_ARTIFACT_DIR receives only summary.json/server.log.
//! This is real loopback mTLS with application-level faults, not real WAN/power loss.
use rcgen::{BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc},
    time::Duration,
};
use wipstash_transport::{
    daemon::AuthorityWorker,
    resumable::{self, CHUNK_MAX},
    *,
};

const PRIVATE_ANCESTRY: &str = "SYNTHETIC-PRIVATE-ANCESTRY-ONLY-4f13b7";
const NAMES: [&str; 4] = ["alice", "bob", "carol", "dave"];

fn guard() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"),
        "live sockets are authorized only on GitHub native CI");
    assert_eq!(std::env::var("WIPSTASH_LIVE_TLS_CI").as_deref(), Ok("1"),
        "explicit native CI opt-in is required");
}
fn engine_path() -> PathBuf {
    std::env::var_os("WIPSTASH_ENGINE").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../target/debug/wipstash{}", std::env::consts::EXE_SUFFIX))
    }).canonicalize().expect("build the root engine first")
}
fn engine(state: &Path, request: Value) -> Value {
    let output = Command::new(engine_path()).arg("--state").arg(state)
        .arg(request.to_string()).output().unwrap();
    assert!(output.status.success(), "request={request}; stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}
fn make_ca() -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    (params.self_signed(&key).unwrap(), key)
}
fn leaf(ca: &Certificate, ca_key: &KeyPair, name: &str, server: bool) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![name.into()]).unwrap();
    params.extended_key_usages = vec![if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else { ExtendedKeyUsagePurpose::ClientAuth }];
    let key = KeyPair::generate().unwrap();
    (params.signed_by(&key, ca, ca_key).unwrap(), key)
}
fn client(ca: &Certificate, cert: &Certificate, key: &KeyPair, pin: &str) -> Client {
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Client {
        tls: Arc::new(client_tls(roots, vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap()),
        server_name: "localhost".into(), authority_fingerprint: pin.into(),
    }
}
fn history_body() -> Vec<u8> {
    serde_json::to_vec(&json!({"after":0,"limit":128,"cursor_kind":"head_sequence"})).unwrap()
}
async fn request(client: &Client, address: SocketAddr, method: &str, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        client.request_stream(tokio::net::TcpStream::connect(address).await?, method, path, body).await
    }).await.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "bounded live request timeout"))?
}
async fn json_request(client: &Client, address: SocketAddr, method: &str, path: &str, body: Vec<u8>) -> Value {
    serde_json::from_slice(&request(client, address, method, path, body).await.unwrap()).unwrap()
}

/// Owns exactly the helper child, never discovers or kills another process.
struct Server(Option<Child>);
impl Server {
    fn start(config: &Path, log: &Path) -> Self {
        let output = fs::OpenOptions::new().create(true).append(true).open(log).unwrap();
        Self(Some(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "live_tls_server_child", "--ignored", "--nocapture"])
            .env("WIPSTASH_TLS_CHILD_CONFIG", config)
            .stdout(Stdio::from(output.try_clone().unwrap())).stderr(Stdio::from(output))
            .spawn().unwrap()))
    }
    fn stop(&mut self) {
        if let Some(mut child) = self.0.take() {
            child.kill().expect("terminate owned server child");
            child.wait().expect("reap owned server child");
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() { let _ = child.kill(); let _ = child.wait(); }
    }
}
async fn ready(server: &mut Server, client: &Client, address: SocketAddr, log: &Path) {
    for _ in 0..100 {
        assert!(server.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "server exited: {}", String::from_utf8_lossy(&bounded_log(log)));
        if request(client, address, "POST", "/v1/history", history_body()).await.is_ok() { return; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not become ready: {}", String::from_utf8_lossy(&bounded_log(log)));
}
fn bounded_log(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Ok(file) = fs::File::open(path) { let _ = file.take(64 * 1024).read_to_end(&mut bytes); }
    bytes
}
/// Declared after the tempdir and before the server, so failure/unwind preserves safe evidence.
struct Evidence {
    source_log: PathBuf,
    destination: Option<PathBuf>,
    summary: Value,
}
impl Evidence {
    fn save(&self) -> std::io::Result<()> {
        if let Some(destination) = &self.destination {
            fs::create_dir_all(destination)?;
            // Explicit output allowlist. No credential/config/state directory is copied.
            fs::write(destination.join("summary.json"), serde_json::to_vec_pretty(&self.summary)?)?;
            fs::write(destination.join("server.log"), bounded_log(&self.source_log))?;
        }
        Ok(())
    }
}
impl Drop for Evidence {
    fn drop(&mut self) {
        if let Err(error) = self.save() { eprintln!("live TLS evidence persistence failed: {error}"); }
    }
}
fn audit_public_blobs(state: &Path) -> Value {
    let repo = state.join("coordinator.git");
    assert!(!repo.join("objects/info/alternates").exists());
    let git = |args: &[&str]| {
        let output = Command::new("git").arg("--git-dir").arg(&repo).args(args).output().unwrap();
        assert!(output.status.success(), "Git audit failed: {}", String::from_utf8_lossy(&output.stderr));
        output.stdout
    };
    // Includes unreachable objects: checking final trees alone would miss private ancestors.
    let listing = String::from_utf8(git(&["cat-file", "--batch-all-objects",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)"])).unwrap();
    assert!(listing.lines().count() < 4096, "bounded synthetic object store");
    let mut blobs = 0;
    for line in listing.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        if fields[1] != "blob" { continue; }
        assert!(fields[2].parse::<usize>().unwrap() <= PAYLOAD_MAX);
        let body = git(&["cat-file", "blob", fields[0]]);
        for marker in [PRIVATE_ANCESTRY, "PRIVATE-NEVER-SEND-", "synthetic-public-carol", "synthetic-public-dave"] {
            assert!(!body.windows(marker.len()).any(|window| window == marker.as_bytes()),
                "private content reached public blob {}", fields[0]);
        }
        blobs += 1;
    }
    assert!(blobs > 0);
    json!({"objects":listing.lines().count(),"blobs_checked":blobs,
        "scope":"actual decoded contents of every stored public Git blob, including unreachable objects"})
}

#[tokio::test]
#[ignore = "helper process for explicitly authorized native CI only"]
async fn live_tls_server_child() {
    guard();
    // A broad --ignored invocation must not accidentally create another listener.
    let Some(path) = std::env::var_os("WIPSTASH_TLS_CHILD_CONFIG") else { return; };
    let config: Config = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert!(config.listen.ip().is_loopback());
    Service::new(config).await.unwrap().serve().await.unwrap();
}
#[tokio::test]
#[ignore = "real loopback sockets and owned child restart; native GitHub CI opt-in only"]
async fn four_devices_live_tls_restart_and_faults() {
    guard();
    tokio::time::timeout(Duration::from_secs(180), scenario()).await.expect("bounded acceptance scenario");
}
async fn scenario() {
    // Resolve the macOS temp-directory alias without relaxing production path checks.
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let root = temp.path();
    let state = root.join("authority");
    let staging = root.join("staging");
    let source = root.join("source");
    let log = root.join("server.log");
    let mut evidence = Evidence {
        source_log: log.clone(),
        destination: std::env::var_os("WIPSTASH_LIVE_TLS_ARTIFACT_DIR").map(PathBuf::from),
        summary: json!({"passed":false,"scope":"native CI real loopback mTLS and application-level faults; no real WAN or power-loss claim",
            "devices":4,"server_restarts":0,"certificate_acl_rejections":0}),
    };
    fs::create_dir(&staging).unwrap();
    fs::create_dir(&source).unwrap();
    fs::write(source.join("base.txt"), "synthetic public base\n").unwrap();
    engine(&state, json!({"op":"init","source":source}));
    engine(&state, json!({"op":"sync_configure","project":"demo","authority":"central",
        "epoch":1,"device":"central-device","role":"authority","peers":NAMES}));
    let (ca, ca_key) = make_ca();
    let (server_cert, server_key) = leaf(&ca, &ca_key, "localhost", true);
    let pin = fingerprint(server_cert.der());
    let identities: Vec<_> = NAMES.iter().map(|name| leaf(&ca, &ca_key, name, false)).collect();
    let clients: Vec<_> = identities.iter().map(|(cert,key)| client(&ca, cert, key, &pin)).collect();
    let mut acl = Acl { peers: HashMap::new() };
    for (name, (cert, _)) in NAMES.iter().zip(&identities) {
        acl.peers.insert(fingerprint(cert.der()), Peer {
            device: (*name).into(), project: "demo".into(), role: "client".into(), revoked: false,
        });
    }
    let acl_path = root.join("acl.json");
    fs::write(&acl_path, serde_json::to_vec(&acl).unwrap()).unwrap();
    // Generated test-only certificates are never configured for real accounts or services.
    fs::write(root.join("ca.pem"), ca.pem()).unwrap();
    fs::write(root.join("server.pem"), server_cert.pem()).unwrap();
    fs::write(root.join("server-key.pem"), server_key.serialize_pem()).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("server-key.pem"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Reserve and release an ephemeral port for the owned child; any bind race fails safely.
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let config_path = root.join("server.json");
    // Current AclSource supports a legacy path string; no managed-enrollment state is modified.
    let config_json = json!({"engine":engine_path(),"state":state,"staging":staging,
        "project":"demo","authority":"central","epoch":1,"device":"central-device",
        "acl":acl_path,"ca":root.join("ca.pem"),"certificate":root.join("server.pem"),
        "key":root.join("server-key.pem"),"listen":address.to_string(),
        "limits":{"request_burst":10000,"requests_per_minute":100000}});
    let _: Config = serde_json::from_value(config_json.clone()).expect("current Config/AclSource shape");
    fs::write(&config_path, serde_json::to_vec(&config_json).unwrap()).unwrap();
    let mut authority = AuthorityWorker::open(engine_path(), state.clone(), staging.clone()).await.unwrap();
    authority.tick().await.unwrap();
    let mut server = Server::start(&config_path, &log);
    ready(&mut server, &clients[0], address, &log).await;
    let wire = request(&clients[0], address, "POST", "/v1/export",
        serde_json::to_vec(&json!({"kind":"head","operation_id":"initial"})).unwrap()).await.unwrap();
    let head = Artifact::decode(&wire).unwrap();
    let head_dir = root.join("head");
    fs::create_dir(&head_dir).unwrap();
    fs::write(head_dir.join("manifest.json"), head.manifest).unwrap();
    fs::write(head_dir.join("objects.json"), head.objects).unwrap();
    let mut artifacts = Vec::new();
    for (index, name) in NAMES.iter().enumerate() {
        let local = root.join(name);
        let workspace = root.join(format!("work-{name}"));
        engine(&local, json!({"op":"sync_configure","project":"demo","authority":"central",
            "epoch":1,"device":name,"role":"client","peers":["central-device"]}));
        engine(&local, json!({"op":"sync_import","source":head_dir,"confirm_trusted_source":true}));
        engine(&local, json!({"op":"open","workspace":"work","path":workspace,"operation_id":"open"}));
        let selected_generation = if index == 0 {
            fs::write(workspace.join("private-ancestor.txt"), PRIVATE_ANCESTRY).unwrap();
            engine(&local, json!({"op":"checkpoint","workspace":"work","expected_generation":0,
                "operation_id":"private-ancestor"}));
            assert!(engine(&local, json!({"op":"sync_pending"}))["proposals"].as_array().unwrap().is_empty());
            fs::remove_file(workspace.join("private-ancestor.txt")).unwrap();
            1
        } else { 0 };
        fs::write(workspace.join(format!("{name}.txt")),
            format!("synthetic-public-{name}\n").repeat(if index == 0 { 20000 } else { 1 })).unwrap();
        engine(&local, json!({"op":"checkpoint","workspace":"work","expected_generation":selected_generation,
            "operation_id":"checkpoint"}));
        if index < 2 {
            engine(&local, json!({"op":"publish","workspace":"work","checkpoint":"checkpoint",
                "intent":"Explicit synthetic CI publication","operation_id":"proposal"}));
            let destination = root.join(format!("export-{name}"));
            engine(&local, json!({"op":"sync_export","kind":"proposal","proposal":"proposal",
                "destination":destination,"operation_id":"upload"}));
            artifacts.push(Artifact {
                manifest: fs::read(destination.join("manifest.json")).unwrap(),
                objects: fs::read(destination.join("objects.json")).unwrap(),
            });
        } else {
            assert!(engine(&local, json!({"op":"sync_pending"}))["proposals"].as_array().unwrap().is_empty());
        }
        fs::write(workspace.join("private.txt"), format!("PRIVATE-NEVER-SEND-{name}")).unwrap();
    }

    // Every negative uses a valid application request, so malformed JSON cannot mask an auth bug.
    let (alien_ca, alien_key) = make_ca();
    let (alien_cert, alien_leaf_key) = leaf(&alien_ca, &alien_key, "alien", false);
    let alien = client(&ca, &alien_cert, &alien_leaf_key, &pin);
    assert!(request(&alien, address, "POST", "/v1/history", history_body()).await.is_err());
    let wrong_pin = client(&ca, &identities[0].0, &identities[0].1, &"0".repeat(64));
    assert!(request(&wrong_pin, address, "POST", "/v1/history", history_body()).await.is_err());
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let no_certificate = Client {
        tls: Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()),
        server_name: "localhost".into(), authority_fingerprint: pin.clone(),
    };
    assert!(request(&no_certificate, address, "POST", "/v1/history", history_body()).await.is_err());
    let (unmapped_cert, unmapped_key) = leaf(&ca, &ca_key, "unmapped", false);
    let unmapped = client(&ca, &unmapped_cert, &unmapped_key, &pin);
    assert!(request(&unmapped, address, "POST", "/v1/history", history_body()).await.is_err());
    let mut wrong_dns = client(&ca, &identities[0].0, &identities[0].1, &pin);
    wrong_dns.server_name = "wrong.invalid".into();
    assert!(request(&wrong_dns, address, "POST", "/v1/history", history_body()).await.is_err());
    request(&clients[3], address, "POST", "/v1/history", history_body()).await
        .expect("Dave is authorized before revocation");
    acl.peers.get_mut(&fingerprint(identities[3].0.der())).unwrap().revoked = true;
    fs::write(&acl_path, serde_json::to_vec(&acl).unwrap()).unwrap();
    assert!(request(&clients[3], address, "POST", "/v1/history", history_body()).await.is_err());
    evidence.summary["certificate_acl_rejections"] = json!(6);
    evidence.summary["rejection_cases"] = json!(["untrusted client CA", "wrong authority pin",
        "missing client certificate", "trusted but unmapped certificate", "wrong server DNS", "revoked client certificate"]);

    let artifact = &artifacts[0];
    assert!(artifact.objects.len() > CHUNK_MAX * 2);
    let begin = json_request(&clients[0], address, "POST", "/v1/transfers", artifact.manifest.clone()).await;
    let transfer = format!("/v1/transfers/{}", begin["transfer_id"].as_str().unwrap());
    let partial = json_request(&clients[0], address, "PUT", &format!("{transfer}/0"),
        artifact.objects[..CHUNK_MAX].to_vec()).await;
    assert_eq!(partial["committed_offset"], CHUNK_MAX);
    assert!(partial["import_result"].is_null());
    // Terminate only our server after a durable chunk acknowledgment, then reopen storage.
    server.stop();
    evidence.summary["server_restarts"] = json!(1);
    server = Server::start(&config_path, &log);
    ready(&mut server, &clients[0], address, &log).await;
    let retained = json_request(&clients[0], address, "GET", &transfer, vec![]).await;
    assert_eq!(retained, partial, "restart preserves exact partial transfer status");
    let identical_replay = json_request(&clients[0], address, "PUT", &format!("{transfer}/0"),
        artifact.objects[..CHUNK_MAX].to_vec()).await;
    assert_eq!(identical_replay, partial, "identical acknowledged chunk replay is stable");
    assert!(request(&clients[1], address, "GET", &transfer, vec![]).await.is_err(),
        "another authorized client must not read Alice's transfer");
    let pre_send_drop = Arc::new(AtomicBool::new(false));
    let lost_ack = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let completed = resumable::upload(artifact, |method, path, body| {
        let dropped = pre_send_drop.clone();
        let lost = lost_ack.clone();
        let attempts = attempts.clone();
        let c = &clients[0];
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(60)).await;
            if method == "PUT" && !dropped.swap(true, Ordering::SeqCst) {
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "synthetic pre-send drop").into());
            }
            let response = request(c, address, &method, &path, body).await?;
            if method == "PUT" && !lost.swap(true, Ordering::SeqCst) {
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset,
                    "synthetic post-commit lost acknowledgment").into());
            }
            Ok(("application/json".into(), response))
        }
    }).await.unwrap();
    assert!(pre_send_drop.load(Ordering::SeqCst) && lost_ack.load(Ordering::SeqCst));
    assert!(completed.import_result.is_some());
    assert_eq!(completed.committed_offset, artifact.objects.len() as u64);
    let completed_replay = json_request(&clients[0], address, "POST", &format!("{transfer}/finish"), vec![]).await;
    assert_eq!(completed_replay, serde_json::to_value(&completed).unwrap());
    let bob = resumable::upload(&artifacts[1], |method, path, body| {
        let c = &clients[1];
        async move { Ok(("application/json".into(), request(c, address, &method, &path, body).await?)) }
    }).await.unwrap();
    assert!(bob.import_result.is_some());
    let mut integrated = 0;
    for _ in 0..3 {
        let tick = authority.tick().await.unwrap();
        if let Some(outcomes) = tick["integration"]["outcomes"].as_array() {
            integrated += outcomes.iter().filter(|outcome| outcome["state"] == "integrated").count();
        }
    }
    assert_eq!(integrated, 2, "only the two explicitly published proposals integrate");
    server.stop();
    evidence.summary["server_restarts"] = json!(2);
    server = Server::start(&config_path, &log);
    ready(&mut server, &clients[0], address, &log).await;
    let durable_finish = json_request(&clients[0], address, "POST", &format!("{transfer}/finish"), vec![]).await;
    assert_eq!(durable_finish, completed_replay, "completed acknowledgment survives process restart");

    let carol_staging = root.join("carol-staging");
    fs::create_dir(&carol_staging).unwrap();
    let carol = Workstation {
        client: client(&ca, &identities[2].0, &identities[2].1, &pin), address,
        engine: engine_path(), state: root.join("carol"), staging: carol_staging,
        project: "demo".into(), authority: "central".into(), epoch: 1,
        device: "carol".into(), authority_device: "central-device".into(),
    };
    carol.catch_up().await.unwrap();
    let observed = root.join("observed");
    engine(&root.join("carol"), json!({"op":"open","workspace":"observed","path":observed,"operation_id":"observe"}));
    assert!(observed.join("alice.txt").exists());
    assert!(observed.join("bob.txt").exists());
    for name in ["carol.txt", "dave.txt", "private.txt", "private-ancestor.txt"] {
        assert!(!observed.join(name).exists(), "private WIP leaked into public tree: {name}");
    }
    for name in NAMES {
        assert_eq!(fs::read_to_string(root.join(format!("work-{name}/private.txt"))).unwrap(),
            format!("PRIVATE-NEVER-SEND-{name}"));
    }
    let mut audit = serde_json::Map::new();
    audit.insert("authority".into(), audit_public_blobs(&state));
    for name in NAMES { audit.insert(name.into(), audit_public_blobs(&root.join(name))); }
    evidence.summary["public_store_audit"] = Value::Object(audit);
    evidence.summary["private_checkpoint_ancestry_checked"] = json!(true);
    evidence.summary["faults"] = json!({"delay_ms_per_upload_attempt":60,
        "upload_attempts":attempts.load(Ordering::SeqCst),
        "pre_send_drops":1,"post_commit_lost_acks":1,"cross_device_transfer_rejections":1});
    evidence.summary["retained_offset_after_restart"] = json!(CHUNK_MAX);
    evidence.summary["integrated_publications"] = json!(integrated);
    server.stop();
    evidence.summary["passed"] = json!(true);
    evidence.save().expect("persist configured safe evidence artifacts");
    eprintln!("PASS: four isolated device actors, real loopback mTLS, six certificate/ACL rejection cases, cross-device transfer denial, two owned server restarts, retained offset, exact chunk/final ACK replay, 60ms application delay, pre-send drop, committed lost ACK, two published files, private ancestry/public blob audit and preserved private worktrees. Not real WAN or power-loss validation.");
}
