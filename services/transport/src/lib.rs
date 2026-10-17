//! Mandatory mutually authenticated HTTPS boundary for the fixed Wipstash engine.
pub mod daemon;
pub mod resumable;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::Semaphore,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const MANIFEST_MAX: usize = 16384;
pub const PAYLOAD_MAX: usize = 8 * 1024 * 1024;
pub const WIRE_MAX: usize = 4 + MANIFEST_MAX + PAYLOAD_MAX;
const OUTPUT_MAX: usize = 16 * 1024 * 1024;
fn error(s: &str) -> Box<dyn std::error::Error + Send + Sync> {
    s.to_owned().into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub device: String,
    pub project: String,
    pub role: String,
    pub revoked: bool,
}
/// Keys are lowercase SHA-256 hashes of the DER leaf certificate. Never HTTP headers.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Acl {
    pub peers: HashMap<String, Peer>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_storage_bytes: u64,
    pub max_storage_entries: u64,
    pub free_space_reserve_bytes: u64,
    pub requests_per_minute: u32,
    pub request_burst: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_storage_bytes: 1024 * 1024 * 1024,
            max_storage_entries: 200_000,
            free_space_reserve_bytes: 64 * 1024 * 1024,
            requests_per_minute: 120,
            request_burst: 30,
        }
    }
}
struct Bucket {
    tokens: f64,
    updated: Instant,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub engine: PathBuf,
    pub state: PathBuf,
    pub staging: PathBuf,
    pub project: String,
    pub authority: String,
    pub epoch: u64,
    pub device: String,
    pub acl: PathBuf,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: KeySource,
    pub listen: std::net::SocketAddr,
    #[serde(default)]
    pub limits: Limits,
}
pub fn fingerprint(cert: &[u8]) -> String {
    format!("{:x}", Sha256::digest(cert))
}
pub fn authorize(acl: &Acl, certificate: &[u8], project: &str) -> Result<Peer> {
    let p = acl
        .peers
        .get(&fingerprint(certificate))
        .ok_or_else(|| error("unknown_device"))?;
    if p.revoked || p.project != project || p.role != "client" {
        return Err(error("forbidden"));
    }
    Ok(p.clone())
}
/// Exactly one private-key source. Legacy JSON strings still select a PEM file.
/// The object form explicitly opts into a pre-provisioned native credential.
/// No secret bytes are part of configuration or its serialization.
#[derive(Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum KeySource {
    File(PathBuf),
    NativeVault {
        #[serde(deserialize_with = "credential_id")]
        native_vault: String,
    },
}
fn credential_id<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let id = String::deserialize(deserializer)?;
    wipstash_platform::vault::CredentialKey::new(&id)
        .map_err(|_| serde::de::Error::custom("invalid_credential_id"))?;
    Ok(id)
}
impl From<PathBuf> for KeySource {
    fn from(path: PathBuf) -> Self {
        Self::File(path)
    }
}
const TLS_KEY_MAX: usize = 64 * 1024;
const TLS_CERT_MAX: usize = 1024 * 1024;
impl KeySource {
    /// Only an explicit NativeVault configuration can reach the native adapter.
    pub fn load(&self) -> Result<PrivateKeyDer<'static>> {
        self.load_with_vault(&wipstash_platform::vault::NativeVault)
    }
    /// Injection point for embedders/tests. A failed lookup never tries a file.
    pub fn load_with_vault(
        &self,
        vault: &dyn wipstash_platform::vault::CredentialVault,
    ) -> Result<PrivateKeyDer<'static>> {
        match self {
            Self::File(path) => {
                let bytes = zeroize::Zeroizing::new(read_file(path, TLS_KEY_MAX)?);
                parse_private_key(&bytes)
            }
            Self::NativeVault { native_vault } => {
                let id = wipstash_platform::vault::CredentialKey::new(native_vault)?;
                let secret = vault.read(&id)?;
                parse_private_key(secret.expose_secret())
            }
        }
    }
}
fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = read_file(path, TLS_CERT_MAX)?;
    Ok(rustls_pemfile::certs(&mut bytes.as_slice()).collect::<std::result::Result<Vec<_>, _>>()?)
}
fn parse_private_key(mut bytes: &[u8]) -> Result<PrivateKeyDer<'static>> {
    if bytes.is_empty() || bytes.len() > TLS_KEY_MAX {
        return Err(error("private_key_bound"));
    }
    let mut key = None;
    for item in rustls_pemfile::read_all(&mut bytes) {
        let next = match item.map_err(|_| error("invalid_private_key"))? {
            rustls_pemfile::Item::Pkcs1Key(value) => PrivateKeyDer::Pkcs1(value),
            rustls_pemfile::Item::Pkcs8Key(value) => PrivateKeyDer::Pkcs8(value),
            rustls_pemfile::Item::Sec1Key(value) => PrivateKeyDer::Sec1(value),
            _ => return Err(error("invalid_private_key")),
        };
        if key.replace(next).is_some() {
            return Err(error("ambiguous_private_key"));
        }
    }
    key.ok_or_else(|| error("missing_private_key"))
}
pub fn server_tls(
    roots: RootCertStore,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut c = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}
pub fn client_tls(
    roots: RootCertStore,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ClientConfig> {
    let mut c = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}
pub fn roots(path: &Path) -> Result<RootCertStore> {
    let mut r = RootCertStore::empty();
    for c in certs(path)? {
        r.add(c)?;
    }
    Ok(r)
}

/// Binary framing: four-byte big-endian manifest length, exact JSON bytes, raw objects.
#[derive(Clone)]
pub struct Artifact {
    pub manifest: Vec<u8>,
    pub objects: Vec<u8>,
}
impl Artifact {
    pub fn decode(wire: &[u8]) -> Result<Self> {
        if wire.len() < 4 || wire.len() > WIRE_MAX {
            return Err(error("artifact_bound"));
        }
        let n = u32::from_be_bytes(wire[..4].try_into()?) as usize;
        if n == 0 || n > MANIFEST_MAX || n + 4 > wire.len() || wire.len() - n - 4 > PAYLOAD_MAX {
            return Err(error("artifact_bound"));
        }
        let a = Self {
            manifest: wire[4..4 + n].to_vec(),
            objects: wire[4 + n..].to_vec(),
        };
        a.validate()?;
        Ok(a)
    }
    pub fn validate(&self) -> Result<Value> {
        if self.manifest.len() > MANIFEST_MAX || self.objects.len() > PAYLOAD_MAX {
            return Err(error("artifact_bound"));
        }
        let m: Value = serde_json::from_slice(&self.manifest)?;
        if m["version"] != 1
            || m["payload_len"].as_u64() != Some(self.objects.len() as u64)
            || m["payload_sha256"].as_str() != Some(&fingerprint(&self.objects))
        {
            return Err(error("artifact_digest"));
        }
        Ok(m)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut b = (self.manifest.len() as u32).to_be_bytes().to_vec();
        b.extend(&self.manifest);
        b.extend(&self.objects);
        Ok(b)
    }
    pub fn validate_upload(&self, p: &Peer, c: &Config) -> Result<()> {
        let m = self.validate()?;
        if m["device"] != p.device
            || m["project"] != c.project
            || m["authority"] != c.authority
            || m["epoch"] != c.epoch
            || m["kind"] != "proposal"
        {
            return Err(error("artifact_identity"));
        }
        Ok(())
    }
    pub fn validate_download(&self, p: &Peer, c: &Config) -> Result<()> {
        let m = self.validate()?;
        if m["device"] != c.device
            || m["project"] != c.project
            || m["authority"] != c.authority
            || m["epoch"] != c.epoch
        {
            return Err(error("artifact_identity"));
        }
        match m["kind"].as_str() {
            Some("head") => Ok(()),
            Some("receipt") if m["receipt"]["recipient"] == p.device => Ok(()),
            _ => Err(error("artifact_recipient")),
        }
    }
}

pub struct Service {
    config: Config,
    gate: Semaphore,
    buckets: Mutex<HashMap<String, Bucket>>,
}
impl Service {
    pub async fn new(mut config: Config) -> Result<Arc<Self>> {
        for p in [&config.engine, &config.state, &config.staging, &config.acl] {
            if !p.is_absolute() {
                return Err(error("absolute_config_paths_required"));
            }
        }
        if config.epoch == 0 {
            return Err(error("invalid_epoch"));
        }
        if config.limits.max_storage_bytes == 0
            || config.limits.max_storage_entries == 0
            || config.limits.requests_per_minute == 0
            || config.limits.requests_per_minute > 100_000
            || config.limits.request_burst == 0
            || config.limits.request_burst > 100_000
        {
            return Err(error("invalid_limits"));
        }
        config.state = std::fs::canonicalize(&config.state)?;
        config.staging = std::fs::canonicalize(&config.staging)?;
        if config.state.starts_with(&config.staging) || config.staging.starts_with(&config.state) {
            return Err(error("overlapping_storage_roots"));
        }
        let s = Arc::new(Self {
            config,
            gate: Semaphore::new(1),
            buckets: Mutex::new(HashMap::new()),
        });
        let status = s.engine(json!({"op":"sync_status"})).await?;
        let c = &status["config"];
        if c["project"] != s.config.project
            || c["authority"] != s.config.authority
            || c["epoch"] != s.config.epoch
            || c["device"] != s.config.device
            || c["role"] != "authority"
        {
            return Err(error("engine_binding_mismatch"));
        }
        Ok(s)
    }
    async fn engine(&self, request: Value) -> Result<Value> {
        run_engine(&self.config.engine, &self.config.state, request).await
    }

    fn peer(&self, certificate: &[u8]) -> Result<Peer> {
        let bytes = read_file(&self.config.acl, 1024 * 1024)?;
        authorize(
            &serde_json::from_slice(&bytes)?,
            certificate,
            &self.config.project,
        )
    }
    fn rate(&self, certificate: &[u8], charge: bool) -> Result<()> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().map_err(|_| error("rate_state"))?;
        buckets.retain(|_, b| now.duration_since(b.updated) < Duration::from_secs(600));
        let id = fingerprint(certificate);
        if !buckets.contains_key(&id) && buckets.len() >= 4096 {
            return Err(error("rate_limited"));
        }
        let burst = self.config.limits.request_burst as f64;
        let b = buckets.entry(id).or_insert(Bucket {
            tokens: burst,
            updated: now,
        });
        b.tokens = (b.tokens
            + now.duration_since(b.updated).as_secs_f64()
                * self.config.limits.requests_per_minute as f64
                / 60.0)
            .min(burst);
        b.updated = now;
        if b.tokens < 1.0 {
            return Err(error("rate_limited"));
        }
        if charge {
            b.tokens -= 1.0;
        }
        Ok(())
    }
    fn storage_admission(&self, incoming: u64) -> Result<()> {
        let limits = &self.config.limits;
        wipstash_storage::admit(
            &[self.config.state.clone(), self.config.staging.clone()],
            wipstash_storage::Budget {
                max_bytes: limits.max_storage_bytes,
                max_entries: limits.max_storage_entries,
                reserve_bytes: limits.free_space_reserve_bytes,
            },
            incoming
                .checked_mul(4)
                .and_then(|v| v.checked_add(64 * 1024))
                .ok_or_else(|| error("storage_quota"))?,
            40_000,
        )
        .map_err(|_| error("storage_quota"))?;
        Ok(())
    }
    pub async fn route(
        &self,
        certificate: &[u8],
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(String, Vec<u8>)> {
        let _permit = self.gate.acquire().await?;
        let p = self.peer(certificate)?; // Reload on every operation; established TLS sessions do not bypass revocation.
        self.rate(certificate, true)?;
        if body.len() > WIRE_MAX {
            return Err(error("body_bound"));
        }
        if path == "/v1/transfers" || path.starts_with("/v1/transfers/") {
            let binding = resumable::Binding {
                certificate: fingerprint(certificate),
                device: p.device.clone(),
                project: p.project.clone(),
            };
            let root = self.config.staging.join("resumable");
            if !root.exists() {
                self.storage_admission(0)?;
            }
            let store = resumable::Store::open(root)?;
            let status = if method == "POST" && path == "/v1/transfers" {
                if body.is_empty() || body.len() > MANIFEST_MAX {
                    return Err(error("artifact_bound"));
                }
                let manifest: Value = serde_json::from_slice(body)?;
                if manifest["authority"] != self.config.authority
                    || manifest["epoch"] != self.config.epoch
                    || manifest["device"] != p.device
                    || manifest["project"] != self.config.project
                    || manifest["kind"] != "proposal"
                {
                    return Err(error("artifact_identity"));
                }
                let id = resumable::transfer_id(&binding, body)?;
                match store.status(&binding, &id) {
                    Ok(_) => (),
                    Err(e) if resumable::is_missing(&*e) => {
                        self.storage_admission(body.len() as u64 + 512 * 1024)?
                    }
                    Err(e) => return Err(e),
                }
                store.begin(&binding, body)?
            } else {
                let tail = path
                    .strip_prefix("/v1/transfers/")
                    .ok_or_else(|| error("unknown_endpoint"))?;
                let parts: Vec<_> = tail.split('/').collect();
                if parts.len() > 2 || parts.is_empty() {
                    return Err(error("unknown_endpoint"));
                }
                let id = parts[0];
                store.validate_authority(
                    &binding,
                    id,
                    &self.config.authority,
                    self.config.epoch,
                )?;
                let previous = store.status(&binding, id)?;
                if method == "GET" && parts.len() == 1 && body.is_empty() {
                    previous
                } else if method == "PUT" && parts.len() == 2 {
                    if body.is_empty() || body.len() > resumable::CHUNK_MAX {
                        return Err(error("chunk_bound"));
                    }
                    let offset = parts[1].parse::<u64>().map_err(|_| error("chunk_offset"))?;
                    if parts[1] != offset.to_string() {
                        return Err(error("chunk_offset"));
                    }
                    if offset == previous.committed_offset && previous.import_result.is_none() {
                        // Includes the maximum temporary journal rewrite, not just new payload bytes.
                        self.storage_admission(body.len() as u64 + 512 * 1024)?;
                    }
                    store.chunk(&binding, id, offset, body)?
                } else if method == "POST"
                    && parts.len() == 2
                    && parts[1] == "finish"
                    && body.is_empty()
                {
                    if previous.import_result.is_some() {
                        previous
                    } else {
                        let artifact = store.artifact(&binding, id)?;
                        artifact.validate_upload(&p, &self.config)?;
                        self.storage_admission(artifact.objects.len() as u64 + 512 * 1024)?;
                        let dir = tempfile::Builder::new()
                            .prefix("resume-import-")
                            .tempdir_in(&self.config.staging)?;
                        std::fs::write(dir.path().join("manifest.json"), &artifact.manifest)?;
                        std::fs::write(dir.path().join("objects.json"), &artifact.objects)?;
                        let result = self.engine(json!({"op":"sync_import","source":dir.path(),"confirm_trusted_source":true})).await?;
                        store.complete(&binding, id, result)?
                    }
                } else {
                    return Err(error("unknown_endpoint"));
                }
            };
            return Ok(("application/json".into(), serde_json::to_vec(&status)?));
        }
        if method == "POST" && path == "/v1/proposals" {
            let a = Artifact::decode(body)?;
            a.validate_upload(&p, &self.config)?;
            self.storage_admission(body.len() as u64)?;
            let dir = tempfile::Builder::new()
                .prefix("receive-")
                .tempdir_in(&self.config.staging)?;
            std::fs::write(dir.path().join("manifest.json"), &a.manifest)?;
            std::fs::write(dir.path().join("objects.json"), &a.objects)?;
            let v = self
                .engine(
                    json!({"op":"sync_import","source":dir.path(),"confirm_trusted_source":true}),
                )
                .await?;
            return Ok(("application/json".into(), serde_json::to_vec(&v)?));
        }
        if path == "/v1/history" && (method == "POST" || (method == "GET" && body.is_empty())) {
            if body.len() > 4096 {
                return Err(error("control_bound"));
            }
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct Page {
                after: Option<u64>,
                limit: Option<u64>,
                cursor_kind: Option<String>,
            }
            let page: Page = if body.is_empty() {
                Page::default()
            } else {
                serde_json::from_slice(body)?
            };
            let v = self.engine(json!({"op":"sync_export_history","kind":"head","cursor_kind":page.cursor_kind.unwrap_or_else(|| "head_sequence".into()),"after":page.after.unwrap_or(0),"limit":page.limit.unwrap_or(128)})).await?;
            // Head-only pagination cannot expose receipt metadata or confuse row IDs with sequences.
            return Ok(("application/json".into(), serde_json::to_vec(&v)?));
        }
        if method == "POST" && (path == "/v1/export" || path == "/v1/current-receipt") {
            if body.len() > 4096 {
                return Err(error("control_bound"));
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Export {
                kind: String,
                operation_id: String,
                proposal: Option<String>,
            }
            let q: Export = if path == "/v1/current-receipt" {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Current {
                    proposal: String,
                }
                let current: Current = serde_json::from_slice(body)?;
                if !valid_id(&current.proposal) {
                    return Err(error("invalid_identifier"));
                }
                let status = self
                    .engine(json!({"op":"proposal_status","proposal":current.proposal}))
                    .await?;
                if status["origin"]["device"] != p.device {
                    return Err(error("receipt_recipient"));
                }
                let observation = json!({"proposal":current.proposal,"commit":status["commit"],
                    "state":status["state"],"head":status["head"],"evidence":status["evidence"],
                    "repaired":status["details"]["repaired"] == true});
                Export {
                    kind: "receipt".into(),
                    proposal: Some(current.proposal),
                    operation_id: format!(
                        "current-{}",
                        fingerprint(&serde_json::to_vec(&observation)?)
                    ),
                }
            } else {
                serde_json::from_slice(body)?
            };
            if !valid_id(&q.operation_id) || q.proposal.as_ref().is_some_and(|s| !valid_id(s)) {
                return Err(error("invalid_identifier"));
            }
            if q.kind == "receipt" {
                let proposal = q.proposal.as_deref().ok_or_else(|| error("export_kind"))?;
                let status = self
                    .engine(json!({"op":"proposal_status","proposal":proposal}))
                    .await?;
                if status["origin"]["device"] != p.device {
                    return Err(error("receipt_recipient"));
                }
            }
            self.storage_admission(PAYLOAD_MAX as u64)?;
            let dir = tempfile::Builder::new()
                .prefix("export-")
                .tempdir_in(&self.config.staging)?;
            let dest = dir.path().join("artifact");
            let op = format!(
                "net-{}",
                fingerprint(format!("{}:{}", p.device, q.operation_id).as_bytes())
            );
            let request = match q.kind.as_str() {
                "head" if q.proposal.is_none() => {
                    json!({"op":"sync_export","kind":"head","operation_id":op,"destination":dest})
                }
                "receipt" if q.proposal.is_some() => {
                    json!({"op":"sync_export","kind":"receipt","proposal":q.proposal,"operation_id":op,"destination":dest})
                }
                "retained" if q.proposal.is_none() => {
                    json!({"op":"sync_reexport","operation_id":q.operation_id,"destination":dest})
                }
                _ => return Err(error("export_kind")),
            };
            // Engine export request digests include destination. Replays use its exact retained artifact.
            let exists = self
                .engine(json!({"op":"sync_export_lookup","operation_id":op}))
                .await?["exists"]
                .as_bool()
                .ok_or_else(|| error("lookup_shape"))?;
            if exists && q.kind != "retained" {
                self.engine(json!({"op":"sync_reexport","operation_id":op,"destination":dest}))
                    .await?;
            } else {
                self.engine(request).await?;
            }
            let a = Artifact {
                manifest: read_file(&dest.join("manifest.json"), MANIFEST_MAX)?,
                objects: read_file(&dest.join("objects.json"), PAYLOAD_MAX)?,
            };
            a.validate_download(&p, &self.config)?;
            let manifest = a.validate()?;
            if q.kind != "retained"
                && (manifest["kind"] != q.kind
                    || (q.kind == "receipt"
                        && manifest["receipt"]["authority_proposal"].as_str()
                            != q.proposal.as_deref()))
            {
                return Err(error("idempotency_mismatch"));
            }
            return Ok(("application/vnd.wipstash.artifact-v1".into(), a.encode()?));
        }
        Err(error("unknown_endpoint"))
    }
    async fn http(&self, certificate: &[u8], req: Request<Incoming>) -> Response<Full<Bytes>> {
        let method = req.method().as_str().to_owned();
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("")
            .to_owned();
        let result = async {
            // Recheck revocation before allocating the request body, then again
            // under the serialized operation gate immediately before engine work.
            self.peer(certificate)?;
            self.rate(certificate, false)?;
            let mut body = req.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame?;
                if let Ok(data) = frame.into_data() {
                    if bytes.len() + data.len() > WIRE_MAX {
                        return Err(error("body_bound"));
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            self.route(certificate, &method, &path, &bytes).await
        };
        match tokio::time::timeout(Duration::from_secs(90), result).await {
            Ok(Ok((kind, bytes))) => Response::builder()
                .header("content-type", kind)
                .body(Full::new(Bytes::from(bytes)))
                .unwrap(),
            Ok(Err(e)) if e.to_string() == "rate_limited" => Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("retry-after", "1")
                .body(Full::new(Bytes::from_static(
                    b"{\"ok\":false,\"error\":\"rate_limited\"}",
                )))
                .unwrap(),
            Ok(Err(e)) if e.to_string() == "storage_quota" => Response::builder()
                .status(StatusCode::INSUFFICIENT_STORAGE)
                .body(Full::new(Bytes::from_static(
                    b"{\"ok\":false,\"error\":\"storage_quota\"}",
                )))
                .unwrap(),
            _ => Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from_static(
                    b"{\"ok\":false,\"error\":\"request_rejected\"}",
                )))
                .unwrap(),
        }
    }
    pub async fn serve_stream<S>(
        self: Arc<Self>,
        stream: S,
        tls: Arc<rustls::ServerConfig>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_rustls::TlsAcceptor::from(tls).accept(stream),
        )
        .await??;
        let cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or_else(|| error("client_certificate_required"))?
            .as_ref()
            .to_vec();
        self.peer(&cert)?;
        hyper::server::conn::http1::Builder::new()
            .max_buf_size(32768)
            .serve_connection(
                TokioIo::new(stream),
                hyper::service::service_fn(move |req| {
                    let s = self.clone();
                    let cert = cert.clone();
                    async move { Ok::<_, std::convert::Infallible>(s.http(&cert, req).await) }
                }),
            )
            .await?;
        Ok(())
    }
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let tls = Arc::new(server_tls(
            roots(&self.config.ca)?,
            certs(&self.config.certificate)?,
            self.config.key.load()?,
        )?);
        let listener = tokio::net::TcpListener::bind(self.config.listen).await?;
        let slots = Arc::new(Semaphore::new(32));
        loop {
            let permit = slots.clone().acquire_owned().await?;
            let (stream, _) = listener.accept().await?;
            let s = self.clone();
            let t = tls.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ =
                    tokio::time::timeout(Duration::from_secs(120), s.serve_stream(stream, t)).await;
            });
        }
    }
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn read_file(path: &Path, max: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > max as u64 {
        return Err(error("artifact_file"));
    }
    let mut b = Vec::new();
    std::fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut b)?;
    if b.len() > max {
        return Err(error("artifact_bound"));
    }
    Ok(b)
}

#[derive(Debug)]
struct RetryableStatus {
    delay: Duration,
}
impl std::fmt::Display for RetryableStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("remote_temporarily_unavailable")
    }
}
impl std::error::Error for RetryableStatus {}

/// Retry only an identical caller-captured request, with bounded attempts and backoff.
async fn retry_request<F, Fut>(mut send: F) -> Result<Vec<u8>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    for attempt in 0..3 {
        let failure = match tokio::time::timeout(Duration::from_secs(120), send()).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(e)) => e,
            Err(e) => Box::new(e) as Box<dyn std::error::Error + Send + Sync>,
        };
        let transient = failure.is::<std::io::Error>()
            || failure.is::<hyper::Error>()
            || failure.is::<tokio::time::error::Elapsed>()
            || failure.is::<RetryableStatus>();
        if !transient || attempt == 2 {
            return Err(failure);
        }
        let delay = failure
            .downcast_ref::<RetryableStatus>()
            .map(|s| s.delay)
            .unwrap_or_else(|| Duration::from_millis(100 * (1 << attempt)));
        tokio::time::sleep(delay).await;
    }
    unreachable!()
}

/// Client validates CA, DNS identity AND pinned authority certificate; no HTTP fallback or redirects.
pub struct Client {
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: String,
    pub authority_fingerprint: String,
}
impl Client {
    pub async fn request_stream<S>(
        &self,
        stream: S,
        method: &str,
        path: &str,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if bytes.len() > WIRE_MAX
            || !(matches!(
                path,
                "/v1/proposals"
                    | "/v1/export"
                    | "/v1/history"
                    | "/v1/current-receipt"
                    | "/v1/transfers"
            ) || valid_transfer_path(path))
        {
            return Err(error("client_request_bound"));
        }
        let stream = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(ServerName::try_from(self.server_name.clone())?, stream)
            .await?;
        let cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or_else(|| error("server_certificate_required"))?;
        if fingerprint(cert.as_ref()) != self.authority_fingerprint {
            return Err(error("authority_pin_mismatch"));
        }
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        // Keep connection-driver lifetime inside this request, including cancellation.
        struct AbortOnDrop(tokio::task::JoinHandle<()>);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _connection = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", &self.server_name)
            .header("connection", "close")
            .body(Full::new(Bytes::from(bytes)))?;
        let response = sender.send_request(request).await?;
        if matches!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        ) {
            let seconds = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1)
                .clamp(1, 5);
            return Err(Box::new(RetryableStatus {
                delay: Duration::from_secs(seconds),
            }));
        }
        if response.status() != StatusCode::OK {
            return Err(error("remote_rejected"));
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                if bytes.len() + data.len() > OUTPUT_MAX {
                    return Err(error("response_bound"));
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(bytes)
    }
    pub async fn request(
        &self,
        address: std::net::SocketAddr,
        method: &str,
        path: &str,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        retry_request(|| async {
            self.request_stream(
                tokio::net::TcpStream::connect(address).await?,
                method,
                path,
                bytes.clone(),
            )
            .await
        })
        .await
    }

    pub fn from_files(
        ca: &Path,
        certificate: &Path,
        private_key: &Path,
        server_name: String,
        authority_fingerprint: String,
    ) -> Result<Self> {
        Self::from_key_source(
            ca,
            certificate,
            &KeySource::File(private_key.to_owned()),
            server_name,
            authority_fingerprint,
        )
    }
    pub fn from_key_source(
        ca: &Path,
        certificate: &Path,
        private_key: &KeySource,
        server_name: String,
        authority_fingerprint: String,
    ) -> Result<Self> {
        if authority_fingerprint.len() != 64
            || !authority_fingerprint
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(error("invalid_authority_pin"));
        }
        Ok(Self {
            tls: Arc::new(client_tls(
                roots(ca)?,
                certs(certificate)?,
                private_key.load()?,
            )?),
            server_name,
            authority_fingerprint,
        })
    }
}

async fn run_engine(engine: &Path, state: &Path, request: Value) -> Result<Value> {
    run_engine_with_timeout(engine, state, request, Duration::from_secs(60)).await
}
async fn run_engine_with_timeout(
    engine: &Path,
    state: &Path,
    request: Value,
    deadline: Duration,
) -> Result<Value> {
    // No shell, no remote argv, no remote state/source/destination. All calls originate below.
    let mut child = tokio::process::Command::new(engine)
        .arg("--state")
        .arg(state)
        .arg(request.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| error("engine_stdout"))?;
    let result = tokio::time::timeout(deadline, async {
        let mut bytes = Vec::new();
        (&mut stdout)
            .take(OUTPUT_MAX as u64 + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > OUTPUT_MAX {
            return Err(error("engine_output_bound"));
        }
        let status = child.wait().await?;
        let value: Value = serde_json::from_slice(&bytes)?;
        if !status.success() || value["ok"] != true {
            return Err(error("engine_rejected"));
        }
        Ok(value)
    })
    .await
    .map_err(|_| error("engine_timeout"))?;
    result
}

/// Outbound-only workstation adapter. Paths and binding come from local operator configuration.
pub struct Workstation {
    pub client: Client,
    pub address: std::net::SocketAddr,
    pub engine: PathBuf,
    pub state: PathBuf,
    pub staging: PathBuf,
    pub project: String,
    pub authority: String,
    pub epoch: u64,
    pub device: String,
    pub authority_device: String,
}
impl Workstation {
    async fn verify_binding(&self) -> Result<()> {
        for path in [&self.engine, &self.state, &self.staging] {
            if !path.is_absolute() {
                return Err(error("absolute_config_paths_required"));
            }
        }
        if self.epoch == 0
            || [
                &self.project,
                &self.authority,
                &self.device,
                &self.authority_device,
            ]
            .iter()
            .any(|id| !valid_id(id))
        {
            return Err(error("invalid_client_binding"));
        }
        let v = run_engine(&self.engine, &self.state, json!({"op":"sync_status"})).await?;
        let c = &v["config"];
        if c["role"] != "client"
            || c["project"] != self.project
            || c["authority"] != self.authority
            || c["epoch"] != self.epoch
            || c["device"] != self.device
        {
            return Err(error("client_binding_mismatch"));
        }
        Ok(())
    }
    pub async fn upload(&self, proposal: &str, operation: &str) -> Result<Value> {
        self.verify_binding().await?;
        if !valid_id(proposal) || !valid_id(operation) {
            return Err(error("invalid_identifier"));
        }
        let dir = tempfile::Builder::new()
            .prefix("client-send-")
            .tempdir_in(&self.staging)?;
        let dest = dir.path().join("artifact");
        let exists = run_engine(
            &self.engine,
            &self.state,
            json!({"op":"sync_export_lookup","operation_id":operation}),
        )
        .await?["exists"]
            .as_bool()
            .ok_or_else(|| error("lookup_shape"))?;
        run_engine(&self.engine,&self.state,if exists {json!({"op":"sync_reexport","operation_id":operation,"destination":dest})} else {json!({"op":"sync_export","kind":"proposal","proposal":proposal,"operation_id":operation,"destination":dest})}).await?;
        let a = Artifact {
            manifest: read_file(&dest.join("manifest.json"), MANIFEST_MAX)?,
            objects: read_file(&dest.join("objects.json"), PAYLOAD_MAX)?,
        };
        let m = a.validate()?;
        if m["kind"] != "proposal"
            || m["proposal"] != proposal
            || m["device"] != self.device
            || m["project"] != self.project
            || m["authority"] != self.authority
            || m["epoch"] != self.epoch
        {
            return Err(error("upload_binding"));
        }
        let status = resumable::upload(&a, |method, path, body| async move {
            let bytes = self
                .client
                .request_stream(
                    tokio::net::TcpStream::connect(self.address).await?,
                    &method,
                    &path,
                    body,
                )
                .await?;
            Ok(("application/json".into(), bytes))
        })
        .await?;
        status
            .import_result
            .ok_or_else(|| error("transfer_not_imported"))
    }
    pub async fn download(
        &self,
        kind: &str,
        operation: &str,
        proposal: Option<&str>,
    ) -> Result<Value> {
        self.verify_binding().await?;
        if !valid_id(operation)
            || proposal.is_some_and(|p| !valid_id(p))
            || !matches!(
                (kind, proposal),
                ("head" | "retained", None) | ("receipt", Some(_))
            )
        {
            return Err(error("invalid_download_request"));
        }
        let b = self
            .client
            .request(
                self.address,
                "POST",
                "/v1/export",
                serde_json::to_vec(
                    &json!({"kind":kind,"operation_id":operation,"proposal":proposal}),
                )?,
            )
            .await?;
        let a = Artifact::decode(&b)?;
        let m = a.validate()?;
        if m["project"] != self.project
            || m["authority"] != self.authority
            || m["epoch"] != self.epoch
            || m["device"] != self.authority_device
            || !(m["kind"] == "head"
                || (m["kind"] == "receipt" && m["receipt"]["recipient"] == self.device))
        {
            return Err(error("download_binding"));
        }
        if kind != "retained"
            && (m["kind"] != kind
                || (kind == "receipt" && m["receipt"]["authority_proposal"].as_str() != proposal))
        {
            return Err(error("download_request_mismatch"));
        }
        let dir = tempfile::Builder::new()
            .prefix("client-receive-")
            .tempdir_in(&self.staging)?;
        std::fs::write(dir.path().join("manifest.json"), a.manifest)?;
        std::fs::write(dir.path().join("objects.json"), a.objects)?;
        run_engine(
            &self.engine,
            &self.state,
            json!({"op":"sync_import","source":dir.path(),"confirm_trusted_source":true}),
        )
        .await
    }
    /// Poll an immutable cached observation; unchanged state reuses the exact receipt artifact.
    pub async fn current_receipt(&self, proposal: &str) -> Result<Value> {
        self.verify_binding().await?;
        if !valid_id(proposal) {
            return Err(error("invalid_identifier"));
        }
        let bytes = self
            .client
            .request(
                self.address,
                "POST",
                "/v1/current-receipt",
                serde_json::to_vec(&json!({"proposal":proposal}))?,
            )
            .await?;
        let a = Artifact::decode(&bytes)?;
        let m = a.validate()?;
        if m["project"] != self.project
            || m["authority"] != self.authority
            || m["epoch"] != self.epoch
            || m["device"] != self.authority_device
            || m["kind"] != "receipt"
            || m["receipt"]["recipient"] != self.device
            || m["receipt"]["authority_proposal"] != proposal
        {
            return Err(error("download_binding"));
        }
        let dir = tempfile::Builder::new()
            .prefix("client-receipt-")
            .tempdir_in(&self.staging)?;
        std::fs::write(dir.path().join("manifest.json"), a.manifest)?;
        std::fs::write(dir.path().join("objects.json"), a.objects)?;
        run_engine(
            &self.engine,
            &self.state,
            json!({"op":"sync_import","source":dir.path(),"confirm_trusted_source":true}),
        )
        .await
    }
    /// Recover every retained head in authority sequence order, preserving the engine's durable cursor.
    pub async fn catch_up(&self) -> Result<Value> {
        self.verify_binding().await?;
        let status = run_engine(&self.engine, &self.state, json!({"op":"sync_status"})).await?;
        let persisted = match &status["cursor"] {
            Value::Null => 0,
            v => v.as_u64().ok_or_else(|| error("cursor_shape"))?,
        };
        // sync_status first runs durable journal/cache recovery in the engine.
        let mut cursor = persisted;
        let mut imported = 0u64;
        loop {
            let b = self
                .client
                .request(
                    self.address,
                    "POST",
                    "/v1/history",
                    serde_json::to_vec(
                        &json!({"after":cursor,"limit":128,"cursor_kind":"head_sequence"}),
                    )?,
                )
                .await?;
            let v: Value = serde_json::from_slice(&b)?;
            let heads = v["exports"]
                .as_array()
                .ok_or_else(|| error("history_shape"))?;
            if heads.len() > 128 || v["cursor_kind"] != "head_sequence" || v["after"] != cursor {
                return Err(error("history_cursor"));
            }
            let next = v["next_cursor"]
                .as_u64()
                .ok_or_else(|| error("history_shape"))?;
            let more = v["has_more"]
                .as_bool()
                .ok_or_else(|| error("history_shape"))?;
            for h in heads {
                let sequence = h["sequence"]
                    .as_u64()
                    .ok_or_else(|| error("history_shape"))?;
                if h["kind"] != "head" || Some(sequence) != cursor.checked_add(1) {
                    return Err(error("history_sequence_gap"));
                }
                let result = self
                    .download(
                        "retained",
                        h["operation_id"]
                            .as_str()
                            .ok_or_else(|| error("history_shape"))?,
                        None,
                    )
                    .await?;
                if result["sequence"] != sequence {
                    return Err(error("import_cursor_mismatch"));
                }
                cursor = sequence;
                imported += 1;
            }
            if next != cursor || (more && heads.is_empty()) || cursor < persisted {
                return Err(error("history_cursor"));
            }
            if !more {
                break;
            }
        }
        Ok(json!({"ok":true,"imports":imported,"cursor":cursor,"files_changed":false}))
    }
}

fn valid_transfer_path(path: &str) -> bool {
    let Some(tail) = path.strip_prefix("/v1/transfers/") else {
        return false;
    };
    let parts: Vec<_> = tail.split('/').collect();
    if parts.is_empty()
        || parts.len() > 2
        || parts[0].len() != 64
        || !parts[0]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return false;
    }
    parts.len() == 1
        || parts[1] == "finish"
        || parts[1]
            .parse::<u64>()
            .is_ok_and(|offset| offset <= PAYLOAD_MAX as u64 && parts[1] == offset.to_string())
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn retries_are_bounded_and_rejections_are_final() {
        let attempts = AtomicUsize::new(0);
        let request = b"immutable-operation-and-payload".to_vec();
        let result = retry_request(|| {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            let bytes = request.clone();
            async move {
                assert_eq!(bytes, b"immutable-operation-and-payload");
                if n < 2 {
                    Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "lost response",
                    ))
                        as Box<dyn std::error::Error + Send + Sync>)
                } else {
                    Ok(bytes)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, request);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        attempts.store(0, Ordering::SeqCst);
        assert!(retry_request(|| {
            attempts.fetch_add(1, Ordering::SeqCst);
            async {
                Err(Box::new(RetryableStatus {
                    delay: Duration::from_millis(1),
                })
                    as Box<dyn std::error::Error + Send + Sync>)
            }
        })
        .await
        .is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        attempts.store(0, Ordering::SeqCst);
        assert!(retry_request(|| {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err(error("remote_rejected")) }
        })
        .await
        .is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        attempts.store(0, Ordering::SeqCst);
        assert!(retry_request(|| {
            attempts.fetch_add(1, Ordering::SeqCst);
            async {
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "lost response",
                ))
                    as Box<dyn std::error::Error + Send + Sync>)
            }
        })
        .await
        .is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }
}

#[cfg(test)]
mod key_config_tests;
