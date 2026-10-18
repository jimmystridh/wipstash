//! Deliberately separate, server-authenticated TLS enrollment boundary.
//!
//! A trusted out-of-band invitation bootstraps CA/name/pin trust. Matching a pin
//! from an untrusted invitation does not authenticate the coordinator. This
//! module never dispatches a sync, administrator, or arbitrary HTTP route.
use crate::pairing::{
    EnrollmentResponse, InviteScope, PairingStore, RecoveryChallenge, RecoveryChallengeRequest,
    RecoveryRequest, RedeemRequest,
};
use crate::pairing_crypto::{validate_enrollment_response, Issuer};
use crate::{error, fingerprint, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Semaphore,
};

pub const REQUEST_MAX: usize = 24 * 1024;
pub const RESPONSE_MAX: usize = 32 * 1024;
pub const CSR_MAX: usize = 8 * 1024;
const HEADER_MAX: usize = 16 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);
const ENROLL: &str = "/v1/enroll";
const CHALLENGE: &str = "/v1/enroll/recovery-challenge";
const RECOVER: &str = "/v1/enroll/recover";
fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
fn csr_bound(csr: &[u8]) -> Result<()> {
    if csr.is_empty() || csr.len() > CSR_MAX {
        return Err(error("enrollment_rejected"));
    }
    Ok(())
}
fn allowed_route(path: &str) -> bool {
    matches!(path, ENROLL | CHALLENGE | RECOVER)
}
fn pin_valid(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}
impl Bucket {
    fn new(tokens: f64) -> Self {
        Self {
            tokens,
            updated: Instant::now(),
        }
    }
    fn charge(&mut self, capacity: f64, rate: f64) -> bool {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.updated).as_secs_f64() * rate).min(capacity);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}
struct Admission {
    global: Bucket,
    sources: Vec<Bucket>,
}
impl Admission {
    fn new() -> Self {
        Self {
            global: Bucket::new(16.0),
            sources: (0..256).map(|_| Bucket::new(8.0)).collect(),
        }
    }
    fn charge(&mut self, source: IpAddr) -> bool {
        // Fixed-size buckets cannot be grown/evicted by unauthenticated traffic.
        // Collisions conservatively share a quota; an IP is never an identity.
        let bytes = match source {
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
            IpAddr::V6(ip) => ip.octets(),
        };
        let slot = bytes
            .iter()
            .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(*b as usize))
            % self.sources.len();
        self.global.charge(16.0, 0.5) && self.sources[slot].charge(8.0, 0.2)
    }
}

pub struct EnrollmentService {
    store: PairingStore,
    issuer: Issuer,
    tls: Arc<rustls::ServerConfig>,
    slots: Arc<Semaphore>,
    admission: Mutex<Admission>,
    work_slots: Arc<Semaphore>,
}
impl EnrollmentService {
    pub fn new(
        store: PairingStore,
        issuer: Issuer,
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        // This listener alone omits client authentication. Existing sync TLS is
        // constructed independently by crate::server_tls and remains mandatory mTLS.
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            store,
            issuer,
            tls: Arc::new(tls),
            slots: Arc::new(Semaphore::new(8)),
            admission: Mutex::new(Admission::new()),
            work_slots: Arc::new(Semaphore::new(8)),
        })
    }
    fn admit(&self, source: IpAddr) -> Result<()> {
        if !self
            .admission
            .lock()
            .map_err(|_| error("enrollment_rejected"))?
            .charge(source)
        {
            return Err(error("enrollment_rejected"));
        }
        Ok(())
    }
    fn dispatch(&self, path: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        let now = now()?;
        match path {
            ENROLL => {
                let req: RedeemRequest = serde_json::from_slice(bytes)?;
                csr_bound(&req.csr_der)?;
                Ok(serde_json::to_vec(&self.store.redeem(
                    &req,
                    &self.issuer,
                    now,
                )?)?)
            }
            CHALLENGE => {
                let req: RecoveryChallengeRequest = serde_json::from_slice(bytes)?;
                csr_bound(&req.csr_der)?;
                Ok(serde_json::to_vec(
                    &self.store.recovery_challenge(&req, now)?,
                )?)
            }
            RECOVER => {
                let req: RecoveryRequest = serde_json::from_slice(bytes)?;
                csr_bound(&req.csr_der)?;
                Ok(serde_json::to_vec(&self.store.recover(&req, now)?)?)
            }
            _ => Err(error("enrollment_rejected")),
        }
    }
    async fn http(self: Arc<Self>, req: Request<Incoming>) -> Response<Full<Bytes>> {
        let result = tokio::time::timeout(DEADLINE, async {
            let path = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("")
                .to_owned();
            if req.method() != hyper::Method::POST
                || !allowed_route(&path)
                || req.uri().scheme().is_some()
                || req.uri().authority().is_some()
                || req.headers().get_all("content-type").iter().count() != 1
                || req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    != Some("application/json")
                || req.headers().contains_key("content-encoding")
                || req.headers().contains_key("expect")
            {
                return Err(error("enrollment_rejected"));
            }
            if req
                .headers()
                .get("content-length")
                .map(|v| {
                    v.to_str()
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .map(|n| n > REQUEST_MAX)
                        .unwrap_or(true)
                })
                .unwrap_or(false)
            {
                return Err(error("enrollment_rejected"));
            }
            let mut body = req.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame?;
                let data = frame
                    .into_data()
                    .map_err(|_| error("enrollment_rejected"))?;
                if bytes.len().saturating_add(data.len()) > REQUEST_MAX {
                    return Err(error("enrollment_rejected"));
                }
                bytes.extend_from_slice(&data);
            }
            let service = self.clone();
            let work_permit = self
                .work_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| error("enrollment_rejected"))?;
            // Do not block the async executor on bounded SQLite/cryptography work.
            let result = tokio::task::spawn_blocking(move || {
                let _permit = work_permit;
                service.dispatch(&path, &bytes)
            })
            .await??;
            if result.len() > RESPONSE_MAX {
                return Err(error("enrollment_rejected"));
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(result)
        })
        .await;
        let (status, bytes) = match result {
            Ok(Ok(bytes)) => (StatusCode::OK, bytes),
            _ => (
                StatusCode::BAD_REQUEST,
                b"{\"error\":\"enrollment_rejected\"}".to_vec(),
            ),
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("connection", "close")
            .header("cache-control", "no-store")
            .body(Full::new(Bytes::from(bytes)))
            .expect("constant valid response")
    }
    /// In-memory transport entry point. No network listener is opened.
    pub async fn serve_stream<S>(self: Arc<Self>, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| error("enrollment_rejected"))?;
        self.serve_stream_from(stream, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), permit)
            .await
    }
    async fn serve_stream_from<S>(
        self: Arc<Self>,
        stream: S,
        source: IpAddr,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.admit(source)?;
        let stream = tokio::time::timeout(
            DEADLINE,
            tokio_rustls::TlsAcceptor::from(self.tls.clone()).accept(stream),
        )
        .await??;
        // Absolute connection deadline also bounds idle/incomplete HTTP headers.
        tokio::time::timeout(
            DEADLINE,
            hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .max_buf_size(HEADER_MAX)
                .max_headers(64)
                .serve_connection(
                    TokioIo::new(stream),
                    hyper::service::service_fn(move |req| {
                        let service = self.clone();
                        async move { Ok::<_, Infallible>(service.http(req).await) }
                    }),
                ),
        )
        .await??;
        Ok(())
    }
    /// Explicit operator deployment entry point; tests use serve_stream.
    pub async fn serve(self: Arc<Self>, listen: SocketAddr) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        loop {
            let (stream, source) = listener.accept().await?;
            let service = self.clone();
            // Reserve before spawning: an accept flood cannot grow a task queue.
            let permit = match self.slots.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let _ = service.serve_stream_from(stream, source.ip(), permit).await;
            });
        }
    }
}

pub struct EnrollmentClient {
    tls: Arc<rustls::ClientConfig>,
    server_name: String,
    enrollment_pin: String,
}
impl EnrollmentClient {
    /// Only ordinary Rustls CA-chain/time/DNS validation is available here.
    pub fn new(roots: RootCertStore, server_name: String, enrollment_pin: String) -> Result<Self> {
        ServerName::try_from(server_name.clone())?;
        if !pin_valid(&enrollment_pin) {
            return Err(error("invalid_enrollment_pin"));
        }
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(tls),
            server_name,
            enrollment_pin,
        })
    }
    async fn request_stream<S, Q: Serialize, T: DeserializeOwned>(
        &self,
        stream: S,
        path: &str,
        request: &Q,
    ) -> Result<T>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !allowed_route(path) {
            return Err(error("enrollment_rejected"));
        }
        tokio::time::timeout(DEADLINE, async {
            let stream = tokio_rustls::TlsConnector::from(self.tls.clone())
                .connect(ServerName::try_from(self.server_name.clone())?, stream)
                .await?;
            let leaf = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .ok_or_else(|| error("enrollment_rejected"))?;
            if fingerprint(leaf.as_ref()) != self.enrollment_pin {
                return Err(error("enrollment_pin_mismatch"));
            }
            // Serialize and send the invitation only AFTER both CA/DNS and pin validation.
            let bytes = serde_json::to_vec(request)?;
            if bytes.len() > REQUEST_MAX {
                return Err(error("enrollment_request_bound"));
            }
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(HEADER_MAX)
                .handshake(TokioIo::new(stream))
                .await?;
            struct AbortOnDrop(tokio::task::JoinHandle<()>);
            impl Drop for AbortOnDrop {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            let _driver = AbortOnDrop(tokio::spawn(async move {
                let _ = connection.await;
            }));
            let response = sender
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("host", &self.server_name)
                        .header("content-type", "application/json")
                        .header("connection", "close")
                        .body(Full::new(Bytes::from(bytes)))?,
                )
                .await?;
            if response.status() != StatusCode::OK
                || response.headers().get_all("content-type").iter().count() != 1
                || response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    != Some("application/json")
                || response.headers().contains_key("content-encoding")
            {
                return Err(error("enrollment_rejected"));
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let data = frame?
                    .into_data()
                    .map_err(|_| error("enrollment_rejected"))?;
                if bytes.len().saturating_add(data.len()) > RESPONSE_MAX {
                    return Err(error("enrollment_response_bound"));
                }
                bytes.extend_from_slice(&data);
            }
            serde_json::from_slice(&bytes).map_err(|_| error("enrollment_rejected"))
        })
        .await?
    }
    fn check_scope(&self, scope: &InviteScope) -> Result<()> {
        scope.validate()?;
        if self.server_name != scope.enrollment_server_name
            || self.enrollment_pin != scope.enrollment_leaf_pin
        {
            return Err(error("enrollment_scope_mismatch"));
        }
        Ok(())
    }
    pub async fn enroll_stream<S>(
        &self,
        stream: S,
        request: &RedeemRequest,
        expected_scope: &InviteScope,
    ) -> Result<EnrollmentResponse>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.check_scope(expected_scope)?;
        csr_bound(&request.csr_der)?;
        let response = self.request_stream(stream, ENROLL, request).await?;
        validate_enrollment_response(
            &response,
            &request.csr_der,
            expected_scope,
            &request.request_id,
            now()?,
        )?;
        Ok(response)
    }
    pub async fn challenge_stream<S>(
        &self,
        stream: S,
        request: &RecoveryChallengeRequest,
    ) -> Result<RecoveryChallenge>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        csr_bound(&request.csr_der)?;
        let challenge: RecoveryChallenge = self.request_stream(stream, CHALLENGE, request).await?;
        let now = now()?;
        if challenge.deadline <= now
            || challenge.deadline > now + 120
            || challenge.nonce.len() > 128
            || challenge.nonce.is_empty()
        {
            return Err(error("enrollment_rejected"));
        }
        Ok(challenge)
    }
    pub async fn recover_stream<S>(
        &self,
        stream: S,
        request: &RecoveryRequest,
        expected_scope: &InviteScope,
    ) -> Result<EnrollmentResponse>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.check_scope(expected_scope)?;
        csr_bound(&request.csr_der)?;
        let response = self.request_stream(stream, RECOVER, request).await?;
        validate_enrollment_response(
            &response,
            &request.csr_der,
            expected_scope,
            &request.request_id,
            now()?,
        )?;
        Ok(response)
    }
    async fn connect(address: SocketAddr) -> Result<tokio::net::TcpStream> {
        Ok(tokio::time::timeout(DEADLINE, tokio::net::TcpStream::connect(address)).await??)
    }
    pub async fn enroll(
        &self,
        address: SocketAddr,
        request: &RedeemRequest,
        expected_scope: &InviteScope,
    ) -> Result<EnrollmentResponse> {
        self.check_scope(expected_scope)?;
        if address != expected_scope.enrollment_address {
            return Err(error("enrollment_scope_mismatch"));
        }
        self.enroll_stream(Self::connect(address).await?, request, expected_scope)
            .await
    }
    pub async fn challenge(
        &self,
        address: SocketAddr,
        request: &RecoveryChallengeRequest,
    ) -> Result<RecoveryChallenge> {
        self.challenge_stream(Self::connect(address).await?, request)
            .await
    }
    pub async fn recover(
        &self,
        address: SocketAddr,
        request: &RecoveryRequest,
        expected_scope: &InviteScope,
    ) -> Result<EnrollmentResponse> {
        self.check_scope(expected_scope)?;
        if address != expected_scope.enrollment_address {
            return Err(error("enrollment_scope_mismatch"));
        }
        self.recover_stream(Self::connect(address).await?, request, expected_scope)
            .await
    }
}

#[cfg(test)]
#[path = "enrollment_tests.rs"]
mod tests;
