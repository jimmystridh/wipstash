//! Outbound-only MCP webhook transport. DNS answers are checked on every request;
//! the checked socket address, never the hostname, is passed to TCP connect.
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{header, Request};
use hyper_util::rt::TokioIo;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{lookup_host, TcpStream},
    time::timeout,
};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};
use url::Url;

pub const MAX_BODY_BYTES: usize = 262_144;
const MAX_RESPONSE_BYTES: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackError {
    InvalidUrl,
    UnsafeAddress,
    Dns,
    Timeout,
    Connect,
    Tls,
    Protocol,
    ResponseTooLarge,
    InvalidSecret,
    Random,
    Revoked,
}
impl CallbackError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_url",
            Self::UnsafeAddress => "unsafe_address",
            Self::Dns => "dns_failed",
            Self::Timeout => "timeout",
            Self::Connect => "connect_failed",
            Self::Tls => "tls_failed",
            Self::Protocol => "protocol_error",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidSecret => "invalid_secret",
            Self::Random => "random_failed",
            Self::Revoked => "access_revoked",
        }
    }
}

// Do not derive Debug: callback paths and signing headers are private.
pub struct CallbackRequest {
    pub url: String,
    pub body: Vec<u8>,
    pub webhook_id: String,
    pub timestamp: u64,
    pub signature: String,
    pub subscription_id: String,
    /// Rechecked immediately before sending bytes after DNS/TLS, so revocation
    /// during connection establishment stops the outbound request too.
    pub authorized: Arc<dyn Fn() -> bool + Send + Sync>,
}
pub struct CallbackResponse {
    pub status: u16,
    pub body: Vec<u8>,
}
pub type CallbackFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CallbackResponse, CallbackError>> + Send + 'a>>;
pub trait CallbackTransport: Send + Sync {
    fn post(&self, request: CallbackRequest) -> CallbackFuture<'_>;
}

pub fn decode_secret(secret: &str) -> Result<Vec<u8>, CallbackError> {
    let encoded = secret
        .strip_prefix("whsec_")
        .ok_or(CallbackError::InvalidSecret)?;
    if encoded.len() > 88 {
        return Err(CallbackError::InvalidSecret);
    }
    let key = STANDARD
        .decode(encoded)
        .map_err(|_| CallbackError::InvalidSecret)?;
    if !(24..=64).contains(&key.len()) {
        return Err(CallbackError::InvalidSecret);
    }
    Ok(key)
}

/// Standard Webhooks v1: HMAC-SHA256(id + '.' + seconds + '.' + exact_body).
pub fn sign(secret: &str, id: &str, seconds: u64, body: &[u8]) -> Result<String, CallbackError> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &decode_secret(secret)?);
    let mut context = hmac::Context::with_key(&key);
    context.update(format!("{id}.{seconds}.").as_bytes());
    context.update(body);
    Ok(format!("v1,{}", STANDARD.encode(context.sign().as_ref())))
}

pub fn random_id(prefix: &str) -> Result<String, CallbackError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CallbackError::Random)?;
    let mut out = String::from(prefix);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Intentionally conservative public-network policy. No alternate ports,
/// credentials, fragments, zone IDs, mapped IPv4, or IPv6 transition ranges.
pub fn validate_callback_url(raw: &str) -> Result<Url, CallbackError> {
    if raw.len() > 2048 || raw.chars().any(char::is_control) {
        return Err(CallbackError::InvalidUrl);
    }
    let url = Url::parse(raw).map_err(|_| CallbackError::InvalidUrl)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return Err(CallbackError::InvalidUrl);
    }
    let host = url.host_str().ok_or(CallbackError::InvalidUrl)?;
    let host = host.trim_end_matches('.');
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || !host.contains('.') && !host.contains(':')
    {
        return Err(CallbackError::UnsafeAddress);
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) if !is_public_ip(IpAddr::V4(ip)) => {
            return Err(CallbackError::UnsafeAddress)
        }
        Some(url::Host::Ipv6(ip)) if !is_public_ip(IpAddr::V6(ip)) => {
            return Err(CallbackError::UnsafeAddress)
        }
        _ => {}
    }
    Ok(url)
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 0 || b == 168))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Only global unicast; conservatively exclude IETF special use,
            // documentation and 6to4 (which can encode a private IPv4 target).
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

pub fn validate_addresses(addresses: &[SocketAddr]) -> Result<(), CallbackError> {
    if addresses.is_empty() || addresses.len() > 32 {
        return Err(CallbackError::Dns);
    }
    if addresses
        .iter()
        .any(|a| !is_public_ip(a.ip()) || a.port() != 443)
    {
        return Err(CallbackError::UnsafeAddress);
    }
    Ok(())
}

pub struct HttpsCallbackTransport {
    tls: Arc<rustls::ClientConfig>,
}
impl Default for HttpsCallbackTransport {
    fn default() -> Self {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Self {
            tls: Arc::new(config),
        }
    }
}

struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl HttpsCallbackTransport {
    async fn send(&self, request: CallbackRequest) -> Result<CallbackResponse, CallbackError> {
        if request.body.len() > MAX_BODY_BYTES {
            return Err(CallbackError::Protocol);
        }
        let url = validate_callback_url(&request.url)?;
        let host = match url.host().ok_or(CallbackError::InvalidUrl)? {
            url::Host::Domain(h) => h.to_owned(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        };
        let addresses: Vec<_> = lookup_host((host.as_str(), 443))
            .await
            .map_err(|_| CallbackError::Dns)?
            .collect();
        validate_addresses(&addresses)?;
        // TcpStream receives a validated SocketAddr, so no second DNS lookup
        // occurs between validation and connect (including DNS rebinding).
        let mut connected = None;
        for address in addresses {
            if let Ok(stream) = TcpStream::connect(address).await {
                connected = Some(stream);
                break;
            }
        }
        let stream = connected.ok_or(CallbackError::Connect)?;
        if !is_public_ip(stream.peer_addr().map_err(|_| CallbackError::Connect)?.ip()) {
            return Err(CallbackError::UnsafeAddress);
        }
        let server_name = ServerName::try_from(host).map_err(|_| CallbackError::InvalidUrl)?;
        let tls = TlsConnector::from(self.tls.clone())
            .connect(server_name, stream)
            .await
            .map_err(|_| CallbackError::Tls)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| CallbackError::Protocol)?;
        let _task = ConnectionTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
        let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let message = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, authority)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONNECTION, "close")
            .header("webhook-id", request.webhook_id)
            .header("webhook-timestamp", request.timestamp.to_string())
            .header("webhook-signature", request.signature)
            .header("X-MCP-Subscription-Id", request.subscription_id)
            .body(Full::new(Bytes::from(request.body)))
            .map_err(|_| CallbackError::Protocol)?;
        if !(request.authorized)() {
            return Err(CallbackError::Revoked);
        }
        let response = sender
            .send_request(message)
            .await
            .map_err(|_| CallbackError::Protocol)?;
        let status = response.status().as_u16();
        // No redirect handling exists: 3xx is returned to the caller unchanged.
        let mut incoming = response.into_body();
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| CallbackError::Protocol)?;
            if let Ok(data) = frame.into_data() {
                if body.len().saturating_add(data.len()) > MAX_RESPONSE_BYTES {
                    return Err(CallbackError::ResponseTooLarge);
                }
                body.extend_from_slice(&data);
            }
        }
        Ok(CallbackResponse { status, body })
    }
}
impl CallbackTransport for HttpsCallbackTransport {
    fn post(&self, request: CallbackRequest) -> CallbackFuture<'_> {
        Box::pin(async move {
            timeout(REQUEST_TIMEOUT, self.send(request))
                .await
                .map_err(|_| CallbackError::Timeout)?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ssrf_and_non_https_urls() {
        for url in [
            "http://example.com/hook",
            "https://a:b@example.com/hook",
            "https://example.com/#x",
            "https://example.com:8443/",
            "https://localhost/",
            "https://localhost./",
            "https://a.local/",
            "https://127.1/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://10.1.2.3/",
            "https://169.254.169.254/",
            "https://[64:ff9b::7f00:1]/",
        ] {
            assert!(validate_callback_url(url).is_err(), "accepted {url}");
        }
        assert!(
            validate_callback_url("https://receiver.example.com/callback?token=opaque").is_ok()
        );
    }
    #[test]
    fn rejects_all_non_public_address_classes_and_mixed_dns_answers() {
        for ip in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.0.1",
            "172.31.0.1",
            "192.168.1.1",
            "192.0.0.9",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "accepted {ip}");
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
        let mixed = [
            "8.8.8.8:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        assert_eq!(
            validate_addresses(&mixed),
            Err(CallbackError::UnsafeAddress)
        );
        assert!(validate_addresses(&[]).is_err());
    }
    #[test]
    fn signing_is_exact_bytes_and_keys_have_required_strength() {
        for size in [0, 23, 65] {
            assert!(decode_secret(&format!("whsec_{}", STANDARD.encode(vec![1; size]))).is_err());
        }
        for size in [24, 32, 64] {
            assert!(decode_secret(&format!("whsec_{}", STANDARD.encode(vec![1; size]))).is_ok());
        }
        assert!(decode_secret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
        assert!(decode_secret("whsec_!!!!").is_err());
        let secret = format!("whsec_{}", STANDARD.encode([0u8; 32]));
        assert_ne!(
            sign(&secret, "evt_1", 1, b"{}").unwrap(),
            sign(&secret, "evt_1", 1, b"{ }").unwrap()
        );
        assert_ne!(
            sign(&secret, "evt_1", 1, b"{}").unwrap(),
            sign(&secret, "evt_1", 2, b"{}").unwrap()
        );
        // Golden result independently generated with Python hmac/hashlib.
        assert_eq!(
            sign(&secret, "evt_1", 1, b"{}").unwrap(),
            "v1,muCx1fPIWZVtN0cl/vho4tzy0i7qQUXwCYxUCtYIGFg="
        );
    }
}
