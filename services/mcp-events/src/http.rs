//! Bounded HTTPS adapter. No route accepts engine commands or private WIP.
use crate::{
    auth::{
        AuthError, AuthStore, AuthorizationRequest, CodeExchange, ConsentChallenge,
        GithubLoginStart, GithubUserId, LoginPurpose, RefreshExchange,
    },
    config::{Config, ConfigResult, TlsFiles},
    github::Github,
    App,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming, header, service::service_fn, HeaderMap, Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    io::{BufReader, Read},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use url::Url;

pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_FORM_BYTES: usize = 16 * 1024;
const MAX_URI_BYTES: usize = 8192;
const LOGIN_COOKIE: &str = "__Host-wipstash-login";
const INVITE_COOKIE: &str = "__Host-wipstash-invite";
const SCOPE: &str = "mcp:events";
type Reply = Response<Full<Bytes>>;
struct Server {
    config: Config,
    app: Arc<App>,
    auth: Arc<AuthStore>,
    github: Github,
}

/// TLS, or explicitly configured same-machine HTTPS termination, is mandatory.
/// Forwarding headers never determine issuer or redirect URLs.
pub async fn serve(config: Config, app: Arc<App>, auth: Arc<AuthStore>) -> ConfigResult<()> {
    config.validate()?;
    let tls = config.tls.as_ref().map(load_tls).transpose()?;
    let github = Github::new(&config.github, config.github_callback())?;
    let listener = TcpListener::bind(config.bind).await?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let server = Arc::new(Server {
        config,
        app,
        auth,
        github,
    });
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { drop(socket); continue; };
                let server = server.clone(); let tls = tls.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Some(tls) = tls {
                        if let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), tls.accept(socket)).await {
                            run_connection(stream, server, peer).await;
                        }
                    } else if peer.ip().is_loopback() { run_connection(socket, server, peer).await; }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}
async fn run_connection<T>(stream: T, server: Arc<Server>, peer: SocketAddr)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let server = server.clone();
        async move { Ok::<_, Infallible>(server.handle(request, peer).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_headers(64)
        .max_buf_size(16 * 1024)
        .keep_alive(false);
    // One bounded request per connection. Parsing errors can contain secrets;
    // never log them or the full request.
    let _ = tokio::time::timeout(
        Duration::from_secs(60),
        builder.serve_connection(TokioIo::new(stream), service),
    )
    .await;
}
impl Server {
    async fn handle(&self, request: Request<Incoming>, peer: SocketAddr) -> Reply {
        if let Err(status) = validate_request(&self.config, &request, peer) {
            return error(status, "request_rejected");
        }
        let path = request.uri().path().to_owned();
        let method = request.method().clone();
        let headers = request.headers().clone();
        let query = request.uri().query().unwrap_or("").to_owned();
        let limit = if path == "/mcp" {
            MAX_REQUEST_BYTES
        } else {
            MAX_FORM_BYTES
        };
        let body = match tokio::time::timeout(
            Duration::from_secs(10),
            Limited::new(request.into_body(), limit).collect(),
        )
        .await
        {
            Ok(Ok(body)) => body.to_bytes(),
            Ok(Err(_)) => return error(StatusCode::PAYLOAD_TOO_LARGE, "request_body_rejected"),
            Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "request_timeout"),
        };
        if (method == Method::GET || method == Method::HEAD) && !body.is_empty() {
            return error(StatusCode::BAD_REQUEST, "unexpected_body");
        }
        match (method, path.as_str()) {
            (Method::GET, "/.well-known/oauth-protected-resource")
            | (Method::GET, "/.well-known/oauth-protected-resource/mcp") => json_reply(
                StatusCode::OK,
                json!({
                    "resource":self.config.resource(), "authorization_servers":[self.config.issuer],
                    "scopes_supported":["mcp:events"], "bearer_methods_supported":["header"],
                    "resource_name":"Wipstash status and events"
                }),
            ),
            (Method::GET, "/.well-known/oauth-authorization-server") => json_reply(
                StatusCode::OK,
                json!({
                    "issuer":self.config.issuer, "authorization_endpoint":format!("{}/oauth/authorize",self.config.issuer),
                    "token_endpoint":format!("{}/oauth/token",self.config.issuer),
                    "response_types_supported":["code"], "grant_types_supported":["authorization_code","refresh_token"],
                    "code_challenge_methods_supported":["S256"], "token_endpoint_auth_methods_supported":["none"],
                    "scopes_supported":["mcp:events"], "client_id_metadata_document_supported":true,
                    "authorization_response_iss_parameter_supported":true
                }),
            ),
            (Method::GET, "/healthz") => json_reply(StatusCode::OK, json!({"status":"running"})),
            (Method::GET, "/oauth/authorize") => self.authorize(&query).await,
            (Method::GET, "/oauth/github/callback") => self.github_callback(&query, &headers).await,
            (Method::POST, "/oauth/consent") => {
                if !same_origin(&headers, &self.config.issuer) {
                    return error(StatusCode::FORBIDDEN, "origin_required");
                }
                self.consent(&headers, &body)
            }
            (Method::GET, "/invite") => self.invitation_page(&query),
            (Method::POST, "/invite") => {
                if !same_origin(&headers, &self.config.issuer) {
                    return error(StatusCode::FORBIDDEN, "origin_required");
                }
                self.begin_invitation(&headers, &body)
            }
            (Method::POST, "/oauth/token") => self.token(&headers, &body),
            (Method::POST, "/mcp") => self.mcp(&headers, &body).await,
            (
                _,
                "/mcp"
                | "/oauth/token"
                | "/oauth/consent"
                | "/oauth/authorize"
                | "/oauth/github/callback",
            ) => error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
            _ => error(StatusCode::NOT_FOUND, "not_found"),
        }
    }
    async fn authorize(&self, query: &str) -> Reply {
        let params = match parameters(query.as_bytes(), 24) {
            Ok(p) => p,
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        };
        if params.get("response_type").map(String::as_str) != Some("code")
            || !valid_scope(params.get("scope"))
        {
            return error(StatusCode::BAD_REQUEST, "unsupported_authorization_request");
        }
        let required = |key| params.get(key).cloned().ok_or(());
        let request = match (
            required("client_id"),
            required("redirect_uri"),
            required("resource"),
            required("state"),
            required("code_challenge"),
            required("code_challenge_method"),
        ) {
            (
                Ok(client_id),
                Ok(redirect_uri),
                Ok(resource),
                Ok(state),
                Ok(code_challenge),
                Ok(code_challenge_method),
            ) => AuthorizationRequest {
                client_id,
                redirect_uri,
                resource,
                state,
                code_challenge,
                code_challenge_method,
                projects: self.config.projects.keys().cloned().collect(),
            },
            _ => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        };
        let Some(client) = self
            .config
            .clients
            .iter()
            .find(|c| c.client_id == request.client_id)
        else {
            return error(StatusCode::BAD_REQUEST, "invalid_client");
        };
        if self
            .github
            .verify_cimd(client, &request.redirect_uri)
            .await
            .is_err()
        {
            return error(StatusCode::BAD_REQUEST, "client_metadata_rejected");
        }
        match self.auth.begin_authorization(request, now()) {
            Ok(start) => self.login_redirect(start),
            Err(e) => auth_error(e),
        }
    }
    fn login_redirect(&self, start: GithubLoginStart) -> Reply {
        let location = self
            .github
            .authorization_url(&start.state, &start.code_challenge);
        let mut reply = redirect(&location);
        set_cookie(&mut reply, LOGIN_COOKIE, &start.browser_binding, 600);
        reply
    }
    async fn github_callback(&self, query: &str, headers: &HeaderMap) -> Reply {
        let params = match parameters(query.as_bytes(), 8) {
            Ok(p) => p,
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        };
        let (Some(state), Some(code)) = (params.get("state"), params.get("code")) else {
            return error(StatusCode::BAD_REQUEST, "github_login_not_completed");
        };
        let Some(binding) = cookie(headers, LOGIN_COOKIE) else {
            return error(StatusCode::BAD_REQUEST, "browser_binding_required");
        };
        let callback = match self.auth.take_github_callback(state, &binding, now()) {
            Ok(callback) => callback,
            Err(e) => return auth_error(e),
        };
        let identity = match self
            .github
            .authenticate(code, &callback.code_verifier)
            .await
        {
            Ok(identity) => identity,
            Err(_) => {
                return error(
                    StatusCode::BAD_GATEWAY,
                    "github_login_failed_restart_sign_in",
                )
            }
        };
        match callback.purpose {
            LoginPurpose::Authorization => {
                match self.auth.complete_github_login(callback, identity, now()) {
                    Ok(challenge) => self.browser_html(consent_page(&challenge)),
                    Err(e) => auth_error(e),
                }
            }
            LoginPurpose::Invitation => {
                match self.auth.complete_invitation(callback, identity, now()) {
                    Ok(project) => {
                        let mut reply = html(StatusCode::OK, page("Invitation accepted", &format!(
                        "<p>Access granted to project <strong>{}</strong>.</p><p>Return to ChatGPT and connect Wipstash to authorize status and events.</p>", escape(&project))));
                        set_cookie(&mut reply, LOGIN_COOKIE, "", 0);
                        reply
                    }
                    Err(e) => auth_error(e),
                }
            }
        }
    }
    fn consent(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        if !form_content_type(headers) {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "form_required");
        }
        let p = match parameters(body, 8) {
            Ok(p) => p,
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        };
        let (Some(flow), Some(csrf), Some(decision), Some(binding)) = (
            p.get("flow_id"),
            p.get("csrf"),
            p.get("decision"),
            cookie(headers, LOGIN_COOKIE),
        ) else {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        if decision == "deny" {
            if let Err(e) = self.auth.cancel_consent(flow, &binding, csrf, now()) {
                return auth_error(e);
            }
            let mut reply = html(
                StatusCode::OK,
                page(
                    "Connection cancelled",
                    "<p>No client access was granted.</p>",
                ),
            );
            set_cookie(&mut reply, LOGIN_COOKIE, "", 0);
            return reply;
        }
        if decision != "allow" {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        match self.auth.approve_consent(flow, &binding, csrf, now()) {
            Ok(result) => {
                let Ok(mut url) = Url::parse(&result.redirect_uri) else {
                    return error(StatusCode::INTERNAL_SERVER_ERROR, "authorization_failed");
                };
                url.query_pairs_mut()
                    .append_pair("code", &result.code)
                    .append_pair("state", &result.state)
                    .append_pair("iss", &self.config.issuer);
                let mut reply = redirect(url.as_str());
                set_cookie(&mut reply, LOGIN_COOKIE, "", 0);
                reply
            }
            Err(e) => auth_error(e),
        }
    }
    fn invitation_page(&self, query: &str) -> Reply {
        let p = match parameters(query.as_bytes(), 2) {
            Ok(p) => p,
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        };
        let Some(token) = p.get("token").filter(|t| valid_secret(t)) else {
            return error(StatusCode::BAD_REQUEST, "invalid_invitation");
        };
        let mut random = [0u8; 32];
        if SystemRandom::new().fill(&mut random).is_err() {
            return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
        let csrf = URL_SAFE_NO_PAD.encode(random);
        let mut reply = self.browser_html(page("Accept a Wipstash invitation", &format!(
            "<p>This invitation works only for the GitHub account selected by the sender. It expires after 24 hours and can be used once.</p><form method=\"post\" action=\"/invite\"><input type=\"hidden\" name=\"token\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\">Sign in with GitHub to accept</button></form>", escape(token), csrf)));
        set_cookie(&mut reply, INVITE_COOKIE, &csrf, 300);
        reply
    }
    fn browser_html(&self, body: String) -> Reply {
        let mut reply = html(StatusCode::OK, body);
        if let Ok(policy) = header::HeaderValue::from_str(&browser_csp(&self.config)) {
            reply
                .headers_mut()
                .insert("content-security-policy", policy);
        }
        reply
    }
    fn begin_invitation(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        if !form_content_type(headers) {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "form_required");
        }
        let p = match parameters(body, 3) {
            Ok(p) => p,
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        };
        let (Some(token), Some(csrf), Some(binding)) = (
            p.get("token"),
            p.get("csrf"),
            cookie(headers, INVITE_COOKIE),
        ) else {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        if !valid_secret(token) || !constant_eq(csrf.as_bytes(), binding.as_bytes()) {
            return error(StatusCode::FORBIDDEN, "csrf_rejected");
        }
        match self.auth.begin_invitation(token, now()) {
            Ok(start) => {
                let mut reply = self.login_redirect(start);
                set_cookie(&mut reply, INVITE_COOKIE, "", 0);
                reply
            }
            Err(e) => auth_error(e),
        }
    }
    fn token(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        if !form_content_type(headers) {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "form_required");
        }
        if headers.contains_key(header::AUTHORIZATION) {
            return error(StatusCode::BAD_REQUEST, "invalid_client");
        }
        let p = match parameters(body, 12) {
            Ok(p) => p,
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        };
        if p.contains_key("client_secret")
            || p.contains_key("client_assertion")
            || p.contains_key("client_assertion_type")
            || !valid_scope(p.get("scope"))
        {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        let required = |key| p.get(key).cloned().ok_or(());
        let result = match p.get("grant_type").map(String::as_str) {
            Some("authorization_code") => match (
                required("code"),
                required("client_id"),
                required("redirect_uri"),
                required("resource"),
                required("code_verifier"),
            ) {
                (Ok(code), Ok(client_id), Ok(redirect_uri), Ok(resource), Ok(code_verifier)) => {
                    self.auth.exchange_code(
                        CodeExchange {
                            code,
                            client_id,
                            redirect_uri,
                            resource,
                            code_verifier,
                        },
                        now(),
                    )
                }
                _ => return error(StatusCode::BAD_REQUEST, "invalid_request"),
            },
            Some("refresh_token") => match (
                required("refresh_token"),
                required("client_id"),
                required("resource"),
            ) {
                (Ok(refresh_token), Ok(client_id), Ok(resource)) => self.auth.rotate_refresh(
                    RefreshExchange {
                        refresh_token,
                        client_id,
                        resource,
                    },
                    now(),
                ),
                _ => return error(StatusCode::BAD_REQUEST, "invalid_request"),
            },
            _ => return error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        };
        match result {
            Ok(tokens) => match serde_json::to_value(tokens) {
                Ok(value) => json_reply(StatusCode::OK, value),
                Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "token_issue_failed"),
            },
            Err(e) => auth_error(e),
        }
    }
    async fn mcp(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        let Some(token) = bearer(headers) else {
            return self.unauthorized();
        };
        let principal = match self
            .auth
            .authenticate_access(&token, &self.config.resource(), now())
        {
            Ok(principal) => principal,
            Err(_) => return self.unauthorized(),
        };
        if !content_type(headers, "application/json") {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required");
        }
        if let Some(version) = headers.get("mcp-protocol-version") {
            if version != "2026-07-28" {
                return error(StatusCode::BAD_REQUEST, "unsupported_protocol_version");
            }
        }
        let request: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => {
                return json_reply(
                    StatusCode::OK,
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}),
                )
            }
        };
        let result = self.app.rpc(&principal, request, now()).await;
        if result.is_null() {
            response(StatusCode::ACCEPTED, "application/json", Bytes::new())
        } else {
            json_reply(StatusCode::OK, result)
        }
    }
    fn unauthorized(&self) -> Reply {
        let mut reply = error(StatusCode::UNAUTHORIZED, "invalid_token");
        let challenge = format!("Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"{}\"", self.config.issuer,SCOPE);
        if let Ok(value) = header::HeaderValue::from_str(&challenge) {
            reply.headers_mut().insert(header::WWW_AUTHENTICATE, value);
        }
        reply
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
fn validate_request<B>(
    config: &Config,
    request: &Request<B>,
    peer: SocketAddr,
) -> Result<(), StatusCode> {
    if request.uri().to_string().len() > MAX_URI_BYTES
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.headers().len() > 64
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let headers = request.headers();
    if single_header(headers, "host") != Some(config.authority().as_str()) {
        return Err(StatusCode::MISDIRECTED_REQUEST);
    }
    if headers.contains_key(header::ORIGIN) && !same_origin(headers, &config.issuer) {
        return Err(StatusCode::FORBIDDEN);
    }
    if headers.contains_key("forwarded") || headers.contains_key("x-forwarded-host") {
        return Err(StatusCode::BAD_REQUEST);
    }
    if config.https_proxy {
        if !peer.ip().is_loopback() || single_header(headers, "x-forwarded-proto") != Some("https")
        {
            return Err(StatusCode::FORBIDDEN);
        }
    } else if headers.contains_key("x-forwarded-proto") {
        return Err(StatusCode::BAD_REQUEST);
    }
    if headers.get_all(header::AUTHORIZATION).iter().count() > 1
        || headers.get_all(header::CONTENT_TYPE).iter().count() > 1
        || headers.get_all("mcp-protocol-version").iter().count() > 1
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if headers.contains_key(header::CONTENT_ENCODING) {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if let Some(length) = headers.get(header::CONTENT_LENGTH) {
        let length: usize = length
            .to_str()
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or(StatusCode::BAD_REQUEST)?;
        if length > MAX_REQUEST_BYTES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    Ok(())
}
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}
fn same_origin(headers: &HeaderMap, issuer: &str) -> bool {
    single_header(headers, "origin") == Some(issuer)
}
fn content_type(headers: &HeaderMap, mime: &str) -> bool {
    single_header(headers, "content-type")
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim() == mime)
}
fn form_content_type(headers: &HeaderMap) -> bool {
    content_type(headers, "application/x-www-form-urlencoded")
}
fn valid_scope(scope: Option<&String>) -> bool {
    scope.is_none_or(|value| {
        !value.is_empty() && value.split_whitespace().all(|s| s == "mcp:events")
    })
}
fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = single_header(headers, "authorization")?;
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") || !valid_secret(token) {
        return None;
    }
    Some(token.into())
}
fn valid_secret(value: &str) -> bool {
    (16..=512).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE).iter() {
        for part in value.to_str().ok()?.split(';') {
            let Some((key, value)) = part.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if found.is_some() || !valid_secret(value) {
                    return None;
                }
                found = Some(value.to_owned());
            }
        }
    }
    found
}
fn set_cookie(reply: &mut Reply, name: &str, value: &str, max_age: u32) {
    let value =
        format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if let Ok(value) = header::HeaderValue::from_str(&value) {
        reply.headers_mut().append(header::SET_COOKIE, value);
    }
}
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
fn parameters(raw: &[u8], max: usize) -> Result<BTreeMap<String, String>, &'static str> {
    if raw.len() > MAX_FORM_BYTES || std::str::from_utf8(raw).is_err() {
        return Err("invalid_request");
    }
    // Reject malformed percent escapes and lossy Unicode decoding.
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            if i + 2 >= raw.len()
                || !raw[i + 1].is_ascii_hexdigit()
                || !raw[i + 2].is_ascii_hexdigit()
            {
                return Err("invalid_request");
            }
            i += 2;
        }
        i += 1;
    }
    let mut result = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw) {
        if key.is_empty()
            || key.len() > 64
            || value.len() > 8192
            || key.contains('\u{fffd}')
            || value.contains('\u{fffd}')
            || key.chars().any(char::is_control)
            || value.chars().any(char::is_control)
            || result.len() >= max
            || result
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err("invalid_request");
        }
    }
    Ok(result)
}
fn browser_csp(config: &Config) -> String {
    // Browsers apply form-action to redirects too. Only fixed GitHub plus
    // origins of explicitly configured, exact downstream redirects are allowed.
    let mut origins = std::collections::BTreeSet::from(["https://github.com".to_owned()]);
    for client in &config.clients {
        for redirect in &client.redirect_uris {
            if let Ok(url) = Url::parse(redirect) {
                origins.insert(url.origin().ascii_serialization());
            }
        }
    }
    format!(
        "default-src 'none'; form-action 'self' {}; frame-ancestors 'none'; base-uri 'none'",
        origins.into_iter().collect::<Vec<_>>().join(" ")
    )
}
fn response(status: StatusCode, content_type: &str, body: Bytes) -> Reply {
    let mut reply = Response::new(Full::new(body));
    *reply.status_mut() = status;
    let headers = reply.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_str(content_type).expect("static content type"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    headers.insert(
        "referrer-policy",
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "x-content-type-options",
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "content-security-policy",
        header::HeaderValue::from_static(
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        "strict-transport-security",
        header::HeaderValue::from_static("max-age=31536000"),
    );
    reply
}
fn json_reply(status: StatusCode, value: Value) -> Reply {
    response(status, "application/json", Bytes::from(value.to_string()))
}
fn error(status: StatusCode, code: &str) -> Reply {
    json_reply(status, json!({"error":code}))
}
fn auth_error(value: AuthError) -> Reply {
    let (status, code) = match value {
        AuthError::AccessDenied => (StatusCode::FORBIDDEN, "access_denied"),
        AuthError::InvalidGrant | AuthError::RefreshReuse => {
            (StatusCode::BAD_REQUEST, "invalid_grant")
        }
        AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid_token"),
        AuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    };
    error(status, code)
}
fn redirect(location: &str) -> Reply {
    let mut reply = response(
        StatusCode::SEE_OTHER,
        "text/plain; charset=utf-8",
        Bytes::new(),
    );
    match header::HeaderValue::from_str(location) {
        Ok(location) => {
            reply.headers_mut().insert(header::LOCATION, location);
            reply
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "redirect_failed"),
    }
}
fn html(status: StatusCode, body: String) -> Reply {
    response(status, "text/html; charset=utf-8", Bytes::from(body))
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn page(title: &str, body: &str) -> String {
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>{}</title></head><body><main><h1>{}</h1>{body}</main></body></html>",escape(title),escape(title))
}
fn consent_page(c: &ConsentChallenge) -> String {
    let projects = c
        .projects
        .iter()
        .map(|p| format!("<li>{}</li>", escape(p)))
        .collect::<String>();
    page("Connect Wipstash",&format!("<p>Signed in as <strong>{}</strong> on GitHub.</p><p>Allow <strong>{}</strong> ({}) to read permitted status and manage event subscriptions for these projects?</p><ul>{projects}</ul><p>This connection cannot publish, integrate, adopt, or change workspaces.</p><form method=\"post\" action=\"/oauth/consent\"><input type=\"hidden\" name=\"flow_id\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button name=\"decision\" value=\"allow\">Allow status and events</button><button name=\"decision\" value=\"deny\">Cancel</button></form>",escape(&c.github_login),escape(&c.client_name),escape(&c.client_id),escape(&c.flow_id),escape(&c.csrf_token)))
}
fn load_tls(files: &TlsFiles) -> ConfigResult<TlsAcceptor> {
    let certificate = read_tls_file(&files.certificate, false)?;
    let private_key = zeroize::Zeroizing::new(read_tls_file(&files.private_key, true)?);
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(private_key.as_slice()))?
        .ok_or("TLS private key missing")?;
    if certificates.is_empty() {
        return Err("TLS certificate chain missing".into());
    }
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}
fn read_tls_file(path: &std::path::Path, private: bool) -> ConfigResult<Vec<u8>> {
    if private {
        return Ok(wipstash_transport::pairing_files::read_private_file(
            path,
            1024 * 1024,
        )?);
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err("TLS files must be bounded regular files".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("TLS file exceeds limit".into());
    }
    Ok(bytes)
}

/// Only local private-DB ownership authorizes these operations. No HTTP route.
pub fn administer(config: &Config, args: &[String]) -> ConfigResult<()> {
    let auth = AuthStore::open(&config.auth_database, config.auth_config())?;
    let command = args
        .first()
        .map(String::as_str)
        .ok_or("admin command required")?;
    if command == "revoke-invite" && args.len() == 1 {
        let mut token = String::new();
        std::io::stdin().take(1025).read_to_string(&mut token)?;
        let token = token.trim();
        if !valid_secret(token) {
            return Err("supply the invitation token on standard input".into());
        }
        auth.revoke_invitation_local(token, now())?;
        println!("Invitation revoked.");
        return Ok(());
    }
    let id = args
        .get(1)
        .ok_or("numeric GitHub user ID required")?
        .parse::<u64>()?;
    let id = GithubUserId::new(id)?;
    if command == "revoke-user" && args.len() == 2 {
        auth.revoke_principal_local(id, now())?;
        println!("User access revoked.");
        return Ok(());
    }
    if args.len() != 3 {
        return Err("expected command, numeric GitHub user ID, and configured project ID".into());
    }
    let project = &args[2];
    if !config.projects.contains_key(project) {
        return Err("project is not configured".into());
    }
    match command {
        "grant" => {
            auth.grant_project_local(id, project, now())?;
            println!("Project access granted.");
        }
        "revoke" => {
            auth.revoke_project_local(id, project, now())?;
            println!("Project access revoked.");
        }
        "invite" => {
            let invitation = auth.issue_invitation_local(id, project, now())?;
            // Intentional one-time operator output, never an access log.
            let mut link = Url::parse(&format!("{}/invite", config.issuer))?;
            link.query_pairs_mut()
                .append_pair("token", &invitation.token);
            println!("{}", link);
            println!(
                "Expires at Unix time {}. Single use; bound to GitHub ID {} and project {}.",
                invitation.expires_at,
                id.get(),
                project
            );
        }
        _ => return Err("unknown admin command".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        serde_json::from_value(json!({
        "issuer":"https://wipstash.example","bind":"127.0.0.1:8400","https_proxy":true,
        "github":{"client_id":"example","client_secret_env":"GITHUB_CLIENT_SECRET"},
        "auth_database":"/data/auth.sqlite","event_database":"/data/events.sqlite","projects":{"p":"/data/p"},
        "clients":[{"client_id":"https://chatgpt.com/oauth/client.json","name":"ChatGPT","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"]}]
    })).unwrap()
    }
    fn request() -> Request<()> {
        Request::builder()
            .uri("/mcp")
            .header("host", "wipstash.example")
            .header("x-forwarded-proto", "https")
            .body(())
            .unwrap()
    }
    #[test]
    fn strict_host_origin_and_proxy_boundary() {
        let c = config();
        let peer = "127.0.0.1:1234".parse().unwrap();
        assert!(validate_request(&c, &request(), peer).is_ok());
        let mut r = request();
        r.headers_mut()
            .insert("host", header::HeaderValue::from_static("attacker.example"));
        assert!(validate_request(&c, &r, peer).is_err());
        let mut r = request();
        r.headers_mut().insert(
            "origin",
            header::HeaderValue::from_static("https://attacker.example"),
        );
        assert!(validate_request(&c, &r, peer).is_err());
        let mut r = request();
        r.headers_mut().insert(
            "x-forwarded-proto",
            header::HeaderValue::from_static("http"),
        );
        assert!(validate_request(&c, &r, peer).is_err());
        assert!(validate_request(&c, &request(), "198.51.100.3:1234".parse().unwrap()).is_err());
    }
    #[test]
    fn rejects_duplicate_parameters_and_lossy_encoding() {
        for query in [
            "state=one&state=two",
            "state=%zz",
            "state=%FF",
            "state=foo%00bar",
            "state=a&%73tate=b",
        ] {
            assert!(parameters(query.as_bytes(), 8).is_err());
        }
        assert_eq!(
            parameters(b"state=a%2Bb", 8).unwrap().get("state").unwrap(),
            "a+b"
        );
    }
    #[test]
    fn rejects_duplicate_browser_cookie_and_authorization_header() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            header::HeaderValue::from_static(
                "__Host-wipstash-login=abcdefghijklmnop; __Host-wipstash-login=qrstuvwxyzabcdef",
            ),
        );
        assert!(cookie(&h, LOGIN_COOKIE).is_none());
        h.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer abcdefghijklmnop"),
        );
        assert!(bearer(&h).is_some());
        h.append(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer qrstuvwxyzabcdef"),
        );
        assert!(bearer(&h).is_none());
    }
    #[test]
    fn secure_cookie_and_page_do_not_enable_script_or_referrers() {
        let mut r = html(StatusCode::OK, page("test", "safe"));
        set_cookie(&mut r, LOGIN_COOKIE, "abcdefghijklmnop", 600);
        let value = r.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(value.contains("Secure; HttpOnly; SameSite=Lax"));
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        assert_eq!(escape("\"<script>&'"), "&quot;&lt;script&gt;&amp;&#39;");
    }
    #[test]
    fn browser_csp_allows_oauth_form_redirects_only_to_configured_origins() {
        let policy = browser_csp(&config());
        assert!(policy.contains("form-action 'self' https://chatgpt.com https://github.com;"));
        assert!(!policy.contains('*'));
        assert!(!policy.contains("unsafe-inline"));
    }
    #[test]
    fn rejects_oversized_and_compressed_requests() {
        let c = config();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let mut r = request();
        r.headers_mut().insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("262145"),
        );
        assert_eq!(
            validate_request(&c, &r, peer),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
        let mut r = request();
        r.headers_mut().insert(
            header::CONTENT_ENCODING,
            header::HeaderValue::from_static("gzip"),
        );
        assert_eq!(
            validate_request(&c, &r, peer),
            Err(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        );
    }
}
