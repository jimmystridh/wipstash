//! Upstream identity leg. GitHub tokens never become Wipstash MCP tokens.
//! Fixed origins, certificate verification, no redirects and bounded network I/O.
use crate::{
    auth::{RegisteredClient, VerifiedGithubIdentity},
    config::{is_allowed_cimd_url, GithubConfig},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
    Method, Request,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;
use url::{form_urlencoded, Url};
use zeroize::Zeroizing;

type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
pub type GithubResult<T> = Result<T, &'static str>;
pub struct Github {
    client: HttpsClient,
    client_id: String,
    client_secret: Zeroizing<String>,
    redirect_uri: String,
}
impl Github {
    pub fn new(config: &GithubConfig, redirect_uri: String) -> GithubResult<Self> {
        let secret = std::env::var(&config.client_secret_env)
            .map_err(|_| "GitHub client secret environment variable is unavailable")?;
        if secret.is_empty() || secret.len() > 4096 {
            return Err("GitHub client secret is empty or too long");
        }
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(Duration::from_secs(10)));
        let https = HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .map_err(|_| "HTTPS client initialization failed")?
            .https_only()
            .enable_http1()
            .wrap_connector(http);
        Ok(Self {
            client: Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(2)
                .build(https),
            client_id: config.client_id.clone(),
            client_secret: Zeroizing::new(secret),
            redirect_uri,
        })
    }
    pub fn authorization_url(&self, state: &str, challenge: &str) -> String {
        let mut url = Url::parse("https://github.com/login/oauth/authorize").expect("constant URL");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            // Basic public identity only, never repo/email/write scopes.
            .append_pair("scope", "")
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("allow_signup", "false")
            .append_pair("prompt", "select_account");
        url.into()
    }
    pub async fn authenticate(
        &self,
        code: &str,
        verifier: &str,
    ) -> GithubResult<VerifiedGithubIdentity> {
        if code.is_empty() || code.len() > 1024 || verifier.len() < 43 || verifier.len() > 128 {
            return Err("invalid GitHub callback");
        }
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret)
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("code_verifier", verifier)
            .finish();
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://github.com/login/oauth/access_token")
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(USER_AGENT, "wipstash-mcp-events/0.1")
            .body(Full::new(Bytes::from(form)))
            .map_err(|_| "GitHub token request could not be built")?;
        let bytes = self.request(request).await?;
        let token: TokenResponse =
            serde_json::from_slice(&bytes).map_err(|_| "GitHub token exchange failed")?;
        if !token.token_type.eq_ignore_ascii_case("bearer")
            || token.access_token.is_empty()
            || token.access_token.len() > 8192
        {
            return Err("GitHub token exchange failed");
        }
        let access_token = Zeroizing::new(token.access_token);
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://api.github.com/user")
            .header(ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(USER_AGENT, "wipstash-mcp-events/0.1")
            .header(AUTHORIZATION, format!("Bearer {}", access_token.as_str()))
            .body(Full::new(Bytes::new()))
            .map_err(|_| "GitHub identity request could not be built")?;
        // Every sign-in revalidates /user. Browser-supplied account IDs are never accepted.
        let bytes = self.request(request).await?;
        let user: UserResponse =
            serde_json::from_slice(&bytes).map_err(|_| "GitHub identity response was invalid")?;
        VerifiedGithubIdentity::from_github_user(user.id, user.login)
            .map_err(|_| "GitHub identity response was invalid")
    }
    /// The client must already be in the configured allowlist. No redirects.
    pub async fn verify_cimd(
        &self,
        client: &RegisteredClient,
        redirect_uri: &str,
    ) -> GithubResult<()> {
        if !is_allowed_cimd_url(&client.client_id)
            || !client.redirect_uris.iter().any(|r| r == redirect_uri)
        {
            return Err("unapproved OAuth client metadata");
        }
        let request = Request::builder()
            .method(Method::GET)
            .uri(&client.client_id)
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, "wipstash-mcp-events/0.1")
            .body(Full::new(Bytes::new()))
            .map_err(|_| "OAuth client metadata request could not be built")?;
        let bytes = self.request(request).await?;
        let document: Value =
            serde_json::from_slice(&bytes).map_err(|_| "OAuth client metadata was invalid")?;
        validate_cimd(client, redirect_uri, &document)
    }
    async fn request(&self, request: Request<Full<Bytes>>) -> GithubResult<Bytes> {
        tokio::time::timeout(Duration::from_secs(15), async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|_| "upstream HTTPS request failed")?;
            if !response.status().is_success() {
                return Err("upstream HTTPS request rejected");
            }
            if !response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';').next().is_some_and(|mime| {
                        let mime = mime.trim();
                        mime == "application/json" || mime.ends_with("+json")
                    })
                })
            {
                return Err("upstream response was not JSON");
            }
            Limited::new(response.into_body(), 64 * 1024)
                .collect()
                .await
                .map(|collected| collected.to_bytes())
                .map_err(|_| "upstream response exceeded limit")
        })
        .await
        .map_err(|_| "upstream HTTPS request timed out")?
    }
}
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
}
#[derive(Deserialize)]
struct UserResponse {
    id: u64,
    login: String,
}
fn validate_cimd(
    client: &RegisteredClient,
    redirect_uri: &str,
    document: &Value,
) -> GithubResult<()> {
    if document["client_id"].as_str() != Some(client.client_id.as_str())
        || !document["redirect_uris"].as_array().is_some_and(|uris| {
            uris.len() <= 64 && uris.iter().any(|uri| uri.as_str() == Some(redirect_uri))
        })
    {
        return Err("OAuth client metadata identity or redirect mismatch");
    }
    // SEP-3149 plural methods are authoritative; legacy singular is a preference.
    let none_supported =
        if let Some(methods) = document.get("token_endpoint_auth_methods_supported") {
            methods
                .as_array()
                .is_some_and(|methods| methods.iter().any(|m| m.as_str() == Some("none")))
        } else {
            document["token_endpoint_auth_method"].as_str() == Some("none")
        };
    if !none_supported {
        return Err("OAuth client does not support public-client S256 exchange");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn client() -> RegisteredClient {
        RegisteredClient {
            client_id: "https://chatgpt.com/oauth/client.json".into(),
            name: "ChatGPT".into(),
            redirect_uris: vec!["https://chatgpt.com/connector_platform_oauth_redirect".into()],
        }
    }
    #[test]
    fn plural_cimd_auth_methods_override_legacy_preference() {
        let c = client();
        let doc = serde_json::json!({"client_id":c.client_id,
            "redirect_uris":c.redirect_uris,"token_endpoint_auth_methods_supported":["none","private_key_jwt"],
            "token_endpoint_auth_method":"private_key_jwt"});
        assert!(validate_cimd(&c, &c.redirect_uris[0], &doc).is_ok());
    }
    #[test]
    fn cimd_identity_redirect_and_method_must_match() {
        let c = client();
        let base = serde_json::json!({"client_id":c.client_id,
            "redirect_uris":c.redirect_uris,"token_endpoint_auth_method":"none"});
        assert!(validate_cimd(&c, &c.redirect_uris[0], &base).is_ok());
        for (field, bad) in [
            (
                "client_id",
                serde_json::json!("https://evil.test/client.json"),
            ),
            (
                "redirect_uris",
                serde_json::json!(["https://evil.test/callback"]),
            ),
            (
                "token_endpoint_auth_method",
                serde_json::json!("private_key_jwt"),
            ),
        ] {
            let mut doc = base.clone();
            doc[field] = bad;
            assert!(validate_cimd(&c, &c.redirect_uris[0], &doc).is_err());
        }
    }
}
