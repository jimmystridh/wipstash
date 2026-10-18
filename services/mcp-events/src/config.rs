//! Explicit deployment configuration. Reading a config never provisions access.
use crate::auth::{AuthConfig, RegisteredClient};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use url::Url;

pub type ConfigResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    pub client_id: String,
    /// Name of a secret environment variable, never the secret itself.
    pub client_secret_env: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Canonical HTTPS origin without a trailing slash, path, query or fragment.
    pub issuer: String,
    pub bind: SocketAddr,
    pub tls: Option<TlsFiles>,
    /// Explicit same-machine HTTPS termination. Preserve Host; overwrite
    /// X-Forwarded-Proto with exactly "https"; strip other forwarding headers.
    #[serde(default)]
    pub https_proxy: bool,
    pub github: GithubConfig,
    pub auth_database: PathBuf,
    pub event_database: PathBuf,
    pub projects: BTreeMap<String, PathBuf>,
    pub clients: Vec<RegisteredClient>,
    #[serde(default = "default_capacity")]
    pub event_capacity: usize,
    #[serde(default = "default_connections")]
    pub max_connections: usize,
}
fn default_capacity() -> usize {
    1024
}
fn default_connections() -> usize {
    128
}

impl Config {
    pub fn load(path: &Path) -> ConfigResult<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 256 * 1024 {
            return Err("configuration must be a regular file of at most 256 KiB".into());
        }
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> ConfigResult<()> {
        let issuer = Url::parse(&self.issuer)?;
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || issuer.path() != "/"
            || issuer.origin().ascii_serialization() != self.issuer
        {
            return Err("issuer must be a canonical HTTPS origin without a trailing slash".into());
        }
        match (&self.tls, self.https_proxy) {
            (Some(tls), false) => {
                if !tls.certificate.is_absolute() || !tls.private_key.is_absolute() {
                    return Err("TLS certificate and key paths must be absolute".into());
                }
            }
            (None, true) if self.bind.ip().is_loopback() => {}
            _ => {
                return Err(
                    "configure TLS or an explicit loopback-only HTTPS proxy, never both".into(),
                )
            }
        }
        if self.bind.port() == 0
            || self.max_connections == 0
            || self.max_connections > 4096
            || self.event_capacity == 0
            || self.event_capacity > 65_536
        {
            return Err("invalid listener or bounded queue configuration".into());
        }
        if self.github.client_id.is_empty()
            || self.github.client_id.len() > 256
            || !self
                .github
                .client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || !valid_env_name(&self.github.client_secret_env)
        {
            return Err(
                "configure the GitHub client ID and a secret environment variable name".into(),
            );
        }
        if !self.auth_database.is_absolute()
            || !self.event_database.is_absolute()
            || self.auth_database == self.event_database
        {
            return Err("distinct absolute database paths are required".into());
        }
        if self.projects.is_empty()
            || self.projects.len() > 128
            || self
                .projects
                .iter()
                .any(|(id, path)| !valid_project_id(id) || !path.is_absolute())
        {
            return Err(
                "configure 1 to 128 named projects with absolute state directory paths".into(),
            );
        }
        if self.clients.is_empty() || self.clients.len() > 32 {
            return Err("configure 1 to 32 explicit OAuth clients".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for client in &self.clients {
            if !ids.insert(&client.client_id)
                || client.name.is_empty()
                || client.name.len() > 128
                || client.client_id.is_empty()
                || client.client_id.len() > 2048
                || client.redirect_uris.is_empty()
                || client.redirect_uris.len() > 16
            {
                return Err("invalid or duplicate client configuration".into());
            }
            if !is_allowed_cimd_url(&client.client_id) {
                return Err("CIMD URLs must be explicit HTTPS documents on chatgpt.com".into());
            }
            for redirect in &client.redirect_uris {
                let url = Url::parse(redirect)?;
                if url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                    || redirect.len() > 2048
                {
                    return Err(
                        "redirect URIs must be exact HTTPS URLs without credentials or fragments"
                            .into(),
                    );
                }
                if url
                    .query_pairs()
                    .any(|(key, _)| matches!(key.as_ref(), "code" | "state" | "iss" | "error"))
                {
                    return Err("redirect URI cannot prepopulate OAuth response parameters".into());
                }
            }
        }
        Ok(())
    }
    pub fn resource(&self) -> String {
        format!("{}/mcp", self.issuer)
    }
    pub fn github_callback(&self) -> String {
        format!("{}/oauth/github/callback", self.issuer)
    }
    pub fn authority(&self) -> String {
        self.issuer
            .strip_prefix("https://")
            .unwrap_or("")
            .to_owned()
    }
    pub fn auth_config(&self) -> AuthConfig {
        AuthConfig {
            issuer: self.issuer.clone(),
            resource: self.resource(),
            clients: self.clients.clone(),
            // Local private DB ownership is the explicit v1 administrative boundary.
            // No guessed numeric ID or username becomes an administrator.
            administrators: Default::default(),
        }
    }
}
pub fn valid_project_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && value != "."
        && value != ".."
}
fn valid_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphabetic() || b == b'_' || (i > 0 && b.is_ascii_digit()))
}
pub fn is_allowed_cimd_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some("chatgpt.com")
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path().starts_with("/oauth/")
            && url.path().ends_with("/client.json")
            && url.as_str() == value
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        let root = std::env::temp_dir().join("wipstash-config-fixture");
        serde_json::from_value(serde_json::json!({
            "issuer":"https://wipstash.example", "bind":"127.0.0.1:8400", "https_proxy":true,
            "github":{"client_id":"example", "client_secret_env":"GITHUB_CLIENT_SECRET"},
            "auth_database":root.join("auth.sqlite"), "event_database":root.join("events.sqlite"),
            "projects":{"sample":root.join("sample")},
            "clients":[{"client_id":"https://chatgpt.com/oauth/client.json", "name":"ChatGPT",
                "redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"]}]
        }))
        .unwrap()
    }
    #[test]
    fn explicit_loopback_proxy_is_valid() {
        assert!(config().validate().is_ok());
    }
    #[test]
    fn rejects_cleartext_public_listener_and_implicit_proxy() {
        let mut c = config();
        c.bind = "0.0.0.0:8400".parse().unwrap();
        assert!(c.validate().is_err());
        c.bind = "127.0.0.1:8400".parse().unwrap();
        c.https_proxy = false;
        assert!(c.validate().is_err());
    }
    #[test]
    fn rejects_ambiguous_issuer() {
        for issuer in [
            "http://wipstash.example",
            "https://wipstash.example/",
            "https://wipstash.example/path",
            "https://user@wipstash.example",
            "https://wipstash.example?q=1",
        ] {
            let mut c = config();
            c.issuer = issuer.into();
            assert!(c.validate().is_err());
        }
    }
    #[test]
    fn cimd_is_exact_public_allowlist_only() {
        assert!(is_allowed_cimd_url("https://chatgpt.com/oauth/client.json"));
        assert!(is_allowed_cimd_url(
            "https://chatgpt.com/oauth/example/client.json"
        ));
        for value in [
            "https://127.0.0.1/oauth/client.json",
            "https://chatgpt.com.evil.test/oauth/client.json",
            "https://chatgpt.com@evil.test/oauth/client.json",
            "https://chatgpt.com/oauth/client.json?q=1",
            "http://chatgpt.com/oauth/client.json",
            "https://chatgpt.com:443/oauth/client.json",
        ] {
            assert!(!is_allowed_cimd_url(value));
        }
    }
    #[test]
    fn secrets_are_only_referenced_by_environment_name() {
        let mut c = config();
        c.github.client_secret_env = "actual-secret-with-dashes".into();
        assert!(c.validate().is_err());
    }
}
