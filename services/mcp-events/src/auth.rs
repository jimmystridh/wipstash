//! Wipstash's MCP authorization boundary. GitHub authenticates a human; its
//! bearer token is never accepted as an MCP token or persisted here.
//!
//! All `now` arguments are trusted server UTC Unix seconds, never client input.
//! Browser adapters must use a Secure, HttpOnly, SameSite=Lax, __Host- cookie for
//! `browser_binding`, POST-only consent, same-origin/CSRF checks, no-store
//! responses, and a no-referrer policy. Only the trusted GitHub HTTPS `/user`
//! adapter may construct a `VerifiedGithubIdentity`. Local-operator methods
//! require the OS-protected database and must never be exposed as HTTP routes.
//! Revoking any project conservatively revokes all token families for that user.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::Duration,
};
use subtle::ConstantTimeEq;
use url::Url;

pub const INVITATION_LIFETIME: i64 = 24 * 60 * 60;
pub const ACCESS_LIFETIME: i64 = 10 * 60;
pub const REFRESH_FAMILY_LIFETIME: i64 = 30 * 24 * 60 * 60;
pub const LOGIN_LIFETIME: i64 = 10 * 60;
pub const CODE_LIFETIME: i64 = 60;
const APPLICATION_ID: i64 = 1464689970;
const MAX_PENDING_LOGINS: i64 = 10_000;

type GrantSnapshot = BTreeMap<String, i64>;
// Ordered SQLite projections, named separately from their optional lookup result.
type GithubCallbackRow = (String, Vec<u8>, String, Option<Vec<u8>>, String, i64);
type ConsentRow = (
    String,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<String>,
    Option<String>,
);
type AuthorizationCodeRow = (
    i64,
    String,
    String,
    String,
    String,
    String,
    i64,
    bool,
    Option<String>,
);
type RefreshTokenRow = (String, bool, i64, String, String, String, i64, bool);
pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug)]
pub enum AuthError {
    InvalidRequest(&'static str),
    InvalidGrant,
    InvalidToken,
    AccessDenied,
    RefreshReuse,
    Capacity,
    Entropy,
    Storage(rusqlite::Error),
    Io(std::io::Error),
    CorruptState,
    LockPoisoned,
}
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest(reason) => reason,
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidToken => "invalid_token",
            Self::AccessDenied => "access_denied",
            Self::RefreshReuse => "invalid_grant",
            Self::Capacity => "temporarily_unavailable",
            Self::Entropy => "secure_random_unavailable",
            Self::Storage(_) | Self::Io(_) | Self::CorruptState | Self::LockPoisoned => {
                "authorization_storage_unavailable"
            }
        })
    }
}
impl std::error::Error for AuthError {}
impl From<rusqlite::Error> for AuthError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<std::io::Error> for AuthError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Stable numeric identity. Login names are display text, never authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GithubUserId(i64);
impl GithubUserId {
    pub fn new(id: u64) -> AuthResult<Self> {
        if id == 0 || id > i64::MAX as u64 {
            return Err(AuthError::InvalidRequest("invalid_github_id"));
        }
        Ok(Self(id as i64))
    }
    pub fn get(self) -> u64 {
        self.0 as u64
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedGithubIdentity {
    user_id: GithubUserId,
    login: String,
}
impl VerifiedGithubIdentity {
    /// Trust boundary: call only after exchanging the bound GitHub code and
    /// fetching `/user` over authenticated GitHub HTTPS. Never use browser IDs.
    pub(crate) fn from_github_user(id: u64, login: String) -> AuthResult<Self> {
        if login.is_empty()
            || login.len() > 100
            || !login
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(AuthError::InvalidRequest("invalid_github_login"));
        }
        Ok(Self {
            user_id: GithubUserId::new(id)?,
            login,
        })
    }
    pub fn user_id(&self) -> GithubUserId {
        self.user_id
    }
    pub fn login(&self) -> &str {
        &self.login
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredClient {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub issuer: String,
    pub resource: String,
    pub clients: Vec<RegisteredClient>,
    #[serde(default)]
    pub administrators: BTreeSet<GithubUserId>,
}
impl AuthConfig {
    pub fn validate(&self) -> AuthResult<()> {
        validate_https(&self.issuer, false)?;
        validate_https(&self.resource, false)?;
        if self.clients.is_empty() || self.clients.len() > 100 {
            return Err(AuthError::InvalidRequest("invalid_clients"));
        }
        let mut ids = BTreeSet::new();
        for client in &self.clients {
            validate_https(&client.client_id, false)?;
            if !ids.insert(&client.client_id)
                || client.name.is_empty()
                || client.name.len() > 200
                || client.redirect_uris.is_empty()
                || client.redirect_uris.len() > 20
            {
                return Err(AuthError::InvalidRequest("invalid_clients"));
            }
            let mut redirects = BTreeSet::new();
            for redirect in &client.redirect_uris {
                validate_https(redirect, true)?;
                if !redirects.insert(redirect) {
                    return Err(AuthError::InvalidRequest("duplicate_redirect"));
                }
            }
        }
        if self.administrators.iter().any(|id| id.0 <= 0) {
            return Err(AuthError::InvalidRequest("invalid_github_id"));
        }
        Ok(())
    }
    fn client(&self, id: &str) -> AuthResult<&RegisteredClient> {
        self.clients
            .iter()
            .find(|c| c.client_id == id)
            .ok_or(AuthError::InvalidRequest("unregistered_client"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub resource: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub projects: Vec<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginPurpose {
    Authorization,
    Invitation,
}
/// Contains secrets; intentionally not Debug or Serialize.
pub struct GithubLoginStart {
    pub flow_id: String,
    pub state: String,
    pub code_challenge: String,
    pub browser_binding: String,
    pub expires_at: i64,
}
/// One-use callback proof; neither constructible nor cloneable by callers.
pub struct GithubCallback {
    pub code_verifier: String,
    pub purpose: LoginPurpose,
    flow_id: String,
    browser_hash: Vec<u8>,
}
pub struct ConsentChallenge {
    pub flow_id: String,
    pub csrf_token: String,
    pub client_id: String,
    pub client_name: String,
    pub projects: Vec<String>,
    pub github_login: String,
}
pub struct AuthorizationRedirect {
    pub redirect_uri: String,
    pub code: String,
    pub state: String,
}
pub struct CodeExchange {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub resource: String,
    pub code_verifier: String,
}
pub struct RefreshExchange {
    pub refresh_token: String,
    pub client_id: String,
    pub resource: String,
}
#[derive(Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub github_user_id: GithubUserId,
    pub client_id: String,
    pub resource: String,
    pub projects: Vec<String>,
}
pub struct IssuedInvitation {
    pub token: String,
    pub expires_at: i64,
}

pub struct AuthStore {
    connection: Mutex<Connection>,
    config: AuthConfig,
}
impl AuthStore {
    /// The existing parent directory and database must be private to the OS
    /// account. Uses Wipstash's audited cross-platform private-file helpers.
    pub fn open(path: impl AsRef<Path>, config: AuthConfig) -> AuthResult<Self> {
        config.validate()?;
        let path = path.as_ref();
        check_private_path(path, false)?;
        if !path.exists() {
            wipstash_transport::pairing_files::create_private_file(path, &[])?;
        }
        check_private_path(path, true)?;
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        Self::initialize(conn, config)
    }
    pub fn in_memory(config: AuthConfig) -> AuthResult<Self> {
        Self::initialize(Connection::open_in_memory()?, config)
    }
    fn initialize(conn: Connection, config: AuthConfig) -> AuthResult<Self> {
        config.validate()?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")?;
        let application: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if application == 0 && version == 0 {
            let tables: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )?;
            if tables != 0 {
                return Err(AuthError::CorruptState);
            }
            conn.execute_batch(SCHEMA)?;
        } else if application != APPLICATION_ID || version != 1 {
            return Err(AuthError::CorruptState);
        }
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
        )?;
        // Refuse accidental reuse of a token database under a different issuer.
        let binding = serde_json::to_string(&(&config.issuer, &config.resource))
            .map_err(|_| AuthError::CorruptState)?;
        conn.execute(
            "INSERT OR IGNORE INTO auth_settings(singleton,binding) VALUES(1,?1)",
            [&binding],
        )?;
        let existing: String = conn.query_row(
            "SELECT binding FROM auth_settings WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if existing != binding {
            return Err(AuthError::InvalidRequest(
                "issuer_resource_database_mismatch",
            ));
        }
        Ok(Self {
            connection: Mutex::new(conn),
            config,
        })
    }
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }
    fn lock(&self) -> AuthResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| AuthError::LockPoisoned)
    }
    fn require_admin(&self, actor: &VerifiedGithubIdentity) -> AuthResult<()> {
        if !self.config.administrators.contains(&actor.user_id) {
            return Err(AuthError::AccessDenied);
        }
        Ok(())
    }
    pub fn grant_project(
        &self,
        admin: &VerifiedGithubIdentity,
        user: GithubUserId,
        project: &str,
        now: i64,
    ) -> AuthResult<()> {
        self.require_admin(admin)?;
        self.grant_project_local(user, project, now)
    }
    pub(crate) fn grant_project_local(
        &self,
        user: GithubUserId,
        project: &str,
        now: i64,
    ) -> AuthResult<()> {
        validate_user_project(user, project)?;
        validate_now(now)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        grant_tx(&tx, user, project, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn revoke_project(
        &self,
        admin: &VerifiedGithubIdentity,
        user: GithubUserId,
        project: &str,
        now: i64,
    ) -> AuthResult<()> {
        self.require_admin(admin)?;
        self.revoke_project_local(user, project, now)
    }
    pub(crate) fn revoke_project_local(
        &self,
        user: GithubUserId,
        project: &str,
        now: i64,
    ) -> AuthResult<()> {
        validate_user_project(user, project)?;
        validate_now(now)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE auth_grants SET active=0,version=version+1,updated_at=?3 WHERE github_user_id=?1 AND project=?2", params![user.0, project, now])?;
        tx.execute(
            "UPDATE auth_token_families SET revoked=1 WHERE github_user_id=?1",
            [user.0],
        )?;
        // Revocation must invalidate unredeemed invitations too.
        tx.execute(
            "UPDATE auth_invitations SET used=1 WHERE github_user_id=?1 AND project=?2",
            params![user.0, project],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn revoke_principal_local(&self, user: GithubUserId, now: i64) -> AuthResult<()> {
        validate_now(now)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE auth_grants SET active=0,version=version+1,updated_at=?2 WHERE github_user_id=?1", params![user.0, now])?;
        tx.execute(
            "UPDATE auth_token_families SET revoked=1 WHERE github_user_id=?1",
            [user.0],
        )?;
        tx.execute(
            "UPDATE auth_invitations SET used=1 WHERE github_user_id=?1",
            [user.0],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn has_project_access(&self, user: GithubUserId, project: &str) -> AuthResult<bool> {
        validate_user_project(user, project)?;
        let conn = self.lock()?;
        Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM auth_grants WHERE github_user_id=?1 AND project=?2 AND active=1)", params![user.0, project], |r| r.get(0))?)
    }
    pub fn issue_invitation(
        &self,
        admin: &VerifiedGithubIdentity,
        user: GithubUserId,
        project: &str,
        now: i64,
    ) -> AuthResult<IssuedInvitation> {
        self.require_admin(admin)?;
        self.issue_invitation_local(user, project, now)
    }
    pub(crate) fn issue_invitation_local(
        &self,
        user: GithubUserId,
        project: &str,
        now: i64,
    ) -> AuthResult<IssuedInvitation> {
        validate_user_project(user, project)?;
        validate_now(now)?;
        let token = random_secret()?;
        let expires_at = deadline(now, INVITATION_LIFETIME)?;
        self.lock()?.execute("INSERT INTO auth_invitations(token_hash,github_user_id,project,expires_at,used) VALUES(?1,?2,?3,?4,0)", params![hash(&token), user.0, project, expires_at])?;
        Ok(IssuedInvitation { token, expires_at })
    }
    pub(crate) fn revoke_invitation_local(&self, token: &str, now: i64) -> AuthResult<()> {
        validate_now(now)?;
        self.lock()?.execute(
            "UPDATE auth_invitations SET used=1 WHERE token_hash=?1",
            [hash(token)],
        )?;
        Ok(())
    }
    pub fn redeem_invitation(
        &self,
        identity: &VerifiedGithubIdentity,
        token: &str,
        now: i64,
    ) -> AuthResult<String> {
        validate_now(now)?;
        validate_secret(token)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let project = redeem_invite_tx(&tx, identity.user_id, &hash(token), now)?;
        tx.commit()?;
        Ok(project)
    }

    pub fn begin_authorization(
        &self,
        mut request: AuthorizationRequest,
        now: i64,
    ) -> AuthResult<GithubLoginStart> {
        self.validate_authorization(&request)?;
        request.projects.sort();
        request.projects.dedup();
        let json = serde_json::to_string(&request).map_err(|_| AuthError::CorruptState)?;
        self.begin_login(Some(json), None, now)
    }
    pub fn begin_invitation(&self, token: &str, now: i64) -> AuthResult<GithubLoginStart> {
        validate_secret(token)?;
        validate_now(now)?;
        let token_hash = hash(token);
        let valid: bool = self.lock()?.query_row("SELECT EXISTS(SELECT 1 FROM auth_invitations WHERE token_hash=?1 AND used=0 AND expires_at>?2)", params![token_hash, now], |r| r.get(0))?;
        if !valid {
            return Err(AuthError::InvalidGrant);
        }
        self.begin_login(None, Some(token_hash), now)
    }
    fn begin_login(
        &self,
        request: Option<String>,
        invitation_hash: Option<Vec<u8>>,
        now: i64,
    ) -> AuthResult<GithubLoginStart> {
        validate_now(now)?;
        let state = random_secret()?;
        let browser_binding = random_secret()?;
        let verifier = random_secret()?;
        let flow_id = random_secret()?;
        let expires_at = deadline(now, LOGIN_LIFETIME)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM auth_logins WHERE expires_at<=?1", [now])?;
        let count: i64 = tx.query_row("SELECT count(*) FROM auth_logins", [], |r| r.get(0))?;
        if count >= MAX_PENDING_LOGINS {
            return Err(AuthError::Capacity);
        }
        tx.execute("INSERT INTO auth_logins(flow_id,state_hash,browser_hash,upstream_verifier,request_json,invitation_hash,stage,expires_at) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7)", params![flow_id, hash(&state), hash(&browser_binding), verifier, request, invitation_hash, expires_at])?;
        tx.commit()?;
        Ok(GithubLoginStart {
            flow_id,
            state,
            code_challenge: pkce_challenge(&verifier),
            browser_binding,
            expires_at,
        })
    }
    pub fn take_github_callback(
        &self,
        state: &str,
        browser_binding: &str,
        now: i64,
    ) -> AuthResult<GithubCallback> {
        validate_now(now)?;
        validate_secret(state)?;
        validate_secret(browser_binding)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<GithubCallbackRow> = tx.query_row("SELECT flow_id,browser_hash,upstream_verifier,invitation_hash,stage,expires_at FROM auth_logins WHERE state_hash=?1", [hash(state)], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
        let (flow_id, browser_hash, verifier, invitation, stage, expires) =
            row.ok_or(AuthError::InvalidGrant)?;
        if stage != "pending" || expires <= now || !same(&browser_hash, &hash(browser_binding)) {
            return Err(AuthError::InvalidGrant);
        }
        tx.execute(
            "UPDATE auth_logins SET stage='exchanging',upstream_verifier='' WHERE flow_id=?1",
            [&flow_id],
        )?;
        tx.commit()?;
        Ok(GithubCallback {
            code_verifier: verifier,
            purpose: if invitation.is_some() {
                LoginPurpose::Invitation
            } else {
                LoginPurpose::Authorization
            },
            flow_id,
            browser_hash,
        })
    }
    pub fn complete_invitation(
        &self,
        callback: GithubCallback,
        identity: VerifiedGithubIdentity,
        now: i64,
    ) -> AuthResult<String> {
        if callback.purpose != LoginPurpose::Invitation {
            return Err(AuthError::InvalidGrant);
        }
        validate_now(now)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (stage, expires, browser, _, invitation) = load_login(&tx, &callback.flow_id)?;
        if stage != "exchanging" || expires <= now || !same(&browser, &callback.browser_hash) {
            return Err(AuthError::InvalidGrant);
        }
        let project = redeem_invite_tx(
            &tx,
            identity.user_id,
            &invitation.ok_or(AuthError::InvalidGrant)?,
            now,
        )?;
        tx.execute(
            "DELETE FROM auth_logins WHERE flow_id=?1",
            [&callback.flow_id],
        )?;
        tx.commit()?;
        Ok(project)
    }
    pub fn complete_github_login(
        &self,
        callback: GithubCallback,
        identity: VerifiedGithubIdentity,
        now: i64,
    ) -> AuthResult<ConsentChallenge> {
        if callback.purpose != LoginPurpose::Authorization {
            return Err(AuthError::InvalidGrant);
        }
        validate_now(now)?;
        let csrf_token = random_secret()?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (stage, expires, browser, request_json, _) = load_login(&tx, &callback.flow_id)?;
        if stage != "exchanging" || expires <= now || !same(&browser, &callback.browser_hash) {
            return Err(AuthError::InvalidGrant);
        }
        let mut request: AuthorizationRequest =
            serde_json::from_str(&request_json.ok_or(AuthError::CorruptState)?)
                .map_err(|_| AuthError::CorruptState)?;
        self.validate_authorization(&request)?;
        let grants = current_grants(&tx, identity.user_id, &request.projects)?;
        if grants.is_empty() {
            return Err(AuthError::AccessDenied);
        }
        request.projects = grants.keys().cloned().collect();
        let json = serde_json::to_string(&request).map_err(|_| AuthError::CorruptState)?;
        tx.execute("UPDATE auth_logins SET stage='consent',github_user_id=?2,csrf_hash=?3,request_json=?4,grants_json=?5 WHERE flow_id=?1", params![callback.flow_id, identity.user_id.0, hash(&csrf_token), json, encode_grants(&grants)?])?;
        tx.commit()?;
        Ok(ConsentChallenge {
            flow_id: callback.flow_id,
            csrf_token,
            client_name: self.config.client(&request.client_id)?.name.clone(),
            client_id: request.client_id,
            projects: request.projects,
            github_login: identity.login,
        })
    }
    pub fn approve_consent(
        &self,
        flow_id: &str,
        browser_binding: &str,
        csrf: &str,
        now: i64,
    ) -> AuthResult<AuthorizationRedirect> {
        validate_now(now)?;
        validate_secret(flow_id)?;
        validate_secret(browser_binding)?;
        validate_secret(csrf)?;
        let code = random_secret()?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<ConsentRow> = tx.query_row("SELECT stage,expires_at,browser_hash,csrf_hash,github_user_id,request_json,grants_json FROM auth_logins WHERE flow_id=?1", [flow_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
        let (stage, expires, browser, csrf_hash, user_id, request_json, grants_json) =
            row.ok_or(AuthError::InvalidGrant)?;
        if stage != "consent"
            || expires <= now
            || !same(&browser, &hash(browser_binding))
            || !same(&csrf_hash.ok_or(AuthError::InvalidGrant)?, &hash(csrf))
        {
            return Err(AuthError::InvalidGrant);
        }
        let user_id = GithubUserId(user_id.ok_or(AuthError::CorruptState)?);
        let request: AuthorizationRequest =
            serde_json::from_str(&request_json.ok_or(AuthError::CorruptState)?)
                .map_err(|_| AuthError::CorruptState)?;
        self.validate_authorization(&request)?;
        let grants = decode_grants(&grants_json.ok_or(AuthError::CorruptState)?)?;
        require_current_grants(&tx, user_id, &grants)?;
        tx.execute("INSERT INTO auth_codes(code_hash,github_user_id,client_id,redirect_uri,resource,challenge,grants_json,expires_at,used) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0)", params![hash(&code), user_id.0, request.client_id, request.redirect_uri, request.resource, request.code_challenge, encode_grants(&grants)?, deadline(now, CODE_LIFETIME)?])?;
        tx.execute("DELETE FROM auth_logins WHERE flow_id=?1", [flow_id])?;
        tx.commit()?;
        Ok(AuthorizationRedirect {
            redirect_uri: request.redirect_uri,
            code,
            state: request.state,
        })
    }
    pub fn cancel_consent(
        &self,
        flow_id: &str,
        browser_binding: &str,
        csrf: &str,
        now: i64,
    ) -> AuthResult<()> {
        validate_now(now)?;
        validate_secret(flow_id)?;
        validate_secret(browser_binding)?;
        validate_secret(csrf)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute("DELETE FROM auth_logins WHERE flow_id=?1 AND browser_hash=?2 AND csrf_hash=?3 AND stage='consent' AND expires_at>?4", params![flow_id, hash(browser_binding), hash(csrf), now])?;
        if changed != 1 {
            return Err(AuthError::InvalidGrant);
        }
        tx.commit()?;
        Ok(())
    }
    fn validate_authorization(&self, request: &AuthorizationRequest) -> AuthResult<()> {
        let client = self.config.client(&request.client_id)?;
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(AuthError::InvalidRequest("redirect_uri_mismatch"));
        }
        if request.resource != self.config.resource {
            return Err(AuthError::InvalidRequest("invalid_target"));
        }
        if request.code_challenge_method != "S256" || !valid_challenge(&request.code_challenge) {
            return Err(AuthError::InvalidRequest("S256_pkce_required"));
        }
        if request.state.is_empty()
            || request.state.len() > 1024
            || request.state.chars().any(char::is_control)
        {
            return Err(AuthError::InvalidRequest("invalid_state"));
        }
        if request.projects.is_empty() || request.projects.len() > 128 {
            return Err(AuthError::InvalidRequest("invalid_projects"));
        }
        for project in &request.projects {
            validate_project(project)?;
        }
        Ok(())
    }
    pub fn exchange_code(&self, request: CodeExchange, now: i64) -> AuthResult<TokenPair> {
        validate_now(now)?;
        validate_secret(&request.code)?;
        self.config.client(&request.client_id)?;
        if request.resource != self.config.resource {
            return Err(AuthError::InvalidGrant);
        }
        if !valid_verifier(&request.code_verifier) {
            return Err(AuthError::InvalidGrant);
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<AuthorizationCodeRow> = tx.query_row("SELECT github_user_id,client_id,redirect_uri,resource,challenge,grants_json,expires_at,used,family_id FROM auth_codes WHERE code_hash=?1", [hash(&request.code)], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))).optional()?;
        let (id, client, redirect, resource, challenge, grants_json, expires, used, issued_family) =
            row.ok_or(AuthError::InvalidGrant)?;
        if client != request.client_id
            || redirect != request.redirect_uri
            || resource != request.resource
            || !same(
                challenge.as_bytes(),
                pkce_challenge(&request.code_verifier).as_bytes(),
            )
        {
            return Err(AuthError::InvalidGrant);
        }
        if used {
            // Reuse proved with the original client bindings and verifier:
            // revoke tokens already derived from this code, not only the code.
            if let Some(family) = issued_family {
                tx.execute(
                    "UPDATE auth_token_families SET revoked=1 WHERE family_id=?1",
                    [&family],
                )?;
            }
            tx.commit()?;
            return Err(AuthError::InvalidGrant);
        }
        if expires <= now {
            return Err(AuthError::InvalidGrant);
        }
        if !self
            .config
            .client(&client)?
            .redirect_uris
            .contains(&redirect)
        {
            return Err(AuthError::InvalidGrant);
        }
        let grants = decode_grants(&grants_json)?;
        require_current_grants(&tx, GithubUserId(id), &grants)?;
        let family = random_secret()?;
        let family_expires = deadline(now, REFRESH_FAMILY_LIFETIME)?;
        tx.execute(
            "UPDATE auth_codes SET used=1,family_id=?2 WHERE code_hash=?1 AND used=0",
            params![hash(&request.code), family],
        )?;
        tx.execute("INSERT INTO auth_token_families(family_id,github_user_id,client_id,resource,grants_json,expires_at,revoked) VALUES(?1,?2,?3,?4,?5,?6,0)", params![family, id, client, resource, grants_json, family_expires])?;
        let pair = issue_tokens_tx(&tx, &family, family_expires, now)?;
        tx.commit()?;
        Ok(pair)
    }
    pub fn rotate_refresh(&self, request: RefreshExchange, now: i64) -> AuthResult<TokenPair> {
        validate_now(now)?;
        validate_secret(&request.refresh_token)?;
        self.config.client(&request.client_id)?;
        if request.resource != self.config.resource {
            return Err(AuthError::InvalidGrant);
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<RefreshTokenRow> = tx.query_row("SELECT t.family_id,t.consumed,f.github_user_id,f.client_id,f.resource,f.grants_json,f.expires_at,f.revoked FROM auth_refresh_tokens t JOIN auth_token_families f ON f.family_id=t.family_id WHERE t.token_hash=?1", [hash(&request.refresh_token)], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
        let (family, consumed, id, client, resource, grants_json, expires, revoked) =
            row.ok_or(AuthError::InvalidGrant)?;
        if client != request.client_id || resource != request.resource {
            return Err(AuthError::InvalidGrant);
        }
        if consumed {
            // Commit this revocation even though the request returns an error.
            tx.execute(
                "UPDATE auth_token_families SET revoked=1 WHERE family_id=?1",
                [&family],
            )?;
            tx.commit()?;
            return Err(AuthError::RefreshReuse);
        }
        if revoked || expires <= now {
            return Err(AuthError::InvalidGrant);
        }
        require_current_grants(&tx, GithubUserId(id), &decode_grants(&grants_json)?)?;
        tx.execute(
            "UPDATE auth_refresh_tokens SET consumed=1 WHERE token_hash=?1 AND consumed=0",
            [hash(&request.refresh_token)],
        )?;
        let pair = issue_tokens_tx(&tx, &family, expires, now)?;
        tx.commit()?;
        Ok(pair)
    }
    pub fn authenticate_access(
        &self,
        token: &str,
        resource: &str,
        now: i64,
    ) -> AuthResult<Principal> {
        validate_now(now)?;
        if resource != self.config.resource || validate_secret(token).is_err() {
            return Err(AuthError::InvalidToken);
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let row: Option<(i64, String, String, String, i64, i64, bool)> = tx.query_row("SELECT f.github_user_id,f.client_id,f.resource,f.grants_json,t.expires_at,f.expires_at,f.revoked FROM auth_access_tokens t JOIN auth_token_families f ON f.family_id=t.family_id WHERE t.token_hash=?1", [hash(token)], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
        let (id, client, audience, grants_json, expires, family_expires, revoked) =
            row.ok_or(AuthError::InvalidToken)?;
        if revoked
            || expires <= now
            || family_expires <= now
            || audience != resource
            || self.config.client(&client).is_err()
        {
            return Err(AuthError::InvalidToken);
        }
        let grants = decode_grants(&grants_json)?;
        require_current_grants(&tx, GithubUserId(id), &grants)
            .map_err(|_| AuthError::InvalidToken)?;
        tx.commit()?;
        Ok(Principal {
            github_user_id: GithubUserId(id),
            client_id: client,
            resource: audience,
            projects: grants.keys().cloned().collect(),
        })
    }
    pub fn project_grant_epoch(&self, principal: &str, project: &str) -> AuthResult<Option<i64>> {
        let user = parse_principal(principal)?;
        validate_project(project)?;
        Ok(self.lock()?.query_row("SELECT version FROM auth_grants WHERE github_user_id=?1 AND project=?2 AND active=1", params![user.0, project], |r| r.get(0)).optional()?)
    }
    pub fn has_any_project_access(&self, principal: &str) -> AuthResult<bool> {
        let user = parse_principal(principal)?;
        Ok(self.lock()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM auth_grants WHERE github_user_id=?1 AND active=1)",
            [user.0],
            |r| r.get(0),
        )?)
    }
    /// Retain consumed code and refresh records until their entire family expires
    /// so replay detection continues after restarts. Grant versions are never purged.
    pub fn prune_expired(&self, now: i64) -> AuthResult<()> {
        validate_now(now)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM auth_logins WHERE expires_at<=?1", [now])?;
        tx.execute(
            "DELETE FROM auth_codes WHERE expires_at<=?1 AND (used=0 OR NOT EXISTS (SELECT 1 FROM auth_token_families WHERE family_id=auth_codes.family_id AND expires_at>?1))",
            [now],
        )?;
        tx.execute("DELETE FROM auth_invitations WHERE expires_at<=?1", [now])?;
        tx.execute("DELETE FROM auth_access_tokens WHERE expires_at<=?1", [now])?;
        tx.execute(
            "DELETE FROM auth_token_families WHERE expires_at<=?1",
            [now],
        )?;
        tx.commit()?;
        Ok(())
    }
}
impl Principal {
    pub fn owner_id(&self) -> String {
        self.github_user_id.0.to_string()
    }
}

fn parse_principal(principal: &str) -> AuthResult<GithubUserId> {
    let id = principal
        .parse::<u64>()
        .map_err(|_| AuthError::AccessDenied)?;
    let id = GithubUserId::new(id).map_err(|_| AuthError::AccessDenied)?;
    if id.get().to_string() != principal {
        return Err(AuthError::AccessDenied);
    }
    Ok(id)
}
fn validate_user_project(user: GithubUserId, project: &str) -> AuthResult<()> {
    if user.0 <= 0 {
        return Err(AuthError::InvalidRequest("invalid_github_id"));
    }
    validate_project(project)
}
fn validate_project(project: &str) -> AuthResult<()> {
    if project.is_empty()
        || project.len() > 128
        || !project
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(AuthError::InvalidRequest("invalid_project"));
    }
    Ok(())
}
fn validate_now(now: i64) -> AuthResult<()> {
    if now < 0 {
        return Err(AuthError::InvalidRequest("invalid_server_time"));
    }
    Ok(())
}
fn deadline(now: i64, seconds: i64) -> AuthResult<i64> {
    now.checked_add(seconds)
        .ok_or(AuthError::InvalidRequest("invalid_server_time"))
}
fn validate_https(raw: &str, allow_query: bool) -> AuthResult<()> {
    if raw.len() > 2048 {
        return Err(AuthError::InvalidRequest("invalid_https_uri"));
    }
    let url = Url::parse(raw).map_err(|_| AuthError::InvalidRequest("invalid_https_uri"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (!allow_query && url.query().is_some())
    {
        return Err(AuthError::InvalidRequest("invalid_https_uri"));
    }
    Ok(())
}
fn random_secret() -> AuthResult<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AuthError::Entropy)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn hash(value: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, value.as_bytes())
        .as_ref()
        .to_vec()
}
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(hash(verifier))
}
fn valid_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
}
fn valid_challenge(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .map(|v| v.len() == 32 && URL_SAFE_NO_PAD.encode(v) == value)
            .unwrap_or(false)
}
fn validate_secret(value: &str) -> AuthResult<()> {
    if !valid_challenge(value) {
        return Err(AuthError::InvalidGrant);
    }
    Ok(())
}
fn same(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}
fn encode_grants(grants: &GrantSnapshot) -> AuthResult<String> {
    serde_json::to_string(grants).map_err(|_| AuthError::CorruptState)
}
fn decode_grants(json: &str) -> AuthResult<GrantSnapshot> {
    let grants: GrantSnapshot = serde_json::from_str(json).map_err(|_| AuthError::CorruptState)?;
    if grants.is_empty()
        || grants.len() > 128
        || grants
            .iter()
            .any(|(project, version)| validate_project(project).is_err() || *version < 1)
    {
        return Err(AuthError::CorruptState);
    }
    Ok(grants)
}
fn grant_tx(tx: &Transaction<'_>, user: GithubUserId, project: &str, now: i64) -> AuthResult<()> {
    tx.execute("INSERT INTO auth_grants(github_user_id,project,version,active,updated_at) VALUES(?1,?2,1,1,?3) ON CONFLICT(github_user_id,project) DO UPDATE SET version=CASE WHEN auth_grants.active=0 THEN auth_grants.version+1 ELSE auth_grants.version END,active=1,updated_at=excluded.updated_at", params![user.0, project, now])?;
    Ok(())
}
fn current_grants(
    tx: &Transaction<'_>,
    user: GithubUserId,
    projects: &[String],
) -> AuthResult<GrantSnapshot> {
    let mut result = BTreeMap::new();
    for project in projects {
        let version: Option<i64> = tx.query_row("SELECT version FROM auth_grants WHERE github_user_id=?1 AND project=?2 AND active=1", params![user.0, project], |r| r.get(0)).optional()?;
        if let Some(version) = version {
            result.insert(project.clone(), version);
        }
    }
    Ok(result)
}
fn require_current_grants(
    tx: &Transaction<'_>,
    user: GithubUserId,
    grants: &GrantSnapshot,
) -> AuthResult<()> {
    if grants.is_empty() {
        return Err(AuthError::AccessDenied);
    }
    let projects = grants.keys().cloned().collect::<Vec<_>>();
    if &current_grants(tx, user, &projects)? != grants {
        return Err(AuthError::AccessDenied);
    }
    Ok(())
}
fn redeem_invite_tx(
    tx: &Transaction<'_>,
    user: GithubUserId,
    token_hash: &[u8],
    now: i64,
) -> AuthResult<String> {
    let invite: Option<(i64, String, i64, bool)> = tx.query_row("SELECT github_user_id,project,expires_at,used FROM auth_invitations WHERE token_hash=?1", [token_hash], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let (intended, project, expires, used) = invite.ok_or(AuthError::InvalidGrant)?;
    if intended != user.0 || used || expires <= now {
        return Err(AuthError::InvalidGrant);
    }
    let changed = tx.execute(
        "UPDATE auth_invitations SET used=1 WHERE token_hash=?1 AND used=0",
        [token_hash],
    )?;
    if changed != 1 {
        return Err(AuthError::InvalidGrant);
    }
    grant_tx(tx, user, &project, now)?;
    Ok(project)
}
type LoginRow = (String, i64, Vec<u8>, Option<String>, Option<Vec<u8>>);
fn load_login(tx: &Transaction<'_>, flow: &str) -> AuthResult<LoginRow> {
    tx.query_row("SELECT stage,expires_at,browser_hash,request_json,invitation_hash FROM auth_logins WHERE flow_id=?1", [flow], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?.ok_or(AuthError::InvalidGrant)
}
fn issue_tokens_tx(
    tx: &Transaction<'_>,
    family: &str,
    family_expires: i64,
    now: i64,
) -> AuthResult<TokenPair> {
    let access_token = random_secret()?;
    let refresh_token = random_secret()?;
    let expires = deadline(now, ACCESS_LIFETIME)?.min(family_expires);
    if expires <= now {
        return Err(AuthError::InvalidGrant);
    }
    tx.execute(
        "INSERT INTO auth_access_tokens(token_hash,family_id,expires_at) VALUES(?1,?2,?3)",
        params![hash(&access_token), family, expires],
    )?;
    tx.execute(
        "INSERT INTO auth_refresh_tokens(token_hash,family_id,consumed) VALUES(?1,?2,0)",
        params![hash(&refresh_token), family],
    )?;
    Ok(TokenPair {
        access_token,
        refresh_token,
        token_type: "Bearer".into(),
        expires_in: (expires - now) as u64,
        scope: "mcp:events".into(),
    })
}
fn check_private_path(path: &Path, must_exist: bool) -> AuthResult<()> {
    wipstash_transport::pairing_files::validate_private_dir(
        path.parent()
            .ok_or(AuthError::InvalidRequest("invalid_auth_store_path"))?,
    )?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => wipstash_transport::pairing_files::validate_private_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !must_exist => {}
        Err(e) => return Err(e.into()),
    }
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) if suffix == "-journal" => {
                wipstash_transport::pairing_files::validate_private_file(&sidecar)?
            }
            Ok(_) => return Err(AuthError::InvalidRequest("unexpected_auth_wal_sidecar")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
const SCHEMA: &str = r#"
BEGIN IMMEDIATE;
PRAGMA application_id=1464689970;
PRAGMA user_version=1;
CREATE TABLE auth_settings(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binding TEXT NOT NULL);
CREATE TABLE auth_grants(github_user_id INTEGER NOT NULL CHECK(github_user_id>0),project TEXT NOT NULL,version INTEGER NOT NULL CHECK(version>0),active INTEGER NOT NULL CHECK(active IN(0,1)),updated_at INTEGER NOT NULL,PRIMARY KEY(github_user_id,project));
CREATE TABLE auth_invitations(token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),github_user_id INTEGER NOT NULL CHECK(github_user_id>0),project TEXT NOT NULL,expires_at INTEGER NOT NULL,used INTEGER NOT NULL CHECK(used IN(0,1)));
CREATE TABLE auth_logins(flow_id TEXT PRIMARY KEY,state_hash BLOB NOT NULL UNIQUE CHECK(length(state_hash)=32),browser_hash BLOB NOT NULL CHECK(length(browser_hash)=32),upstream_verifier TEXT NOT NULL,request_json TEXT,invitation_hash BLOB,stage TEXT NOT NULL CHECK(stage IN('pending','exchanging','consent')),expires_at INTEGER NOT NULL,github_user_id INTEGER,csrf_hash BLOB,grants_json TEXT,CHECK((request_json IS NULL)!=(invitation_hash IS NULL)));
CREATE TABLE auth_codes(code_hash BLOB PRIMARY KEY CHECK(length(code_hash)=32),github_user_id INTEGER NOT NULL,client_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,resource TEXT NOT NULL,challenge TEXT NOT NULL,grants_json TEXT NOT NULL,expires_at INTEGER NOT NULL,used INTEGER NOT NULL CHECK(used IN(0,1)),family_id TEXT);
CREATE TABLE auth_token_families(family_id TEXT PRIMARY KEY,github_user_id INTEGER NOT NULL,client_id TEXT NOT NULL,resource TEXT NOT NULL,grants_json TEXT NOT NULL,expires_at INTEGER NOT NULL,revoked INTEGER NOT NULL CHECK(revoked IN(0,1)));
CREATE TABLE auth_access_tokens(token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),family_id TEXT NOT NULL REFERENCES auth_token_families(family_id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
CREATE TABLE auth_refresh_tokens(token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),family_id TEXT NOT NULL REFERENCES auth_token_families(family_id) ON DELETE CASCADE,consumed INTEGER NOT NULL CHECK(consumed IN(0,1)));
CREATE INDEX auth_families_user ON auth_token_families(github_user_id);
CREATE INDEX auth_access_family ON auth_access_tokens(family_id);
CREATE INDEX auth_refresh_family ON auth_refresh_tokens(family_id);
CREATE INDEX auth_logins_expiry ON auth_logins(expires_at);
COMMIT;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    const NOW: i64 = 1_800_000_000;
    const RESOURCE: &str = "https://wipstash.example/mcp";
    const CLIENT: &str = "https://chatgpt.example/client.json";
    const REDIRECT: &str = "https://chatgpt.example/callback";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    fn user(id: u64) -> GithubUserId {
        GithubUserId::new(id).unwrap()
    }
    fn identity(id: u64) -> VerifiedGithubIdentity {
        VerifiedGithubIdentity::from_github_user(id, format!("user-{id}")).unwrap()
    }
    fn config() -> AuthConfig {
        AuthConfig {
            issuer: "https://wipstash.example".into(),
            resource: RESOURCE.into(),
            clients: vec![RegisteredClient {
                client_id: CLIENT.into(),
                name: "Test client".into(),
                redirect_uris: vec![REDIRECT.into()],
            }],
            administrators: [user(1)].into_iter().collect(),
        }
    }
    fn store() -> AuthStore {
        AuthStore::in_memory(config()).unwrap()
    }
    fn request() -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: CLIENT.into(),
            redirect_uri: REDIRECT.into(),
            resource: RESOURCE.into(),
            state: "downstream-client-state".into(),
            code_challenge: pkce_challenge(VERIFIER),
            code_challenge_method: "S256".into(),
            projects: vec!["alpha".into()],
        }
    }
    fn consent(store: &AuthStore) -> (GithubLoginStart, ConsentChallenge) {
        let start = store.begin_authorization(request(), NOW).unwrap();
        let callback = store
            .take_github_callback(&start.state, &start.browser_binding, NOW)
            .unwrap();
        assert_ne!(callback.code_verifier, VERIFIER);
        assert_eq!(
            pkce_challenge(&callback.code_verifier),
            start.code_challenge
        );
        let consent = store
            .complete_github_login(callback, identity(7), NOW)
            .unwrap();
        (start, consent)
    }
    fn authorize(store: &AuthStore) -> AuthorizationRedirect {
        let (start, consent) = consent(store);
        store
            .approve_consent(
                &consent.flow_id,
                &start.browser_binding,
                &consent.csrf_token,
                NOW,
            )
            .unwrap()
    }
    fn exchange(code: &str) -> CodeExchange {
        CodeExchange {
            code: code.into(),
            client_id: CLIENT.into(),
            redirect_uri: REDIRECT.into(),
            resource: RESOURCE.into(),
            code_verifier: VERIFIER.into(),
        }
    }
    fn refresh(token: &str) -> RefreshExchange {
        RefreshExchange {
            refresh_token: token.into(),
            client_id: CLIENT.into(),
            resource: RESOURCE.into(),
        }
    }
    fn token(store: &AuthStore) -> TokenPair {
        store
            .grant_project(&identity(1), user(7), "alpha", NOW)
            .unwrap();
        let code = authorize(store);
        store.exchange_code(exchange(&code.code), NOW).unwrap()
    }
    fn private_path() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private");
        wipstash_transport::pairing_files::ensure_private_dir(&private).unwrap();
        let path = private.join("auth.sqlite");
        (root, path)
    }

    #[test]
    fn numeric_identity_and_config_fail_closed() {
        assert!(GithubUserId::new(0).is_err());
        assert!(GithubUserId::new(u64::MAX).is_err());
        assert!(VerifiedGithubIdentity::from_github_user(7, "<script>".into()).is_err());
        let mut c = config();
        c.clients[0].redirect_uris = vec!["http://example.test/callback".into()];
        assert!(AuthStore::in_memory(c).is_err());
        let mut c = config();
        c.clients[0].redirect_uris = vec![format!("{REDIRECT}#fragment")];
        assert!(AuthStore::in_memory(c).is_err());
        let mut c = config();
        c.clients.push(c.clients[0].clone());
        assert!(AuthStore::in_memory(c).is_err());
        let c: AuthConfig = serde_json::from_str(
            &serde_json::to_string(&config())
                .unwrap()
                .replace("\"administrators\":[1]", "\"administrators\":[-1]"),
        )
        .unwrap();
        assert!(c.validate().is_err());
    }
    #[test]
    fn invitations_require_admin_and_matching_numeric_id_and_are_single_use() {
        let store = store();
        assert!(matches!(
            store.issue_invitation(&identity(2), user(7), "alpha", NOW),
            Err(AuthError::AccessDenied)
        ));
        assert!(matches!(
            store.grant_project(&identity(2), user(7), "alpha", NOW),
            Err(AuthError::AccessDenied)
        ));
        let invite = store
            .issue_invitation(&identity(1), user(7), "alpha", NOW)
            .unwrap();
        assert_eq!(invite.expires_at, NOW + 86_400);
        // A forwarded link cannot grant another account and does not consume it.
        assert!(store
            .redeem_invitation(&identity(8), &invite.token, NOW)
            .is_err());
        assert!(!store.has_project_access(user(8), "alpha").unwrap());
        assert_eq!(
            store
                .redeem_invitation(&identity(7), &invite.token, NOW)
                .unwrap(),
            "alpha"
        );
        assert!(store
            .redeem_invitation(&identity(7), &invite.token, NOW)
            .is_err());
        assert!(store.has_project_access(user(7), "alpha").unwrap());
        assert!(!store.has_project_access(user(7), "beta").unwrap());
    }
    #[test]
    fn invitations_expire_at_exact_24_hour_boundary_and_revoke_locally() {
        let store = store();
        let invite = store
            .issue_invitation(&identity(1), user(7), "alpha", NOW)
            .unwrap();
        assert!(store
            .redeem_invitation(&identity(7), &invite.token, invite.expires_at)
            .is_err());
        let invite = store
            .issue_invitation(&identity(1), user(7), "alpha", NOW)
            .unwrap();
        store.revoke_invitation_local(&invite.token, NOW).unwrap();
        assert!(store
            .redeem_invitation(&identity(7), &invite.token, NOW)
            .is_err());
        let invite = store
            .issue_invitation(&identity(1), user(7), "alpha", NOW)
            .unwrap();
        store
            .revoke_project(&identity(1), user(7), "alpha", NOW)
            .unwrap();
        assert!(store
            .redeem_invitation(&identity(7), &invite.token, NOW)
            .is_err());
    }
    #[test]
    fn invite_login_uses_bound_single_use_github_flow() {
        let store = store();
        let invite = store
            .issue_invitation(&identity(1), user(7), "alpha", NOW)
            .unwrap();
        let start = store.begin_invitation(&invite.token, NOW).unwrap();
        assert!(store
            .take_github_callback(&start.state, &random_secret().unwrap(), NOW)
            .is_err());
        let callback = store
            .take_github_callback(&start.state, &start.browser_binding, NOW)
            .unwrap();
        assert_eq!(callback.purpose, LoginPurpose::Invitation);
        assert!(store
            .take_github_callback(&start.state, &start.browser_binding, NOW)
            .is_err());
        assert!(store
            .complete_invitation(callback, identity(8), NOW)
            .is_err());
        let start = store.begin_invitation(&invite.token, NOW).unwrap();
        let callback = store
            .take_github_callback(&start.state, &start.browser_binding, NOW)
            .unwrap();
        assert_eq!(
            store
                .complete_invitation(callback, identity(7), NOW)
                .unwrap(),
            "alpha"
        );
        assert!(store.begin_invitation(&invite.token, NOW).is_err());
    }
    #[test]
    fn downstream_requests_require_exact_registration_resource_and_s256() {
        let store = store();
        let mut r = request();
        r.redirect_uri.push('/');
        assert!(store.begin_authorization(r, NOW).is_err());
        let mut r = request();
        r.resource = "https://attacker.example/mcp".into();
        assert!(store.begin_authorization(r, NOW).is_err());
        let mut r = request();
        r.client_id = "https://attacker.example/client.json".into();
        assert!(store.begin_authorization(r, NOW).is_err());
        let mut r = request();
        r.code_challenge_method = "plain".into();
        assert!(store.begin_authorization(r, NOW).is_err());
        let mut r = request();
        r.code_challenge = "x".repeat(43);
        assert!(store.begin_authorization(r, NOW).is_err());
    }
    #[test]
    fn github_state_pkce_and_browser_are_independent_and_one_use() {
        let store = store();
        store.grant_project_local(user(7), "alpha", NOW).unwrap();
        let start = store.begin_authorization(request(), NOW).unwrap();
        assert_ne!(start.state, "downstream-client-state");
        assert_ne!(start.code_challenge, pkce_challenge(VERIFIER));
        assert!(store
            .take_github_callback("downstream-client-state", &start.browser_binding, NOW)
            .is_err());
        assert!(store
            .take_github_callback(&start.state, &random_secret().unwrap(), NOW)
            .is_err());
        let callback = store
            .take_github_callback(&start.state, &start.browser_binding, NOW)
            .unwrap();
        assert!(store
            .take_github_callback(&start.state, &start.browser_binding, NOW)
            .is_err());
        store
            .complete_github_login(callback, identity(7), NOW)
            .unwrap();
        let expired = store.begin_authorization(request(), NOW).unwrap();
        assert!(store
            .take_github_callback(&expired.state, &expired.browser_binding, expired.expires_at)
            .is_err());
    }
    #[test]
    fn consent_is_explicit_browser_bound_csrf_protected_and_single_use() {
        let store = store();
        store.grant_project_local(user(7), "alpha", NOW).unwrap();
        let (start, c) = consent(&store);
        assert!(store
            .approve_consent(&c.flow_id, &random_secret().unwrap(), &c.csrf_token, NOW)
            .is_err());
        assert!(store
            .approve_consent(
                &c.flow_id,
                &start.browser_binding,
                &random_secret().unwrap(),
                NOW
            )
            .is_err());
        let code = store
            .approve_consent(&c.flow_id, &start.browser_binding, &c.csrf_token, NOW)
            .unwrap();
        assert_eq!(code.redirect_uri, REDIRECT);
        assert_eq!(code.state, "downstream-client-state");
        assert!(store
            .approve_consent(&c.flow_id, &start.browser_binding, &c.csrf_token, NOW)
            .is_err());
        let (start, c) = consent(&store);
        store
            .cancel_consent(&c.flow_id, &start.browser_binding, &c.csrf_token, NOW)
            .unwrap();
        assert!(store
            .approve_consent(&c.flow_id, &start.browser_binding, &c.csrf_token, NOW)
            .is_err());
    }
    #[test]
    fn consent_only_shows_available_grants_and_rechecks_revocation() {
        let store = store();
        store.grant_project_local(user(7), "alpha", NOW).unwrap();
        let mut r = request();
        r.projects.push("beta".into());
        let start = store.begin_authorization(r, NOW).unwrap();
        let callback = store
            .take_github_callback(&start.state, &start.browser_binding, NOW)
            .unwrap();
        let c = store
            .complete_github_login(callback, identity(7), NOW)
            .unwrap();
        assert_eq!(c.projects, vec!["alpha"]);
        store.revoke_project_local(user(7), "alpha", NOW).unwrap();
        store.grant_project_local(user(7), "alpha", NOW).unwrap();
        assert!(store
            .approve_consent(&c.flow_id, &start.browser_binding, &c.csrf_token, NOW)
            .is_err());
    }
    #[test]
    fn codes_are_exactly_bound_and_redeemable_once() {
        let store = store();
        store.grant_project_local(user(7), "alpha", NOW).unwrap();
        let code = authorize(&store);
        let mut e = exchange(&code.code);
        e.code_verifier = "b".repeat(43);
        assert!(store.exchange_code(e, NOW).is_err());
        let mut e = exchange(&code.code);
        e.redirect_uri.push('/');
        assert!(store.exchange_code(e, NOW).is_err());
        let mut e = exchange(&code.code);
        e.resource.push('/');
        assert!(store.exchange_code(e, NOW).is_err());
        let mut e = exchange(&code.code);
        e.client_id = "https://other.example/client.json".into();
        assert!(store.exchange_code(e, NOW).is_err());
        let pair = store.exchange_code(exchange(&code.code), NOW).unwrap();
        assert_eq!(
            store
                .authenticate_access(&pair.access_token, RESOURCE, NOW)
                .unwrap()
                .owner_id(),
            "7"
        );
        let mut wrong = exchange(&code.code);
        wrong.code_verifier = "b".repeat(43);
        assert!(store.exchange_code(wrong, NOW).is_err());
        assert!(store
            .authenticate_access(&pair.access_token, RESOURCE, NOW)
            .is_ok());
        assert!(store.exchange_code(exchange(&code.code), NOW).is_err());
        assert!(store
            .authenticate_access(&pair.access_token, RESOURCE, NOW)
            .is_err());
        assert!(store
            .rotate_refresh(refresh(&pair.refresh_token), NOW)
            .is_err());
        let expired = authorize(&store);
        assert!(store
            .exchange_code(exchange(&expired.code), NOW + CODE_LIFETIME)
            .is_err());
    }
    #[test]
    fn consumed_code_replay_survives_code_expiry_maintenance_and_restart() {
        let (_root, path) = private_path();
        let store = AuthStore::open(&path, config()).unwrap();
        store.grant_project_local(user(7), "alpha", NOW).unwrap();
        let code = authorize(&store).code;
        let pair = store.exchange_code(exchange(&code), NOW).unwrap();
        // Unused expired codes can be deleted; a consumed code must remain a
        // replay marker for as long as its derived family can authorize access.
        let unused = authorize(&store).code;
        let later = NOW + CODE_LIFETIME + 1;
        store.prune_expired(later).unwrap();
        drop(store);
        let reopened = AuthStore::open(&path, config()).unwrap();
        assert!(reopened.exchange_code(exchange(&unused), later).is_err());
        let mut wrong = exchange(&code);
        wrong.code_verifier = "b".repeat(43);
        assert!(reopened.exchange_code(wrong, later).is_err());
        assert!(reopened
            .authenticate_access(&pair.access_token, RESOURCE, later)
            .is_ok());
        let refreshed = reopened
            .rotate_refresh(refresh(&pair.refresh_token), later)
            .unwrap();
        assert!(reopened.exchange_code(exchange(&code), later).is_err());
        assert!(reopened
            .authenticate_access(&pair.access_token, RESOURCE, later)
            .is_err());
        assert!(reopened
            .authenticate_access(&refreshed.access_token, RESOURCE, later)
            .is_err());
        assert!(reopened
            .rotate_refresh(refresh(&refreshed.refresh_token), later)
            .is_err());
        let count_codes = || {
            reopened
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM auth_codes", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert_eq!(count_codes(), 1);
        reopened
            .prune_expired(NOW + REFRESH_FAMILY_LIFETIME)
            .unwrap();
        assert_eq!(count_codes(), 0);
    }
    #[test]
    fn access_tokens_are_audience_bound_expiring_and_github_tokens_are_rejected() {
        let store = store();
        let pair = token(&store);
        assert!(store
            .authenticate_access("gho_not_an_mcp_token", RESOURCE, NOW)
            .is_err());
        assert!(store
            .authenticate_access(&pair.access_token, "https://other.example/mcp", NOW)
            .is_err());
        assert!(store
            .authenticate_access(&pair.refresh_token, RESOURCE, NOW)
            .is_err());
        assert!(store
            .authenticate_access(&pair.access_token, RESOURCE, NOW + ACCESS_LIFETIME)
            .is_err());
        assert_eq!(pair.expires_in, ACCESS_LIFETIME as u64);
    }
    #[test]
    fn refresh_rotation_replay_revokes_entire_family_including_new_access() {
        let store = store();
        let first = token(&store);
        let mut wrong = refresh(&first.refresh_token);
        wrong.resource.push('/');
        assert!(store.rotate_refresh(wrong, NOW + 1).is_err());
        let second = store
            .rotate_refresh(refresh(&first.refresh_token), NOW + 1)
            .unwrap();
        assert_ne!(first.refresh_token, second.refresh_token);
        assert!(store
            .authenticate_access(&second.access_token, RESOURCE, NOW + 2)
            .is_ok());
        assert!(matches!(
            store.rotate_refresh(refresh(&first.refresh_token), NOW + 2),
            Err(AuthError::RefreshReuse)
        ));
        assert!(store
            .authenticate_access(&first.access_token, RESOURCE, NOW + 2)
            .is_err());
        assert!(store
            .authenticate_access(&second.access_token, RESOURCE, NOW + 2)
            .is_err());
        assert!(store
            .rotate_refresh(refresh(&second.refresh_token), NOW + 2)
            .is_err());
    }
    #[test]
    fn project_revocation_and_regrant_do_not_resurrect_codes_tokens_or_subscriptions() {
        let store = store();
        let pair = token(&store);
        let code = authorize(&store);
        let old_epoch = store.project_grant_epoch("7", "alpha").unwrap().unwrap();
        store.revoke_project_local(user(7), "alpha", NOW).unwrap();
        assert!(!store.has_any_project_access("7").unwrap());
        assert!(store
            .authenticate_access(&pair.access_token, RESOURCE, NOW)
            .is_err());
        assert!(store
            .rotate_refresh(refresh(&pair.refresh_token), NOW)
            .is_err());
        store.grant_project_local(user(7), "alpha", NOW).unwrap();
        assert_ne!(
            store.project_grant_epoch("7", "alpha").unwrap(),
            Some(old_epoch)
        );
        assert!(store
            .authenticate_access(&pair.access_token, RESOURCE, NOW)
            .is_err());
        assert!(store.exchange_code(exchange(&code.code), NOW).is_err());
        assert!(store.project_grant_epoch("007", "alpha").is_err());
    }
    #[test]
    fn secrets_are_hashed_in_database_and_refresh_family_expiration_is_absolute() {
        let store = store();
        let pair = token(&store);
        let conn = store.lock().unwrap();
        let access_hash: Vec<u8> = conn
            .query_row("SELECT token_hash FROM auth_access_tokens", [], |r| {
                r.get(0)
            })
            .unwrap();
        let refresh_hash: Vec<u8> = conn
            .query_row("SELECT token_hash FROM auth_refresh_tokens", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(access_hash, hash(&pair.access_token));
        assert_eq!(refresh_hash, hash(&pair.refresh_token));
        assert_ne!(access_hash, pair.access_token.as_bytes());
        let verifier_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM auth_logins WHERE upstream_verifier!=''",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(verifier_count, 0);
        drop(conn);
        let almost = NOW + REFRESH_FAMILY_LIFETIME - 1;
        let last = store
            .rotate_refresh(refresh(&pair.refresh_token), almost)
            .unwrap();
        assert_eq!(last.expires_in, 1);
        assert!(store
            .rotate_refresh(refresh(&last.refresh_token), almost + 1)
            .is_err());
    }
    #[test]
    fn restart_keeps_grants_invites_tokens_and_refresh_replay_memory() {
        let (_root, path) = private_path();
        let store = AuthStore::open(&path, config()).unwrap();
        let first = token(&store);
        let second = store
            .rotate_refresh(refresh(&first.refresh_token), NOW)
            .unwrap();
        let invite = store.issue_invitation_local(user(8), "beta", NOW).unwrap();
        drop(store);
        let reopened = AuthStore::open(&path, config()).unwrap();
        assert!(reopened
            .authenticate_access(&second.access_token, RESOURCE, NOW)
            .is_ok());
        assert_eq!(
            reopened
                .redeem_invitation(&identity(8), &invite.token, NOW)
                .unwrap(),
            "beta"
        );
        assert!(matches!(
            reopened.rotate_refresh(refresh(&first.refresh_token), NOW),
            Err(AuthError::RefreshReuse)
        ));
        assert!(reopened
            .authenticate_access(&second.access_token, RESOURCE, NOW)
            .is_err());
        drop(reopened);
        let mut changed = config();
        changed.resource.push('/');
        assert!(AuthStore::open(&path, changed).is_err());
    }
    #[test]
    fn concurrent_code_redemption_has_one_winner_across_database_connections() {
        let (_root, path) = private_path();
        let store = AuthStore::open(&path, config()).unwrap();
        store.grant_project_local(user(7), "alpha", NOW).unwrap();
        let code = authorize(&store).code;
        drop(store);
        let one = AuthStore::open(&path, config()).unwrap();
        let two = AuthStore::open(&path, config()).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let workers = [one, two]
            .into_iter()
            .map(|store| {
                let code = code.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.exchange_code(exchange(&code), NOW).is_ok()
                })
            })
            .collect::<Vec<_>>();
        let winners = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }
    #[test]
    fn concurrent_invitation_redemption_has_one_winner_across_connections() {
        let (_root, path) = private_path();
        let store = AuthStore::open(&path, config()).unwrap();
        let invite = store
            .issue_invitation_local(user(7), "alpha", NOW)
            .unwrap()
            .token;
        drop(store);
        let one = AuthStore::open(&path, config()).unwrap();
        let two = AuthStore::open(&path, config()).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let workers = [one, two]
            .into_iter()
            .map(|store| {
                let invite = invite.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.redeem_invitation(&identity(7), &invite, NOW).is_ok()
                })
            })
            .collect::<Vec<_>>();
        let winners = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }
}
