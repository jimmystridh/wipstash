//! Transactional enrollment authority. No JSON projection or enrollment grant cache.
//! The private database (and its journals) is the sole source of managed authorization.
use crate::pairing_crypto::{self, Issuer};
use crate::{error, fingerprint, Peer, Result};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

pub const VERSION: u32 = 1;
pub const MAX_CSR_BYTES: usize = 8192;
pub const MAX_ENROLLMENT_RESPONSE_BYTES: usize = 32 * 1024;
pub const MAX_DEVICES: i64 = 100;
pub const MAX_INVITES: i64 = 1000;
pub const MAX_CERTIFICATES: i64 = 1000;
pub const RECOVERY_SECONDS: i64 = 86400;
pub const CHALLENGE_SECONDS: i64 = 120;
pub const MAX_INVITE_SECONDS: i64 = 7 * 86400;
pub const MAX_CERTIFICATE_SECONDS: u64 = 90 * 86400;
const APPLICATION_ID: i64 = 0x57505031;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum AclSource {
    File(PathBuf),
    Managed { managed: PathBuf },
}
impl From<PathBuf> for AclSource {
    fn from(p: PathBuf) -> Self {
        Self::File(p)
    }
}
impl AsRef<Path> for AclSource {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}
impl AclSource {
    pub fn path(&self) -> &Path {
        match self {
            Self::File(p) => p,
            Self::Managed { managed } => managed,
        }
    }
    pub fn authorize(&self, cert_der: &[u8], project: &str) -> Result<Peer> {
        match self {
            Self::File(p) => crate::authorize(
                &serde_json::from_slice(&crate::read_file(p, 1024 * 1024)?)?,
                cert_der,
                project,
            ),
            Self::Managed { managed } => {
                PairingStore::open_existing(managed)?.authorize(&fingerprint(cert_der), project)
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBinding {
    pub project: String,
    pub authority: String,
    pub epoch: u64,
    pub authority_device: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvitePurpose {
    New,
    Rotate { expected_generation: u64 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteScope {
    pub project: String,
    pub authority: String,
    pub epoch: u64,
    pub authority_device: String,
    pub client_device: String,
    pub purpose: InvitePurpose,
    pub enrollment_address: SocketAddr,
    pub enrollment_server_name: String,
    pub enrollment_leaf_pin: String,
    pub sync_address: SocketAddr,
    pub sync_server_name: String,
    pub sync_leaf_pin: String,
    pub ca_certificate_der: Vec<u8>,
    pub certificate_lifetime_secs: u64,
}
impl InviteScope {
    pub fn binding(&self) -> AuthorityBinding {
        AuthorityBinding {
            project: self.project.clone(),
            authority: self.authority.clone(),
            epoch: self.epoch,
            authority_device: self.authority_device.clone(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        validate_binding(&self.binding())?;
        valid_name(&self.client_device)?;
        if self.client_device == self.authority_device
            || self.ca_certificate_der.is_empty()
            || self.ca_certificate_der.len() > 16384
            || self.certificate_lifetime_secs == 0
            || self.certificate_lifetime_secs > MAX_CERTIFICATE_SECONDS
            || self.enrollment_address.port() == 0
            || self.sync_address.port() == 0
            || self.enrollment_address.ip().is_unspecified()
            || self.sync_address.ip().is_unspecified()
            || !valid_id(&self.enrollment_leaf_pin)
            || !valid_id(&self.sync_leaf_pin)
        {
            return Err(error("invalid_invite_scope"));
        }
        for name in [&self.enrollment_server_name, &self.sync_server_name] {
            if name.is_empty()
                || name.len() > 253
                || rustls::pki_types::ServerName::try_from(name.as_str()).is_err()
            {
                return Err(error("invalid_server_name"));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    pub version: u32,
    pub invite_id: String,
    pub secret: String,
    pub expires_at: i64,
    pub scope: InviteScope,
}
impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("invite_id", &self.invite_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl Invite {
    pub fn validate(&self, now: i64) -> Result<()> {
        if self.version != VERSION
            || !valid_id(&self.invite_id)
            || !valid_id(&self.secret)
            || now < 0
            || self.expires_at <= now
            || self.expires_at - now > MAX_INVITE_SECONDS
        {
            return Err(error("invalid_invite"));
        }
        self.scope.validate()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemRequest {
    pub version: u32,
    pub invite_id: String,
    pub secret: String,
    pub request_id: String,
    pub csr_der: Vec<u8>,
}
impl fmt::Debug for RedeemRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedeemRequest([REDACTED])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentResponse {
    pub version: u32,
    pub certificate_der: Vec<u8>,
    pub ca_certificate_der: Vec<u8>,
    pub fingerprint: String,
    pub scope: InviteScope,
    pub generation: u64,
    pub request_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryChallengeRequest {
    pub version: u32,
    pub invite_id: String,
    pub request_id: String,
    pub csr_der: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryChallenge {
    pub nonce: String,
    pub deadline: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequest {
    pub version: u32,
    pub invite_id: String,
    pub request_id: String,
    pub csr_der: Vec<u8>,
    pub challenge: RecoveryChallenge,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub device: String,
    pub state: String,
    pub generation: u64,
}

pub fn random_id() -> Result<String> {
    let mut b = [0u8; 32];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| error("random_source_failed"))?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}
fn secret_digest(invite_id: &str, secret: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"wipstash/enrollment/invite-secret/v1\0");
    hash.update(invite_id.as_bytes());
    hash.update(secret.as_bytes());
    hash.finalize().to_vec()
}
pub fn unix_now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
fn valid_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid_name(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 96
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        Err(error("invalid_identity"))
    } else {
        Ok(())
    }
}
fn validate_binding(b: &AuthorityBinding) -> Result<()> {
    valid_name(&b.project)?;
    valid_name(&b.authority)?;
    valid_name(&b.authority_device)?;
    if b.epoch == 0 || b.epoch > i64::MAX as u64 {
        return Err(error("invalid_epoch"));
    }
    Ok(())
}
fn validate_request(version: u32, invite: &str, request: &str, csr: &[u8], now: i64) -> Result<()> {
    if version != VERSION
        || !valid_id(invite)
        || !valid_id(request)
        || csr.is_empty()
        || csr.len() > MAX_CSR_BYTES
        || now < 0
    {
        return Err(error("enrollment_denied"));
    }
    Ok(())
}
/// Canonical domain-separated bytes. JSON ambiguity is avoided by fixed-size IDs/digests.
pub fn recovery_message(
    request: &RecoveryChallengeRequest,
    challenge: &RecoveryChallenge,
) -> Result<Vec<u8>> {
    validate_request(
        request.version,
        &request.invite_id,
        &request.request_id,
        &request.csr_der,
        0,
    )?;
    if !valid_id(&challenge.nonce) || challenge.deadline < 0 {
        return Err(error("enrollment_denied"));
    }
    let mut bytes = b"wipstash/enrollment/recovery/v1\0".to_vec();
    bytes.extend_from_slice(request.invite_id.as_bytes());
    bytes.extend_from_slice(request.request_id.as_bytes());
    bytes.extend_from_slice(&Sha256::digest(&request.csr_der));
    bytes.extend_from_slice(challenge.nonce.as_bytes());
    bytes.extend_from_slice(&challenge.deadline.to_be_bytes());
    Ok(bytes)
}

pub struct PairingStore {
    connection: Mutex<Connection>,
}
impl PairingStore {
    /// Operator-only creation/open. Parent directory must already be private.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        check_private_path(path, false)?;
        if !path.exists() {
            crate::pairing_files::create_private_file(path, &[])?;
        }
        check_private_path(path, true)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&conn)?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let application: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        if version == 0 && application == 0 {
            let tables: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )?;
            if tables != 0 {
                return Err(error("unknown_pairing_database"));
            }
        } else {
            validate_database(&conn)?;
        }
        // Reject unknown databases before any durable configuration change.
        let mode: String = conn.query_row("PRAGMA journal_mode=PERSIST", [], |r| r.get(0))?;
        if mode != "persist" {
            return Err(error("unsupported_pairing_journal"));
        }
        conn.pragma_update(None, "synchronous", "EXTRA")?;
        if version == 0 {
            conn.execute_batch(SCHEMA)?;
        }
        validate_database(&conn)?;
        check_private_path(path, true)?;
        #[cfg(unix)]
        {
            std::fs::File::open(path.parent().ok_or_else(|| error("invalid_store_path"))?)?
                .sync_all()?;
        }
        Ok(Self {
            connection: Mutex::new(conn),
        })
    }
    /// Authorization must not create, migrate, or repair a missing/corrupt store.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        check_private_path(path, true)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&conn)?;
        conn.pragma_update(None, "query_only", true)?;
        validate_database(&conn)?;
        Ok(Self {
            connection: Mutex::new(conn),
        })
    }
    pub fn binding(&self) -> Result<AuthorityBinding> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let json: String =
            conn.query_row("SELECT binding FROM authority WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        Ok(serde_json::from_str(&json)?)
    }
    pub fn initialize(&self, binding: &AuthorityBinding) -> Result<()> {
        validate_binding(binding)?;
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row("SELECT binding FROM authority WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(existing) = existing {
            if serde_json::from_str::<AuthorityBinding>(&existing)? != *binding {
                return Err(error("authority_binding_conflict"));
            }
        } else {
            tx.execute(
                "INSERT INTO authority(singleton,binding) VALUES(1,?1)",
                [serde_json::to_string(binding)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// A reservation grants no access and cannot resurrect a permanent tombstone.
    pub fn reserve_device(&self, device: &str) -> Result<()> {
        valid_name(device)?;
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let binding = binding_tx(&tx)?;
        if binding.authority_device == device {
            return Err(error("authority_cannot_be_client"));
        }
        let existing: Option<String> = tx
            .query_row("SELECT state FROM devices WHERE device=?1", [device], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(state) = existing {
            if state != "reserved" {
                return Err(error("device_identity_already_used"));
            }
        } else {
            quota(&tx, "devices", MAX_DEVICES)?;
            tx.execute(
                "INSERT INTO devices(device,state,generation) VALUES(?1,'reserved',0)",
                [device],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn create_invite(&self, scope: InviteScope, expires_at: i64, now: i64) -> Result<Invite> {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let invite = create_invite_tx(&tx, scope, expires_at, now)?;
        tx.commit()?;
        Ok(invite)
    }
    /// Local operator recovery when an invitation export was lost. Never revokes
    /// an active certificate or removes an identity reservation/tombstone.
    pub fn cancel_pending_invite(&self, device: &str) -> Result<usize> {
        valid_name(device)?;
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE invites SET state='cancelled' WHERE device=?1 AND state='pending'",
            [device],
        )?;
        tx.commit()?;
        Ok(changed)
    }
    pub fn rotate_invite(
        &self,
        device: &str,
        expected_generation: u64,
        expires_at: i64,
        now: i64,
    ) -> Result<Invite> {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let scope: String = tx.query_row("SELECT scope FROM invites WHERE device=?1 AND response IS NOT NULL ORDER BY generation DESC LIMIT 1", [device], |r| r.get(0))?;
        let mut scope: InviteScope = serde_json::from_str(&scope)?;
        scope.purpose = InvitePurpose::Rotate {
            expected_generation,
        };
        let invite = create_invite_tx(&tx, scope, expires_at, now)?;
        tx.commit()?;
        Ok(invite)
    }
    pub fn redeem(
        &self,
        request: &RedeemRequest,
        issuer: &Issuer,
        now: i64,
    ) -> Result<EnrollmentResponse> {
        validate_request(
            request.version,
            &request.invite_id,
            &request.request_id,
            &request.csr_der,
            now,
        )?;
        if !valid_id(&request.secret) {
            return Err(error("enrollment_denied"));
        }
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let invite = invite_tx(&tx, &request.invite_id)?;
        let hash = secret_digest(&request.invite_id, &request.secret);
        if invite.secret_hash.len() != hash.len()
            || !bool::from(invite.secret_hash.as_slice().ct_eq(hash.as_slice()))
            || now >= invite.expires_at
        {
            return Err(error("enrollment_denied"));
        }
        let csr_digest = fingerprint(&request.csr_der);
        if invite.state == "committed" {
            let response = committed_response(&tx, &invite, &request.request_id, &csr_digest, now)?;
            tx.commit()?;
            return Ok(response);
        }
        if invite.state != "pending" {
            return Err(error("enrollment_denied"));
        }
        let scope: InviteScope = serde_json::from_str(&invite.scope)?;
        scope.validate()?;
        if scope.binding() != binding_tx(&tx)?
            || issuer.certificate_der() != scope.ca_certificate_der
        {
            return Err(error("enrollment_denied"));
        }
        let generation = next_generation(&tx, &scope)?;
        quota(&tx, "certificates", MAX_CERTIFICATES)?;
        // Persistent authenticated attempt budget: repeated bad CSRs cannot reset
        // their allowance by disconnecting, changing source IP, or restarting us.
        if tx.execute(
            "UPDATE invites SET attempts=attempts+1 WHERE invite_id=?1 AND attempts<16",
            [&request.invite_id],
        )? != 1
        {
            return Err(error("enrollment_denied"));
        }
        let csr = match pairing_crypto::verify_csr(&request.csr_der) {
            Ok(csr) => csr,
            Err(_) => {
                tx.commit()?;
                return Err(error("enrollment_denied"));
            }
        };
        let certificate_der =
            match pairing_crypto::issue_client_certificate(&csr, &scope, issuer, now) {
                Ok(cert) => cert,
                Err(_) => {
                    tx.commit()?;
                    return Err(error("enrollment_denied"));
                }
            };
        let response = EnrollmentResponse {
            version: VERSION,
            fingerprint: fingerprint(&certificate_der),
            certificate_der,
            ca_certificate_der: scope.ca_certificate_der.clone(),
            scope: scope.clone(),
            generation,
            request_id: request.request_id.clone(),
        };
        let saved = bounded_enrollment_response(&response)?;
        if saved.len() > 32 * 1024 {
            tx.commit()?;
            return Err(error("enrollment_response_bound"));
        }
        let recovery_until = now
            .checked_add(RECOVERY_SECONDS)
            .ok_or_else(|| error("invalid_time"))?;
        let not_after = now
            .checked_add(scope.certificate_lifetime_secs as i64)
            .ok_or_else(|| error("invalid_time"))?;
        tx.execute(
            "UPDATE certificates SET revoked=1 WHERE device=?1",
            [&scope.client_device],
        )?;
        tx.execute("INSERT INTO certificates(fingerprint,device,generation,revoked,not_after) VALUES(?1,?2,?3,0,?4)", params![response.fingerprint, scope.client_device, generation, not_after])?;
        tx.execute(
            "UPDATE devices SET state='active',generation=?2 WHERE device=?1",
            params![scope.client_device, generation],
        )?;
        tx.execute("UPDATE invites SET state='committed',request_id=?2,csr_digest=?3,key_digest=?4,response=?5,recovery_until=?6,generation=?7 WHERE invite_id=?1 AND state='pending'", params![request.invite_id,request.request_id,csr_digest,csr.public_key_digest(),saved,recovery_until,generation])?;
        tx.commit()?;
        Ok(response)
    }
    pub fn recovery_challenge(
        &self,
        request: &RecoveryChallengeRequest,
        now: i64,
    ) -> Result<RecoveryChallenge> {
        validate_request(
            request.version,
            &request.invite_id,
            &request.request_id,
            &request.csr_der,
            now,
        )?;
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let invite = invite_tx(&tx, &request.invite_id)?;
        committed_response(
            &tx,
            &invite,
            &request.request_id,
            &fingerprint(&request.csr_der),
            now,
        )?;
        tx.execute(
            "DELETE FROM challenges WHERE deadline<=?1 OR consumed=1",
            [now],
        )?;
        quota(&tx, "challenges", 256)?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM challenges WHERE invite_id=?1",
            [&request.invite_id],
            |r| r.get(0),
        )?;
        if count >= 8 {
            return Err(error("enrollment_denied"));
        }
        let challenge = RecoveryChallenge {
            nonce: random_id()?,
            deadline: now
                .checked_add(CHALLENGE_SECONDS)
                .ok_or_else(|| error("invalid_time"))?
                .min(invite.recovery_until.unwrap_or(0)),
        };
        tx.execute("INSERT INTO challenges(nonce,invite_id,request_id,csr_digest,deadline,consumed) VALUES(?1,?2,?3,?4,?5,0)", params![challenge.nonce,request.invite_id,request.request_id,fingerprint(&request.csr_der),challenge.deadline])?;
        tx.commit()?;
        Ok(challenge)
    }
    pub fn recover(&self, request: &RecoveryRequest, now: i64) -> Result<EnrollmentResponse> {
        validate_request(
            request.version,
            &request.invite_id,
            &request.request_id,
            &request.csr_der,
            now,
        )?;
        if request.signature.is_empty()
            || request.signature.len() > 128
            || !valid_id(&request.challenge.nonce)
            || request.challenge.deadline <= now
        {
            return Err(error("enrollment_denied"));
        }
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let invite = invite_tx(&tx, &request.invite_id)?;
        let digest = fingerprint(&request.csr_der);
        let response = committed_response(&tx, &invite, &request.request_id, &digest, now)?;
        let consumed = tx.execute("UPDATE challenges SET consumed=1 WHERE nonce=?1 AND invite_id=?2 AND request_id=?3 AND csr_digest=?4 AND deadline=?5 AND consumed=0 AND deadline>?6", params![request.challenge.nonce,request.invite_id,request.request_id,digest,request.challenge.deadline,now])?;
        if consumed != 1 {
            return Err(error("enrollment_denied"));
        }
        let challenge_request = RecoveryChallengeRequest {
            version: request.version,
            invite_id: request.invite_id.clone(),
            request_id: request.request_id.clone(),
            csr_der: request.csr_der.clone(),
        };
        let message = recovery_message(&challenge_request, &request.challenge)?;
        let proof = pairing_crypto::verify_recovery_signature(
            &request.csr_der,
            &message,
            &request.signature,
        );
        // Consume even a bad proof; rollback must not make a tried challenge reusable.
        tx.commit()?;
        proof?;
        Ok(response)
    }
    pub fn revoke(&self, device: &str, now: i64) -> Result<()> {
        valid_name(device)?;
        if now < 0 {
            return Err(error("invalid_time"));
        }
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.execute(
            "UPDATE devices SET state='revoked' WHERE device=?1",
            [device],
        )? != 1
        {
            return Err(error("unknown_device"));
        }
        tx.execute(
            "UPDATE certificates SET revoked=1 WHERE device=?1",
            [device],
        )?;
        tx.execute("UPDATE invites SET state='revoked' WHERE device=?1 AND state IN ('pending','committed')",[device])?;
        tx.execute("DELETE FROM challenges WHERE invite_id IN (SELECT invite_id FROM invites WHERE device=?1)",[device])?;
        tx.commit()?;
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<DeviceRecord>> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let mut statement =
            conn.prepare("SELECT device,state,generation FROM devices ORDER BY device")?;
        let rows = statement.query_map([], |r| {
            Ok(DeviceRecord {
                device: r.get(0)?,
                state: r.get(1)?,
                generation: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn authorize(&self, fingerprint: &str, project: &str) -> Result<Peer> {
        if !valid_id(fingerprint) {
            return Err(error("forbidden"));
        }
        let conn = self
            .connection
            .lock()
            .map_err(|_| error("pairing_store_unavailable"))?;
        let binding: String =
            conn.query_row("SELECT binding FROM authority WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        let binding: AuthorityBinding = serde_json::from_str(&binding)?;
        if binding.project != project {
            return Err(error("forbidden"));
        }
        let device: Option<String> = conn.query_row("SELECT c.device FROM certificates c JOIN devices d ON d.device=c.device WHERE c.fingerprint=?1 AND c.revoked=0 AND d.state='active' AND d.generation=c.generation AND c.not_after>?2",params![fingerprint,unix_now()?],|r|r.get(0)).optional()?;
        Ok(Peer {
            device: device.ok_or_else(|| error("forbidden"))?,
            project: project.to_owned(),
            role: "client".into(),
            revoked: false,
        })
    }
}

// Refuse an unsendable response before committing certificate authorization.
fn bounded_enrollment_response(response: &EnrollmentResponse) -> Result<String> {
    let encoded = serde_json::to_string(response)?;
    if encoded.len() > MAX_ENROLLMENT_RESPONSE_BYTES {
        return Err(error("enrollment_response_bound"));
    }
    Ok(encoded)
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(2))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "trusted_schema", false)?;
    Ok(())
}
fn validate_database(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let application: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    if version != 1 || application != APPLICATION_ID {
        return Err(error("unsupported_pairing_database"));
    }
    Ok(())
}
fn quota(tx: &Transaction<'_>, table: &str, max: i64) -> Result<()> {
    // table is selected exclusively by this module, never by request input.
    let count: i64 = tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
    if count >= max {
        return Err(error("pairing_quota_exceeded"));
    }
    Ok(())
}
fn binding_tx(tx: &Transaction<'_>) -> Result<AuthorityBinding> {
    let binding: String =
        tx.query_row("SELECT binding FROM authority WHERE singleton=1", [], |r| {
            r.get(0)
        })?;
    Ok(serde_json::from_str(&binding)?)
}
fn next_generation(tx: &Transaction<'_>, scope: &InviteScope) -> Result<u64> {
    let row: Option<(String, u64)> = tx
        .query_row(
            "SELECT state,generation FROM devices WHERE device=?1",
            [&scope.client_device],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (state, generation) = row.ok_or_else(|| error("device_not_reserved"))?;
    match scope.purpose {
        InvitePurpose::New if state == "reserved" && generation == 0 => Ok(1),
        InvitePurpose::Rotate {
            expected_generation,
        } if (state == "active" || state == "revoked")
            && generation == expected_generation
            && generation > 0
            && generation < i64::MAX as u64 =>
        {
            Ok(generation + 1)
        }
        _ => Err(error("device_generation_conflict")),
    }
}
fn create_invite_tx(
    tx: &Transaction<'_>,
    scope: InviteScope,
    expires_at: i64,
    now: i64,
) -> Result<Invite> {
    scope.validate()?;
    if now < 0
        || expires_at <= now
        || expires_at - now > MAX_INVITE_SECONDS
        || scope.binding() != binding_tx(tx)?
    {
        return Err(error("invalid_invite_scope"));
    }
    next_generation(tx, &scope)?;
    quota(tx, "invites", MAX_INVITES)?;
    tx.execute(
        "UPDATE invites SET state='expired' WHERE device=?1 AND state='pending' AND expires_at<=?2",
        params![scope.client_device, now],
    )?;
    let pending: i64 = tx.query_row(
        "SELECT count(*) FROM invites WHERE device=?1 AND state='pending'",
        [&scope.client_device],
        |r| r.get(0),
    )?;
    if pending != 0 {
        return Err(error("device_invite_pending"));
    }
    let invite = Invite {
        version: VERSION,
        invite_id: random_id()?,
        secret: random_id()?,
        expires_at,
        scope,
    };
    tx.execute("INSERT INTO invites(invite_id,secret_hash,device,scope,expires_at,state) VALUES(?1,?2,?3,?4,?5,'pending')",params![invite.invite_id,secret_digest(&invite.invite_id, &invite.secret).as_slice(),invite.scope.client_device,serde_json::to_string(&invite.scope)?,expires_at])?;
    Ok(invite)
}
struct StoredInvite {
    secret_hash: Vec<u8>,
    scope: String,
    expires_at: i64,
    state: String,
    request_id: Option<String>,
    csr_digest: Option<String>,
    response: Option<String>,
    recovery_until: Option<i64>,
    generation: Option<u64>,
}
fn invite_tx(tx: &Transaction<'_>, id: &str) -> Result<StoredInvite> {
    tx.query_row("SELECT secret_hash,scope,expires_at,state,request_id,csr_digest,response,recovery_until,generation FROM invites WHERE invite_id=?1",[id],|r|Ok(StoredInvite {
        secret_hash:r.get(0)?,scope:r.get(1)?,expires_at:r.get(2)?,state:r.get(3)?,request_id:r.get(4)?,
        csr_digest:r.get(5)?,response:r.get(6)?,recovery_until:r.get(7)?,generation:r.get(8)?,
    })).optional()?.ok_or_else(||error("enrollment_denied"))
}
fn committed_response(
    tx: &Transaction<'_>,
    invite: &StoredInvite,
    request: &str,
    digest: &str,
    now: i64,
) -> Result<EnrollmentResponse> {
    if invite.state != "committed"
        || invite.request_id.as_deref() != Some(request)
        || invite.csr_digest.as_deref() != Some(digest)
        || now >= invite.recovery_until.unwrap_or(0)
    {
        return Err(error("enrollment_denied"));
    }
    let response: EnrollmentResponse = serde_json::from_str(
        invite
            .response
            .as_deref()
            .ok_or_else(|| error("enrollment_denied"))?,
    )?;
    if response.scope.binding() != binding_tx(tx)? || Some(response.generation) != invite.generation
    {
        return Err(error("enrollment_denied"));
    }
    let active:i64 = tx.query_row("SELECT count(*) FROM certificates c JOIN devices d ON d.device=c.device WHERE c.fingerprint=?1 AND c.device=?2 AND c.generation=?3 AND c.revoked=0 AND d.state='active' AND d.generation=c.generation AND c.not_after>?4",params![response.fingerprint,response.scope.client_device,response.generation,now],|r|r.get(0))?;
    if active != 1 {
        return Err(error("enrollment_denied"));
    }
    Ok(response)
}
fn check_private_path(path: &Path, must_exist: bool) -> Result<()> {
    crate::pairing_files::validate_private_dir(
        path.parent().ok_or_else(|| error("invalid_store_path"))?,
    )?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => crate::pairing_files::validate_private_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !must_exist => {}
        Err(e) => return Err(e.into()),
    }
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) if suffix == "-journal" => crate::pairing_files::validate_private_file(&sidecar)?,
            Ok(_) => return Err(error("unexpected_pairing_wal_sidecar")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
const SCHEMA: &str = r#"
BEGIN IMMEDIATE;
PRAGMA application_id=1464881201;
PRAGMA user_version=1;
CREATE TABLE authority(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binding TEXT NOT NULL);
CREATE TABLE devices(device TEXT PRIMARY KEY,state TEXT NOT NULL CHECK(state IN ('reserved','active','revoked')),generation INTEGER NOT NULL CHECK(generation>=0));
CREATE TABLE invites(
 invite_id TEXT PRIMARY KEY CHECK(length(invite_id)=64),secret_hash BLOB NOT NULL CHECK(length(secret_hash)=32),
 device TEXT NOT NULL REFERENCES devices(device),scope TEXT NOT NULL,expires_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','committed','revoked','expired','cancelled')),
 request_id TEXT,csr_digest TEXT,key_digest TEXT,response TEXT,recovery_until INTEGER,generation INTEGER,attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 16),
 CHECK(state!='committed' OR (request_id IS NOT NULL AND csr_digest IS NOT NULL AND key_digest IS NOT NULL AND response IS NOT NULL AND recovery_until IS NOT NULL AND generation IS NOT NULL))
);
CREATE UNIQUE INDEX one_pending_invite ON invites(device) WHERE state='pending';
CREATE TABLE certificates(fingerprint TEXT PRIMARY KEY CHECK(length(fingerprint)=64),device TEXT NOT NULL REFERENCES devices(device),generation INTEGER NOT NULL CHECK(generation>0),revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),not_after INTEGER NOT NULL,UNIQUE(device,generation));
CREATE UNIQUE INDEX one_active_certificate ON certificates(device) WHERE revoked=0;
CREATE TABLE challenges(nonce TEXT PRIMARY KEY CHECK(length(nonce)=64),invite_id TEXT NOT NULL REFERENCES invites(invite_id),request_id TEXT NOT NULL,csr_digest TEXT NOT NULL,deadline INTEGER NOT NULL,consumed INTEGER NOT NULL CHECK(consumed IN (0,1)));
COMMIT;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing_crypto::{generate_bootstrap, generate_local_csr, sign_recovery, LocalCsr};
    use std::sync::{Arc, Barrier};
    struct Fixture {
        _temp: tempfile::TempDir,
        path: PathBuf,
        store: PairingStore,
        issuer: Issuer,
        scope: InviteScope,
        now: i64,
    }
    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().canonicalize().unwrap().join("private");
        crate::pairing_files::ensure_private_dir(&private).unwrap();
        let path = private.join("pairing.sqlite3");
        let store = PairingStore::open(&path).unwrap();
        let now = unix_now().unwrap();
        let bootstrap = generate_bootstrap(&["localhost".into()], now).unwrap();
        let issuer = Issuer::from_pem(&bootstrap.ca_pem, &bootstrap.ca_key_pem, now).unwrap();
        let scope = InviteScope {
            project: "project".into(),
            authority: "authority".into(),
            epoch: 1,
            authority_device: "coordinator".into(),
            client_device: "client".into(),
            purpose: InvitePurpose::New,
            enrollment_address: "127.0.0.1:4433".parse().unwrap(),
            enrollment_server_name: "localhost".into(),
            enrollment_leaf_pin: fingerprint(&bootstrap.server_certificate_der),
            sync_address: "127.0.0.1:4434".parse().unwrap(),
            sync_server_name: "localhost".into(),
            sync_leaf_pin: fingerprint(&bootstrap.server_certificate_der),
            ca_certificate_der: bootstrap.ca_certificate_der,
            certificate_lifetime_secs: 7 * 86400,
        };
        store.initialize(&scope.binding()).unwrap();
        store.reserve_device("client").unwrap();
        Fixture {
            _temp: temp,
            path,
            store,
            issuer,
            scope,
            now,
        }
    }
    fn request(invite: &Invite, key: &LocalCsr) -> RedeemRequest {
        RedeemRequest {
            version: VERSION,
            invite_id: invite.invite_id.clone(),
            secret: invite.secret.clone(),
            request_id: random_id().unwrap(),
            csr_der: key.csr_der.clone(),
        }
    }
    fn challenge_request(request: &RedeemRequest) -> RecoveryChallengeRequest {
        RecoveryChallengeRequest {
            version: request.version,
            invite_id: request.invite_id.clone(),
            request_id: request.request_id.clone(),
            csr_der: request.csr_der.clone(),
        }
    }
    fn proof(
        store: &PairingStore,
        request: &RedeemRequest,
        key: &LocalCsr,
        now: i64,
    ) -> RecoveryRequest {
        let r = challenge_request(request);
        let challenge = store.recovery_challenge(&r, now).unwrap();
        let signature =
            sign_recovery(&key.key_pem, &recovery_message(&r, &challenge).unwrap()).unwrap();
        RecoveryRequest {
            version: VERSION,
            invite_id: r.invite_id,
            request_id: r.request_id,
            csr_der: r.csr_der,
            challenge,
            signature,
        }
    }
    #[test]
    fn reserve_and_invite_never_grant_access_and_secret_is_hashed_and_redacted() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        assert!(f.store.authorize(&"a".repeat(64), "project").is_err());
        assert!(!format!("{invite:?}").contains(&invite.secret));
        let c = f.store.connection.lock().unwrap();
        let hash: Vec<u8> = c
            .query_row("SELECT secret_hash FROM invites", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hash, secret_digest(&invite.invite_id, &invite.secret));
        assert_ne!(hash, secret_digest(&"0".repeat(64), &invite.secret));
        assert!(!std::fs::read(&f.path)
            .unwrap()
            .windows(invite.secret.len())
            .any(|w| w == invite.secret.as_bytes()));
    }
    #[test]
    fn exact_retry_and_recovery_after_expiry_survive_reopen() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 10, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let request = request(&invite, &key);
        let response = f.store.redeem(&request, &f.issuer, f.now).unwrap();
        let bytes = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            bytes,
            serde_json::to_vec(&f.store.redeem(&request, &f.issuer, f.now + 1).unwrap()).unwrap()
        );
        assert!(f.store.redeem(&request, &f.issuer, f.now + 11).is_err());
        let reopened = PairingStore::open(&f.path).unwrap();
        let proof = proof(&reopened, &request, &key, f.now + 11);
        assert_eq!(
            bytes,
            serde_json::to_vec(&reopened.recover(&proof, f.now + 11).unwrap()).unwrap()
        );
        assert!(reopened.recover(&proof, f.now + 11).is_err());
        assert!(reopened
            .recovery_challenge(&challenge_request(&request), f.now + RECOVERY_SECONDS)
            .is_err());
        let c = reopened.connection.lock().unwrap();
        let count: i64 = c
            .query_row("SELECT count(*) FROM certificates", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
    #[test]
    fn expired_uncommitted_and_wrong_secret_cannot_enroll_or_recover() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 10, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let mut r = request(&invite, &key);
        r.secret = "0".repeat(64);
        assert!(f.store.redeem(&r, &f.issuer, f.now).is_err());
        r.secret = invite.secret;
        assert!(f.store.redeem(&r, &f.issuer, f.now + 10).is_err());
        assert!(f
            .store
            .recovery_challenge(&challenge_request(&r), f.now + 11)
            .is_err());
        assert_eq!(f.store.list().unwrap()[0].state, "reserved");
    }
    #[test]
    fn competing_request_and_csr_cannot_replace_committed_response() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let r = request(&invite, &key);
        let response = f.store.redeem(&r, &f.issuer, f.now).unwrap();
        let mut other = r.clone();
        other.request_id = random_id().unwrap();
        assert!(f.store.redeem(&other, &f.issuer, f.now).is_err());
        other = r.clone();
        other.csr_der = generate_local_csr().unwrap().csr_der;
        assert!(f.store.redeem(&other, &f.issuer, f.now).is_err());
        assert!(f
            .store
            .recovery_challenge(&challenge_request(&other), f.now)
            .is_err());
        assert_eq!(f.store.redeem(&r, &f.issuer, f.now).unwrap(), response);
    }
    #[test]
    fn wrong_key_consumes_challenge_and_changed_deadline_or_nonce_fails() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let r = request(&invite, &key);
        f.store.redeem(&r, &f.issuer, f.now).unwrap();
        let mut p = proof(&f.store, &r, &key, f.now);
        let good_signature = p.signature.clone();
        let bad_key = generate_local_csr().unwrap();
        p.signature = sign_recovery(
            &bad_key.key_pem,
            &recovery_message(&challenge_request(&r), &p.challenge).unwrap(),
        )
        .unwrap();
        assert!(f.store.recover(&p, f.now).is_err());
        p.signature = good_signature;
        assert!(f.store.recover(&p, f.now).is_err());
        let mut p = proof(&f.store, &r, &key, f.now);
        p.challenge.deadline += 1;
        assert!(f.store.recover(&p, f.now).is_err());
        p.challenge.nonce = random_id().unwrap();
        assert!(f.store.recover(&p, f.now).is_err());
    }
    #[test]
    fn revoke_is_immediate_and_permanent_and_blocks_recovery() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let r = request(&invite, &key);
        let response = f.store.redeem(&r, &f.issuer, f.now).unwrap();
        let reader = PairingStore::open_existing(&f.path).unwrap();
        assert!(reader.authorize(&response.fingerprint, "project").is_ok());
        let p = proof(&f.store, &r, &key, f.now);
        f.store.revoke("client", f.now + 1).unwrap();
        assert!(reader.authorize(&response.fingerprint, "project").is_err());
        assert!(f.store.recover(&p, f.now + 1).is_err());
        assert!(f.store.reserve_device("client").is_err());
        assert!(f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now + 1)
            .is_err());
        assert_eq!(f.store.list().unwrap()[0].state, "revoked");
    }
    #[test]
    fn rotation_preserves_device_and_revokes_exact_old_generation() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let r = request(&invite, &key);
        let old = f.store.redeem(&r, &f.issuer, f.now).unwrap();
        let p = proof(&f.store, &r, &key, f.now);
        assert!(f
            .store
            .rotate_invite("client", 2, f.now + 60, f.now)
            .is_err());
        let rotate = f
            .store
            .rotate_invite("client", 1, f.now + 60, f.now)
            .unwrap();
        let replacement = generate_local_csr().unwrap();
        let rr = request(&rotate, &replacement);
        let new = f.store.redeem(&rr, &f.issuer, f.now).unwrap();
        assert_eq!(new.generation, 2);
        assert_eq!(new.scope.client_device, old.scope.client_device);
        assert_ne!(new.fingerprint, old.fingerprint);
        assert!(f.store.authorize(&old.fingerprint, "project").is_err());
        assert!(f.store.authorize(&new.fingerprint, "project").is_ok());
        assert!(f.store.recover(&p, f.now).is_err());
        assert!(f.store.redeem(&r, &f.issuer, f.now).is_err());
    }
    #[test]
    fn revocation_invalidates_pending_rotation() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        f.store
            .redeem(&request(&invite, &key), &f.issuer, f.now)
            .unwrap();
        let rotate = f
            .store
            .rotate_invite("client", 1, f.now + 60, f.now)
            .unwrap();
        f.store.revoke("client", f.now).unwrap();
        assert!(f
            .store
            .redeem(&request(&rotate, &key), &f.issuer, f.now)
            .is_err());
        // A fresh explicit rotation is the only way to replace a retired credential.
        let replacement = f
            .store
            .rotate_invite("client", 1, f.now + 60, f.now)
            .unwrap();
        assert_eq!(
            f.store
                .redeem(&request(&replacement, &key), &f.issuer, f.now)
                .unwrap()
                .generation,
            2
        );
    }
    #[test]
    fn concurrent_redemptions_have_one_winner_across_connections() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let a = request(&invite, &generate_local_csr().unwrap());
        let b = request(&invite, &generate_local_csr().unwrap());
        let store_a = PairingStore::open(&f.path).unwrap();
        let store_b = PairingStore::open(&f.path).unwrap();
        let issuer = Arc::new(f.issuer);
        let barrier = Arc::new(Barrier::new(2));
        let now = f.now;
        let one = {
            let issuer = issuer.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store_a.redeem(&a, &issuer, now).is_ok()
            })
        };
        let two = std::thread::spawn(move || {
            barrier.wait();
            store_b.redeem(&b, &issuer, now).is_ok()
        });
        assert_ne!(one.join().unwrap(), two.join().unwrap());
        assert_eq!(f.store.list().unwrap()[0].generation, 1);
    }
    #[test]
    fn cancelled_export_can_retry_without_retiring_identity_or_active_certificate() {
        let f = fixture();
        let lost = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        assert_eq!(f.store.cancel_pending_invite("client").unwrap(), 1);
        let key = generate_local_csr().unwrap();
        assert!(f
            .store
            .redeem(&request(&lost, &key), &f.issuer, f.now)
            .is_err());
        assert_eq!(f.store.list().unwrap()[0].state, "reserved");
        let fresh = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let response = f
            .store
            .redeem(&request(&fresh, &key), &f.issuer, f.now)
            .unwrap();
        f.store
            .rotate_invite("client", 1, f.now + 60, f.now)
            .unwrap();
        assert_eq!(f.store.cancel_pending_invite("client").unwrap(), 1);
        assert!(f.store.authorize(&response.fingerprint, "project").is_ok());
        assert_eq!(f.store.list().unwrap()[0].generation, 1);
    }
    #[test]
    fn invalid_csr_budget_persists_and_never_grants() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let mut r = request(&invite, &key);
        r.csr_der = vec![0];
        for _ in 0..16 {
            assert!(f.store.redeem(&r, &f.issuer, f.now).is_err());
        }
        let reopened = PairingStore::open(&f.path).unwrap();
        r.csr_der = key.csr_der;
        assert!(reopened.redeem(&r, &f.issuer, f.now).is_err());
        assert_eq!(reopened.list().unwrap()[0].state, "reserved");
    }
    #[test]
    fn quota_and_scope_and_binding_fail_closed() {
        let f = fixture();
        let mut wrong = f.scope.binding();
        wrong.epoch = 2;
        assert!(f.store.initialize(&wrong).is_err());
        let mut wrong = f.scope.clone();
        wrong.epoch = 2;
        assert!(f.store.create_invite(wrong, f.now + 10, f.now).is_err());
        for i in 1..MAX_DEVICES {
            f.store.reserve_device(&format!("device{i}")).unwrap();
        }
        assert!(f.store.reserve_device("overflow").is_err());
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let r = request(&invite, &key);
        f.store.redeem(&r, &f.issuer, f.now).unwrap();
        for _ in 0..8 {
            f.store
                .recovery_challenge(&challenge_request(&r), f.now)
                .unwrap();
        }
        assert!(f
            .store
            .recovery_challenge(&challenge_request(&r), f.now)
            .is_err());
        assert!(f
            .store
            .recovery_challenge(&challenge_request(&r), f.now + CHALLENGE_SECONDS)
            .is_ok());
    }
    #[test]
    fn readonly_authorization_never_creates_missing_database() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().canonicalize().unwrap().join("private");
        crate::pairing_files::ensure_private_dir(&dir).unwrap();
        let path = dir.join("missing.sqlite3");
        let source = AclSource::Managed {
            managed: path.clone(),
        };
        assert!(source.authorize(b"not-a-cert", "project").is_err());
        assert!(!path.exists());
        crate::pairing_files::create_private_file(&path, b"not SQLite").unwrap();
        let original = std::fs::read(&path).unwrap();
        assert!(PairingStore::open_existing(&path).is_err());
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
    #[test]
    fn transaction_failure_before_response_commit_rolls_back_grant_and_consumption() {
        let f = fixture();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let key = generate_local_csr().unwrap();
        let r = request(&invite, &key);
        f.store.connection.lock().unwrap().execute_batch("CREATE TRIGGER fail_commit BEFORE UPDATE OF response ON invites WHEN NEW.response IS NOT NULL BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;").unwrap();
        assert!(f.store.redeem(&r, &f.issuer, f.now).is_err());
        assert_eq!(f.store.list().unwrap()[0].state, "reserved");
        {
            let c = f.store.connection.lock().unwrap();
            assert_eq!(
                c.query_row("SELECT count(*) FROM certificates", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                c.query_row("SELECT state FROM invites", [], |r| r.get::<_, String>(0))
                    .unwrap(),
                "pending"
            );
            c.execute_batch("DROP TRIGGER fail_commit;").unwrap();
        }
        assert_eq!(f.store.redeem(&r, &f.issuer, f.now).unwrap().generation, 1);
    }
    #[test]
    fn unknown_database_is_not_reconfigured_or_adopted() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().canonicalize().unwrap().join("private");
        crate::pairing_files::ensure_private_dir(&dir).unwrap();
        let path = dir.join("unrelated.sqlite3");
        crate::pairing_files::create_private_file(&path, &[]).unwrap();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE important(value TEXT); INSERT INTO important VALUES('keep'); PRAGMA application_id=123;").unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        assert!(PairingStore::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    #[test]
    fn schema_journal_durability_and_acl_compatibility() {
        let f = fixture();
        let c = f.store.connection.lock().unwrap();
        assert_eq!(
            c.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "persist"
        );
        assert_eq!(
            c.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            c.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        let source: AclSource = serde_json::from_str("\"acl.json\"").unwrap();
        assert_eq!(source.path(), Path::new("acl.json"));
        assert!(serde_json::from_str::<AclSource>(r#"{"managed":"x","extra":true}"#).is_err());
        for bad in ["has.dot", "has space", "ümlaut"] {
            assert!(valid_name(bad).is_err());
        }
    }
    #[test]
    fn oversized_response_never_commits_a_grant() {
        let mut f = fixture();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&[1]));
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "X".repeat(6000));
        let ca = params.self_signed(&key).unwrap();
        f.scope.ca_certificate_der = ca.der().to_vec();
        let issuer = Issuer::from_pem(&ca.pem(), &key.serialize_pem(), f.now).unwrap();
        let invite = f
            .store
            .create_invite(f.scope.clone(), f.now + 60, f.now)
            .unwrap();
        let local = generate_local_csr().unwrap();
        let failure = f
            .store
            .redeem(&request(&invite, &local), &issuer, f.now)
            .unwrap_err();
        assert_eq!(failure.to_string(), "enrollment_response_bound");
        let connection = f.store.connection.lock().unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM certificates", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let state: String = connection
            .query_row("SELECT state FROM invites", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "pending");
    }

    #[cfg(unix)]
    #[test]
    fn insecure_database_or_journal_and_symlink_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let f = fixture();
        let journal = PathBuf::from(format!("{}-journal", f.path.display()));
        assert!(journal.exists());
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(PairingStore::open_existing(&f.path).is_err());
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(PairingStore::open_existing(&f.path).is_err());
        std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = f.path.with_file_name("link.sqlite3");
        symlink(&f.path, &link).unwrap();
        assert!(PairingStore::open(&link).is_err());
    }
}
