//! Persistent subscription metadata; strictly volatile, bounded best-effort delivery.
//! Wire contract: https://developers.openai.com/plugins/build/mcp-events (2026-07-28).
use crate::callback::{self, CallbackRequest, CallbackTransport};
use ring::digest::{digest, SHA256};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const BUFFER_MS: u64 = 300_000;
const DEFAULT_TTL_MS: u64 = 86_400_000;
const MAX_TTL_MS: u64 = 7 * DEFAULT_TTL_MS;
const MIN_TTL_MS: u64 = 60_000;
const VERIFY_CACHE_MS: u64 = 60_000;
const ROTATE_MS: u64 = 60_000;
const MAX_SUBSCRIPTIONS: usize = 4096;
const MAX_CACHE: usize = 1024;
const MAX_ATTEMPTS: u8 = 8;
const NAMES: [&str; 3] = [
    "action_required",
    "proposal.integrated",
    "public_head.advanced",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventError {
    pub code: i64,
    pub message: &'static str,
    pub reason: Option<&'static str>,
}
impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for EventError {}
impl EventError {
    fn invalid() -> Self {
        Self {
            code: -32602,
            message: "Invalid event arguments",
            reason: None,
        }
    }
    fn denied() -> Self {
        Self {
            code: -32001,
            message: "Project access denied",
            reason: None,
        }
    }
    fn storage() -> Self {
        Self {
            code: -32603,
            message: "Event subscription storage unavailable",
            reason: None,
        }
    }
    fn callback(reason: &'static str) -> Self {
        Self {
            code: -32015,
            message: "CallbackEndpointError",
            reason: Some(reason),
        }
    }
}
impl From<rusqlite::Error> for EventError {
    fn from(_: rusqlite::Error) -> Self {
        Self::storage()
    }
}

/// Use current persisted permissions, never claims cached in a bearer token.
pub trait ProjectAccess: Send + Sync {
    fn has_project_access(&self, principal: &str, project: &str) -> bool;
    fn has_any_project_access(&self, principal: &str) -> bool;
    /// Must change on revocation/regrant; None means not currently granted.
    fn project_grant_epoch(&self, principal: &str, project: &str) -> Option<i64>;
    /// For action-required events, suppress observations whose current proposal
    /// state no longer needs attention. Other transition events return true.
    fn event_is_current(&self, event: &SanitizedTransition) -> bool;
}

/// The only input accepted from the event projector. No raw engine JSON can
/// become a webhook. Workspace is used for filtering, never put on the wire.
#[derive(Clone, Debug)]
pub struct SanitizedTransition {
    pub id: String,
    pub name: String,
    pub project: String,
    pub workspace: Option<String>,
    pub proposal: Option<String>,
    pub occurred_at: i64,
    pub status: String,
}
impl SanitizedTransition {
    fn body(&self) -> Result<Vec<u8>, EventError> {
        if !identifier(&self.id)
            || !identifier(&self.project)
            || self.occurred_at < 0
            || self.workspace.as_deref().is_some_and(|s| !identifier(s))
            || self.proposal.as_deref().is_some_and(|s| !identifier(s))
        {
            return Err(EventError::invalid());
        }
        let valid = match self.name.as_str() {
            "action_required" => {
                self.proposal.is_some()
                    && ["conflict", "checks_failed", "policy_error"].contains(&self.status.as_str())
            }
            "proposal.integrated" => {
                self.proposal.is_some()
                    && ["integrated", "already_included"].contains(&self.status.as_str())
            }
            "public_head.advanced" => self.status == "advanced",
            _ => false,
        };
        if !valid {
            return Err(EventError::invalid());
        }
        let mut data = json!({"project_id":self.project,"status":self.status});
        if let Some(proposal) = &self.proposal {
            data["proposal_id"] = json!(proposal);
        }
        let timestamp = iso((self.occurred_at as u64)
            .checked_mul(1000)
            .ok_or_else(EventError::invalid)?)?;
        serde_json::to_vec(&json!({"eventId":self.id,"name":self.name,"timestamp":timestamp,"data":data,"cursor":null}))
            .map_err(|_| EventError::invalid())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proposal_id: Option<String>,
}
impl Scope {
    fn matches(&self, e: &SanitizedTransition) -> bool {
        self.project_id == e.project
            && self
                .proposal_id
                .as_ref()
                .is_none_or(|id| Some(id) == e.proposal.as_ref())
            && self.workspace_id.as_ref().is_none_or(|id| {
                e.name == "public_head.advanced" || Some(id) == e.workspace.as_ref()
            })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    mode: String,
    url: String,
    #[serde(default)]
    secret: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionRequest {
    name: String,
    arguments: Value,
    delivery: Delivery,
    #[serde(default, rename = "ttlMs")]
    ttl_ms: Option<Value>,
    #[serde(default)]
    cursor: Option<Value>,
}
struct Validated {
    name: String,
    scope: Scope,
    args: String,
    url: String,
    secret: Option<String>,
    ttl: u64,
}
fn parse_request(value: Value, subscribe: bool) -> Result<Validated, EventError> {
    let request: SubscriptionRequest =
        serde_json::from_value(value).map_err(|_| EventError::invalid())?;
    if !NAMES.contains(&request.name.as_str())
        || request.delivery.mode != "webhook"
        || request.cursor.is_some_and(|v| !v.is_null())
    {
        return Err(EventError::invalid());
    }
    let scope: Scope =
        serde_json::from_value(request.arguments.clone()).map_err(|_| EventError::invalid())?;
    if !identifier(&scope.project_id)
        || scope
            .workspace_id
            .as_deref()
            .is_some_and(|s| !identifier(s))
        || scope.proposal_id.as_deref().is_some_and(|s| !identifier(s))
        || scope.workspace_id.is_some() && scope.proposal_id.is_some()
    {
        return Err(EventError::invalid());
    }
    let url = callback::validate_callback_url(&request.delivery.url)
        .map_err(|e| EventError::callback(e.reason()))?
        .to_string();
    if subscribe {
        callback::decode_secret(
            request
                .delivery
                .secret
                .as_deref()
                .ok_or_else(EventError::invalid)?,
        )
        .map_err(|_| EventError::invalid())?;
    }
    let ttl = match request.ttl_ms {
        None | Some(Value::Null) => DEFAULT_TTL_MS,
        Some(value) => value
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or_else(EventError::invalid)?
            .clamp(MIN_TTL_MS, MAX_TTL_MS),
    };
    // Re-serialize the validated shape, so omitted optional fields are canonical.
    let args = canonical_json(&serde_json::to_value(&scope).map_err(|_| EventError::invalid())?)?;
    Ok(Validated {
        name: request.name,
        scope,
        args,
        url,
        secret: request.delivery.secret,
        ttl,
    })
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:".contains(&c))
}
fn iso(ms: u64) -> Result<String, EventError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|_| EventError::invalid())?
        .format(&Rfc3339)
        .map_err(|_| EventError::invalid())
}
fn hash(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn canonical_json(value: &Value) -> Result<String, EventError> {
    fn normalize(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let sorted: BTreeMap<_, _> =
                    map.iter().map(|(k, v)| (k.clone(), normalize(v))).collect();
                json!(sorted)
            }
            Value::Array(values) => Value::Array(values.iter().map(normalize).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_string(&normalize(value)).map_err(|_| EventError::invalid())
}
fn subscription_id(principal: &str, v: &Validated) -> String {
    format!(
        "sub_{}",
        hash(
            serde_json::to_string(&(
                "wipstash-subscription-v1",
                principal,
                &v.url,
                &v.name,
                &v.args
            ))
            .expect("string tuple serialization")
            .as_bytes()
        )
    )
}
fn cache_key(principal: &str, url: &str) -> String {
    hash(
        serde_json::to_string(&(principal, url))
            .expect("string tuple serialization")
            .as_bytes(),
    )
}
fn new_revision() -> Result<i64, EventError> {
    let random = callback::random_id("").map_err(|_| EventError::storage())?;
    i64::from_str_radix(&random[..15], 16).map_err(|_| EventError::storage())
}

// Deliberately not Debug: contains callback signing keys.
struct Subscription {
    id: String,
    principal: String,
    scope: Scope,
    url: String,
    secret: String,
    old_secret: Option<String>,
    old_until: u64,
    expires: u64,
    epoch: i64,
    revision: i64,
    created: u64,
}
struct Pending {
    subscription: String,
    event: Arc<SanitizedTransition>,
    body: Arc<Vec<u8>>,
    deadline: u64,
    inserted: Instant,
    next: u64,
    attempts: u8,
    revision: i64,
}
#[derive(Default)]
struct Counters {
    dropped: u64,
    duplicates: u64,
    expired: u64,
    revoked: u64,
    stale: u64,
    failed: u64,
    received: u64,
    storage_faults: u64,
}
struct State {
    db: Connection,
    queue: VecDeque<Pending>,
    seen: HashMap<String, u64>,
    verified: HashMap<String, (String, u64)>,
    counters: Counters,
    starts: u64,
}
pub struct EventService {
    state: Arc<Mutex<State>>,
    grants: Arc<dyn ProjectAccess>,
    transport: Arc<dyn CallbackTransport>,
    capacity: usize,
    degraded: AtomicBool,
    ticking: AtomicBool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Queued(usize),
    Duplicate,
    NoSubscribers,
    Dropped,
}

impl EventService {
    /// Requires an existing private parent directory. Signing keys persist only
    /// in this private SQLite database; event bodies never persist here.
    pub fn open(
        path: impl AsRef<Path>,
        grants: Arc<dyn ProjectAccess>,
        transport: Arc<dyn CallbackTransport>,
        queue_capacity: usize,
    ) -> Result<Self, EventError> {
        let path = path.as_ref();
        let parent = path.parent().ok_or_else(EventError::storage)?;
        wipstash_transport::pairing_files::validate_private_dir(parent)
            .map_err(|_| EventError::storage())?;
        match std::fs::symlink_metadata(path) {
            Ok(_) => wipstash_transport::pairing_files::validate_private_file(path)
                .map_err(|_| EventError::storage())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                wipstash_transport::pairing_files::create_private_file(path, &[])
                    .map_err(|_| EventError::storage())?
            }
            Err(_) => return Err(EventError::storage()),
        }
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            let sidecar = PathBuf::from(name);
            match std::fs::symlink_metadata(&sidecar) {
                Ok(_) if suffix == "-journal" => {
                    wipstash_transport::pairing_files::validate_private_file(&sidecar)
                        .map_err(|_| EventError::storage())?
                }
                Ok(_) => return Err(EventError::storage()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(EventError::storage()),
            }
        }
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_millis(250))?;
        let app: i64 = db.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if app == 0 && version == 0 {
            let tables: i64 = db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )?;
            if tables != 0 {
                return Err(EventError::storage());
            }
        } else if app != 1464421701 || version != 1 {
            return Err(EventError::storage());
        }
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY, principal TEXT NOT NULL, project TEXT NOT NULL, name TEXT NOT NULL, args TEXT NOT NULL, url TEXT NOT NULL, secret TEXT NOT NULL, old_secret TEXT, old_until INTEGER NOT NULL, expires INTEGER NOT NULL, epoch INTEGER NOT NULL, revision INTEGER NOT NULL, created INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS subscription_project ON subscriptions(project,name,expires);
            CREATE TABLE IF NOT EXISTS event_service_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), starts INTEGER NOT NULL);
            INSERT INTO event_service_meta(singleton,starts) VALUES(1,1) ON CONFLICT(singleton) DO UPDATE SET starts=starts+1;
            PRAGMA application_id=1464421701; PRAGMA user_version=1; COMMIT;")?;
        let starts = db.query_row(
            "SELECT starts FROM event_service_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                db,
                queue: VecDeque::new(),
                seen: HashMap::new(),
                verified: HashMap::new(),
                counters: Counters::default(),
                starts,
            })),
            grants,
            transport,
            capacity: queue_capacity.clamp(1, 65_536),
            degraded: AtomicBool::new(starts > 1),
            ticking: AtomicBool::new(false),
        })
    }

    pub async fn rpc(
        &self,
        principal: &str,
        method: &str,
        params: Value,
        now_ms: u64,
    ) -> Result<Value, EventError> {
        if principal.is_empty() || principal.len() > 256 {
            return Err(EventError::denied());
        }
        match method {
            "events/list" => {
                if !params.is_object()
                    || params
                        .as_object()
                        .is_some_and(|o| o.keys().any(|k| k != "cursor"))
                    || params.get("cursor").is_some_and(|v| !v.is_null())
                {
                    return Err(EventError::invalid());
                }
                if !self.grants.has_any_project_access(principal) {
                    return Ok(json!({"events":[]}));
                }
                Ok(event_definitions())
            }
            "events/subscribe" => self.subscribe(principal, params, now_ms).await,
            "events/unsubscribe" => self.unsubscribe(principal, params),
            _ => Err(EventError {
                code: -32601,
                message: "Method not found",
                reason: None,
            }),
        }
    }

    async fn subscribe(
        &self,
        principal: &str,
        params: Value,
        now: u64,
    ) -> Result<Value, EventError> {
        let v = parse_request(params, true)?;
        if !self
            .grants
            .has_project_access(principal, &v.scope.project_id)
        {
            return Err(EventError::denied());
        }
        let epoch = self
            .grants
            .project_grant_epoch(principal, &v.scope.project_id)
            .ok_or_else(EventError::denied)?;
        let id = subscription_id(principal, &v);
        let secret = v.secret.as_deref().ok_or_else(EventError::invalid)?;
        let cache = cache_key(principal, &v.url);
        let key_hash = hash(secret.as_bytes());
        let verified = {
            let mut state = self.state.lock().map_err(|_| EventError::storage())?;
            state.verified.retain(|_, (_, until)| *until > now);
            state
                .verified
                .get(&cache)
                .is_some_and(|(key, _)| key == &key_hash)
        };
        if !verified {
            let challenge =
                callback::random_id("challenge_").map_err(|e| EventError::callback(e.reason()))?;
            let webhook_id = callback::random_id("msg_verification_")
                .map_err(|e| EventError::callback(e.reason()))?;
            let body = serde_json::to_vec(&json!({"type":"verification","challenge":challenge}))
                .map_err(|_| EventError::invalid())?;
            let signature = callback::sign(secret, &webhook_id, now / 1000, &body)
                .map_err(|e| EventError::callback(e.reason()))?;
            let access = self.grants.clone();
            let owner = principal.to_owned();
            let project = v.scope.project_id.clone();
            let request = CallbackRequest {
                url: v.url.clone(),
                body,
                webhook_id,
                timestamp: now / 1000,
                signature,
                subscription_id: id.clone(),
                authorized: Arc::new(move || {
                    access.has_project_access(&owner, &project)
                        && access.project_grant_epoch(&owner, &project) == Some(epoch)
                }),
            };
            let response =
                tokio::time::timeout(Duration::from_secs(10), self.transport.post(request))
                    .await
                    .map_err(|_| EventError::callback("timeout"))?
                    .map_err(|e| EventError::callback(e.reason()))?;
            if !(200..300).contains(&response.status) || response.body.len() > 4096 {
                return Err(EventError::callback("challenge_failed"));
            }
            let echoed: Value = serde_json::from_slice(&response.body)
                .map_err(|_| EventError::callback("challenge_failed"))?;
            let echoed = echoed
                .get("challenge")
                .and_then(Value::as_str)
                .ok_or_else(|| EventError::callback("challenge_failed"))?;
            if !bool::from(challenge.as_bytes().ct_eq(echoed.as_bytes())) {
                return Err(EventError::callback("challenge_failed"));
            }
        }
        // Authorization can change while callback verification is in flight.
        if !self
            .grants
            .has_project_access(principal, &v.scope.project_id)
            || self
                .grants
                .project_grant_epoch(principal, &v.scope.project_id)
                != Some(epoch)
        {
            return Err(EventError::denied());
        }
        let expires = now.checked_add(v.ttl).ok_or_else(EventError::invalid)?;
        let refresh = iso(expires)?;
        let mut state = self.state.lock().map_err(|_| EventError::storage())?;
        state
            .db
            .execute("DELETE FROM subscriptions WHERE expires<=?1", params![now])?;
        let previous = read_subscription(&state.db, &id)?;
        if previous.is_none() {
            let count: usize =
                state
                    .db
                    .query_row("SELECT count(*) FROM subscriptions", [], |r| r.get(0))?;
            if count >= MAX_SUBSCRIPTIONS {
                return Err(EventError {
                    code: -32000,
                    message: "Subscription capacity reached",
                    reason: None,
                });
            }
        }
        let replaced_generation = previous.as_ref().is_some_and(|p| p.epoch != epoch);
        // New creations, including unsubscribe/recreate and regrant, must not
        // revive a delivery already dequeued by another task.
        let revision = match previous.as_ref() {
            Some(p) if !replaced_generation => p.revision,
            _ => new_revision()?,
        };
        let created = match previous.as_ref() {
            Some(p) if !replaced_generation => p.created,
            _ => now,
        };
        let (old_secret, old_until) = match previous.as_ref() {
            Some(p) if p.epoch == epoch && p.secret != secret => {
                (Some(p.secret.clone()), now.saturating_add(ROTATE_MS))
            }
            Some(p) if p.epoch == epoch && p.old_until > now => (p.old_secret.clone(), p.old_until),
            _ => (None, 0),
        };
        state.db.execute("INSERT INTO subscriptions(id,principal,project,name,args,url,secret,old_secret,old_until,expires,epoch,revision,created) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret,old_secret=excluded.old_secret,old_until=excluded.old_until,expires=excluded.expires,epoch=excluded.epoch,revision=excluded.revision,created=excluded.created",
            params![id,principal,v.scope.project_id,v.name,v.args,v.url,secret,old_secret,old_until,expires,epoch,revision,created])?;
        if replaced_generation {
            state.queue.retain(|p| p.subscription != id);
        }
        // A cache hit must never extend the original proof lifetime.
        if !verified {
            if state.verified.len() >= MAX_CACHE {
                if let Some(key) = state
                    .verified
                    .iter()
                    .min_by_key(|(_, (_, until))| *until)
                    .map(|(key, _)| key.clone())
                {
                    state.verified.remove(&key);
                }
            }
            state
                .verified
                .insert(cache, (key_hash, now.saturating_add(VERIFY_CACHE_MS)));
        }
        Ok(json!({"id":id,"refreshBefore":refresh,"cursor":null,"truncated":false}))
    }

    fn unsubscribe(&self, principal: &str, params: Value) -> Result<Value, EventError> {
        let v = parse_request(params, false)?;
        // Ownership is bound into the identity. Revoked owners may still delete
        // their own subscription; they cannot address another owner's record.
        let id = subscription_id(principal, &v);
        let mut state = self.state.lock().map_err(|_| EventError::storage())?;
        state.db.execute(
            "DELETE FROM subscriptions WHERE id=?1 AND principal=?2",
            params![id, principal],
        )?;
        state.queue.retain(|p| p.subscription != id);
        Ok(json!({}))
    }

    /// Failure never escapes to the integration authority. Old observations are
    /// dropped, overflow drops the new delivery, and status reports degradation.
    pub fn ingest(&self, event: SanitizedTransition, now: u64) -> EnqueueOutcome {
        let body = match event.body() {
            Ok(body) if body.len() <= callback::MAX_BODY_BYTES => Arc::new(body),
            _ => {
                self.degraded.store(true, Ordering::Relaxed);
                return EnqueueOutcome::Dropped;
            }
        };
        let occurred = match u64::try_from(event.occurred_at)
            .ok()
            .and_then(|n| n.checked_mul(1000))
        {
            Some(v) => v,
            None => {
                self.degraded.store(true, Ordering::Relaxed);
                return EnqueueOutcome::Dropped;
            }
        };
        if occurred > now.saturating_add(1000) || now.saturating_sub(occurred) >= BUFFER_MS {
            self.degraded.store(true, Ordering::Relaxed);
            return EnqueueOutcome::Dropped;
        }
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => {
                self.degraded.store(true, Ordering::Relaxed);
                return EnqueueOutcome::Dropped;
            }
        };
        prune(&mut state, now, &self.degraded);
        if state.seen.contains_key(&event.id) {
            state.counters.duplicates += 1;
            return EnqueueOutcome::Duplicate;
        }
        if state.seen.len() >= self.capacity.saturating_mul(2) {
            state.counters.dropped += 1;
            self.degraded.store(true, Ordering::Relaxed);
            return EnqueueOutcome::Dropped;
        }
        let subscriptions = match matching_subscriptions(&state.db, &event, now) {
            Ok(s) => s,
            Err(_) => {
                state.counters.storage_faults += 1;
                self.degraded.store(true, Ordering::Relaxed);
                return EnqueueOutcome::Dropped;
            }
        };
        let deadline = now
            .saturating_add(BUFFER_MS)
            .min(occurred.saturating_add(BUFFER_MS));
        state.seen.insert(event.id.clone(), deadline);
        let event = Arc::new(event);
        let mut queued = 0;
        let mut dropped = false;
        for subscription in subscriptions {
            // Never turn delayed source polling into replay for a new subscriber.
            // Second-resolution source times are conservatively excluded if the
            // subscription began later within that same second.
            if occurred < subscription.created
                || !subscription.scope.matches(&event)
                || !self
                    .grants
                    .has_project_access(&subscription.principal, &event.project)
                || self
                    .grants
                    .project_grant_epoch(&subscription.principal, &event.project)
                    != Some(subscription.epoch)
            {
                continue;
            }
            if state.queue.len() >= self.capacity {
                state.counters.dropped += 1;
                dropped = true;
                continue;
            }
            state.queue.push_back(Pending {
                subscription: subscription.id,
                event: event.clone(),
                body: body.clone(),
                deadline,
                inserted: Instant::now(),
                next: now,
                attempts: 0,
                revision: subscription.revision,
            });
            queued += 1;
        }
        if dropped {
            self.degraded.store(true, Ordering::Relaxed);
        }
        if queued > 0 {
            EnqueueOutcome::Queued(queued)
        } else if dropped {
            EnqueueOutcome::Dropped
        } else {
            EnqueueOutcome::NoSubscribers
        }
    }

    /// Call regularly from an independent task. At most one pump runs at once;
    /// every attempt re-reads subscription ownership, expiry and current grants.
    pub async fn tick(&self, now: u64) {
        if self.ticking.swap(true, Ordering::Acquire) {
            return;
        }
        struct PumpGuard<'a>(&'a AtomicBool);
        impl Drop for PumpGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _guard = PumpGuard(&self.ticking);
        let started = Instant::now();
        // One bounded batch per tick prevents a busy producer starving requests.
        for _ in 0..64 {
            let current =
                now.saturating_add(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            let pending = {
                let mut state = match self.state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        self.degraded.store(true, Ordering::Relaxed);
                        return;
                    }
                };
                prune(&mut state, current, &self.degraded);
                let Some(index) = state.queue.iter().position(|p| p.next <= current) else {
                    return;
                };
                state.queue.remove(index).expect("queue index exists")
            };
            let subscription = {
                let mut state = match self.state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        self.degraded.store(true, Ordering::Relaxed);
                        return;
                    }
                };
                match read_subscription(&state.db, &pending.subscription) {
                    Ok(Some(s)) => s,
                    Ok(None) => {
                        state.counters.revoked += 1;
                        continue;
                    }
                    Err(_) => {
                        state.counters.storage_faults += 1;
                        self.degraded.store(true, Ordering::Relaxed);
                        continue;
                    }
                }
            };
            if subscription.expires <= current
                || subscription.revision != pending.revision
                || !self
                    .grants
                    .has_project_access(&subscription.principal, &pending.event.project)
                || self
                    .grants
                    .project_grant_epoch(&subscription.principal, &pending.event.project)
                    != Some(subscription.epoch)
            {
                if let Ok(mut state) = self.state.lock() {
                    state.counters.revoked += 1;
                }
                continue;
            }
            if !self.grants.event_is_current(&pending.event) {
                if let Ok(mut state) = self.state.lock() {
                    state.counters.stale += 1;
                }
                continue;
            }
            let mut signature = match callback::sign(
                &subscription.secret,
                &pending.event.id,
                current / 1000,
                &pending.body,
            ) {
                Ok(s) => s,
                Err(_) => {
                    self.degraded.store(true, Ordering::Relaxed);
                    continue;
                }
            };
            if subscription.old_until > current {
                if let Some(old) = &subscription.old_secret {
                    match callback::sign(old, &pending.event.id, current / 1000, &pending.body) {
                        Ok(s) => {
                            signature.push(' ');
                            signature.push_str(&s);
                        }
                        Err(_) => {
                            self.degraded.store(true, Ordering::Relaxed);
                            continue;
                        }
                    }
                }
            }
            let access = self.grants.clone();
            let owner = subscription.principal.clone();
            let event = pending.event.clone();
            let epoch = subscription.epoch;
            let shared = self.state.clone();
            let sub_id = subscription.id.clone();
            let revision = subscription.revision;
            let expiry = subscription.expires;
            let deadline = pending.deadline;
            let inserted = pending.inserted;
            let check_started = Instant::now();
            let request = CallbackRequest {
                url: subscription.url,
                body: (*pending.body).clone(),
                webhook_id: pending.event.id.clone(),
                timestamp: current / 1000,
                signature,
                subscription_id: subscription.id,
                authorized: Arc::new(move || {
                    let at = current.saturating_add(check_started.elapsed().as_millis() as u64);
                    at < expiry
                        && at < deadline
                        && inserted.elapsed() < Duration::from_millis(BUFFER_MS)
                        && access.has_project_access(&owner, &event.project)
                        && access.project_grant_epoch(&owner, &event.project) == Some(epoch)
                        && access.event_is_current(&event)
                        && shared
                            .lock()
                            .ok()
                            .and_then(|s| read_subscription(&s.db, &sub_id).ok().flatten())
                            .is_some_and(|s| {
                                s.revision == revision && s.epoch == epoch && s.expires > at
                            })
                }),
            };
            let remaining =
                Duration::from_millis(pending.deadline.saturating_sub(current).min(10_000))
                    .min(Duration::from_millis(BUFFER_MS).saturating_sub(inserted.elapsed()));
            let response = tokio::time::timeout(remaining, self.transport.post(request)).await;
            let result = match response {
                Ok(Ok(response)) => Some(response.status),
                _ => None,
            };
            let mut state = match self.state.lock() {
                Ok(s) => s,
                Err(_) => {
                    self.degraded.store(true, Ordering::Relaxed);
                    return;
                }
            };
            if result.is_some_and(|s| (200..300).contains(&s)) {
                state.counters.received += 1;
                continue;
            }
            let retry = result.is_none_or(|s| s == 408 || s == 429 || (500..600).contains(&s));
            state.counters.failed += 1;
            self.degraded.store(true, Ordering::Relaxed);
            let mut pending = pending;
            pending.attempts += 1;
            let after = now.saturating_add(started.elapsed().as_millis() as u64);
            let delay = 1000u64.saturating_mul(1u64 << pending.attempts.min(6));
            pending.next = after.saturating_add(delay);
            if retry
                && pending.attempts < MAX_ATTEMPTS
                && pending.next < pending.deadline
                && pending.inserted.elapsed() < Duration::from_millis(BUFFER_MS)
            {
                if state.queue.len() < self.capacity {
                    state.queue.push_back(pending);
                } else {
                    state.counters.dropped += 1;
                }
            }
        }
    }

    pub fn health(&self) -> Value {
        match self.state.lock() {
            Ok(s) => {
                json!({"best_effort":true,"buffer_ms":BUFFER_MS,"historical_replay":false,"degraded":self.degraded.load(Ordering::Relaxed),"possible_restart_gap":s.starts>1,"queue_depth":s.queue.len(),"queue_capacity":self.capacity,"dropped":s.counters.dropped,"duplicate_observations":s.counters.duplicates,"expired":s.counters.expired,"revoked":s.counters.revoked,"superseded":s.counters.stale,"delivery_failures":s.counters.failed,"webhook_receipts":s.counters.received,"storage_faults":s.counters.storage_faults})
            }
            Err(_) => {
                json!({"best_effort":true,"historical_replay":false,"degraded":true,"storage_faults":true})
            }
        }
    }
}

fn prune(state: &mut State, now: u64, degraded: &AtomicBool) {
    let before = state.queue.len();
    state
        .queue
        .retain(|p| p.deadline > now && p.inserted.elapsed() < Duration::from_millis(BUFFER_MS));
    let removed = before - state.queue.len();
    state.counters.expired += removed as u64;
    if removed > 0 {
        degraded.store(true, Ordering::Relaxed);
    }
    state.seen.retain(|_, until| *until > now);
    state.verified.retain(|_, (_, until)| *until > now);
}
fn read_subscription(db: &Connection, id: &str) -> Result<Option<Subscription>, EventError> {
    let row=db.query_row("SELECT id,principal,args,url,secret,old_secret,old_until,expires,epoch,revision,created FROM subscriptions WHERE id=?1",params![id],|r|{
        let args:String=r.get(2)?;
        let scope=serde_json::from_str(&args).map_err(|e|rusqlite::Error::FromSqlConversionFailure(2,rusqlite::types::Type::Text,Box::new(e)))?;
        Ok(Subscription{id:r.get(0)?,principal:r.get(1)?,scope,url:r.get(3)?,secret:r.get(4)?,old_secret:r.get(5)?,old_until:r.get(6)?,expires:r.get(7)?,epoch:r.get(8)?,revision:r.get(9)?,created:r.get(10)?})
    }).optional()?;
    Ok(row)
}
fn matching_subscriptions(
    db: &Connection,
    event: &SanitizedTransition,
    now: u64,
) -> Result<Vec<Subscription>, EventError> {
    let mut query = db.prepare(
        "SELECT id FROM subscriptions WHERE project=?1 AND name=?2 AND expires>?3 LIMIT 4096",
    )?;
    let ids = query
        .query_map(params![event.project, event.name, now], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|id| read_subscription(db, &id))
        .filter_map(|r| match r {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
        .collect()
}
fn event_definitions() -> Value {
    let events:Vec<_>=NAMES.into_iter().map(|name|{
        let (description,statuses)=match name {
            "action_required"=>("A newly failed proposal attempt needs attention because of a conflict, failed check, or policy evaluation error.",vec!["conflict","checks_failed","policy_error"]),
            "proposal.integrated"=>("A proposal was integrated or confirmed already included.",vec!["integrated","already_included"]),
            _=>("The integration authority advanced the project's public head; all project workspaces are affected.",vec!["advanced"]),
        };
        json!({"name":name,"description":description,"delivery":["webhook"],"inputSchema":{"type":"object","properties":{"project_id":{"type":"string","minLength":1,"maxLength":128},"workspace_id":{"type":"string","minLength":1,"maxLength":128},"proposal_id":{"type":"string","minLength":1,"maxLength":128}},"required":["project_id"],"additionalProperties":false,"not":{"required":["workspace_id","proposal_id"]}},"payloadSchema":{"type":"object","properties":{"project_id":{"type":"string"},"proposal_id":{"type":"string"},"status":{"type":"string","enum":statuses}},"required":if name=="public_head.advanced"{vec!["project_id","status"]}else{vec!["project_id","proposal_id","status"]},"additionalProperties":false}})
    }).collect();
    json!({"events":events})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback::{CallbackError, CallbackFuture, CallbackResponse};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::sync::atomic::{AtomicI64, AtomicU16, AtomicU8};
    use tokio::sync::Notify;

    const NOW: u64 = 1_000_000;
    struct Grants {
        epoch: AtomicI64,
        current: AtomicBool,
    }
    impl Grants {
        fn new() -> Self {
            Self {
                epoch: AtomicI64::new(1),
                current: AtomicBool::new(true),
            }
        }
    }
    impl ProjectAccess for Grants {
        fn has_project_access(&self, p: &str, project: &str) -> bool {
            self.project_grant_epoch(p, project).is_some()
        }
        fn has_any_project_access(&self, p: &str) -> bool {
            self.has_project_access(p, "project1")
        }
        fn project_grant_epoch(&self, p: &str, project: &str) -> Option<i64> {
            let e = self.epoch.load(Ordering::Relaxed);
            if ["alice", "bob"].contains(&p) && project == "project1" && e > 0 {
                Some(e)
            } else {
                None
            }
        }
        fn event_is_current(&self, _: &SanitizedTransition) -> bool {
            self.current.load(Ordering::Relaxed)
        }
    }
    #[derive(Clone)]
    struct Record {
        body: Vec<u8>,
        id: String,
        timestamp: u64,
        signature: String,
        subscription: String,
    }
    struct MockTransport {
        records: Mutex<Vec<Record>>,
        status: AtomicU16,
        challenge_mode: AtomicU8,
        pause: AtomicBool,
        started: Notify,
        resume: Notify,
    }
    impl MockTransport {
        fn new() -> Self {
            Self {
                records: Mutex::new(vec![]),
                status: AtomicU16::new(202),
                challenge_mode: AtomicU8::new(0),
                pause: AtomicBool::new(false),
                started: Notify::new(),
                resume: Notify::new(),
            }
        }
        fn records(&self) -> Vec<Record> {
            self.records.lock().unwrap().clone()
        }
        fn deliveries(&self) -> Vec<Record> {
            self.records()
                .into_iter()
                .filter(|r| {
                    serde_json::from_slice::<Value>(&r.body)
                        .unwrap()
                        .get("eventId")
                        .is_some()
                })
                .collect()
        }
        fn verifications(&self) -> usize {
            self.records().len() - self.deliveries().len()
        }
    }
    impl CallbackTransport for MockTransport {
        fn post(&self, r: CallbackRequest) -> CallbackFuture<'_> {
            Box::pin(async move {
                let body: Value = serde_json::from_slice(&r.body).unwrap();
                let verification = body["type"] == "verification";
                if !verification && self.pause.swap(false, Ordering::Relaxed) {
                    self.started.notify_one();
                    self.resume.notified().await;
                }
                if !(r.authorized)() {
                    return Err(CallbackError::Revoked);
                }
                self.records.lock().unwrap().push(Record {
                    body: r.body,
                    id: r.webhook_id,
                    timestamp: r.timestamp,
                    signature: r.signature,
                    subscription: r.subscription_id,
                });
                if verification {
                    let mode = self.challenge_mode.load(Ordering::Relaxed);
                    let echoed = if mode == 1 {
                        json!("incorrect")
                    } else {
                        body["challenge"].clone()
                    };
                    Ok(CallbackResponse {
                        status: if mode == 2 { 302 } else { 200 },
                        body: if mode == 3 {
                            b"invalid".to_vec()
                        } else {
                            serde_json::to_vec(&json!({"challenge":echoed})).unwrap()
                        },
                    })
                } else {
                    Ok(CallbackResponse {
                        status: self.status.load(Ordering::Relaxed),
                        body: vec![],
                    })
                }
            })
        }
    }
    fn secret(n: u8) -> String {
        format!("whsec_{}", STANDARD.encode([n; 32]))
    }
    fn request(name: &str) -> Value {
        json!({"name":name,"arguments":{"project_id":"project1"},"delivery":{"mode":"webhook","url":"https://receiver.example.com/callback","secret":secret(1)},"cursor":null})
    }
    fn transition(id: &str) -> SanitizedTransition {
        SanitizedTransition {
            id: id.into(),
            name: "action_required".into(),
            project: "project1".into(),
            workspace: Some("workspace1".into()),
            proposal: Some("proposal1".into()),
            occurred_at: 1000,
            status: "conflict".into(),
        }
    }
    fn service(
        capacity: usize,
    ) -> (
        Arc<EventService>,
        Arc<Grants>,
        Arc<MockTransport>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().canonicalize().unwrap().join("private");
        wipstash_transport::pairing_files::ensure_private_dir(&private).unwrap();
        let grants = Arc::new(Grants::new());
        let transport = Arc::new(MockTransport::new());
        let events = Arc::new(
            EventService::open(
                private.join("events.sqlite"),
                grants.clone(),
                transport.clone(),
                capacity,
            )
            .unwrap(),
        );
        (events, grants, transport, dir)
    }
    async fn subscribe(events: &EventService, params: Value) -> Value {
        events
            .rpc("alice", "events/subscribe", params, NOW)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn wire_identity_is_canonical_owned_and_unsubscribe_is_idempotent() {
        let (events, _, transport, _dir) = service(10);
        let mut a = request("action_required");
        a["arguments"] = json!({"workspace_id":"workspace1","project_id":"project1"});
        let first = subscribe(&events, a.clone()).await;
        let mut b = a.clone();
        b["arguments"] =
            serde_json::from_str(r#"{"project_id":"project1","workspace_id":"workspace1"}"#)
                .unwrap();
        let again = subscribe(&events, b).await;
        assert_eq!(first, again);
        assert_eq!(first["cursor"], Value::Null);
        assert_eq!(first["truncated"], false);
        assert!(first["refreshBefore"].is_string());
        assert_eq!(transport.verifications(), 1);
        let bob = events
            .rpc("bob", "events/subscribe", a.clone(), NOW)
            .await
            .unwrap();
        assert_ne!(bob["id"], first["id"]);
        events
            .rpc("bob", "events/unsubscribe", a.clone(), NOW)
            .await
            .unwrap();
        assert_eq!(
            events.ingest(transition("evt_1"), NOW),
            EnqueueOutcome::Queued(1)
        );
        events.tick(NOW).await;
        assert_eq!(transport.deliveries().len(), 1);
        assert_eq!(
            transport.deliveries()[0].subscription,
            first["id"].as_str().unwrap()
        );
        for _ in 0..2 {
            assert_eq!(
                events
                    .rpc("alice", "events/unsubscribe", a.clone(), NOW)
                    .await
                    .unwrap(),
                json!({})
            );
        }
        assert_eq!(
            events.ingest(transition("evt_2"), NOW),
            EnqueueOutcome::NoSubscribers
        );
    }
    #[tokio::test]
    async fn authorization_and_argument_failures_never_send_a_challenge() {
        let (events, grants, transport, _dir) = service(10);
        let mut cases = Vec::new();
        let mut bad = request("action_required");
        bad["arguments"]["project_id"] = json!("other");
        cases.push(bad);
        let mut bad = request("action_required");
        bad["arguments"]["source"] = json!("private source");
        cases.push(bad);
        let mut bad = request("action_required");
        bad["arguments"]["workspace_id"] = json!("workspace1");
        bad["arguments"]["proposal_id"] = json!("proposal1");
        cases.push(bad);
        let mut bad = request("action_required");
        bad["arguments"]["project_id"] = json!("/home/user/private");
        cases.push(bad);
        let mut bad = request("action_required");
        bad["delivery"]["mode"] = json!("stream");
        cases.push(bad);
        let mut bad = request("action_required");
        bad["delivery"]["secret"] = json!("whsec_short");
        cases.push(bad);
        let mut bad = request("unknown");
        bad["ttlMs"] = json!(-1);
        cases.push(bad);
        let mut bad = request("action_required");
        bad["cursor"] = json!("history");
        cases.push(bad);
        let mut bad = request("action_required");
        bad["delivery"]["url"] = json!("https://127.0.0.1/");
        cases.push(bad);
        for bad in cases {
            assert!(events
                .rpc("alice", "events/subscribe", bad, NOW)
                .await
                .is_err());
        }
        assert!(events
            .rpc(
                "mallory",
                "events/subscribe",
                request("action_required"),
                NOW
            )
            .await
            .is_err());
        assert_eq!(
            events
                .rpc("mallory", "events/list", json!({}), NOW)
                .await
                .unwrap(),
            json!({"events":[]})
        );
        grants.epoch.store(0, Ordering::Relaxed);
        assert!(events
            .rpc("alice", "events/subscribe", request("action_required"), NOW)
            .await
            .is_err());
        assert!(transport.records().is_empty());
    }
    #[tokio::test]
    async fn failed_callback_is_never_activated_and_uses_openai_error_code() {
        let (events, _, transport, _dir) = service(10);
        let mut ids = Vec::new();
        for mode in [1, 2, 3] {
            transport.challenge_mode.store(mode, Ordering::Relaxed);
            let error = events
                .rpc("alice", "events/subscribe", request("action_required"), NOW)
                .await
                .unwrap_err();
            assert_eq!(error.code, -32015);
            assert_eq!(error.reason, Some("challenge_failed"));
            ids.push(transport.records().last().unwrap().id.clone());
            assert_eq!(
                events.ingest(transition(&format!("evt_{mode}")), NOW),
                EnqueueOutcome::NoSubscribers
            );
        }
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
    }
    #[tokio::test]
    async fn verification_cache_is_owner_url_key_bound_and_expires() {
        let (events, _, transport, _dir) = service(10);
        subscribe(&events, request("action_required")).await;
        subscribe(&events, request("proposal.integrated")).await;
        assert_eq!(transport.verifications(), 1);
        events
            .rpc("bob", "events/subscribe", request("action_required"), NOW)
            .await
            .unwrap();
        assert_eq!(transport.verifications(), 2);
        let mut changed = request("action_required");
        changed["delivery"]["secret"] = json!(secret(2));
        subscribe(&events, changed).await;
        assert_eq!(transport.verifications(), 3);
        events
            .rpc(
                "alice",
                "events/subscribe",
                request("proposal.integrated"),
                NOW + VERIFY_CACHE_MS,
            )
            .await
            .unwrap();
        assert_eq!(transport.verifications(), 4);
    }
    #[tokio::test]
    async fn backward_wall_clock_does_not_extend_monotonic_delivery_budget() {
        let (events, _, transport, _dir) = service(10);
        subscribe(&events, request("action_required")).await;
        events.ingest(transition("clock_step"), NOW);
        events
            .state
            .lock()
            .unwrap()
            .queue
            .front_mut()
            .unwrap()
            .inserted = Instant::now() - Duration::from_millis(BUFFER_MS - 100);
        transport.pause.store(true, Ordering::Relaxed);
        let worker = events.clone();
        let tick = tokio::spawn(async move { worker.tick(NOW).await });
        tokio::time::timeout(Duration::from_secs(1), transport.started.notified())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        transport.resume.notify_one();
        tick.await.unwrap();
        assert!(transport.deliveries().is_empty());
        assert!(events.state.lock().unwrap().queue.is_empty());
    }
    #[tokio::test]
    async fn cache_hits_do_not_slide_callback_verification_expiry() {
        let (events, _, transport, _dir) = service(10);
        for offset in [0, 59_000, 118_000] {
            events
                .rpc(
                    "alice",
                    "events/subscribe",
                    request("action_required"),
                    NOW + offset,
                )
                .await
                .unwrap();
            assert_eq!(
                transport.verifications(),
                if offset < VERIFY_CACHE_MS { 1 } else { 2 }
            );
        }
    }
    #[tokio::test]
    async fn retries_keep_event_identity_and_body_but_refresh_timestamp_and_signature() {
        let (events, _, transport, _dir) = service(10);
        subscribe(&events, request("action_required")).await;
        transport.status.store(503, Ordering::Relaxed);
        assert_eq!(
            events.ingest(transition("evt_1"), NOW),
            EnqueueOutcome::Queued(1)
        );
        assert_eq!(
            events.ingest(transition("evt_1"), NOW),
            EnqueueOutcome::Duplicate
        );
        events.tick(NOW).await;
        transport.status.store(202, Ordering::Relaxed);
        events.tick(NOW + 2001).await;
        let sent = transport.deliveries();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].id, sent[1].id);
        assert_eq!(sent[0].body, sent[1].body);
        assert_ne!(sent[0].timestamp, sent[1].timestamp);
        assert_ne!(sent[0].signature, sent[1].signature);
        let body: Value = serde_json::from_slice(&sent[0].body).unwrap();
        assert_eq!(
            body,
            json!({"eventId":"evt_1","name":"action_required","timestamp":"1970-01-01T00:16:40Z","data":{"project_id":"project1","proposal_id":"proposal1","status":"conflict"},"cursor":null})
        );
        assert_eq!(
            sent[0].signature,
            callback::sign(&secret(1), "evt_1", 1000, &sent[0].body).unwrap()
        );
        assert_eq!(events.health()["queue_depth"], 0);
        assert_eq!(events.health()["webhook_receipts"], 1);
    }
    #[tokio::test]
    async fn terminal_http_responses_are_not_retried_and_retry_attempts_are_bounded() {
        for status in [301, 400, 401, 403, 404, 410, 413] {
            let (events, _, transport, _dir) = service(10);
            subscribe(&events, request("action_required")).await;
            transport.status.store(status, Ordering::Relaxed);
            events.ingest(transition("evt_1"), NOW);
            events.tick(NOW).await;
            events.tick(NOW + 10_000).await;
            assert_eq!(transport.deliveries().len(), 1, "status {status}");
            assert_eq!(events.health()["queue_depth"], 0);
        }
        let (events, _, transport, _dir) = service(10);
        subscribe(&events, request("action_required")).await;
        transport.status.store(500, Ordering::Relaxed);
        events.ingest(transition("evt_1"), NOW);
        for delta in [
            0, 2_001, 6_002, 14_003, 30_004, 62_005, 126_006, 190_007, 254_008,
        ] {
            events.tick(NOW + delta).await;
        }
        assert_eq!(transport.deliveries().len(), usize::from(MAX_ATTEMPTS));
        assert_eq!(events.health()["queue_depth"], 0);
    }
    #[tokio::test]
    async fn full_queue_old_events_and_storage_faults_fail_open_and_report_degraded() {
        let (events, _, transport, _dir) = service(1);
        subscribe(&events, request("action_required")).await;
        assert_eq!(
            events.ingest(transition("evt_1"), NOW),
            EnqueueOutcome::Queued(1)
        );
        assert_eq!(
            events.ingest(transition("evt_2"), NOW),
            EnqueueOutcome::Dropped
        );
        assert_eq!(events.health()["queue_depth"], 1);
        assert_eq!(events.health()["degraded"], true);
        events.tick(NOW + BUFFER_MS).await;
        assert!(transport.deliveries().is_empty());
        assert_eq!(events.health()["expired"], 1);
        assert_eq!(
            events.ingest(transition("old"), NOW + BUFFER_MS),
            EnqueueOutcome::Dropped
        );
        events
            .state
            .lock()
            .unwrap()
            .db
            .execute("DROP TABLE subscriptions", [])
            .unwrap();
        assert_eq!(
            events.ingest(transition("fault"), NOW + BUFFER_MS - 1),
            EnqueueOutcome::Dropped
        );
        assert_eq!(events.health()["storage_faults"], 1);
    }
    #[tokio::test]
    async fn ttl_expiry_and_refresh_stop_delivery_without_granting_unbounded_lifetime() {
        let (events, _, transport, _dir) = service(10);
        let mut p = request("action_required");
        p["ttlMs"] = json!(1);
        let reply = subscribe(&events, p.clone()).await;
        assert_eq!(reply["refreshBefore"], iso(NOW + MIN_TTL_MS).unwrap());
        events.ingest(transition("evt_1"), NOW);
        events.tick(NOW + MIN_TTL_MS).await;
        assert!(transport.deliveries().is_empty());
        p["ttlMs"] = Value::Null;
        let reply = subscribe(&events, p.clone()).await;
        assert_eq!(reply["refreshBefore"], iso(NOW + DEFAULT_TTL_MS).unwrap());
        p["ttlMs"] = json!(MAX_TTL_MS + 1);
        let reply = subscribe(&events, p).await;
        assert_eq!(reply["refreshBefore"], iso(NOW + MAX_TTL_MS).unwrap());
    }
    #[tokio::test]
    async fn restart_retains_subscription_but_never_replays_buffer() {
        let (events, grants, transport, dir) = service(10);
        let id = subscribe(&events, request("action_required")).await["id"].clone();
        events.ingest(transition("evt_lost"), NOW);
        drop(events);
        let restarted = EventService::open(
            dir.path()
                .canonicalize()
                .unwrap()
                .join("private/events.sqlite"),
            grants,
            transport.clone(),
            10,
        )
        .unwrap();
        restarted.tick(NOW + 1).await;
        assert!(transport.deliveries().is_empty());
        assert_eq!(restarted.health()["possible_restart_gap"], true);
        let same = subscribe(&restarted, request("action_required")).await;
        assert_eq!(same["id"], id);
        assert_eq!(
            restarted.ingest(transition("evt_new"), NOW),
            EnqueueOutcome::Queued(1)
        );
        restarted.tick(NOW).await;
        assert_eq!(transport.deliveries().len(), 1);
    }
    #[tokio::test]
    async fn new_subscription_does_not_replay_source_catch_up_but_refresh_preserves_start() {
        let (events, _, transport, _dir) = service(10);
        events
            .rpc(
                "alice",
                "events/subscribe",
                request("action_required"),
                NOW + 1,
            )
            .await
            .unwrap();
        assert_eq!(
            events.ingest(transition("before_subscribe"), NOW + 1),
            EnqueueOutcome::NoSubscribers
        );
        let mut live = transition("after_subscribe");
        live.occurred_at += 1;
        assert_eq!(events.ingest(live, NOW + 1000), EnqueueOutcome::Queued(1));
        events
            .rpc(
                "alice",
                "events/subscribe",
                request("action_required"),
                NOW + 2000,
            )
            .await
            .unwrap();
        events.tick(NOW + 2000).await;
        assert_eq!(transport.deliveries().len(), 1);
    }
    #[tokio::test]
    async fn revocation_and_regrant_do_not_revive_an_old_subscription_or_pending_event() {
        let (events, grants, transport, _dir) = service(10);
        subscribe(&events, request("action_required")).await;
        events.ingest(transition("evt_old"), NOW);
        grants.epoch.store(0, Ordering::Relaxed);
        events.tick(NOW).await;
        assert!(transport.deliveries().is_empty());
        grants.epoch.store(3, Ordering::Relaxed);
        assert_eq!(
            events.ingest(transition("evt_regrant"), NOW),
            EnqueueOutcome::NoSubscribers
        );
        subscribe(&events, request("action_required")).await;
        assert_eq!(
            events.ingest(transition("evt_new"), NOW),
            EnqueueOutcome::Queued(1)
        );
        events.tick(NOW).await;
        assert_eq!(transport.deliveries().len(), 1);
    }
    #[tokio::test]
    async fn revoke_during_connect_and_unsubscribe_recreate_during_connect_are_blocked() {
        for recreate in [false, true] {
            let (events, grants, transport, _dir) = service(10);
            subscribe(&events, request("action_required")).await;
            events.ingest(transition("evt_old"), NOW);
            transport.pause.store(true, Ordering::Relaxed);
            let task = {
                let events = events.clone();
                tokio::spawn(async move {
                    events.tick(NOW).await;
                })
            };
            transport.started.notified().await;
            if recreate {
                events
                    .rpc(
                        "alice",
                        "events/unsubscribe",
                        request("action_required"),
                        NOW,
                    )
                    .await
                    .unwrap();
                subscribe(&events, request("action_required")).await;
            } else {
                grants.epoch.store(0, Ordering::Relaxed);
            }
            transport.resume.notify_one();
            task.await.unwrap();
            assert!(transport.deliveries().is_empty());
        }
    }
    #[tokio::test]
    async fn stale_action_is_suppressed_and_new_attempt_is_new_identity() {
        let (events, grants, transport, _dir) = service(10);
        subscribe(&events, request("action_required")).await;
        events.ingest(transition("attempt1"), NOW);
        grants.current.store(false, Ordering::Relaxed);
        events.tick(NOW).await;
        assert!(transport.deliveries().is_empty());
        grants.current.store(true, Ordering::Relaxed);
        events.ingest(transition("attempt2"), NOW);
        events.tick(NOW).await;
        assert_eq!(transport.deliveries().len(), 1);
        assert_eq!(transport.deliveries()[0].id, "attempt2");
        assert_eq!(events.health()["superseded"], 1);
    }
    #[tokio::test]
    async fn refreshed_secret_dual_signs_only_during_rotation_window() {
        let (events, _, transport, _dir) = service(10);
        subscribe(&events, request("action_required")).await;
        events.ingest(transition("evt_1"), NOW);
        let mut rotated = request("action_required");
        rotated["delivery"]["secret"] = json!(secret(2));
        subscribe(&events, rotated).await;
        events.tick(NOW).await;
        let first = transport.deliveries()[0].clone();
        assert_eq!(
            first.signature,
            format!(
                "{} {}",
                callback::sign(&secret(2), &first.id, first.timestamp, &first.body).unwrap(),
                callback::sign(&secret(1), &first.id, first.timestamp, &first.body).unwrap()
            )
        );
        let mut next = transition("evt_2");
        next.occurred_at += 61;
        events.ingest(next, NOW + 61_000);
        events.tick(NOW + 61_000).await;
        let second = transport.deliveries()[1].clone();
        assert_eq!(second.signature.split(' ').count(), 1);
    }
    #[test]
    fn projection_rejects_private_payloads_invalid_statuses_and_overflowing_times() {
        let event = transition("evt_1");
        let body = event.body().unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(!text.contains("workspace1"));
        assert!(!text.contains("source"));
        assert!(!text.contains("path"));
        for status in ["stdout: PRIVATE", "failed /Users/me/repo", "<script>"] {
            let mut bad = event.clone();
            bad.status = status.into();
            assert!(bad.body().is_err());
        }
        let mut bad = event.clone();
        bad.project = "/Users/me/repo".into();
        assert!(bad.body().is_err());
        let mut bad = event.clone();
        bad.occurred_at = i64::MAX;
        assert!(bad.body().is_err());
        let mut bad = event.clone();
        bad.name = "private.wip".into();
        assert!(bad.body().is_err());
        let mut bad = event;
        bad.proposal = None;
        assert!(bad.body().is_err());
    }
    #[test]
    fn scope_matching_is_explicit_and_public_head_affects_all_project_workspaces() {
        let scope = Scope {
            project_id: "project1".into(),
            workspace_id: Some("workspace1".into()),
            proposal_id: None,
        };
        let event = transition("evt_1");
        assert!(scope.matches(&event));
        let mut other = event.clone();
        other.workspace = Some("workspace2".into());
        assert!(!scope.matches(&other));
        other.name = "public_head.advanced".into();
        other.workspace = None;
        assert!(scope.matches(&other));
        other.project = "other".into();
        assert!(!scope.matches(&other));
        let proposal = Scope {
            project_id: "project1".into(),
            workspace_id: None,
            proposal_id: Some("proposal2".into()),
        };
        assert!(!proposal.matches(&event));
    }
    #[test]
    fn metadata_is_bounded_even_without_receivers() {
        let (events, _, _, _dir) = service(1);
        assert_eq!(
            events.ingest(transition("evt_1"), NOW),
            EnqueueOutcome::NoSubscribers
        );
        assert_eq!(
            events.ingest(transition("evt_2"), NOW),
            EnqueueOutcome::NoSubscribers
        );
        assert_eq!(
            events.ingest(transition("evt_3"), NOW),
            EnqueueOutcome::Dropped
        );
        assert_eq!(events.state.lock().unwrap().seen.len(), 2);
        assert_eq!(
            events.ingest(transition("evt_1"), NOW),
            EnqueueOutcome::Duplicate
        );
    }
}
