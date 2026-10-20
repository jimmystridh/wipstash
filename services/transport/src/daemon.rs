//! Durable, outbound-only coordination. Source actions remain explicitly user driven.
use crate::{error, fingerprint, run_engine, Result, Workstation};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};

pub type Reply<'a> = Pin<Box<dyn Future<Output = Result<Value>> + Send + 'a>>;
/// Each implementation must authenticate its peer and import through the engine verifier.
pub trait PeerSync: Send + Sync {
    fn flush_coordination(&self) -> Reply<'_> {
        Box::pin(async { Ok(json!({"ok":true,"available":false})) })
    }
    fn flush_audit(&self) -> Reply<'_> {
        Box::pin(async { Ok(json!({"ok":true,"available":false})) })
    }
    fn upload<'a>(&'a self, proposal: &'a str, operation: &'a str) -> Reply<'a>;
    fn catch_up(&self) -> Reply<'_>;
    fn current_receipt<'a>(&'a self, proposal: &'a str) -> Reply<'a>;
}
impl PeerSync for Workstation {
    fn flush_coordination(&self) -> Reply<'_> {
        Box::pin(self.flush_coordination())
    }
    fn flush_audit(&self) -> Reply<'_> {
        Box::pin(self.flush_audit())
    }
    fn upload<'a>(&'a self, proposal: &'a str, operation: &'a str) -> Reply<'a> {
        Box::pin(self.upload(proposal, operation))
    }
    fn catch_up(&self) -> Reply<'_> {
        Box::pin(self.catch_up())
    }
    fn current_receipt<'a>(&'a self, proposal: &'a str) -> Reply<'a> {
        Box::pin(self.current_receipt(proposal))
    }
}
#[derive(Default, Serialize, Deserialize)]
struct Entry {
    operation: String,
    authority_proposal: Option<String>,
    terminal: bool,
    #[serde(default)]
    blocked: Option<String>,
    failures: u32,
    next_attempt: u64,
}
#[derive(Default, Serialize, Deserialize)]
struct Journal {
    #[serde(default)]
    binding: Value,
    entries: BTreeMap<String, Entry>,
    catch_up_failures: u32,
    catch_up_after: u64,
    #[serde(default)]
    audit_failures: u32,
    #[serde(default)]
    audit_after: u64,
    #[serde(default)]
    coordination_failures: u32,
    #[serde(default)]
    coordination_after: u64,
}
fn backoff(failures: u32) -> u64 {
    2u64.saturating_pow(failures.min(8)).min(300)
}
fn lock(state: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join("transport-worker.lock"))?;
    file.try_lock_exclusive()
        .map_err(|_| error("transport_worker_already_running"))?;
    Ok(file)
}
/// Holds an OS-backed lock for its lifetime; process exit releases it without stale PID recovery.
pub struct Worker<T> {
    engine: PathBuf,
    state: PathBuf,
    transport: T,
    journal: Journal,
    _lock: File,
}
impl<T: PeerSync> Worker<T> {
    /// One explicit CLI invocation, ignoring historical background retry delays.
    pub async fn once(&mut self) -> Result<Value> {
        self.journal.coordination_after = 0;
        self.journal.audit_after = 0;
        self.journal.catch_up_after = 0;
        for entry in self.journal.entries.values_mut() {
            if !entry.terminal && entry.blocked.is_none() {
                entry.next_attempt = 0;
            }
        }
        self.save()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        self.tick(now).await
    }
    pub async fn open(engine: PathBuf, state: PathBuf, transport: T) -> Result<Self> {
        if !engine.is_absolute() || !state.is_absolute() {
            return Err(error("absolute_config_paths_required"));
        }
        let recovery = run_engine(&engine, &state, json!({"op":"recovery_status"})).await?;
        if recovery["activation_required"] == true {
            return Err(error("public_recovery_activation_required"));
        }
        let status = run_engine(&engine, &state, json!({"op":"sync_status"})).await?;
        if status["config"]["role"] != "client" {
            return Err(error("client_required"));
        }
        let guard = lock(&state)?;
        let journal_path = state.join("transport-outbox.json");
        if let Ok(meta) = std::fs::symlink_metadata(&journal_path) {
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8 * 1024 * 1024 {
                return Err(error("outbox_bound"));
            }
        }
        let mut journal: Journal = match std::fs::read(&journal_path) {
            Ok(bytes) => {
                if bytes.len() > 8 * 1024 * 1024 {
                    return Err(error("outbox_bound"));
                }
                serde_json::from_slice(&bytes)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Journal::default(),
            Err(e) => return Err(e.into()),
        };
        if journal.binding.is_null() && journal.entries.is_empty() {
            journal.binding = status["config"].clone();
        }
        if journal.entries.len() > 10000
            || journal.entries.iter().any(|(id, e)| {
                !crate::valid_id(id)
                    || e.operation != format!("daemon-{}", fingerprint(id.as_bytes()))
                    || e.authority_proposal
                        .as_ref()
                        .is_some_and(|p| !crate::valid_id(p))
            })
        {
            return Err(error("invalid_outbox"));
        }
        if journal.binding != status["config"] {
            return Err(error("outbox_binding_mismatch"));
        }
        Ok(Self {
            engine,
            state,
            transport,
            journal,
            _lock: guard,
        })
    }
    fn save(&self) -> Result<()> {
        let mut tmp = tempfile::NamedTempFile::new_in(&self.state)?;
        tmp.write_all(&serde_json::to_vec(&self.journal)?)?;
        tmp.as_file().sync_all()?;
        tmp.persist(self.state.join("transport-outbox.json"))?;
        File::open(&self.state)?.sync_all()?;
        Ok(())
    }
    /// One bounded pass. Failures on one proposal do not prevent unrelated proposals or heads.
    /// `now` is Unix seconds, injectable for deterministic retry tests.
    pub async fn tick(&mut self, now: u64) -> Result<Value> {
        let mut coordination_status = json!({"ok":false,"pending":true});
        if now >= self.journal.coordination_after {
            match self.transport.flush_coordination().await {
                Ok(value) => {
                    coordination_status = value;
                    self.journal.coordination_failures = 0;
                    self.journal.coordination_after = now.saturating_add(5);
                }
                Err(_) => {
                    self.journal.coordination_failures =
                        self.journal.coordination_failures.saturating_add(1);
                    self.journal.coordination_after =
                        now.saturating_add(backoff(self.journal.coordination_failures));
                }
            }
            self.save()?;
        }
        let mut audit_status = json!({"ok":false,"pending":true});
        if now >= self.journal.audit_after {
            match self.transport.flush_audit().await {
                Ok(status) => {
                    audit_status = status;
                    self.journal.audit_failures = 0;
                    self.journal.audit_after = now.saturating_add(5);
                }
                Err(_) => {
                    self.journal.audit_failures = self.journal.audit_failures.saturating_add(1);
                    self.journal.audit_after =
                        now.saturating_add(backoff(self.journal.audit_failures));
                }
            }
            self.save()?;
        }
        let mut after = 0;
        loop {
            let page = run_engine(
                &self.engine,
                &self.state,
                json!({"op":"sync_pending","after":after,"limit":128}),
            )
            .await?;
            let rows = page["proposals"]
                .as_array()
                .ok_or_else(|| error("pending_shape"))?;
            for row in rows {
                let id = row["proposal"]
                    .as_str()
                    .ok_or_else(|| error("pending_shape"))?;
                if !self.journal.entries.contains_key(id) && self.journal.entries.len() >= 10000 {
                    return Err(error("outbox_capacity"));
                }
                self.journal
                    .entries
                    .entry(id.into())
                    .or_insert_with(|| Entry {
                        operation: format!("daemon-{}", fingerprint(id.as_bytes())),
                        ..Entry::default()
                    });
            }
            if page["has_more"] != true {
                break;
            }
            let next = page["next_cursor"]
                .as_u64()
                .ok_or_else(|| error("pending_shape"))?;
            if next <= after {
                return Err(error("pending_cursor"));
            }
            after = next;
        }
        self.save()?; // Persist identities before making any ambiguous network request.
        let mut failures = 0;
        let mut due: Vec<_> = self
            .journal
            .entries
            .iter()
            .filter(|(_, e)| !e.terminal && e.blocked.is_none() && e.next_attempt <= now)
            .map(|(id, e)| (e.next_attempt, id.clone()))
            .collect();
        due.sort();
        let ids = due
            .into_iter()
            .take(128)
            .map(|(_, id)| id)
            .collect::<Vec<_>>();
        for id in ids {
            let local = run_engine(
                &self.engine,
                &self.state,
                json!({"op":"proposal_status","proposal":id}),
            )
            .await?;
            if local["state"] == "cancelled" || local["local_state"] == "cancelled" {
                self.journal.entries.get_mut(&id).unwrap().terminal = true;
                self.save()?;
                continue;
            }
            let entry = self.journal.entries.get(&id).unwrap();
            let result = if let Some(remote) = &entry.authority_proposal {
                self.transport.current_receipt(remote).await
            } else {
                self.transport.upload(&id, &entry.operation).await
            };
            let result = result.and_then(|v| {
                if v["ok"] != true {
                    return Err(error("peer_rejected"));
                }
                if entry.authority_proposal.is_none()
                    && (v["source_proposal"] != id
                        || !v["proposal"].as_str().is_some_and(crate::valid_id))
                {
                    return Err(error("upload_ack_identity"));
                }
                if entry.authority_proposal.is_some()
                    && (v["proposal"] != id || !v["remote_observation"].is_object())
                {
                    return Err(error("receipt_ack_identity"));
                }
                Ok(v)
            });
            let mut newly_uploaded = None;
            let entry = self.journal.entries.get_mut(&id).unwrap();
            match result {
                Ok(v) if v["ok"] == true => {
                    if entry.authority_proposal.is_none() {
                        let remote = v["proposal"]
                            .as_str()
                            .filter(|s| crate::valid_id(s))
                            .ok_or_else(|| error("upload_ack_shape"))?;
                        if v["source_proposal"] != id {
                            return Err(error("upload_ack_identity"));
                        }
                        entry.authority_proposal = Some(remote.into());
                        newly_uploaded = Some(remote.to_owned());
                    } else {
                        entry.terminal = matches!(
                            v["remote_observation"]["state"].as_str(),
                            Some("integrated" | "already_included" | "cancelled" | "superseded")
                        );
                    }
                    entry.failures = 0;
                    entry.next_attempt = now.saturating_add(5);
                }
                result => {
                    if let Err(err) = &result {
                        let reason = err.to_string();
                        if matches!(
                            reason.as_str(),
                            "peer_rejected"
                                | "upload_ack_identity"
                                | "receipt_ack_identity"
                                | "download_binding"
                                | "download_request_mismatch"
                                | "invalid_identifier"
                                | "invalid_client_binding"
                                | "client_binding_mismatch"
                                | "history_shape"
                                | "history_cursor"
                                | "history_sequence_gap"
                                | "import_cursor_mismatch"
                        ) {
                            entry.blocked = Some(reason);
                        }
                    }
                    failures += 1;
                    entry.failures = entry.failures.saturating_add(1);
                    entry.next_attempt = now.saturating_add(backoff(entry.failures));
                }
            }
            self.save()?;
            if let Some(remote) = newly_uploaded {
                if let Ok(receipt) = self.transport.current_receipt(&remote).await {
                    if receipt["ok"] == true && receipt["proposal"] == id {
                        self.journal.entries.get_mut(&id).unwrap().terminal = matches!(
                            receipt["remote_observation"]["state"].as_str(),
                            Some("integrated" | "already_included" | "cancelled" | "superseded")
                        );
                        self.save()?;
                    }
                }
            }
        }
        if now >= self.journal.catch_up_after {
            if self.transport.catch_up().await.is_ok() {
                self.journal.catch_up_failures = 0;
                self.journal.catch_up_after = now.saturating_add(5);
            } else {
                failures += 1;
                self.journal.catch_up_failures = self.journal.catch_up_failures.saturating_add(1);
                self.journal.catch_up_after =
                    now.saturating_add(backoff(self.journal.catch_up_failures));
            }
            self.save()?;
        }
        let status = run_engine(&self.engine, &self.state, json!({"op":"sync_status"})).await?;
        Ok(
            json!({"ok":true,"failures":failures,"tracked":self.journal.entries.len(),"audit":audit_status,"audit_failures":self.journal.audit_failures,"coordination":coordination_status,"coordination_failures":self.journal.coordination_failures,"files_changed":false,"resolution_tasks":status["resolution_tasks"],"resolution_tasks_truncated":status["resolution_tasks_truncated"]}),
        )
    }
    pub async fn run(&mut self) -> Result<()> {
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            self.tick(now).await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

/// Authority coordinator, using the configured engine policy (default checks=[]).
/// No workspace is checkpointed, published or adopted by this worker.
pub struct AuthorityWorker {
    engine: PathBuf,
    state: PathBuf,
    staging: PathBuf,
    limits: crate::Limits,
    backup_failures: u32,
    next_backup: std::time::Instant,
    _lock: File,
}
impl AuthorityWorker {
    pub async fn open(engine: PathBuf, state: PathBuf, staging: PathBuf) -> Result<Self> {
        Self::open_with_limits(engine, state, staging, crate::Limits::default()).await
    }
    pub async fn open_with_limits(
        engine: PathBuf,
        state: PathBuf,
        staging: PathBuf,
        limits: crate::Limits,
    ) -> Result<Self> {
        if [&engine, &state, &staging].iter().any(|p| !p.is_absolute()) {
            return Err(error("absolute_config_paths_required"));
        }
        let recovery = run_engine(&engine, &state, json!({"op":"recovery_status"})).await?;
        if recovery["activation_required"] == true {
            return Err(error("public_recovery_activation_required"));
        }
        let status = run_engine(&engine, &state, json!({"op":"sync_status"})).await?;
        if status["config"]["role"] != "authority" {
            return Err(error("authority_required"));
        }
        let guard = lock(&state)?;
        Ok(Self {
            engine,
            state,
            staging,
            limits,
            backup_failures: 0,
            next_backup: std::time::Instant::now(),
            _lock: guard,
        })
    }
    fn admission(&self) -> Result<()> {
        wipstash_storage::admit(
            &[self.state.clone(), self.staging.clone()],
            wipstash_storage::Budget {
                max_bytes: self.limits.max_storage_bytes,
                max_entries: self.limits.max_storage_entries,
                reserve_bytes: self.limits.free_space_reserve_bytes,
            },
            (crate::PAYLOAD_MAX as u64) * 4 + 64 * 1024,
            40_000,
        )
        .map_err(|_| error("storage_quota"))?;
        Ok(())
    }
    async fn promotion_tick(&mut self) -> Result<Value> {
        self.admission()?;
        let integrated = crate::run_engine_with_timeout(
            &self.engine,
            &self.state,
            json!({"op":"integrate","max_proposals":1}),
            Duration::from_secs(660),
        )
        .await?;
        self.admission()?;
        let dir = tempfile::tempdir_in(&self.staging)?;
        let exported = run_engine(
            &self.engine,
            &self.state,
            json!({"op":"sync_export_current_head","destination":dir.path().join("artifact")}),
        )
        .await?;
        Ok(
            json!({"ok":true,"integration":integrated,"head":exported["head"],"exported":exported["exported"],"files_changed":false}),
        )
    }
    async fn backup_tick(&mut self) -> Value {
        if std::time::Instant::now() < self.next_backup {
            return json!({"ok":true,"state":"deferred"});
        }
        // Local configured destination only. No network or credentials enter the engine.
        let result = run_engine(&self.engine, &self.state, json!({"op":"backup_tick"})).await;
        let observation = match result {
            Ok(v) => v,
            Err(e) => json!({"ok":false,"state":"blocked","error":e.to_string()}),
        };
        let blocked = observation["ok"] != true || observation["state"] == "blocked";
        let delay = if blocked {
            self.backup_failures = self.backup_failures.saturating_add(1);
            eprintln!("authority local backup paused: {observation}");
            backoff(self.backup_failures)
        } else {
            self.backup_failures = 0;
            5
        };
        self.next_backup = std::time::Instant::now() + Duration::from_secs(delay);
        observation
    }
    pub async fn tick(&mut self) -> Result<Value> {
        let promotion = self.promotion_tick().await;
        // Even a failed promotion/export must not suppress backup of previously retained work.
        let backup = self.backup_tick().await;
        match promotion {
            Ok(mut v) => {
                v["backup"] = backup;
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }
    pub async fn run(&mut self) -> Result<()> {
        let engine = self.engine.clone();
        let state = self.state.clone();
        let validation = async move {
            loop {
                if let Err(e) = crate::run_engine_with_timeout(
                    &engine,
                    &state,
                    json!({"op":"validation_tick"}),
                    Duration::from_secs(660),
                )
                .await
                {
                    eprintln!("authority validation paused: {e}");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };
        tokio::select! {
            result=self.run_promotions()=>result,
            ()=validation=>Ok(()),
        }
    }
    async fn run_promotions(&mut self) -> Result<()> {
        let mut failures: u32 = 0;
        loop {
            let delay = match self.tick().await {
                Ok(_) => {
                    failures = 0;
                    5
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    eprintln!("authority worker paused: {e}");
                    backoff(failures)
                }
            };
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    }
}
