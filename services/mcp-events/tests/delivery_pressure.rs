//! Synthetic, in-process pressure tests. No sockets, OAuth, or real grants.
//! Seeds fix action sequences; Tokio is deliberately free to vary interleavings.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{Barrier, Notify};
use wipstash_mcp_events::{
    callback::{
        self, CallbackError, CallbackFuture, CallbackRequest, CallbackResponse, CallbackTransport,
    },
    events::{EnqueueOutcome, EventService, ProjectAccess, SanitizedTransition, BUFFER_MS},
};

const NOW: u64 = 1_000_000;
const ACTORS: usize = 8;
const SEEDS: [u64; 3] = [0x5eed_0001, 0xdec0_de02, 0xcafe_0003];
const RECORD_LIMIT: usize = 32_768;
const PRESSURE_CAPACITY: usize = 1024;
const PRESSURE_STEPS: usize = 512;
const RACE_ROUNDS: usize = 96;
const COMPETING_TICKS: usize = 8;
// Native Windows completed two race seeds before the old 30-second aggregate
// cutoff; the concurrent campaign also exhausted its 45-second cutoff. These
// durable SQLite correctness workloads are not cross-platform throughput SLOs.
// Retain those references in the output and give all seeds a separate finite
// liveness budget, consistent with auth_pressure_tests. Tokio timeouts are
// cooperative: synchronous filesystem/database work cannot be interrupted, so
// the CI job's outer timeout remains the final backstop. Do not reduce work,
// relax assertions, or change production SQLite durability to fit a reference.
const CAMPAIGN_LIVENESS_BUDGET: Duration = Duration::from_secs(300);

struct PhaseProgress {
    seed: u64,
    phase: &'static str,
    started: Instant,
    completed: usize,
    expected: usize,
}

struct Campaign {
    name: &'static str,
    started: Instant,
    performance_reference: Duration,
    progress: Mutex<Option<PhaseProgress>>,
}

impl Campaign {
    fn new(name: &'static str, performance_reference: Duration) -> Self {
        eprintln!(
            "{name}_START seeds={} reference_seconds={} liveness_seconds={}",
            SEEDS.len(),
            performance_reference.as_secs(),
            CAMPAIGN_LIVENESS_BUDGET.as_secs()
        );
        Self {
            name,
            started: Instant::now(),
            performance_reference,
            progress: Mutex::new(None),
        }
    }

    fn phase(&self, seed: u64, phase: &'static str, expected: usize) {
        let mut progress = self.progress.lock().unwrap();
        if let Some(previous) = &*progress {
            assert_eq!(previous.completed, previous.expected, "incomplete phase");
        }
        let next = PhaseProgress {
            seed,
            phase,
            started: Instant::now(),
            completed: 0,
            expected,
        };
        self.report(&next);
        *progress = Some(next);
    }

    fn completed(&self) {
        let mut progress = self.progress.lock().unwrap();
        let progress = progress.as_mut().unwrap();
        progress.completed += 1;
        assert!(progress.completed <= progress.expected);
        if progress.completed == progress.expected
            || progress
                .completed
                .is_multiple_of((progress.expected / 4).max(1))
        {
            self.report(progress);
        }
    }

    fn report(&self, progress: &PhaseProgress) {
        eprintln!(
            "{}_PROGRESS seed={} phase={} completed={} expected={} phase_elapsed_ms={} total_elapsed_ms={}",
            self.name, progress.seed, progress.phase, progress.completed, progress.expected,
            progress.started.elapsed().as_millis(), self.started.elapsed().as_millis()
        );
    }

    fn finish(&self, completed: bool) {
        let progress = self.progress.lock().unwrap();
        if let Some(progress) = &*progress {
            self.report(progress);
        }
        let elapsed = self.started.elapsed();
        if elapsed > self.performance_reference {
            eprintln!("{}_PERFORMANCE_REFERENCE_EXCEEDED reference_seconds={} elapsed_ms={}; correctness completion is not a throughput guarantee", self.name, self.performance_reference.as_secs(), elapsed.as_millis());
        }
        assert!(
            completed && elapsed < CAMPAIGN_LIVENESS_BUDGET,
            "{} exhausted the {}-second cooperative liveness guard; elapsed={elapsed:?}",
            self.name,
            CAMPAIGN_LIVENESS_BUDGET.as_secs()
        );
        if let Some(progress) = &*progress {
            assert_eq!(progress.completed, progress.expected, "incomplete phase");
        }
        eprintln!(
            "{}_OK seeds={} elapsed_ms={} reference_seconds={} liveness_seconds={}",
            self.name,
            SEEDS.len(),
            elapsed.as_millis(),
            self.performance_reference.as_secs(),
            CAMPAIGN_LIVENESS_BUDGET.as_secs()
        );
    }
}

struct Grants {
    epochs: [AtomicI64; ACTORS],
    current: AtomicBool,
}
impl Grants {
    fn new() -> Self {
        Self {
            epochs: std::array::from_fn(|_| AtomicI64::new(1)),
            current: AtomicBool::new(true),
        }
    }
}
impl ProjectAccess for Grants {
    fn has_project_access(&self, owner: &str, project: &str) -> bool {
        self.project_grant_epoch(owner, project).is_some()
    }
    fn has_any_project_access(&self, owner: &str) -> bool {
        self.has_project_access(owner, "project1")
    }
    fn project_grant_epoch(&self, owner: &str, project: &str) -> Option<i64> {
        let index = owner.strip_prefix("actor_")?.parse::<usize>().ok()?;
        let epoch = self.epochs.get(index)?.load(Ordering::SeqCst);
        (project == "project1" && epoch > 0).then_some(epoch)
    }
    fn event_is_current(&self, _: &SanitizedTransition) -> bool {
        self.current.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
struct Record {
    id: String,
    subscription: String,
    timestamp: u64,
    signature: String,
    body: Vec<u8>,
    status: u16,
}
#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
    // Some(value) intentionally substitutes a stale challenge echo.
    echo_override: Mutex<Option<Value>>,
    observed_challenge: Mutex<Option<Value>>,
}
struct MockCallback {
    records: Mutex<Vec<Record>>,
    attempts: Mutex<HashMap<(String, String), usize>>,
    gates: Mutex<HashMap<String, Arc<Gate>>>,
    challenge_ids: Mutex<Vec<String>>,
    active: AtomicUsize,
    maximum_active: AtomicUsize,
    denied: AtomicUsize,
    failures: AtomicBool,
}
impl MockCallback {
    fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            attempts: Mutex::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
            challenge_ids: Mutex::new(Vec::new()),
            active: AtomicUsize::new(0),
            maximum_active: AtomicUsize::new(0),
            denied: AtomicUsize::new(0),
            failures: AtomicBool::new(false),
        }
    }
    fn gate(&self, key: String) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        assert!(self
            .gates
            .lock()
            .unwrap()
            .insert(key, gate.clone())
            .is_none());
        gate
    }
    fn records(&self) -> Vec<Record> {
        self.records.lock().unwrap().clone()
    }
}
struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl CallbackTransport for MockCallback {
    fn post(&self, request: CallbackRequest) -> CallbackFuture<'_> {
        Box::pin(async move {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let verification = body["type"] == "verification";
            let key = if verification {
                format!("verify:{}", request.url)
            } else {
                request.webhook_id.clone()
            };
            let gate = self.gates.lock().unwrap().remove(&key);
            let _active = if verification {
                None
            } else {
                let count = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.maximum_active.fetch_max(count, Ordering::SeqCst);
                Some(Active(&self.active))
            };
            if let Some(gate) = &gate {
                *gate.observed_challenge.lock().unwrap() = body.get("challenge").cloned();
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            // This models the production transport's check immediately before bytes.
            tokio::task::yield_now().await;
            if !(request.authorized)() {
                self.denied.fetch_add(1, Ordering::SeqCst);
                return Err(CallbackError::Revoked);
            }
            if verification {
                self.challenge_ids.lock().unwrap().push(request.webhook_id);
                let echoed = gate
                    .as_ref()
                    .and_then(|g| g.echo_override.lock().unwrap().clone())
                    .unwrap_or_else(|| body["challenge"].clone());
                return Ok(CallbackResponse {
                    status: 200,
                    body: serde_json::to_vec(&json!({"challenge": echoed})).unwrap(),
                });
            }
            let attempt = {
                let mut attempts = self.attempts.lock().unwrap();
                let n = attempts
                    .entry((request.subscription_id.clone(), request.webhook_id.clone()))
                    .or_default();
                *n += 1;
                *n
            };
            // A later event may succeed before an earlier retry. Repeated errors
            // exercise bounded retry without treating response bodies as events.
            let bucket = request
                .webhook_id
                .bytes()
                .fold(0usize, |n, b| n.wrapping_add(b as usize))
                % 7;
            let status = if self.failures.load(Ordering::SeqCst) {
                match (bucket, attempt) {
                    (0, _) => 503,
                    (1, 1..=2) => 429,
                    (2, 1) => 408,
                    (3, _) => 410,
                    (4, 1) => 500,
                    _ => 202,
                }
            } else {
                202
            };
            let mut records = self.records.lock().unwrap();
            assert!(
                records.len() < RECORD_LIMIT,
                "mock evidence must stay memory bounded"
            );
            records.push(Record {
                id: request.webhook_id,
                subscription: request.subscription_id,
                timestamp: request.timestamp,
                signature: request.signature,
                body: request.body,
                status,
            });
            Ok(CallbackResponse {
                status,
                body: b"repeated untrusted receiver response".to_vec(),
            })
        })
    }
}

fn secret(n: u8) -> String {
    format!("whsec_{}", STANDARD.encode([n; 32]))
}
fn owner(actor: usize) -> String {
    format!("actor_{actor}")
}
fn url(actor: usize) -> String {
    format!("https://receiver.example.com/actor_{actor}")
}
fn request(actor: usize, key: u8) -> Value {
    json!({"name":"action_required", "arguments":{"project_id":"project1","workspace_id":format!("workspace_{actor}")},
        "delivery":{"mode":"webhook","url":url(actor),"secret":secret(key)},"cursor":null})
}
fn event(id: String, actor: usize, now: u64) -> SanitizedTransition {
    SanitizedTransition {
        id,
        name: "action_required".into(),
        project: "project1".into(),
        workspace: Some(format!("workspace_{actor}")),
        proposal: Some(format!("proposal_{actor}")),
        occurred_at: (now / 1000) as i64,
        status: "checks_failed".into(),
    }
}
struct Fixture {
    events: Arc<EventService>,
    grants: Arc<Grants>,
    callback: Arc<MockCallback>,
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new(capacity: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().canonicalize().unwrap().join("private");
        wipstash_transport::pairing_files::ensure_private_dir(&private).unwrap();
        let grants = Arc::new(Grants::new());
        let callback = Arc::new(MockCallback::new());
        let events = Arc::new(
            EventService::open(
                private.join("events.sqlite"),
                grants.clone(),
                callback.clone(),
                capacity,
            )
            .unwrap(),
        );
        Self {
            events,
            grants,
            callback,
            dir,
        }
    }
    async fn subscribe(&self, actor: usize, key: u8, now: u64) -> Value {
        self.events
            .rpc(&owner(actor), "events/subscribe", request(actor, key), now)
            .await
            .unwrap()
    }
}
fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn audit(records: &[Record]) {
    let mut identities = BTreeMap::<(&str, &str), (Vec<u8>, usize, u64, bool)>::new();
    for record in records {
        let body: Value = serde_json::from_slice(&record.body).unwrap();
        assert_eq!(body["eventId"], record.id);
        assert_eq!(body["name"], "action_required");
        assert_eq!(body["cursor"], Value::Null);
        assert_eq!(body.as_object().unwrap().len(), 5);
        assert_eq!(body["data"].as_object().unwrap().len(), 3);
        assert_eq!(body["data"]["project_id"], "project1");
        assert_eq!(body["data"]["status"], "checks_failed");
        assert!(!String::from_utf8_lossy(&record.body).contains("workspace_"));
        assert!(!String::from_utf8_lossy(&record.body).contains("private"));
        for signature in record.signature.split(' ') {
            assert!((1..=4).any(|key| callback::sign(
                &secret(key),
                &record.id,
                record.timestamp,
                &record.body
            )
            .unwrap()
                == signature));
        }
        assert!((1..=2).contains(&record.signature.split(' ').count()));
        let entry = identities
            .entry((&record.subscription, &record.id))
            .or_insert_with(|| (record.body.clone(), 0, record.timestamp, false));
        assert_eq!(entry.0, record.body, "retry changed event body");
        assert!(!entry.3, "successful or terminal event was retried");
        assert!(record.timestamp >= entry.2, "retry timestamp regressed");
        entry.1 += 1;
        entry.2 = record.timestamp;
        entry.3 = (200..300).contains(&record.status) || record.status == 410;
        assert!(entry.1 <= 8, "attempt budget exceeded");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seeded_concurrent_delivery_pressure_is_bounded_and_signed() {
    let campaign = Arc::new(Campaign::new("DELIVERY_PRESSURE", Duration::from_secs(45)));
    let result = tokio::time::timeout(CAMPAIGN_LIVENESS_BUDGET, async {
        for seed in SEEDS {
            let seed_started = Instant::now();
            campaign.phase(seed, "setup", ACTORS + 1);
            let fixture = Fixture::new(PRESSURE_CAPACITY);
            campaign.completed();
            fixture.callback.failures.store(true, Ordering::SeqCst);
            for actor in 0..ACTORS { fixture.subscribe(actor, 1, NOW).await; campaign.completed(); }
            campaign.phase(seed, "actor-steps", ACTORS * PRESSURE_STEPS);
            let barrier = Arc::new(Barrier::new(ACTORS));
            let actions = Arc::new(AtomicUsize::new(0));
            let mut tasks = Vec::new();
            for actor in 0..ACTORS {
                let events = fixture.events.clone();
                let grants = fixture.grants.clone();
                let barrier = barrier.clone();
                let actions = actions.clone();
                let campaign = campaign.clone();
                tasks.push(tokio::spawn(async move {
                    let mut rng = seed ^ ((actor as u64 + 1) * 0x9e37_79b9);
                    let mut epoch = 1;
                    let mut key = 1;
                    barrier.wait().await;
                    for step in 0..PRESSURE_STEPS {
                        match random(&mut rng) % 12 {
                            0..=5 => {
                                let id = format!("seed_{seed}_actor_{actor}_event_{step}");
                                let e = event(id, actor, NOW);
                                events.ingest(e.clone(), NOW);
                                if step % 3 == 0 { events.ingest(e, NOW); actions.fetch_add(1, Ordering::SeqCst); }
                            }
                            6 => { key = (key % 4) + 1; events.rpc(&owner(actor), "events/subscribe", request(actor, key), NOW).await.unwrap(); }
                            7 => {
                                events.rpc(&owner(actor), "events/unsubscribe", request(actor, key), NOW).await.unwrap();
                                tokio::task::yield_now().await;
                                events.rpc(&owner(actor), "events/subscribe", request(actor, key), NOW).await.unwrap();
                                actions.fetch_add(1, Ordering::SeqCst);
                            }
                            8 => {
                                grants.epochs[actor].store(0, Ordering::SeqCst);
                                assert!(events.rpc(&owner(actor), "events/subscribe", request(actor, key), NOW).await.is_err());
                                epoch += 1;
                                grants.epochs[actor].store(epoch, Ordering::SeqCst);
                                events.rpc(&owner(actor), "events/subscribe", request(actor, key), NOW).await.unwrap();
                                actions.fetch_add(3, Ordering::SeqCst);
                            }
                            _ => events.tick(NOW).await,
                        }
                        actions.fetch_add(1, Ordering::SeqCst);
                        assert!(events.health()["queue_depth"].as_u64().unwrap() <= PRESSURE_CAPACITY as u64);
                        campaign.completed();
                        tokio::task::yield_now().await;
                    }
                }));
            }
            for task in tasks { task.await.unwrap(); }
            campaign.phase(seed, "retry-drain", 10);
            for delta in [1000, 4000, 9000, 18000, 35000, 70000, 135000, 200000, 270000, BUFFER_MS] {
                fixture.events.tick(NOW + delta).await;
                campaign.completed();
            }
            campaign.phase(seed, "audit", 1);
            assert_eq!(fixture.events.health()["queue_depth"], 0);
            assert_eq!(fixture.events.health()["storage_faults"], 0);
            assert_eq!(fixture.events.health()["historical_replay"], false);
            assert_eq!(fixture.callback.maximum_active.load(Ordering::SeqCst), 1);
            let records = fixture.callback.records();
            assert!(!records.is_empty());
            audit(&records);
            assert!(actions.load(Ordering::SeqCst) >= ACTORS * PRESSURE_STEPS);
            campaign.completed();
            eprintln!("DELIVERY_PRESSURE seed={seed} actions={} callback_attempts={} denied_before_bytes={} health={} seed_elapsed_ms={}",
                actions.load(Ordering::SeqCst), records.len(), fixture.callback.denied.load(Ordering::SeqCst), fixture.events.health(), seed_started.elapsed().as_millis());
            campaign.phase(seed, "cleanup", 1);
            drop(fixture);
            campaign.completed();
        }
    }).await;
    campaign.finish(result.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gated_generation_races_never_send_revoked_or_recreated_deliveries() {
    let campaign = Campaign::new("DELIVERY_RACES", Duration::from_secs(30));
    let result = tokio::time::timeout(CAMPAIGN_LIVENESS_BUDGET, async {
        for seed in SEEDS {
            let seed_started = Instant::now();
            campaign.phase(seed, "setup", 2);
            let fixture = Fixture::new(64);
            campaign.completed();
            let mut rng = seed;
            let mut epoch = 1;
            fixture.subscribe(0, 1, NOW).await;
            campaign.completed();
            campaign.phase(seed, "gated-races", RACE_ROUNDS);
            for step in 0..RACE_ROUNDS {
                let now = NOW + step as u64 * 4000;
                fixture.subscribe(0, 1, now).await;
                let id = format!("race_{seed}_{step}");
                let gate = fixture.callback.gate(id.clone());
                assert_eq!(
                    fixture.events.ingest(event(id.clone(), 0, now), now),
                    EnqueueOutcome::Queued(1)
                );
                let pump = {
                    let events = fixture.events.clone();
                    tokio::spawn(async move { events.tick(now).await })
                };
                gate.entered.notified().await;
                // Concurrent pumps must not dequeue another copy of the event.
                let mut contenders = Vec::new();
                for _ in 0..COMPETING_TICKS {
                    let e = fixture.events.clone();
                    contenders.push(tokio::spawn(async move { e.tick(now).await }));
                }
                for contender in contenders {
                    contender.await.unwrap();
                }
                let mode = random(&mut rng) % 4;
                match mode {
                    0 => {
                        fixture.subscribe(0, 2, now).await;
                    }
                    1 => {
                        fixture
                            .events
                            .rpc("actor_0", "events/unsubscribe", request(0, 1), now)
                            .await
                            .unwrap();
                        fixture.subscribe(0, 2, now).await;
                    }
                    2 => {
                        fixture.grants.epochs[0].store(0, Ordering::SeqCst);
                        epoch += 1;
                        fixture.grants.epochs[0].store(epoch, Ordering::SeqCst);
                        fixture.subscribe(0, 2, now).await;
                    }
                    _ => {
                        fixture.grants.current.store(false, Ordering::SeqCst);
                    }
                }
                let before = fixture.callback.records().len();
                gate.release.notify_one();
                pump.await.unwrap();
                fixture.events.tick(now + 3000).await;
                let after = fixture.callback.records();
                if mode == 0 {
                    assert_eq!(after.len(), before + 1, "refresh may retain a queued event");
                    assert_eq!(after.last().unwrap().id, id);
                } else {
                    assert_eq!(
                        after.len(),
                        before,
                        "old generation or superseded event crossed send boundary"
                    );
                }
                fixture.grants.current.store(true, Ordering::SeqCst);
                campaign.completed();
            }
            campaign.phase(seed, "audit", 1);
            assert_eq!(fixture.callback.maximum_active.load(Ordering::SeqCst), 1);
            audit(&fixture.callback.records());
            campaign.completed();
            eprintln!(
                "DELIVERY_RACES seed={seed} gated_races={RACE_ROUNDS} competing_ticks={} blocked={} seed_elapsed_ms={}",
                RACE_ROUNDS * COMPETING_TICKS, fixture.callback.denied.load(Ordering::SeqCst), seed_started.elapsed().as_millis()
            );
            campaign.phase(seed, "cleanup", 1);
            drop(fixture);
            campaign.completed();
        }
    })
    .await;
    campaign.finish(result.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reordered_verifications_reject_replayed_challenges_and_regrant() {
    let fixture = Fixture::new(16);
    let mut gates = Vec::new();
    let mut tasks = Vec::new();
    for actor in 0..ACTORS {
        gates.push(fixture.callback.gate(format!("verify:{}", url(actor))));
        let events = fixture.events.clone();
        tasks.push(tokio::spawn(async move {
            events
                .rpc(&owner(actor), "events/subscribe", request(actor, 1), NOW)
                .await
        }));
    }
    for gate in &gates {
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .unwrap();
    }
    let stale_echo = gates[0].observed_challenge.lock().unwrap().clone().unwrap();
    for gate in gates.iter().take(4).skip(1) {
        *gate.echo_override.lock().unwrap() = Some(stale_echo.clone());
    }
    fixture.grants.epochs[4].store(0, Ordering::SeqCst);
    fixture.grants.epochs[4].store(3, Ordering::SeqCst);
    for gate in gates.iter().rev() {
        gate.release.notify_one();
        tokio::task::yield_now().await;
    }
    for (actor, task) in tasks.into_iter().enumerate() {
        let result = task.await.unwrap();
        match actor {
            1..=3 => {
                let error = result.unwrap_err();
                assert_eq!(error.code, -32015);
                assert_eq!(error.reason, Some("challenge_failed"));
            }
            4 => assert!(result.is_err()),
            _ => assert!(result.is_ok()),
        }
        let queued = fixture
            .events
            .ingest(event(format!("verification_{actor}"), actor, NOW), NOW);
        assert_eq!(
            queued,
            if (1..=4).contains(&actor) {
                EnqueueOutcome::NoSubscribers
            } else {
                EnqueueOutcome::Queued(1)
            }
        );
    }
    fixture.events.tick(NOW).await;
    assert_eq!(fixture.callback.records().len(), 4);
    let ids = fixture.callback.challenge_ids.lock().unwrap();
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(
        ids.len(),
        unique.len(),
        "verification message IDs must be single-use"
    );
}

#[tokio::test]
async fn overflow_expiry_and_restarts_keep_metadata_but_never_persist_event_bodies() {
    let started = Instant::now();
    let fixture = Fixture::new(7);
    let subscription = fixture.subscribe(0, 1, NOW).await["id"].clone();
    for n in 0..2048 {
        let outcome = fixture
            .events
            .ingest(event(format!("never_persist_marker_{n}"), 0, NOW), NOW);
        assert_eq!(
            outcome,
            if n < 7 {
                EnqueueOutcome::Queued(1)
            } else {
                EnqueueOutcome::Dropped
            }
        );
        assert!(fixture.events.health()["queue_depth"].as_u64().unwrap() <= 7);
    }
    assert_eq!(fixture.events.health()["degraded"], true);
    fixture.events.tick(NOW + BUFFER_MS).await;
    assert!(fixture.callback.records().is_empty());
    assert_eq!(fixture.events.health()["expired"], 7);
    assert_eq!(fixture.events.health()["queue_depth"], 0);
    let path = fixture
        .dir
        .path()
        .canonicalize()
        .unwrap()
        .join("private/events.sqlite");
    let Fixture {
        mut events,
        grants,
        callback,
        dir: _dir,
    } = fixture;
    for restart in 1..=32 {
        let now = NOW + BUFFER_MS + restart * 1000;
        assert_eq!(
            events.ingest(event(format!("lost_restart_{restart}"), 0, now), now),
            EnqueueOutcome::Queued(1)
        );
        drop(events);
        events = Arc::new(EventService::open(&path, grants.clone(), callback.clone(), 7).unwrap());
        assert_eq!(events.health()["possible_restart_gap"], true);
        assert_eq!(events.health()["degraded"], true);
        assert_eq!(events.health()["historical_replay"], false);
        assert_eq!(events.health()["queue_depth"], 0);
        events.tick(now).await;
        assert!(callback.records().is_empty());
        let answer = events
            .rpc("actor_0", "events/subscribe", request(0, 1), now)
            .await
            .unwrap();
        assert_eq!(answer["id"], subscription);
    }
    let db = rusqlite::Connection::open(&path).unwrap();
    let starts: u64 = db
        .query_row("SELECT starts FROM event_service_meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(starts, 33);
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(tables, ["event_service_meta", "subscriptions"]);
    let bytes = std::fs::read(path).unwrap();
    assert!(!bytes
        .windows(b"never_persist_marker".len())
        .any(|w| w == b"never_persist_marker"));
    assert!(!bytes
        .windows(b"lost_restart".len())
        .any(|w| w == b"lost_restart"));
    assert!(started.elapsed() < Duration::from_secs(30));
    eprintln!("DELIVERY_OVERFLOW observations=2048 capacity=7 restart_cycles=32 starts={starts}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_during_callback_preparation_cannot_send_past_deadline() {
    for subscription_expiry in [false, true] {
        let fixture = Fixture::new(8);
        let mut params = request(0, 1);
        if subscription_expiry {
            params["ttlMs"] = json!(60_000);
        }
        fixture
            .events
            .rpc("actor_0", "events/subscribe", params, NOW)
            .await
            .unwrap();
        let id = format!("expiry_{subscription_expiry}");
        let gate = fixture.callback.gate(id.clone());
        assert_eq!(
            fixture.events.ingest(event(id, 0, NOW), NOW),
            EnqueueOutcome::Queued(1)
        );
        let deadline = NOW
            + if subscription_expiry {
                60_000
            } else {
                BUFFER_MS
            };
        let pump = {
            let events = fixture.events.clone();
            tokio::spawn(async move { events.tick(deadline - 50).await })
        };
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        gate.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .unwrap()
            .unwrap();
        fixture.events.tick(deadline + 10_000).await;
        assert!(
            fixture.callback.records().is_empty(),
            "expired bytes crossed the mock send boundary"
        );
        assert_eq!(fixture.events.health()["queue_depth"], 0);
    }
}
