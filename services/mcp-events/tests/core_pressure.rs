//! Four synthetic CLI workload actors, concurrently observed through Source.
//! Actual native-agent feature authoring is a separate campaign and is not claimed here.
//! No listeners, CI-only harness, process termination, command_run, or policy processes.
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Barrier, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wipstash_mcp_events::source::{identifier, Source, Transition};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn text(value: &Value, field: &str) -> String {
    value[field].as_str().unwrap().to_owned()
}
fn write(path: &Path, body: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}
fn manifest(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}
#[derive(Clone)]
struct Core {
    root: PathBuf,
    binary: PathBuf,
    log: Arc<Mutex<Vec<Value>>>,
    serial: Arc<AtomicU64>,
    started: Instant,
}
impl Core {
    fn request(&self, mut req: Value, ok: bool) -> Value {
        assert!(
            self.started.elapsed() < Duration::from_secs(90),
            "bounded campaign exceeded 90 seconds"
        );
        if req.get("operation_id").is_none() {
            req["operation_id"] = json!(format!(
                "core-pressure-{}",
                self.serial.fetch_add(1, Ordering::Relaxed)
            ));
        }
        let started = Instant::now();
        // output() waits for normal child exit; deliberately no timeout/kill fallback.
        let output = Command::new(&self.binary)
            .arg("--state")
            .arg(self.root.join("state"))
            .arg(req.to_string())
            .output()
            .unwrap();
        let response: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|_| panic!("CLI did not return JSON: {:?}", output));
        let record = json!({"request": req, "response": response, "exit": output.status.code(), "stderr": String::from_utf8_lossy(&output.stderr), "seconds": started.elapsed().as_secs_f64()});
        let mut log = self.log.lock().unwrap();
        log.push(record.clone());
        fs::write(
            self.root.join("commands.json"),
            serde_json::to_vec_pretty(&*log).unwrap(),
        )
        .unwrap();
        drop(log);
        assert_eq!(response["ok"], ok, "{record}");
        assert_eq!(output.status.success(), ok, "{record}");
        response
    }
    fn cp(&self, workspace: &str, generation: u64) -> Value {
        self.request(
            json!({"op":"checkpoint", "workspace":workspace,"expected_generation":generation}),
            true,
        )
    }
    fn publish(&self, workspace: &str, generation: u64) -> String {
        let cp = self.cp(workspace, generation);
        text(&self.request(json!({"op":"publish","workspace":workspace,"checkpoint":cp["checkpoint"],"intent":"Synthetic parallel core event pressure"}), true), "proposal")
    }
    fn git(&self, repo: &Path, args: &[&str]) -> String {
        let result = Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap().trim().to_owned()
    }
    fn project_map(&self) -> BTreeMap<String, PathBuf> {
        BTreeMap::from([("pressure-project".into(), self.root.join("state"))])
    }
    fn source(&self) -> Source {
        Source::new(self.project_map()).unwrap()
    }
    fn open_resolution(&self, owner: &str, proposal: &str, suffix: &str) -> Value {
        let workspace = format!("resolve-{owner}-{suffix}");
        self.request(json!({"op":"resolution_open","workspace":owner,"proposal":proposal,"resolution_workspace":workspace,"path":self.root.join(&workspace)}), true)
    }
    fn submit(
        &self,
        owner: &str,
        proposal: &str,
        workspace: &str,
        opened: &Value,
        body: &str,
    ) -> Value {
        write(&self.root.join(workspace).join("common.txt"), body);
        let cp = self.cp(workspace, opened["generation"].as_u64().unwrap());
        self.request(json!({"op":"resolution_submit","workspace":owner,"proposal":proposal,"resolution_workspace":workspace,"checkpoint":cp["checkpoint"],"expected_head":opened["current_head"],"resolved_conflicts":opened["conflict_paths"]}), true)
    }
}
fn event_value(e: &Transition) -> Value {
    json!({"id":e.id,"name":e.name,"project":e.project,"workspace":e.workspace,"proposal":e.proposal,"occurred_at":e.occurred_at,"status":e.status})
}
#[derive(Default)]
struct Observations {
    events: Vec<Transition>,
    polls: u64,
    statuses: u64,
    busy_statuses: u64,
    degraded: bool,
}
struct Observer {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    shared: Arc<Mutex<Observations>>,
}
impl Observer {
    fn start(core: &Core) -> Self {
        let mut source = core.source();
        let stop = Arc::new(AtomicBool::new(false));
        let end = stop.clone();
        let shared = Arc::new(Mutex::new(Observations::default()));
        let data = shared.clone();
        let handle = thread::spawn(move || {
            while !end.load(Ordering::Relaxed) {
                let events = source.poll(now());
                let status = source.status("pressure-project", None, None);
                let mut data = data.lock().unwrap();
                data.polls += 1;
                data.events.extend(events);
                data.degraded = source.degraded;
                match status {
                    Ok(status) => {
                        let value = status.to_string();
                        assert!(
                            !value.contains("SYNTHETIC_PRIVATE")
                                && !value.contains("PRIVATE_ANCESTOR")
                        );
                        assert!(status.get("path").is_none());
                        data.statuses += 1;
                    }
                    Err(error) => {
                        assert_eq!(error, "project_busy");
                        data.busy_statuses += 1;
                    }
                }
                drop(data);
                thread::sleep(Duration::from_millis(5));
            }
            let mut data = data.lock().unwrap();
            data.events.extend(source.poll(now()));
        });
        Self {
            stop,
            handle: Some(handle),
            shared,
        }
    }
    fn settle(&self, count: usize) {
        let start = Instant::now();
        while self.shared.lock().unwrap().events.len() < count
            && start.elapsed() < Duration::from_secs(3)
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            self.shared.lock().unwrap().events.len() >= count,
            "observer did not catch up"
        );
    }
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn parallel_cli_conflicts_handback_and_source_observation() {
    let binary = std::env::var_os("WIPSTASH_CORE_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug")
                .join(format!("wipstash{}", std::env::consts::EXE_SUFFIX))
        });
    assert!(
        binary.is_file(),
        "build the core CLI first: {}",
        binary.display()
    );
    let evidence = std::env::var_os("WIPSTASH_PRESSURE_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("wipstash-core-pressure"));
    fs::create_dir_all(&evidence).unwrap();
    let root = evidence.join(format!(
        "run-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let core = Core {
        root: root.clone(),
        binary,
        log: Arc::new(Mutex::new(Vec::new())),
        serial: Arc::new(AtomicU64::new(1)),
        started: Instant::now(),
    };
    write(&root.join("source/common.txt"), "baseline\n");
    write(
        &root.join("source/.gitignore"),
        ".env\nlocal/\nbuild/\n.agent/\n",
    );
    core.request(json!({"op":"init","source":root.join("source")}), true);
    for actor in ["A", "B", "C", "D"] {
        core.request(
            json!({"op":"open","workspace":actor,"path":root.join(actor)}),
            true,
        );
        write(
            &root.join(actor).join(".env"),
            format!("SYNTHETIC_PRIVATE_{actor}\n"),
        );
        write(
            &root.join(actor).join("local/keep.txt"),
            format!("SYNTHETIC_PRIVATE_{actor}\n"),
        );
    }
    write(
        &root.join("B/private-only.txt"),
        "PRIVATE_ANCESTOR_MUST_NOT_ESCAPE\n",
    );
    let private_cp = core.cp("B", 0);
    let private_commit = text(&private_cp, "commit");
    let private_repo = root.join("state/locals/B/objects.git");
    let private_blob = core.git(
        &private_repo,
        &["rev-parse", &format!("{private_commit}:private-only.txt")],
    );
    fs::remove_file(root.join("B/private-only.txt")).unwrap();
    let mut aged_source = core.source();
    let mut observer = Observer::start(&core);
    let gate = Arc::new(Barrier::new(4));
    let actors: Vec<_> = ["A", "B", "C", "D"]
        .into_iter()
        .map(|actor| {
            let core = core.clone();
            let gate = gate.clone();
            thread::spawn(move || {
                gate.wait();
                write(
                    &core.root.join(actor).join("common.txt"),
                    format!("change-{actor}\n"),
                );
                write(
                    &core.root.join(actor).join(format!("feature-{actor}.txt")),
                    format!("public-{actor}\n"),
                );
                let proposal = core.publish(actor, if actor == "B" { 1 } else { 0 });
                write(
                    &core.root.join(actor).join("unsaved.txt"),
                    format!("SYNTHETIC_PRIVATE_unsaved_{actor}\n"),
                );
                (actor.to_owned(), proposal)
            })
        })
        .collect();
    let proposals: BTreeMap<_, _> = actors
        .into_iter()
        .map(|actor| actor.join().unwrap())
        .collect();
    let frozen: BTreeMap<_, _> = proposals
        .keys()
        .map(|actor| (actor.clone(), manifest(&root.join(actor))))
        .collect();
    let integrated = core.request(json!({"op":"integrate"}), true);
    let outcomes = integrated["outcomes"].as_array().unwrap();
    assert_eq!(outcomes.len(), 4);
    assert_eq!(
        outcomes
            .iter()
            .filter(|v| v["state"] == "integrated")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|v| v["state"] == "quarantined")
            .count(),
        3
    );
    observer.settle(5);
    let losers: Vec<(String, String)> = outcomes
        .iter()
        .filter(|v| v["state"] == "quarantined")
        .map(|v| {
            let proposal = text(v, "proposal");
            let owner = proposals
                .iter()
                .find(|(_, p)| **p == proposal)
                .unwrap()
                .0
                .clone();
            (owner, proposal)
        })
        .collect();
    let original_event = observer
        .shared
        .lock()
        .unwrap()
        .events
        .iter()
        .find(|e| {
            e.proposal.as_deref() == Some(losers[0].1.as_str()) && e.name == "action_required"
        })
        .unwrap()
        .clone();
    assert!(core.source().still_relevant(&original_event));
    let mut suppressed_source = core.source();
    let (owner, proposal) = &losers[0];
    let opened = core.open_resolution(owner, proposal, "first");
    // Queue a competing public update before the resolution submission. Both
    // are based on the same current head, so the replacement fails afresh.
    core.request(
        json!({"op":"open","workspace":"rival","path":root.join("rival")}),
        true,
    );
    write(&root.join("rival/common.txt"), "rival-first\n");
    core.publish("rival", 0);
    let replacement = core.submit(
        owner,
        proposal,
        &format!("resolve-{owner}-first"),
        &opened,
        "first-resolution\n",
    );
    let replacement_id = text(&replacement, "proposal");
    assert!(!core.source().still_relevant(&original_event));
    let failed_again = core.request(json!({"op":"integrate"}), true);
    assert_eq!(failed_again["outcomes"][0]["state"], "integrated");
    assert_eq!(failed_again["outcomes"][1]["state"], "quarantined");
    assert_eq!(failed_again["outcomes"][1]["resolution_task"]["attempt"], 1);
    observer.settle(8);
    let second_event = observer
        .shared
        .lock()
        .unwrap()
        .events
        .iter()
        .find(|e| {
            e.proposal.as_deref() == Some(replacement_id.as_str()) && e.name == "action_required"
        })
        .unwrap()
        .clone();
    assert_ne!(original_event.id, second_event.id);
    // Create stale resolution sessions before advancing the public head.
    let stale: Vec<_> = losers[1..]
        .iter()
        .map(|(owner, proposal)| {
            (
                owner.clone(),
                proposal.clone(),
                core.open_resolution(owner, proposal, "stale"),
            )
        })
        .collect();
    let fresh = core.open_resolution(owner, &replacement_id, "second");
    let fixed = core.submit(
        owner,
        &replacement_id,
        &format!("resolve-{owner}-second"),
        &fresh,
        "resolved-all-first\n",
    );
    let fixed_id = text(&fixed, "proposal");
    core.request(json!({"op":"integrate"}), true);
    assert_eq!(
        core.request(json!({"op":"proposal_status","proposal":fixed_id}), true)["state"],
        "integrated"
    );
    assert!(!core.source().still_relevant(&second_event));
    for (index, (owner, proposal, opened)) in stale.into_iter().enumerate() {
        let workspace = format!("resolve-{owner}-stale");
        write(
            &root.join(&workspace).join("common.txt"),
            "stale-resolution-must-not-land\n",
        );
        let cp = core.cp(&workspace, opened["generation"].as_u64().unwrap());
        let stale_result=core.request(json!({"op":"resolution_submit","workspace":owner,"proposal":proposal,"resolution_workspace":workspace,"checkpoint":cp["checkpoint"],"expected_head":opened["current_head"],"resolved_conflicts":opened["conflict_paths"]}),false);
        assert_eq!(stale_result["error"]["code"], "stale_resolution");
        let fresh = core.open_resolution(&owner, &proposal, "fresh");
        core.submit(
            &owner,
            &proposal,
            &format!("resolve-{owner}-fresh"),
            &fresh,
            &format!("resolved-all-{}\n", index + 2),
        );
        core.request(json!({"op":"integrate"}), true);
    }
    observer.settle(14);
    observer.stop();
    for (owner, original) in &frozen {
        assert_eq!(
            manifest(&root.join(owner)),
            *original,
            "private WIP changed for {owner}"
        );
        assert!(
            core.request(json!({"op":"resolution_tasks","workspace":owner}), true)["tasks"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    let suppressed = suppressed_source.poll(now());
    assert!(
        !suppressed
            .iter()
            .any(|event| event.name == "action_required"),
        "superseded delayed action escaped"
    );
    assert!(
        aged_source.poll(now() + 301).is_empty(),
        "expired transitions escaped"
    );
    assert!(aged_source.degraded);
    assert!(
        core.source().poll(now()).is_empty(),
        "historic transitions replayed after restart"
    );
    let observed = observer.shared.lock().unwrap();
    assert!(observed.polls > 10 && observed.statuses > 0);
    let mut ids = BTreeSet::new();
    for event in &observed.events {
        assert!(
            ids.insert(event.id.clone()),
            "transition replayed: {}",
            event.id
        );
        assert_eq!(event.id.len(), 68);
        assert!(event.id.starts_with("evt_"));
        assert!(event.id[4..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(identifier(&event.project));
        if let Some(workspace) = &event.workspace {
            assert!(identifier(workspace));
        }
        if let Some(proposal) = &event.proposal {
            assert!(identifier(proposal));
        }
        let safe = event_value(event).to_string();
        assert!(
            !safe.contains("SYNTHETIC_PRIVATE")
                && !safe.contains("PRIVATE_ANCESTOR")
                && !safe.contains(&root.to_string_lossy().to_string())
        );
    }
    let repo = root.join("state/coordinator.git");
    let objects = core.git(
        &repo,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
    );
    assert!(!objects
        .lines()
        .any(|oid| oid == private_commit || oid == private_blob));
    assert_eq!(
        core.git(
            &private_repo,
            &["rev-parse", &format!("{private_commit}:private-only.txt")]
        ),
        private_blob
    );
    core.git(&repo, &["fsck", "--full", "--strict"]);
    let public = core.git(&repo, &["ls-tree", "-r", "refs/wipstash/integration"]);
    assert!(
        !public.contains("unsaved.txt")
            && !public.contains("private-only.txt")
            && !public.contains(".env")
            && !public.contains("local/")
    );
    let db = rusqlite::Connection::open(root.join("state/state.sqlite")).unwrap();
    let integrity: String = db
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let duplicates:i64=db.query_row("SELECT COUNT(*) FROM (SELECT proposal FROM promotions WHERE state='committed' GROUP BY proposal HAVING COUNT(*)>1)",[],|r|r.get(0)).unwrap();
    assert_eq!(duplicates, 0);
    assert!(core.started.elapsed() < Duration::from_secs(90));
    let summary = json!({"kind":"synthetic-cli-workload-actors-not-native-agent-authors","actors":4,"commands":core.log.lock().unwrap().len(),"seconds":core.started.elapsed().as_secs_f64(),"source_polls":observed.polls,"successful_status_reads":observed.statuses,"busy_status_reads":observed.busy_statuses,"source_degraded_seen":observed.degraded,"events":observed.events.iter().map(event_value).collect::<Vec<_>>(),"private_wip_unchanged":true,"private_ancestor_unpublished":true,"new_failed_attempt_distinct":true,"stale_resolution_rejected":true,"superseded_actions_suppressed":true,"expired_events_suppressed":true,"historic_replay":false,"sqlite_integrity":integrity,"duplicate_committed_promotions":duplicates});
    fs::write(
        root.join("summary.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
    eprintln!("Core pressure evidence: {}", root.display());
    eprintln!("{summary}");
}
