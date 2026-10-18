//! Read-only Source observer for an actual native-agent synthetic-project campaign.
//! This example does not exercise the webhook delivery chain or open any sockets.
//! Start before authors publish; stop normally by creating ROOT/observer.stop.
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
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
fn saved(root: &Path, filename: &str, value: &Value) {
    let temporary = root.join(format!("{filename}.next"));
    fs::write(&temporary, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    fs::rename(&temporary, root.join(filename)).unwrap();
}
fn collect(
    source: &mut Source,
    events: &mut Vec<Transition>,
    ids: &mut BTreeSet<String>,
    counts: &mut BTreeMap<String, u64>,
) {
    for event in source.poll(now()) {
        assert!(ids.insert(event.id.clone()), "duplicate transition ID");
        assert_eq!(event.id.len(), 68);
        assert!(event.id.starts_with("evt_"));
        assert!(event.id[4..].bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(identifier(&event.project));
        if let Some(workspace) = &event.workspace {
            assert!(identifier(workspace));
        }
        if let Some(proposal) = &event.proposal {
            assert!(identifier(proposal));
        }
        assert!(matches!(
            event.name.as_str(),
            "action_required" | "proposal.integrated" | "public_head.advanced"
        ));
        *counts.entry(event.name.clone()).or_default() += 1;
        events.push(event);
    }
}
fn main() {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/workspace/shared/mcp-pressure/real-agents"));
    let state = root.join("state");
    assert!(
        state.join("state.sqlite").is_file(),
        "campaign must be initialized first"
    );
    assert!(
        !root.join("observer.stop").exists(),
        "stop sentinel already exists; use a fresh campaign"
    );
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/wipstash");
    let hash = digest(&SHA256, &fs::read(&binary).unwrap())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let projects = BTreeMap::from([("real-agents".into(), state)]);
    let mut source = Source::new(projects.clone()).unwrap();
    assert!(!source.degraded, "start observer before actor activity");
    assert!(
        source.poll(now()).is_empty(),
        "startup must not replay historic events"
    );
    let started = Instant::now();
    let start_epoch = now();
    let mut events = Vec::<Transition>::new();
    let mut ids = BTreeSet::new();
    let mut polls = 0u64;
    let mut successful_status_reads = 0u64;
    let mut busy_status_reads = 0u64;
    let mut saved_at = Instant::now();
    let mut counts = BTreeMap::<String, u64>::new();
    saved(
        &root,
        "observer.ready.json",
        &json!({"ready":true,"pid":std::process::id(),"started_at":start_epoch,"core_binary_sha256":hash,"poll_interval_ms":20,"max_seconds":900,"source_only":true,"webhook_delivery_chain":false}),
    );
    println!("Read-only Source observer ready; core SHA256 {hash}");
    let report = |events: &[Transition],
                  polls,
                  successful_status_reads,
                  busy_status_reads,
                  counts: &BTreeMap<String, u64>,
                  degraded,
                  complete,
                  stop_reason: &str,
                  restart_no_replay: Option<bool>,
                  stale_ids: &[String],
                  final_status: &Value| {
        json!({"kind":"actual-native-agent-campaign-source-only-observer","source_only":true,"webhook_delivery_chain":false,"core_binary_sha256":hash,"started_at":start_epoch,"seconds":started.elapsed().as_secs_f64(),"complete":complete,"stop_reason":stop_reason,"polls":polls,"successful_status_reads":successful_status_reads,"busy_status_reads":busy_status_reads,"source_degraded_seen":degraded,"event_count":events.len(),"counts":counts,"events":events.iter().map(|event|json!({"id":event.id,"name":event.name,"project":event.project,"workspace":event.workspace,"proposal":event.proposal,"occurred_at":event.occurred_at,"status":event.status})).collect::<Vec<_>>(),"duplicate_event_ids":false,"restart_no_replay_verified":restart_no_replay,"action_ids_no_longer_current":stale_ids,"final_status":final_status})
    };
    while !root.join("observer.stop").exists() && started.elapsed() < Duration::from_secs(900) {
        polls += 1;
        collect(&mut source, &mut events, &mut ids, &mut counts);
        match source.status("real-agents", None, None) {
            Ok(status) => {
                successful_status_reads += 1;
                let status = status.to_string();
                assert!(
                    !status.contains("SYNTHETIC_PRIVATE")
                        && !status.contains("PRIVATE_WIP")
                        && !status.contains("/workspace/")
                );
            }
            Err(error) => {
                assert_eq!(error, "project_busy");
                busy_status_reads += 1;
            }
        }
        if saved_at.elapsed() >= Duration::from_millis(250) {
            saved(
                &root,
                "observer-summary.json",
                &report(
                    &events,
                    polls,
                    successful_status_reads,
                    busy_status_reads,
                    &counts,
                    source.degraded,
                    false,
                    "running",
                    None,
                    &[],
                    &Value::Null,
                ),
            );
            saved_at = Instant::now();
        }
        thread::sleep(Duration::from_millis(20));
    }
    // Drain transitions committed immediately before the stop sentinel.
    polls += 1;
    collect(&mut source, &mut events, &mut ids, &mut counts);
    let stop_reason = if root.join("observer.stop").exists() {
        "sentinel"
    } else {
        "15-minute observation deadline"
    };
    // Parent stops after writers settle. If it does not, fail rather than claim
    // a successful no-replay check merely because startup could not read state.
    let mut restarted = Source::new(projects).unwrap();
    assert!(
        !restarted.degraded,
        "stop observer after actor writes finish"
    );
    let final_status = source.status("real-agents", None, None).unwrap();
    assert!(
        restarted.poll(now()).is_empty(),
        "historical event replay after restart"
    );
    let stale_ids: Vec<String> = events
        .iter()
        .filter(|event| event.name == "action_required" && !source.still_relevant(event))
        .map(|event| event.id.clone())
        .collect();
    let summary = report(
        &events,
        polls,
        successful_status_reads,
        busy_status_reads,
        &counts,
        source.degraded,
        true,
        stop_reason,
        Some(true),
        &stale_ids,
        &final_status,
    );
    saved(&root, "observer-summary.json", &summary);
    println!("Source observer completed: {} events, {polls} polls, {} action IDs no longer current. No webhook chain was exercised.",events.len(),stale_ids.len());
}
