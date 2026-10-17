//! Application-layer delivery simulation; deliberately no network sockets.
#[path = "../../../src/replication.rs"]
mod replication;
use replication::*;
use rusqlite::Connection;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};
const TICK_MS: u64 = 10;
const WINDOW: u64 = 8;
const BASE_MAX_TICKS: u64 = 9000;
fn id(s: &str) -> Id {
    Id::try_from(s.to_owned()).unwrap()
}
fn binding() -> Authority {
    Authority {
        project: id("wan-project"),
        authority: id("coordinator"),
        epoch: 7,
    }
}
fn identity() -> PeerIdentity {
    PeerIdentity {
        project: id("wan-project"),
        device: id("source"),
        authority: id("coordinator"),
        may_replicate: true,
    }
}
fn envelope(n: u64) -> Envelope {
    Envelope {
        version: 1,
        project: id("wan-project"),
        authority: id("coordinator"),
        device: id("source"),
        epoch: 7,
        sequence: n,
        operation: id(&format!("op-{n}")),
        event: if n.is_multiple_of(5) {
            Event::ProposalAccepted {
                proposal: id(&format!("proposal-{n}")),
                head: format!("{:040x}", n),
            }
        } else {
            Event::HeadAdvanced {
                head: format!("{:040x}", n),
            }
        },
    }
}
fn expected_head(n: u64) -> Option<String> {
    if n == 0 {
        None
    } else {
        Some(format!(
            "{:040x}",
            if n.is_multiple_of(5) { n - 1 } else { n }
        ))
    }
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn range(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}
#[derive(Clone)]
struct Packet {
    peer: usize,
    seq: u64,
    ack: bool,
    sent: u64,
    enqueued_at: Instant,
    delay: u64,
}
struct Peer {
    path: PathBuf,
    store: Option<ReplayStore>,
    acked: Vec<bool>,
    last: Vec<Option<u64>>,
    highest: u64,
    reopened: bool,
}
#[derive(Default, serde::Serialize)]
struct Stats {
    sent: u64,
    data_loss: u64,
    ack_loss: u64,
    partition_loss: u64,
    duplicate_injected: u64,
    duplicate_admitted: u64,
    reordered: u64,
    gaps: u64,
    applied: u64,
    acks: u64,
    reopens: u64,
    epoch_rejected: u64,
    permission_rejected: u64,
    binding_rejected: u64,
    max_queue: usize,
    max_delivery_lateness_ms: u128,
    delivered: u64,
    measured_delay_total_ms: u128,
    configured_delay_total_ms: u128,
    measured_delay_max_ms: u128,
}
fn log(file: &mut File, tick: u64, value: serde_json::Value) {
    writeln!(
        file,
        "{}",
        json!({"tick":tick,"nominal_ms":tick*TICK_MS,"event":value})
    )
    .unwrap();
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() == 5,
        "usage: wipstash-wan-sim SEED broadband|satellite EVENT_COUNT OUTPUT_DIR"
    );
    let seed: u64 = args[1].parse().unwrap();
    assert!(seed > 0);
    let satellite = match args[2].as_str() {
        "broadband" => false,
        "satellite" => true,
        _ => panic!("invalid profile"),
    };
    let count: u64 = args[3].parse().unwrap();
    assert!((16..=1000).contains(&count));
    let out = PathBuf::from(&args[4]);
    fs::create_dir_all(&out).unwrap();
    let mut trace = File::create(out.join("trace.jsonl")).unwrap();
    let mut rng = Rng(seed);
    let mut stats = Stats::default();
    let mut peers: Vec<Peer> = (0..4)
        .map(|i| {
            let path = out.join(format!("receiver-{i}.sqlite"));
            assert!(!path.exists(), "output must be fresh");
            let store =
                Some(ReplayStore::open(Connection::open(&path).unwrap(), binding()).unwrap());
            Peer {
                path,
                store,
                acked: vec![false; count as usize + 1],
                last: vec![None; count as usize + 1],
                highest: 0,
                reopened: false,
            }
        })
        .collect();
    let mut queue: BTreeMap<(u64, u64), Packet> = BTreeMap::new();
    let mut serial = 0;
    let mut finished = None;
    let start = Instant::now();
    let retry = if satellite { 140 } else { 65 };
    log(
        &mut trace,
        0,
        json!({"kind":"config","seed":seed,"profile":args[2],"events":count,"tick_ms":TICK_MS,"window":WINDOW,"retry_ms":retry*TICK_MS,"partition_ms":[1000,3500],"base_ms":if satellite{180}else{30},"jitter_max_ms":if satellite{420}else{170}}),
    );
    for tick in 0..=BASE_MAX_TICKS.max(count * 140) {
        let due = start + Duration::from_millis(tick * TICK_MS);
        if let Some(wait) = due.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        // Fault probes recur across delivery/reopen, proving failures never mutate state.
        if tick == 100 || tick == 350 {
            log(
                &mut trace,
                tick,
                json!({"kind":if tick==100{"partition_start"}else{"reconnect"},"peers":[2,3]}),
            );
        }
        if tick % 71 == 0 {
            for (i, p) in peers.iter_mut().enumerate() {
                let s = p.store.as_mut().unwrap();
                let before = s.cursor().unwrap();
                let head = s.cached_head().unwrap();
                let mut e = envelope(before.max(1));
                e.epoch = 6;
                assert_eq!(
                    s.receive(&identity(), &serde_json::to_vec(&e).unwrap())
                        .unwrap_err(),
                    "authority_fenced"
                );
                stats.epoch_rejected += 1;
                let mut forbidden = identity();
                forbidden.may_replicate = false;
                assert_eq!(
                    s.receive(
                        &forbidden,
                        &serde_json::to_vec(&envelope(before.max(1))).unwrap()
                    )
                    .unwrap_err(),
                    "replication_forbidden"
                );
                stats.permission_rejected += 1;
                assert_eq!(s.cursor().unwrap(), before);
                assert_eq!(s.cached_head().unwrap(), head);
                log(
                    &mut trace,
                    tick,
                    json!({"kind":"rejected_probes","peer":i,"cursor":before}),
                );
            }
        }
        // A bounded pipelined sender retains every unacknowledged operation.
        for (i, p) in peers.iter_mut().enumerate() {
            let low = (1..=count)
                .find(|n| !p.acked[*n as usize])
                .unwrap_or(count + 1);
            for seq in low..=(low + WINDOW - 1).min(count) {
                if p.acked[seq as usize] {
                    continue;
                }
                if p.last[seq as usize].is_some_and(|t| tick - t < retry) {
                    continue;
                }
                p.last[seq as usize] = Some(tick);
                stats.sent += 1;
                // Force loss for first operation to peer 0, in addition to seeded 12% drops.
                let forced = i == 0 && seq == 1 && tick == 0;
                if forced || rng.range(100) < 12 {
                    stats.data_loss += 1;
                    log(
                        &mut trace,
                        tick,
                        json!({"kind":"data_loss","peer":i,"seq":seq,"forced":forced}),
                    );
                    continue;
                }
                let mut delay = if satellite {
                    18 + rng.range(43)
                } else {
                    3 + rng.range(18)
                };
                // Guaranteed reordered first window for peer 1.
                if i == 1 && tick == 0 {
                    delay = if seq == 1 { 70 } else { 2 + seq };
                }
                serial += 1;
                queue.insert(
                    (tick + delay, serial),
                    Packet {
                        peer: i,
                        seq,
                        ack: false,
                        sent: tick,
                        enqueued_at: Instant::now(),
                        delay,
                    },
                );
                if rng.range(100) < 20 || (i == 2 && seq == 1 && tick == 0) {
                    serial += 1;
                    queue.insert(
                        (tick + delay + 1, serial),
                        Packet {
                            peer: i,
                            seq,
                            ack: false,
                            sent: tick,
                            enqueued_at: Instant::now(),
                            delay: delay + 1,
                        },
                    );
                    stats.duplicate_injected += 1;
                }
            }
        }
        while let Some((&key, _)) = queue.first_key_value() {
            if key.0 > tick {
                break;
            }
            let packet = queue.remove(&key).unwrap();
            let i = packet.peer;
            let minimum_delay = Duration::from_millis(packet.delay * TICK_MS);
            if let Some(remaining) = minimum_delay.checked_sub(packet.enqueued_at.elapsed()) {
                std::thread::sleep(remaining);
            }
            let measured_delay_ms = packet.enqueued_at.elapsed().as_millis();
            assert!(packet.enqueued_at.elapsed() >= minimum_delay);
            stats.measured_delay_total_ms += measured_delay_ms;
            stats.configured_delay_total_ms += (packet.delay * TICK_MS) as u128;
            stats.measured_delay_max_ms = stats.measured_delay_max_ms.max(measured_delay_ms);
            assert!(tick >= packet.sent + packet.delay);
            stats.delivered += 1;
            log(
                &mut trace,
                tick,
                json!({"kind":"delivery_timing","peer":i,"seq":packet.seq,"ack":packet.ack,"configured_delay_ms":packet.delay*TICK_MS,"measured_delay_ms":measured_delay_ms}),
            );
            stats.max_delivery_lateness_ms = stats.max_delivery_lateness_ms.max(
                start
                    .elapsed()
                    .as_millis()
                    .saturating_sub(key.0 as u128 * TICK_MS as u128),
            );
            // Two receivers experience a full bidirectional outage; scheduled in-flight packets also drop.
            if (i == 2 || i == 3) && (100..350).contains(&tick) {
                stats.partition_loss += 1;
                log(
                    &mut trace,
                    tick,
                    json!({"kind":"partition_drop","peer":i,"seq":packet.seq,"ack":packet.ack}),
                );
                continue;
            }
            let p = &mut peers[i];
            if packet.ack {
                p.acked[packet.seq as usize] = true;
                stats.acks += 1;
                log(
                    &mut trace,
                    tick,
                    json!({"kind":"ack","peer":i,"seq":packet.seq,"delay_ms":packet.delay*TICK_MS}),
                );
                continue;
            }
            if packet.seq < p.highest {
                stats.reordered += 1;
            }
            p.highest = p.highest.max(packet.seq);
            let s = p.store.as_mut().unwrap();
            let before = s.cursor().unwrap();
            let head = s.cached_head().unwrap();
            let result = s.receive(
                &identity(),
                &serde_json::to_vec(&envelope(packet.seq)).unwrap(),
            );
            let admitted = match result {
                Ok(Admission::Applied) => {
                    assert_eq!(packet.seq, before + 1);
                    stats.applied += 1;
                    true
                }
                Ok(Admission::Duplicate) => {
                    assert!(packet.seq <= before);
                    assert_eq!(s.cursor().unwrap(), before);
                    assert_eq!(s.cached_head().unwrap(), head);
                    stats.duplicate_admitted += 1;
                    true
                }
                Err(e) => {
                    assert_eq!(e, "sequence_gap");
                    assert!(packet.seq > before + 1);
                    assert_eq!(s.cursor().unwrap(), before);
                    assert_eq!(s.cached_head().unwrap(), head);
                    stats.gaps += 1;
                    false
                }
            };
            assert_eq!(s.cached_head().unwrap(), expected_head(s.cursor().unwrap()));
            log(
                &mut trace,
                tick,
                json!({"kind":"receive","peer":i,"seq":packet.seq,"before":before,"after":s.cursor().unwrap(),"admitted":admitted,"delay_ms":packet.delay*TICK_MS,"actual_age_ms":measured_delay_ms}),
            );
            if admitted {
                let forced = i == 3 && packet.seq <= 2 && tick < retry;
                if forced || rng.range(100) < 18 {
                    stats.ack_loss += 1;
                    log(
                        &mut trace,
                        tick,
                        json!({"kind":"ack_loss","peer":i,"seq":packet.seq,"forced":forced}),
                    );
                    continue;
                }
                let delay = if satellite {
                    18 + rng.range(43)
                } else {
                    3 + rng.range(18)
                };
                serial += 1;
                queue.insert(
                    (tick + delay, serial),
                    Packet {
                        peer: i,
                        seq: packet.seq,
                        ack: true,
                        sent: tick,
                        enqueued_at: Instant::now(),
                        delay,
                    },
                );
            }
        }
        for (i, p) in peers.iter_mut().enumerate() {
            if !p.reopened
                && tick >= 180 + i as u64 * 35
                && p.store.as_ref().unwrap().cursor().unwrap() > 0
            {
                let before = p.store.as_ref().unwrap().cursor().unwrap();
                let head = p.store.as_ref().unwrap().cached_head().unwrap();
                drop(p.store.take());
                let mut bad = binding();
                bad.epoch += 1;
                assert!(
                    matches!(ReplayStore::open(Connection::open(&p.path).unwrap(),bad),Err(e) if e=="authority_binding_mismatch")
                );
                stats.binding_rejected += 1;
                let mut s =
                    ReplayStore::open(Connection::open(&p.path).unwrap(), binding()).unwrap();
                assert_eq!(s.cursor().unwrap(), before);
                assert_eq!(s.cached_head().unwrap(), head);
                assert_eq!(
                    s.receive(&identity(), &serde_json::to_vec(&envelope(before)).unwrap())
                        .unwrap(),
                    Admission::Duplicate
                );
                p.store = Some(s);
                p.reopened = true;
                stats.reopens += 1;
                log(
                    &mut trace,
                    tick,
                    json!({"kind":"durable_reopen","peer":i,"cursor":before}),
                );
            }
        }
        stats.max_queue = stats.max_queue.max(queue.len());
        assert!(queue.len() < 4096, "queue memory bound");
        assert!(stats.sent < 100000, "attempt bound");
        if tick >= 350
            && peers
                .iter()
                .all(|p| p.reopened && (1..=count).all(|n| p.acked[n as usize]))
        {
            finished = Some(tick);
            break;
        }
    }
    let ticks = finished.expect("convergence deadline exceeded");
    for p in &mut peers {
        drop(p.store.take());
        let s = ReplayStore::open(Connection::open(&p.path).unwrap(), binding()).unwrap();
        assert_eq!(s.cursor().unwrap(), count);
        assert_eq!(s.cached_head().unwrap(), expected_head(count));
        let db = Connection::open(&p.path).unwrap();
        let rows: u64 = db
            .query_row("SELECT COUNT(*) FROM replication_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, count);
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }
    assert_eq!(stats.applied, count * 4);
    assert_eq!(stats.reopens, 4);
    assert!(
        stats.data_loss > 0
            && stats.ack_loss > 0
            && stats.partition_loss > 0
            && stats.duplicate_admitted > 0
            && stats.reordered > 0
            && stats.gaps > 0
    );
    assert!(start.elapsed() >= Duration::from_millis(ticks * TICK_MS));
    let summary = json!({"result":"PASS","seed":seed,"profile":args[2],"events_per_peer":count,"peers":4,"elapsed_ms":start.elapsed().as_millis(),"ticks":ticks,"retries":stats.sent-count*4,"stats":stats,"scope":"application-layer delayed delivery; no TCP/TLS/service or OS network shaping"});
    fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(&summary).unwrap(),
    )
    .unwrap();
    println!("{}", summary);
}
