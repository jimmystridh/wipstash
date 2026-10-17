//! Independent oracle for the production replay contract, not a socket/network test.
#[path = "../../../src/replication.rs"]
mod replication;
use replication::{Admission, Authority, Envelope, Event, Id, PeerIdentity, ReplayStore};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

fn id(s: &str) -> Id {
    Id::try_from(s.to_owned()).unwrap()
}
fn binding() -> Authority {
    Authority {
        project: id("review"),
        authority: id("source"),
        epoch: 1,
    }
}
fn peer() -> PeerIdentity {
    PeerIdentity {
        project: id("review"),
        authority: id("source"),
        device: id("sender"),
        may_replicate: true,
    }
}
fn envelope(n: u64) -> Envelope {
    Envelope {
        version: 1,
        project: id("review"),
        authority: id("source"),
        device: id("sender"),
        epoch: 1,
        sequence: n,
        operation: id(&format!("op-{n}")),
        event: if n.is_multiple_of(3) {
            Event::ProposalAccepted {
                proposal: id(&format!("proposal-{n}")),
                head: format!("{n:040x}"),
            }
        } else {
            Event::HeadAdvanced {
                head: format!("{n:040x}"),
            }
        },
    }
}
fn bytes(n: u64) -> Vec<u8> {
    serde_json::to_vec(&envelope(n)).unwrap()
}
fn head(n: u64) -> Option<String> {
    if n == 0 {
        None
    } else {
        Some(format!(
            "{:040x}",
            if n.is_multiple_of(3) { n - 1 } else { n }
        ))
    }
}
fn open(path: &Path) -> ReplayStore {
    ReplayStore::open(Connection::open(path).unwrap(), binding()).unwrap()
}
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "wan-independent-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn four_reopened_replicas_match_exact_durable_prefix_after_hostile_order_and_ack_loss() {
    let directory = Directory::new("prefix");
    for actor in 0..4 {
        let path = directory.0.join(format!("actor-{actor}.sqlite"));
        let mut store = open(&path);
        // Reverse delivery genuinely hits the gap path: events must not be buffered or acknowledged as applied.
        for n in (2..=48).rev() {
            assert_eq!(
                store.receive(&peer(), &bytes(n)).unwrap_err(),
                "sequence_gap"
            );
            assert_eq!(store.cursor().unwrap(), 0);
            assert_eq!(store.cached_head().unwrap(), None);
        }
        for n in 1..=48 {
            // A successful commit followed by a deliberately lost ACK and reopen.
            assert_eq!(
                store.receive(&peer(), &bytes(n)).unwrap(),
                Admission::Applied
            );
            drop(store);
            store = open(&path);
            assert_eq!(store.cursor().unwrap(), n);
            assert_eq!(store.cached_head().unwrap(), head(n));
            assert_eq!(
                store
                    .receive(&peer(), &serde_json::to_vec_pretty(&envelope(n)).unwrap())
                    .unwrap(),
                Admission::Duplicate
            );
            // Delayed old retries must not rewind the cache or cursor.
            for old in [1, n] {
                assert_eq!(
                    store.receive(&peer(), &bytes(old)).unwrap(),
                    Admission::Duplicate
                );
                assert_eq!(store.cursor().unwrap(), n);
                assert_eq!(store.cached_head().unwrap(), head(n));
            }
            if n < 47 {
                assert_eq!(
                    store.receive(&peer(), &bytes(n + 2)).unwrap_err(),
                    "sequence_gap"
                );
                assert_eq!(store.cursor().unwrap(), n);
                assert_eq!(store.cached_head().unwrap(), head(n));
            }
            let db = Connection::open(&path).unwrap();
            let count: u64 = db
                .query_row("SELECT COUNT(*) FROM replication_events", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, n, "exactly one durable row per applied event");
            let mut statement = db
                .prepare(
                    "SELECT sequence,operation,envelope FROM replication_events ORDER BY sequence",
                )
                .unwrap();
            let rows = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, u64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .unwrap();
            for (index, row) in rows.enumerate() {
                let (seq, op, wire) = row.unwrap();
                assert_eq!(seq, index as u64 + 1);
                assert_eq!(op, format!("op-{seq}"));
                assert_eq!(wire, serde_json::to_string(&envelope(seq)).unwrap());
            }
        }
    }
}

#[test]
fn failed_storage_transaction_survives_reopen_without_acknowledgeable_partial_state() {
    let directory = Directory::new("rollback");
    let path = directory.0.join("replica.sqlite");
    let mut store = open(&path);
    assert_eq!(
        store.receive(&peer(), &bytes(1)).unwrap(),
        Admission::Applied
    );
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER fail_review_cursor BEFORE UPDATE OF cursor ON replication_binding BEGIN SELECT RAISE(ABORT, 'review injected failure'); END;").unwrap();
    assert!(store
        .receive(&peer(), &bytes(2))
        .unwrap_err()
        .contains("review injected failure"));
    drop(store);
    let mut store = open(&path);
    assert_eq!(store.cursor().unwrap(), 1);
    assert_eq!(store.cached_head().unwrap(), head(1));
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM replication_events", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
    db.execute_batch("DROP TRIGGER fail_review_cursor").unwrap();
    assert_eq!(
        store.receive(&peer(), &bytes(2)).unwrap(),
        Admission::Applied
    );
    assert_eq!(store.cursor().unwrap(), 2);
    assert_eq!(store.cached_head().unwrap(), head(2));
}
