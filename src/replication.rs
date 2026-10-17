//! Transport-independent admission and durable replay contract, not a network service.
//! Callers must obtain PeerIdentity from an authenticated, authorized transport.
#![allow(dead_code)]
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
pub const MAX_OBJECT_BYTES: usize = 8 * 1024 * 1024;
pub const PROTOCOL_VERSION: u32 = 1;
type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);
impl TryFrom<String> for Id {
    type Error = String;
    fn try_from(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 100
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("invalid_identifier".into());
        }
        Ok(Self(value))
    }
}
impl From<Id> for String {
    fn from(value: Id) -> Self {
        value.0
    }
}

/// Trusted caller input. Constructing this value does not authenticate a device.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub project: Id,
    pub device: Id,
    /// Authority whose event stream this peer is authorized to attest.
    pub authority: Id,
    pub may_replicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub project: Id,
    pub authority: Id,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub project: Id,
    pub device: Id,
    pub authority: Id,
    pub epoch: u64,
    pub sequence: u64,
    pub operation: Id,
    pub event: Event,
}

/// Public metadata only. No arbitrary engine requests or workspace mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    HeadAdvanced { head: String },
    ProposalAccepted { proposal: Id, head: String },
}

fn storage(e: rusqlite::Error) -> String {
    format!("replication_storage: {e}")
}
fn oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_epoch(epoch: u64) -> bool {
    epoch > 0 && epoch <= i64::MAX as u64
}

/// Check the serialized limit BEFORE parsing. Unknown fields and variants fail closed.
pub fn decode(bytes: &[u8]) -> Result<Envelope> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err("envelope_too_large".into());
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| "invalid_envelope".to_string())?;
    envelope.validate()?;
    Ok(envelope)
}
impl Envelope {
    fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            return Err("unsupported_protocol".into());
        }
        if !valid_epoch(self.epoch) || self.sequence == 0 || self.sequence > i64::MAX as u64 {
            return Err("invalid_counter".into());
        }
        let head = match &self.event {
            Event::HeadAdvanced { head } | Event::ProposalAccepted { head, .. } => head,
        };
        if !oid(head) {
            return Err("invalid_object_id".into());
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Applied,
    Duplicate,
}

/// Dedicated SQLite replay journal. Do not point this at the engine database.
/// The connection is exclusively borrowed during replay to prevent cursor races.
pub struct ReplayStore {
    db: Connection,
    binding: Authority,
}
impl ReplayStore {
    /// Binding is supplied from trusted local configuration, never from an envelope.
    /// Reopening with any different binding fails closed (no automatic migration).
    pub fn open(mut db: Connection, binding: Authority) -> Result<Self> {
        if !valid_epoch(binding.epoch) {
            return Err("invalid_counter".into());
        }
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS replication_binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), project TEXT NOT NULL, authority TEXT NOT NULL, epoch INTEGER NOT NULL, cursor INTEGER NOT NULL, head TEXT);
            CREATE TABLE IF NOT EXISTS replication_events (sequence INTEGER PRIMARY KEY, operation TEXT NOT NULL UNIQUE, digest TEXT NOT NULL, envelope TEXT NOT NULL);").map_err(storage)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            "INSERT OR IGNORE INTO replication_binding VALUES(1,?1,?2,?3,0,NULL)",
            params![binding.project.0, binding.authority.0, binding.epoch as i64],
        )
        .map_err(storage)?;
        let stored: (String, String, i64) = tx
            .query_row(
                "SELECT project,authority,epoch FROM replication_binding WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(storage)?;
        if stored
            != (
                binding.project.0.clone(),
                binding.authority.0.clone(),
                binding.epoch as i64,
            )
        {
            return Err("authority_binding_mismatch".into());
        }
        tx.commit().map_err(storage)?;
        Ok(Self { db, binding })
    }

    pub fn cursor(&self) -> Result<u64> {
        self.db
            .query_row(
                "SELECT cursor FROM replication_binding WHERE singleton=1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)
            .map_err(storage)
    }
    pub fn cached_head(&self) -> Result<Option<String>> {
        self.db
            .query_row(
                "SELECT head FROM replication_binding WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(storage)
    }

    /// Validated event, cached public head and cursor commit in one transaction.
    /// ACK only after this returns. This never imports objects or adopts live files.
    pub fn receive(&mut self, peer: &PeerIdentity, bytes: &[u8]) -> Result<Admission> {
        self.receive_inner(peer, bytes, true)
    }

    /// Non-mutating admission preflight under the caller's external engine lock.
    /// The caller must still call receive after durably installing verified objects.
    pub fn check(&mut self, peer: &PeerIdentity, bytes: &[u8]) -> Result<Admission> {
        self.receive_inner(peer, bytes, false)
    }
    fn receive_inner(
        &mut self,
        peer: &PeerIdentity,
        bytes: &[u8],
        commit: bool,
    ) -> Result<Admission> {
        let envelope = decode(bytes)?;
        if !peer.may_replicate {
            return Err("replication_forbidden".into());
        }
        if peer.project != self.binding.project || envelope.project != self.binding.project {
            return Err("wrong_project".into());
        }
        if envelope.device != peer.device {
            return Err("wrong_device".into());
        }
        if peer.authority != self.binding.authority
            || envelope.authority != self.binding.authority
            || envelope.epoch != self.binding.epoch
        {
            return Err("authority_fenced".into());
        }
        // Re-encode typed data so harmless JSON whitespace/key order is idempotent.
        let canonical = serde_json::to_string(&envelope).map_err(|e| e.to_string())?;
        let digest = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
        let cursor: i64 = tx
            .query_row(
                "SELECT cursor FROM replication_binding WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(storage)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT digest FROM replication_events WHERE sequence=?1",
                [envelope.sequence as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        if let Some(existing) = existing {
            return if existing == digest {
                Ok(Admission::Duplicate)
            } else {
                Err("replay_conflict".into())
            };
        }
        let reused: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM replication_events WHERE operation=?1)",
                [&envelope.operation.0],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if reused {
            return Err("idempotency_mismatch".into());
        }
        if envelope.sequence <= cursor as u64 {
            return Err("cursor_expired".into());
        }
        if envelope.sequence != cursor as u64 + 1 {
            return Err("sequence_gap".into());
        }
        tx.execute(
            "INSERT INTO replication_events VALUES(?1,?2,?3,?4)",
            params![
                envelope.sequence as i64,
                envelope.operation.0,
                digest,
                canonical
            ],
        )
        .map_err(storage)?;
        if let Event::HeadAdvanced { head } = &envelope.event {
            tx.execute(
                "UPDATE replication_binding SET head=?1 WHERE singleton=1",
                [head],
            )
            .map_err(storage)?;
        }
        tx.execute(
            "UPDATE replication_binding SET cursor=?1 WHERE singleton=1",
            [envelope.sequence as i64],
        )
        .map_err(storage)?;
        if commit {
            tx.commit().map_err(storage)?;
        } else {
            tx.rollback().map_err(storage)?;
        }
        Ok(Admission::Applied)
    }
}

/// A bounded raw transfer checksum, NOT a Git OID, object graph or signature check.
/// This cannot install refs. A future importer must quarantine and validate Git data.
#[derive(Debug)]
pub struct VerifiedPayload(Vec<u8>);
impl VerifiedPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
pub fn verify_payload(
    mut reader: impl std::io::Read,
    declared_len: u64,
    sha256: &str,
) -> Result<VerifiedPayload> {
    use std::io::Read;
    if declared_len > MAX_OBJECT_BYTES as u64 {
        return Err("object_too_large".into());
    }
    if sha256.len() != 64 || !oid(sha256) {
        return Err("invalid_checksum".into());
    }
    let mut bytes = Vec::new();
    // At most one extra byte is consumed to detect under-declared streams.
    (&mut reader)
        .take(declared_len + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("object_io: {e}"))?;
    if bytes.len() as u64 != declared_len {
        return Err("object_length_mismatch".into());
    }
    if format!("{:x}", Sha256::digest(&bytes)) != sha256 {
        return Err("object_checksum_mismatch".into());
    }
    Ok(VerifiedPayload(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(s: &str) -> Id {
        Id::try_from(s.to_string()).unwrap()
    }
    fn binding() -> Authority {
        Authority {
            project: id("project"),
            authority: id("coordinator"),
            epoch: 3,
        }
    }
    fn peer() -> PeerIdentity {
        PeerIdentity {
            project: id("project"),
            device: id("device"),
            authority: id("coordinator"),
            may_replicate: true,
        }
    }
    fn envelope(n: u64) -> Envelope {
        Envelope {
            version: 1,
            project: id("project"),
            device: id("device"),
            authority: id("coordinator"),
            epoch: 3,
            sequence: n,
            operation: id(&format!("op-{n}")),
            event: Event::HeadAdvanced {
                head: "a".repeat(40),
            },
        }
    }
    fn bytes(e: &Envelope) -> Vec<u8> {
        serde_json::to_vec(e).unwrap()
    }
    fn store() -> ReplayStore {
        ReplayStore::open(Connection::open_in_memory().unwrap(), binding()).unwrap()
    }
    #[test]
    fn ordered_replay_is_idempotent_and_conflicts_fail_closed() {
        let mut store = store();
        assert_eq!(
            store.receive(&peer(), &bytes(&envelope(2))).unwrap_err(),
            "sequence_gap"
        );
        assert_eq!(store.cursor().unwrap(), 0);
        assert_eq!(
            store.receive(&peer(), &bytes(&envelope(1))).unwrap(),
            Admission::Applied
        );
        let pretty = serde_json::to_vec_pretty(&envelope(1)).unwrap();
        assert_eq!(
            store.receive(&peer(), &pretty).unwrap(),
            Admission::Duplicate
        );
        let mut changed = envelope(1);
        changed.event = Event::HeadAdvanced {
            head: "b".repeat(40),
        };
        assert_eq!(
            store.receive(&peer(), &bytes(&changed)).unwrap_err(),
            "replay_conflict"
        );
        let mut reused = envelope(2);
        reused.operation = id("op-1");
        assert_eq!(
            store.receive(&peer(), &bytes(&reused)).unwrap_err(),
            "idempotency_mismatch"
        );
        assert_eq!(store.cursor().unwrap(), 1);
        assert_eq!(store.cached_head().unwrap(), Some("a".repeat(40)));
        assert_eq!(
            store.receive(&peer(), &bytes(&envelope(2))).unwrap(),
            Admission::Applied
        );
    }
    #[test]
    fn authenticated_context_and_authority_are_required_even_for_duplicates() {
        let mut store = store();
        store.receive(&peer(), &bytes(&envelope(1))).unwrap();
        for (field, expected) in [
            ("project", "wrong_project"),
            ("device", "wrong_device"),
            ("authority", "authority_fenced"),
            ("epoch", "authority_fenced"),
        ] {
            let mut e = envelope(1);
            match field {
                "project" => e.project = id("other"),
                "device" => e.device = id("other"),
                "authority" => e.authority = id("other"),
                _ => e.epoch = 4,
            }
            assert_eq!(store.receive(&peer(), &bytes(&e)).unwrap_err(), expected);
        }
        let mut old = envelope(2);
        old.epoch = 2;
        assert_eq!(
            store.receive(&peer(), &bytes(&old)).unwrap_err(),
            "authority_fenced"
        );
        let mut p = peer();
        p.project = id("other");
        assert_eq!(
            store.receive(&p, &bytes(&envelope(1))).unwrap_err(),
            "wrong_project"
        );
        let mut p = peer();
        p.authority = id("other");
        assert_eq!(
            store.receive(&p, &bytes(&envelope(1))).unwrap_err(),
            "authority_fenced"
        );
        let mut p = peer();
        p.may_replicate = false;
        assert_eq!(
            store.receive(&p, &bytes(&envelope(1))).unwrap_err(),
            "replication_forbidden"
        );
        assert_eq!(store.cursor().unwrap(), 1);
    }
    #[test]
    fn strict_bounded_decoding() {
        assert_eq!(
            decode(&vec![b' '; MAX_ENVELOPE_BYTES + 1]).unwrap_err(),
            "envelope_too_large"
        );
        let mut value = serde_json::to_value(envelope(1)).unwrap();
        value["unexpected"] = true.into();
        assert_eq!(
            decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            "invalid_envelope"
        );
        value.as_object_mut().unwrap().remove("unexpected");
        value["event"]["kind"] = "unknown".into();
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        for bad in ["", "../project", "a/b", "é"] {
            assert!(Id::try_from(bad.to_string()).is_err());
        }
        let mut e = envelope(0);
        assert_eq!(decode(&bytes(&e)).unwrap_err(), "invalid_counter");
        e.sequence = u64::MAX;
        assert_eq!(decode(&bytes(&e)).unwrap_err(), "invalid_counter");
        e.sequence = 1;
        e.version = 2;
        assert_eq!(decode(&bytes(&e)).unwrap_err(), "unsupported_protocol");
        e.version = 1;
        e.event = Event::HeadAdvanced {
            head: "not-an-oid".into(),
        };
        assert_eq!(decode(&bytes(&e)).unwrap_err(), "invalid_object_id");
    }
    #[test]
    fn event_cache_and_cursor_roll_back_together() {
        let mut store = store();
        store.db.execute_batch("CREATE TRIGGER fail_cursor BEFORE UPDATE OF cursor ON replication_binding BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;").unwrap();
        assert!(store.receive(&peer(), &bytes(&envelope(1))).is_err());
        assert_eq!(store.cursor().unwrap(), 0);
        assert_eq!(store.cached_head().unwrap(), None);
        assert_eq!(
            store
                .db
                .query_row("SELECT COUNT(*) FROM replication_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        store.db.execute_batch("DROP TRIGGER fail_cursor").unwrap();
        assert_eq!(
            store.receive(&peer(), &bytes(&envelope(1))).unwrap(),
            Admission::Applied
        );
    }
    #[test]
    fn reopen_retains_cursor_deduplication_and_pinned_authority() {
        let path = std::env::temp_dir().join(format!(
            "wipstash-replay-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let mut store = ReplayStore::open(Connection::open(&path).unwrap(), binding()).unwrap();
            store.receive(&peer(), &bytes(&envelope(1))).unwrap();
        }
        {
            let mut store = ReplayStore::open(Connection::open(&path).unwrap(), binding()).unwrap();
            assert_eq!(store.cursor().unwrap(), 1);
            assert_eq!(store.cached_head().unwrap(), Some("a".repeat(40)));
            assert_eq!(
                store.receive(&peer(), &bytes(&envelope(1))).unwrap(),
                Admission::Duplicate
            );
            store.receive(&peer(), &bytes(&envelope(2))).unwrap();
        }
        let mut different = binding();
        different.epoch += 1;
        assert!(
            matches!(ReplayStore::open(Connection::open(&path).unwrap(), different), Err(e) if e == "authority_binding_mismatch")
        );
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn proposal_event_is_journaled_without_implicit_head_change() {
        let mut store = store();
        let mut e = envelope(1);
        e.event = Event::ProposalAccepted {
            proposal: id("proposal"),
            head: "b".repeat(40),
        };
        store.receive(&peer(), &bytes(&e)).unwrap();
        assert_eq!(store.cursor().unwrap(), 1);
        assert_eq!(store.cached_head().unwrap(), None);
    }
    #[test]
    fn object_limits_truncation_and_corruption_fail_closed() {
        let data = b"public object transfer";
        let hash = format!("{:x}", Sha256::digest(data));
        assert_eq!(
            verify_payload(&data[..], data.len() as u64, &hash)
                .unwrap()
                .as_bytes(),
            data
        );
        assert_eq!(
            verify_payload(&data[..], data.len() as u64 - 1, &hash).unwrap_err(),
            "object_length_mismatch"
        );
        assert_eq!(
            verify_payload(&data[..], data.len() as u64 + 1, &hash).unwrap_err(),
            "object_length_mismatch"
        );
        assert_eq!(
            verify_payload(&data[..], MAX_OBJECT_BYTES as u64 + 1, &hash).unwrap_err(),
            "object_too_large"
        );
        assert_eq!(
            verify_payload(&data[..], data.len() as u64, &"0".repeat(64)).unwrap_err(),
            "object_checksum_mismatch"
        );
        assert_eq!(
            verify_payload(&data[..], data.len() as u64, "../path").unwrap_err(),
            "invalid_checksum"
        );
    }
    #[test]
    fn hostile_wire_values_and_payload_read_budget_are_bounded() {
        let mut e = envelope(1);
        e.epoch = 0;
        assert_eq!(decode(&bytes(&e)).unwrap_err(), "invalid_counter");
        e.epoch = u64::MAX;
        assert_eq!(decode(&bytes(&e)).unwrap_err(), "invalid_counter");
        let wire = String::from_utf8(bytes(&envelope(1))).unwrap();
        let duplicate = wire.replacen("{", "{\"version\":1,", 1);
        assert_eq!(
            decode(duplicate.as_bytes()).unwrap_err(),
            "invalid_envelope"
        );
        let mut value = serde_json::to_value(envelope(1)).unwrap();
        value["event"]["hidden"] = true.into();
        assert_eq!(
            decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            "invalid_envelope"
        );
        value = serde_json::to_value(envelope(1)).unwrap();
        value["sequence"] = (-1).into();
        assert_eq!(
            decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            "invalid_envelope"
        );
        struct CountingReader(usize);
        impl std::io::Read for CountingReader {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                self.0 += out.len();
                out.fill(b'a');
                Ok(out.len())
            }
        }
        let mut reader = CountingReader(0);
        assert_eq!(
            verify_payload(&mut reader, MAX_OBJECT_BYTES as u64 + 1, &"0".repeat(64)).unwrap_err(),
            "object_too_large"
        );
        assert_eq!(reader.0, 0);
        assert_eq!(
            verify_payload(&mut reader, 8, &"0".repeat(64)).unwrap_err(),
            "object_length_mismatch"
        );
        assert_eq!(reader.0, 9);
    }
}
