//! Windows transactional staging, also compiled privately in portable unit tests.
use super::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

const DATABASE: &str = "resumable-v1.sqlite3";
const APPLICATION: i64 = 0x57545231;
const SCHEMA: &str = "CREATE TABLE transfers(id TEXT PRIMARY KEY NOT NULL, record BLOB NOT NULL, payload BLOB NOT NULL) STRICT";
pub struct Store {
    root: PathBuf,
    #[cfg(test)]
    fault_vfs: bool,
}
impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let store = Self {
            root: root.as_ref().to_path_buf(),
            #[cfg(test)]
            fault_vfs: false,
        };
        store.connection()?;
        Ok(store)
    }
    fn connection(&self) -> Result<Connection> {
        #[cfg(windows)]
        super::windows_path::check(&self.root)?;
        #[cfg(not(windows))]
        {
            check_ancestors(&self.root)?;
            if !self.root.is_dir() {
                return Err(error("existing_transfer_root_required"));
            }
        }
        // Never silently abandon retained Unix acknowledgements.
        for legacy in ["resumable", "lock"] {
            match fs::symlink_metadata(self.root.join(legacy)) {
                Ok(_) => return Err(error("transfer_storage_format")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_name().to_str().is_some_and(valid_id) && entry.file_type()?.is_dir() {
                return Err(error("transfer_storage_format"));
            }
        }
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let path = self.root.join(format!("{DATABASE}{suffix}"));
            #[cfg(windows)]
            super::windows_path::check_file(&path)?;
            #[cfg(not(windows))]
            check_ancestors(&path)?;
            if path.exists() && !path.is_file() {
                return Err(error("transfer_storage_format"));
            }
        }
        #[cfg(not(test))]
        let mut db = Connection::open(self.root.join(DATABASE))?;
        #[cfg(test)]
        let mut db = if self.fault_vfs {
            sqlite_fault::open(self.root.join(DATABASE))?
        } else {
            Connection::open(self.root.join(DATABASE))?
        };
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        // Reject foreign databases before changing their journal settings. Repeat
        // the check under the write transaction to serialize concurrent bootstrap.
        Self::schema(&db)?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=PERSIST; PRAGMA synchronous=EXTRA; PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0; PRAGMA auto_vacuum=NONE;")?;
        let journal: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        let sync: i64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        let vacuum: i64 = db.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
        if journal != "persist" || sync != 3 || vacuum != 0 {
            return Err(error("transfer_sqlite_durability"));
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if Self::schema(&tx)? {
            tx.execute_batch(SCHEMA)?;
            tx.pragma_update(None, "application_id", APPLICATION)?;
            tx.pragma_update(None, "user_version", 1)?;
        }
        tx.commit()?;
        Ok(db)
    }
    /// True only for an uninitialized empty SQLite database.
    fn schema(db: &Connection) -> Result<bool> {
        let app: i64 = db.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let schema: Vec<(String, String)> = {
            let mut q = db.prepare(
                "SELECT name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
            )?;
            let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        if app == 0 && version == 0 && schema.is_empty() {
            return Ok(true);
        }
        if app != APPLICATION || version != 1 || schema != vec![("transfers".into(), SCHEMA.into())]
        {
            return Err(error("transfer_storage_schema"));
        }
        Ok(false)
    }
    fn read(db: &Connection, binding: &Binding, id: &str) -> Result<(Record, Vec<u8>)> {
        if !valid_id(id) {
            return Err(error("transfer_id"));
        }
        let lengths: Option<(i64, i64)> = db
            .query_row(
                "SELECT length(record),length(payload) FROM transfers WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (record_len, payload_len) = lengths
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "transfer absent"))?;
        if !(1..=RECORD_BOUND as i64).contains(&record_len)
            || !(0..=PAYLOAD_MAX as i64).contains(&payload_len)
        {
            return Err(error("transfer_record_bound"));
        }
        let (bytes, payload): (Vec<u8>, Vec<u8>) = db.query_row(
            "SELECT record,payload FROM transfers WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let record: Record = serde_json::from_slice(&bytes)?;
        if record.version != 1 || record.binding != *binding || record.status.transfer_id != id {
            return Err(error("transfer_binding"));
        }
        let manifest: Value = serde_json::from_slice(&record.manifest)?;
        if record.manifest.len() > MANIFEST_MAX
            || transfer_id(binding, &record.manifest)? != id
            || record.status.committed_offset > record.status.payload_len
            || record.status.payload_len > PAYLOAD_MAX as u64
            || manifest["payload_len"].as_u64() != Some(record.status.payload_len)
            || manifest["payload_sha256"].as_str() != Some(&record.status.payload_sha256)
            || manifest["version"] != 1
            || manifest["kind"] != "proposal"
            || manifest["device"] != binding.device
            || manifest["project"] != binding.project
            || !valid_id(&record.status.payload_sha256)
            || record.chunks.len() > 4096
        {
            return Err(error("transfer_record"));
        }
        let mut offset = 0u64;
        for chunk in &record.chunks {
            if chunk.offset != offset
                || chunk.len == 0
                || chunk.len > CHUNK_MAX as u64
                || !valid_id(&chunk.sha256)
            {
                return Err(error("transfer_record"));
            }
            offset = offset
                .checked_add(chunk.len)
                .ok_or_else(|| error("transfer_record"))?;
            if record.status.import_result.is_none() {
                let bytes = payload
                    .get(chunk.offset as usize..offset as usize)
                    .ok_or_else(|| error("transfer_corrupt"))?;
                if fingerprint(bytes) != chunk.sha256 {
                    return Err(error("transfer_corrupt"));
                }
            }
        }
        if offset != record.status.committed_offset
            || (record.status.import_result.is_none() && payload.len() as u64 != offset)
            || (record.status.import_result.is_some()
                && (!payload.is_empty() || offset != record.status.payload_len))
            || record
                .status
                .import_result
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()?
                .is_some_and(|v| v.len() > 1024 * 1024)
        {
            return Err(error("transfer_corrupt"));
        }
        Ok((record, payload))
    }
    fn write(db: &Connection, record: &Record, payload: &[u8]) -> Result<()> {
        let bytes = serde_json::to_vec(record)?;
        if bytes.len() > RECORD_BOUND {
            return Err(error("transfer_record_bound"));
        }
        db.execute("INSERT INTO transfers(id,record,payload) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET record=excluded.record,payload=excluded.payload",params![record.status.transfer_id,bytes,payload])?;
        Ok(())
    }
    pub fn begin(&self, binding: &Binding, manifest: &[u8]) -> Result<Status> {
        if manifest.is_empty() || manifest.len() > MANIFEST_MAX {
            return Err(error("artifact_bound"));
        }
        let m: Value = serde_json::from_slice(manifest)?;
        let length = m["payload_len"]
            .as_u64()
            .ok_or_else(|| error("artifact_bound"))?;
        let digest = m["payload_sha256"]
            .as_str()
            .ok_or_else(|| error("artifact_digest"))?;
        if m["version"] != 1
            || m["kind"] != "proposal"
            || m["device"] != binding.device
            || m["project"] != binding.project
            || length > PAYLOAD_MAX as u64
            || !valid_id(digest)
        {
            return Err(error("artifact_identity"));
        }
        let id = transfer_id(binding, manifest)?;
        let mut db = self.connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match Self::read(&tx, binding, &id) {
            Ok((r, _)) => {
                if r.manifest != manifest {
                    return Err(error("transfer_manifest_changed"));
                }
                return Ok(r.status);
            }
            Err(e) if super::is_missing(&*e) => (),
            Err(e) => return Err(e),
        }
        let r = Record {
            version: 1,
            binding: binding.clone(),
            manifest: manifest.to_vec(),
            chunks: vec![],
            status: Status {
                transfer_id: id,
                committed_offset: 0,
                payload_len: length,
                payload_sha256: digest.into(),
                import_result: None,
                retention: "durable_until_explicit_operator_cleanup_no_automatic_expiry".into(),
            },
        };
        Self::write(&tx, &r, &[])?;
        tx.commit()?;
        Ok(r.status)
    }
    pub fn validate_authority(
        &self,
        binding: &Binding,
        id: &str,
        authority: &str,
        epoch: u64,
    ) -> Result<()> {
        let mut db = self.connection()?;
        let tx = db.transaction()?;
        let (r, _) = Self::read(&tx, binding, id)?;
        let m: Value = serde_json::from_slice(&r.manifest)?;
        if m["authority"].as_str() != Some(authority) || m["epoch"].as_u64() != Some(epoch) {
            return Err(error("artifact_identity"));
        }
        Ok(())
    }
    pub fn status(&self, binding: &Binding, id: &str) -> Result<Status> {
        let mut db = self.connection()?;
        let tx = db.transaction()?;
        Ok(Self::read(&tx, binding, id)?.0.status)
    }
    pub fn chunk(&self, binding: &Binding, id: &str, offset: u64, bytes: &[u8]) -> Result<Status> {
        if bytes.is_empty() || bytes.len() > CHUNK_MAX {
            return Err(error("chunk_bound"));
        }
        let mut db = self.connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut r, mut payload) = Self::read(&tx, binding, id)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| error("chunk_bound"))?;
        if end > r.status.payload_len || offset > r.status.committed_offset {
            return Err(error("chunk_offset"));
        }
        if r.status.import_result.is_some() {
            if r.chunks.iter().any(|c| {
                c.offset == offset && c.len == bytes.len() as u64 && c.sha256 == fingerprint(bytes)
            }) {
                return Ok(r.status);
            }
            return Err(error("chunk_changed"));
        }
        if offset < r.status.committed_offset {
            if end > r.status.committed_offset {
                return Err(error("chunk_overlap"));
            }
            if payload[offset as usize..end as usize] != *bytes {
                return Err(error("chunk_changed"));
            }
            return Ok(r.status);
        }
        if r.chunks.len() as u64 + 1 + (r.status.payload_len - end).div_ceil(CHUNK_MAX as u64)
            > 4096
        {
            return Err(error("chunk_count_bound"));
        }
        payload.extend_from_slice(bytes);
        r.status.committed_offset = end;
        r.chunks.push(Chunk {
            offset,
            len: bytes.len() as u64,
            sha256: fingerprint(bytes),
        });
        Self::write(&tx, &r, &payload)?;
        tx.commit()?;
        Ok(r.status)
    }
    pub fn artifact(&self, binding: &Binding, id: &str) -> Result<Artifact> {
        let mut db = self.connection()?;
        let tx = db.transaction()?;
        let (r, objects) = Self::read(&tx, binding, id)?;
        if r.status.committed_offset != r.status.payload_len || r.status.import_result.is_some() {
            return Err(error("transfer_incomplete"));
        }
        let a = Artifact {
            manifest: r.manifest,
            objects,
        };
        a.validate()?;
        Ok(a)
    }
    pub fn complete(&self, binding: &Binding, id: &str, import_result: Value) -> Result<Status> {
        if import_result.is_null() {
            return Err(error("transfer_result_null"));
        }
        if serde_json::to_vec(&import_result)?.len() > 1024 * 1024 {
            return Err(error("transfer_result_bound"));
        }
        let mut db = self.connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut r, _) = Self::read(&tx, binding, id)?;
        if r.status.committed_offset != r.status.payload_len {
            return Err(error("transfer_incomplete"));
        }
        if let Some(prior) = &r.status.import_result {
            if prior != &import_result {
                return Err(error("transfer_result_changed"));
            }
            return Ok(r.status);
        }
        r.status.import_result = Some(import_result);
        Self::write(&tx, &r, &[])?;
        tx.commit()?;
        Ok(r.status)
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn binding() -> Binding {
        Binding {
            certificate: fingerprint(b"certificate"),
            device: "alice".into(),
            project: "demo".into(),
        }
    }
    fn manifest(payload: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({"version":1,"kind":"proposal","device":"alice","project":"demo","authority":"central","epoch":1,"payload_len":payload.len(),"payload_sha256":fingerprint(payload)})).unwrap()
    }
    #[test]
    fn sqlite_restart_lost_ack_subranges_completion_and_binding() {
        let t = tempfile::tempdir().unwrap();
        let b = binding();
        let payload = vec![42; CHUNK_MAX + 33];
        let m = manifest(&payload);
        let s = Store::open(t.path()).unwrap();
        let id = s.begin(&b, &m).unwrap().transfer_id;
        assert_eq!(id, transfer_id(&b, &m).unwrap());
        assert!(s.artifact(&b, &id).is_err());
        assert!(s.complete(&b, &id, json!({"ok":true})).is_err());
        s.chunk(&b, &id, 0, &payload[..CHUNK_MAX]).unwrap();
        drop(s);
        let s = Store::open(t.path()).unwrap();
        assert_eq!(s.begin(&b, &m).unwrap().committed_offset, CHUNK_MAX as u64);
        assert!(s
            .chunk(&b, &id, 0, &payload[..CHUNK_MAX])
            .unwrap()
            .import_result
            .is_none());
        assert!(s.chunk(&b, &id, 17, &payload[17..89]).is_ok());
        assert!(s.chunk(&b, &id, 0, b"changed").is_err());
        assert!(s.chunk(&b, &id, CHUNK_MAX as u64 - 1, &[42; 3]).is_err());
        assert!(s.chunk(&b, &id, CHUNK_MAX as u64 + 1, b"gap").is_err());
        for other in [
            Binding {
                certificate: "other".into(),
                ..b.clone()
            },
            Binding {
                device: "other".into(),
                ..b.clone()
            },
            Binding {
                project: "other".into(),
                ..b.clone()
            },
        ] {
            assert!(s.status(&other, &id).is_err());
            assert!(s.chunk(&other, &id, 0, b"x").is_err());
        }
        assert!(s.validate_authority(&b, &id, "central", 1).is_ok());
        assert!(s.validate_authority(&b, &id, "central", 2).is_err());
        assert!(s.validate_authority(&b, &id, "other", 1).is_err());
        s.chunk(&b, &id, CHUNK_MAX as u64, &payload[CHUNK_MAX..])
            .unwrap();
        assert!(s.chunk(&b, &id, CHUNK_MAX as u64 - 2, &[42; 5]).is_ok());
        assert_eq!(s.artifact(&b, &id).unwrap().objects, payload);
        assert!(s.complete(&b, &id, Value::Null).is_err());
        assert_eq!(s.artifact(&b, &id).unwrap().objects, payload);
        let imported = json!({"ok":true,"proposal":"core"});
        s.complete(&b, &id, imported.clone()).unwrap();
        drop(s);
        let s = Store::open(t.path()).unwrap();
        assert_eq!(
            s.status(&b, &id).unwrap().import_result,
            Some(imported.clone())
        );
        assert!(s.chunk(&b, &id, 0, &payload[..CHUNK_MAX]).is_ok());
        assert!(s.chunk(&b, &id, 17, &payload[17..89]).is_err());
        assert!(s.complete(&b, &id, imported).is_ok());
        assert!(s.complete(&b, &id, json!({"changed":true})).is_err());
        let db = s.connection().unwrap();
        let len: i64 = db
            .query_row("SELECT length(payload) FROM transfers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(len, 0);
        assert!(t.path().join(DATABASE).metadata().unwrap().len() > CHUNK_MAX as u64);
        assert!(t.path().join(format!("{DATABASE}-journal")).exists());
    }
    #[test]
    fn sqlite_conflicting_appends_serialize() {
        let t = tempfile::tempdir().unwrap();
        let b = binding();
        let s = Store::open(t.path()).unwrap();
        let id = s.begin(&b, &manifest(b"abc")).unwrap().transfer_id;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [b"abc", b"xyz"]
            .into_iter()
            .map(|bytes| {
                let root = t.path().to_path_buf();
                let b = b.clone();
                let id = id.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    Store::open(root).unwrap().chunk(&b, &id, 0, bytes).is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .filter_map(|h| h.join().ok())
                .filter(|v| *v)
                .count(),
            1
        );
        assert_eq!(s.status(&b, &id).unwrap().committed_offset, 3);
    }
    #[test]
    fn sqlite_schema_records_and_copied_unix_fail_closed() {
        let t = tempfile::tempdir().unwrap();
        let b = binding();
        let s = Store::open(t.path()).unwrap();
        let id = s.begin(&b, &manifest(b"abc")).unwrap().transfer_id;
        let db = s.connection().unwrap();
        let mut r = SelfRecord::get(&db, &id);
        r["status"]["payload_len"] = json!(4);
        db.execute(
            "UPDATE transfers SET record=?1",
            [serde_json::to_vec(&r).unwrap()],
        )
        .unwrap();
        assert!(s.status(&b, &id).is_err());
        db.execute_batch("PRAGMA user_version=2").unwrap();
        assert!(Store::open(t.path()).is_err());
        drop(db);
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("resumable")).unwrap();
        assert!(Store::open(t.path()).is_err());
        let t = tempfile::tempdir().unwrap();
        let db = Connection::open(t.path().join(DATABASE)).unwrap();
        db.execute_batch("CREATE TABLE unrelated(x)").unwrap();
        assert!(Store::open(t.path()).is_err());
    }
    struct SelfRecord;
    impl SelfRecord {
        fn get(db: &Connection, id: &str) -> Value {
            let bytes: Vec<u8> = db
                .query_row("SELECT record FROM transfers WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .unwrap();
            serde_json::from_slice(&bytes).unwrap()
        }
    }
    #[test]
    fn sqlite_full_transaction_rolls_back_bytes_and_offset() {
        let t = tempfile::tempdir().unwrap();
        let b = binding();
        let s = Store::open(t.path()).unwrap();
        let payload = vec![42; CHUNK_MAX];
        let id = s.begin(&b, &manifest(&payload)).unwrap().transfer_id;
        let mut db = s.connection().unwrap();
        let pages: i64 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        db.pragma_update(None, "max_page_count", pages).unwrap();
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let (mut r, _) = Store::read(&tx, &b, &id).unwrap();
        r.status.committed_offset = payload.len() as u64;
        r.chunks.push(Chunk {
            offset: 0,
            len: payload.len() as u64,
            sha256: fingerprint(&payload),
        });
        let err = Store::write(&tx, &r, &payload).unwrap_err();
        assert!(err.to_string().contains("full"), "{err}");
        drop(tx);
        drop(db);
        assert_eq!(s.status(&b, &id).unwrap().committed_offset, 0);
        s.chunk(&b, &id, 0, &payload).unwrap();
    }
    #[test]
    fn sqlite_aborted_transaction_does_not_ack_or_discard_prior_bytes() {
        let t = tempfile::tempdir().unwrap();
        let b = binding();
        let s = Store::open(t.path()).unwrap();
        let id = s.begin(&b, &manifest(b"abcdef")).unwrap().transfer_id;
        s.chunk(&b, &id, 0, b"abc").unwrap();
        let mut db = s.connection().unwrap();
        {
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let (mut r, mut bytes) = Store::read(&tx, &b, &id).unwrap();
            r.status.committed_offset = 6;
            bytes.extend_from_slice(b"BAD");
            Store::write(&tx, &r, &bytes).unwrap();
        }
        drop(db);
        drop(s);
        let s = Store::open(t.path()).unwrap();
        assert_eq!(s.status(&b, &id).unwrap().committed_offset, 3);
        s.chunk(&b, &id, 0, b"abc").unwrap();
        s.chunk(&b, &id, 3, b"def").unwrap();
        assert_eq!(s.artifact(&b, &id).unwrap().objects, b"abcdef");
    }
    #[test]
    fn sqlite_receipt_budget_and_corrupt_payload_fail_closed() {
        let t = tempfile::tempdir().unwrap();
        let b = binding();
        let s = Store::open(t.path()).unwrap();
        let all = vec![42; PAYLOAD_MAX];
        let id = s.begin(&b, &manifest(&all)).unwrap().transfer_id;
        let mut db = s.connection().unwrap();
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let (mut record, _) = Store::read(&tx, &b, &id).unwrap();
        record.chunks = (0..4095)
            .map(|offset| Chunk {
                offset,
                len: 1,
                sha256: fingerprint(&[42]),
            })
            .collect();
        record.status.committed_offset = 4095;
        Store::write(&tx, &record, &all[..4095]).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            s.chunk(&b, &id, 4095, &[42]).unwrap_err().to_string(),
            "chunk_count_bound"
        );
        assert_eq!(s.status(&b, &id).unwrap().committed_offset, 4095);
        db.execute("UPDATE transfers SET payload=?1", [vec![43u8; 4095]])
            .unwrap();
        assert!(s.status(&b, &id).is_err());
        db.execute(
            "UPDATE transfers SET record=zeroblob(?1)",
            [RECORD_BOUND + 1],
        )
        .unwrap();
        assert_eq!(
            s.status(&b, &id).unwrap_err().to_string(),
            "transfer_record_bound"
        );
    }
}

#[cfg(test)]
#[path = "sqlite_fault.rs"]
mod sqlite_fault;
