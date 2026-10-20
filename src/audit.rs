//! Durable action evidence and authenticated, acknowledged delivery to the authority.
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type R<T> = Result<T, String>;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RECORD_MAX: usize = 16 * 1024;
const BATCH_MAX: usize = 64 * 1024;
const PAYLOAD_MAX: usize = 16 * 1024 * 1024;
fn err(e: impl std::fmt::Display) -> String {
    format!("audit_error: {e}")
}
fn hash(v: &Value) -> String {
    format!("{:x}", Sha256::digest(v.to_string().as_bytes()))
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as u64
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 160
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:./".contains(&b))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn random_id() -> R<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 24];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| err("randomness_unavailable"))?;
    Ok(bytes.iter().map(|v| format!("{v:02x}")).collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub sequence: u64,
    pub recorded_at_ms: u64,
    pub previous_hash: String,
    pub hash: String,
    pub data: Value,
}
impl Record {
    fn expected_hash(&self) -> String {
        hash(
            &json!({"sequence":self.sequence,"recorded_at_ms":self.recorded_at_ms,"previous_hash":self.previous_hash,"data":self.data}),
        )
    }
    fn validate(&self) -> R<()> {
        if self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.recorded_at_ms > i64::MAX as u64
            || !digest(&self.previous_hash)
            || !digest(&self.hash)
            || self.expected_hash() != self.hash
            || !self.data.is_object()
            || self.data.to_string().len() > RECORD_MAX
        {
            return Err(err("invalid_record"));
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub producer: String,
    pub records: Vec<Record>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub project: String,
    pub authority: String,
    pub epoch: u64,
    pub device: String,
}
impl Binding {
    fn validate(&self) -> R<()> {
        if self.epoch == 0
            || self.epoch > i64::MAX as u64
            || [&self.project, &self.authority, &self.device]
                .iter()
                .any(|s| !identifier(s))
        {
            return Err(err("invalid_binding"));
        }
        Ok(())
    }
    fn key(&self) -> String {
        hash(&serde_json::to_value(self).unwrap())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub binding: Binding,
    pub producer: String,
    pub through: u64,
    pub source_hash: String,
    pub server_sequence: u64,
    pub server_hash: String,
}

fn private_lock(state: &Path, name: &str) -> R<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(state.join(name)).map_err(err)?;
    fs2::FileExt::lock_exclusive(&file).map_err(err)?;
    Ok(file)
}

pub struct Store {
    db: Connection,
    producer: String,
}
impl Store {
    pub fn open(state: &Path) -> R<Self> {
        fs::create_dir_all(state).map_err(err)?;
        let _initialization = private_lock(state, "audit-init.lock")?;
        let path = state.join("audit.sqlite");
        match fs::symlink_metadata(&path) {
            Ok(m) if !m.is_file() || m.file_type().is_symlink() => {
                return Err(err("unsafe_database_path"))
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(err(e)),
            _ => (),
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => file.sync_all().map_err(err)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(err(e)),
        }
        let db = Connection::open(&path).map_err(err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(err)?;
        }
        db.busy_timeout(Duration::from_secs(30)).map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS audit_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_local(sequence INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,data_digest TEXT NOT NULL,record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_server(sequence INTEGER PRIMARY KEY,project TEXT NOT NULL,device TEXT NOT NULL,producer TEXT NOT NULL,source_sequence INTEGER NOT NULL,source_hash TEXT NOT NULL,record TEXT NOT NULL,entry TEXT NOT NULL,hash TEXT NOT NULL,UNIQUE(project,device,producer,source_sequence));
CREATE TABLE IF NOT EXISTS audit_delivery(binding TEXT PRIMARY KEY,through INTEGER NOT NULL,source_hash TEXT NOT NULL,receipt TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_operation_cache(id TEXT PRIMARY KEY,result TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_local_no_update BEFORE UPDATE ON audit_local BEGIN SELECT RAISE(ABORT,'immutable_audit_record'); END;
CREATE TRIGGER IF NOT EXISTS audit_local_no_delete BEFORE DELETE ON audit_local BEGIN SELECT RAISE(ABORT,'immutable_audit_record'); END;
CREATE TRIGGER IF NOT EXISTS audit_server_no_update BEFORE UPDATE ON audit_server BEGIN SELECT RAISE(ABORT,'immutable_audit_record'); END;
CREATE TRIGGER IF NOT EXISTS audit_server_no_delete BEFORE DELETE ON audit_server BEGIN SELECT RAISE(ABORT,'immutable_audit_record'); END;").map_err(err)?;
        db.execute(
            "INSERT OR IGNORE INTO audit_meta VALUES('producer',?1)",
            [random_id()?],
        )
        .map_err(err)?;
        let producer = db
            .query_row(
                "SELECT value FROM audit_meta WHERE key='producer'",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        Ok(Self { db, producer })
    }
    fn transaction<T>(&self, action: impl FnOnce() -> R<T>) -> R<T> {
        self.db.execute_batch("BEGIN IMMEDIATE").map_err(err)?;
        match action() {
            Ok(value) => {
                if let Err(error) = self.db.execute_batch("COMMIT") {
                    let _ = self.db.execute_batch("ROLLBACK");
                    return Err(err(error));
                }
                Ok(value)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }
    fn append(&self, id: &str, data: &Value) -> R<u64> {
        if !identifier(id) || !data.is_object() || data.to_string().len() > RECORD_MAX {
            return Err(err("record_bound"));
        }
        let bound = hash(data);
        let old: Option<(u64, String)> = self
            .db
            .query_row(
                "SELECT sequence,data_digest FROM audit_local WHERE event_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        if let Some((sequence, previous)) = old {
            return if previous == bound {
                Ok(sequence)
            } else {
                Err(err("event_identity_conflict"))
            };
        }
        let previous: Option<(u64, String)> = self
            .db
            .query_row(
                "SELECT sequence,record FROM audit_local ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        let (sequence, previous_hash) = match previous {
            Some((seq, raw)) => {
                let old: Record = serde_json::from_str(&raw).map_err(err)?;
                old.validate()?;
                (
                    seq.checked_add(1).ok_or_else(|| err("sequence_overflow"))?,
                    old.hash,
                )
            }
            None => (1, ZERO.to_owned()),
        };
        let mut record = Record {
            sequence,
            previous_hash,
            recorded_at_ms: now(),
            hash: String::new(),
            data: data.clone(),
        };
        record.hash = record.expected_hash();
        record.validate()?;
        self.db
            .execute(
                "INSERT INTO audit_local VALUES(?1,?2,?3,?4)",
                params![
                    sequence,
                    id,
                    bound,
                    serde_json::to_string(&record).map_err(err)?
                ],
            )
            .map_err(err)?;
        Ok(sequence)
    }
    pub fn capture(&self, id: &str, metadata: &Value, payload: &Value) -> R<u64> {
        if !identifier(id) || !metadata.is_object() || metadata.to_string().len() > 4096 {
            return Err(err("invalid_action_metadata"));
        }
        let clean = redact(payload);
        let bytes = clean.to_string();
        if bytes.len() > PAYLOAD_MAX {
            return Err(err("payload_bound"));
        }
        self.transaction(|| {
            if bytes.len() <= 8192 {
                let mut data=metadata.clone(); data["payload"]=clean;
                self.append(id,&data)
            } else {
                let content_hash=format!("{:x}",Sha256::digest(bytes.as_bytes()));
                let mut chunks=Vec::new(); let mut offset=0;
                while offset < bytes.len() { let mut end=(offset+4096).min(bytes.len()); while !bytes.is_char_boundary(end) {end-=1;} chunks.push(&bytes[offset..end]);offset=end; }
                let mut last=0;
                for (index,text) in chunks.iter().enumerate() {
                    let mut data=metadata.clone(); data["payload"]=json!({"format":"json-utf8-parts","sha256":content_hash,"bytes":bytes.len(),"index":index,"parts":chunks.len(),"text":text});
                    last=self.append(&format!("part-{}-{index}", hash(&json!(id))),&data)?;
                }
                Ok(last)
            }
        })
    }
    pub fn batch(&self, binding: &Binding) -> R<Batch> {
        binding.validate()?;
        let through: u64 = self
            .db
            .query_row(
                "SELECT through FROM audit_delivery WHERE binding=?1",
                [binding.key()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?
            .unwrap_or(0);
        let mut statement = self
            .db
            .prepare("SELECT record FROM audit_local WHERE sequence>?1 ORDER BY sequence LIMIT 16")
            .map_err(err)?;
        let rows = statement
            .query_map([through], |r| r.get::<_, String>(0))
            .map_err(err)?;
        let mut batch = Batch {
            producer: self.producer.clone(),
            records: Vec::new(),
        };
        for row in rows {
            let record: Record = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
            record.validate()?;
            batch.records.push(record);
            if serde_json::to_vec(&batch).map_err(err)?.len() > BATCH_MAX {
                batch.records.pop();
                break;
            }
        }
        Ok(batch)
    }
    pub fn ingest(
        &self,
        binding: &Binding,
        certificate: &str,
        batch: &Batch,
        origin: &str,
    ) -> R<Receipt> {
        binding.validate()?;
        if !identifier(&batch.producer)
            || !digest(certificate)
            || !matches!(origin, "server" | "agent_reported")
            || batch.records.is_empty()
            || batch.records.len() > 16
            || serde_json::to_vec(batch).map_err(err)?.len() > BATCH_MAX
        {
            return Err(err("batch_bound"));
        }
        self.transaction(|| {
            let mut last_receipt=None;
            let mut expected=None;
            for record in &batch.records {
                record.validate()?;
                if expected.is_some_and(|n|n!=record.sequence) {return Err(err("sequence_gap"));} expected=Some(record.sequence+1);
                let existing: Option<(String,String)> = self.db.query_row("SELECT record,entry FROM audit_server WHERE project=?1 AND device=?2 AND producer=?3 AND source_sequence=?4",params![binding.project,binding.device,batch.producer,record.sequence],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
                let encoded=serde_json::to_string(record).map_err(err)?;
                let entry = if let Some((old,entry))=existing {if old!=encoded {return Err(err("replay_conflict"));}
                    let entry:Value=serde_json::from_str(&entry).map_err(err)?;
                    if entry["binding"]!=serde_json::to_value(binding).map_err(err)? || entry["origin"]!=origin {return Err(err("replay_binding_conflict"));}
                    entry} else {
                    let predecessor:Option<(u64,String)>=self.db.query_row("SELECT source_sequence,source_hash FROM audit_server WHERE project=?1 AND device=?2 AND producer=?3 ORDER BY source_sequence DESC LIMIT 1",params![binding.project,binding.device,batch.producer],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
                    let (prior,prior_hash)=predecessor.unwrap_or((0,ZERO.into()));
                    if record.sequence!=prior+1 || record.previous_hash!=prior_hash {return Err(err("sequence_gap"));}
                    let tip:Option<(u64,String)>=self.db.query_row("SELECT sequence,hash FROM audit_server ORDER BY sequence DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
                    let (seq,prev)=tip.unwrap_or((0,ZERO.into()));
                    let mut entry=json!({"sequence":seq+1,"received_at_ms":now(),"binding":binding,"certificate_sha256":certificate,"producer":batch.producer,"source_sequence":record.sequence,"source_hash":record.hash,"previous_hash":prev,"origin":origin,"record":record});
                    let entry_hash=hash(&entry); entry["hash"]=json!(entry_hash);
                    self.db.execute("INSERT INTO audit_server(sequence,project,device,producer,source_sequence,source_hash,record,entry,hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![seq+1,binding.project,binding.device,batch.producer,record.sequence,record.hash,encoded,entry.to_string(),entry_hash]).map_err(err)?;
                    entry
                };
                last_receipt=Some(Receipt {binding:binding.clone(),producer:batch.producer.clone(),through:record.sequence,source_hash:record.hash.clone(),server_sequence:entry["sequence"].as_u64().ok_or_else(||err("invalid_server_record"))?,server_hash:entry["hash"].as_str().ok_or_else(||err("invalid_server_record"))?.to_owned()});
            }
            last_receipt.ok_or_else(||err("empty_batch"))
        })
    }
    pub fn acknowledge(&self, binding: &Binding, receipt: &Receipt) -> R<()> {
        if &receipt.binding != binding
            || receipt.producer != self.producer
            || receipt.server_sequence == 0
            || !digest(&receipt.server_hash)
        {
            return Err(err("ack_identity"));
        }
        self.transaction(|| {
            let record:Option<String>=self.db.query_row("SELECT record FROM audit_local WHERE sequence=?1",[receipt.through],|r|r.get(0)).optional().map_err(err)?;
            let record:Record=serde_json::from_str(&record.ok_or_else(||err("ack_unknown_sequence"))?).map_err(err)?; record.validate()?;
            if record.hash!=receipt.source_hash {return Err(err("ack_hash_mismatch"));}
            let prior:Option<String>=self.db.query_row("SELECT receipt FROM audit_delivery WHERE binding=?1",[binding.key()],|r|r.get(0)).optional().map_err(err)?;
            if let Some(raw)=prior {
                let old:Receipt=serde_json::from_str(&raw).map_err(err)?;
                if receipt.through<old.through || receipt.server_sequence<old.server_sequence {return Err(err("stale_ack"));}
                if receipt.through==old.through && serde_json::to_value(receipt).map_err(err)?!=serde_json::to_value(&old).map_err(err)? {return Err(err("ack_conflict"));}
                if receipt.through>old.through && receipt.server_sequence<=old.server_sequence {return Err(err("ack_conflict"));}
            }
            self.db.execute("INSERT INTO audit_delivery VALUES(?1,?2,?3,?4) ON CONFLICT(binding) DO UPDATE SET through=excluded.through,source_hash=excluded.source_hash,receipt=excluded.receipt",params![binding.key(),receipt.through,receipt.source_hash,serde_json::to_string(receipt).map_err(err)?]).map_err(err)?; Ok(())
        })
    }
    fn flush_local(&self, binding: &Binding) -> R<()> {
        let database = Path::new(
            self.db
                .path()
                .ok_or_else(|| err("database_path_required"))?,
        );
        let _delivery = private_lock(
            database
                .parent()
                .ok_or_else(|| err("database_parent_required"))?,
            "audit-local-delivery.lock",
        )?;
        loop {
            let batch = self.batch(binding)?;
            if batch.records.is_empty() {
                return Ok(());
            }
            let origin = if batch.records[0].data["origin"] == "agent_reported" {
                "agent_reported"
            } else {
                "server"
            };
            let mut batch = batch;
            let count = batch
                .records
                .iter()
                .take_while(|r| {
                    (r.data["origin"] == "agent_reported") == (origin == "agent_reported")
                })
                .count();
            batch.records.truncate(count);
            let receipt = self.ingest(binding, ZERO, &batch, origin)?;
            self.acknowledge(binding, &receipt)?;
        }
    }
    pub fn status(&self, binding: &Binding, remote: bool) -> R<Value> {
        let local: u64 = self
            .db
            .query_row(
                "SELECT COALESCE(MAX(sequence),0) FROM audit_local",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        let acknowledged: u64 = self
            .db
            .query_row(
                "SELECT through FROM audit_delivery WHERE binding=?1",
                [binding.key()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?
            .unwrap_or(0);
        let central: u64 = self
            .db
            .query_row(
                "SELECT COALESCE(MAX(sequence),0) FROM audit_server",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        Ok(
            json!({"ok":true,"producer":self.producer,"binding":binding,"remote":remote,"recorded":local,"acknowledged":acknowledged,"pending":local.saturating_sub(acknowledged),"synced":local==acknowledged,"server_records":central}),
        )
    }
    fn archive_ready(&self, binding: &Binding, operation: &str) -> R<bool> {
        let status = self.status(binding, true)?;
        if status["pending"] == 0 {
            return Ok(true);
        }
        if status["pending"] != 1 {
            return Ok(false);
        }
        let raw: String = self
            .db
            .query_row(
                "SELECT record FROM audit_local ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .map_err(err)?;
        let record: Record = serde_json::from_str(&raw).map_err(err)?;
        record.validate()?;
        Ok(record.data["origin"] == "server"
            && record.data["action"] == "workspace_close"
            && record.data["phase"] == "started"
            && record.data["operation_id"] == operation
            && record.data["payload"]["op"] == "workspace_close"
            && record.data["payload"]["operation_id"] == operation)
    }
    pub fn log(&self, after: u64, limit: u64) -> R<Value> {
        if after > i64::MAX as u64 || !(1..=32).contains(&limit) {
            return Err(err("invalid_page"));
        }
        let mut statement = self
            .db
            .prepare("SELECT entry FROM audit_server WHERE sequence>?1 ORDER BY sequence LIMIT ?2")
            .map_err(err)?;
        let entries = statement
            .query_map(params![after, limit], |r| r.get::<_, String>(0))
            .map_err(err)?
            .map(|r| serde_json::from_str::<Value>(&r.map_err(err)?).map_err(err))
            .collect::<R<Vec<_>>>()?;
        let cursor = entries
            .last()
            .and_then(|r| r["sequence"].as_u64())
            .unwrap_or(after);
        let more: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM audit_server WHERE sequence>?1)",
                [cursor],
                |r| r.get(0),
            )
            .map_err(err)?;
        Ok(json!({"ok":true,"records":entries,"next_cursor":cursor,"has_more":more}))
    }
    fn export(&self, target: &Path) -> R<Value> {
        if !target.is_absolute() {
            return Err(err("absolute_destination_required"));
        }
        let parent = target
            .parent()
            .ok_or_else(|| err("destination_parent_required"))?;
        let temporary = parent.join(format!(".wipstash-audit-{}.tmp", random_id()?));
        let result = (|| {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary).map_err(err)?;
            let tx = self.db.unchecked_transaction().map_err(err)?;
            let mut through = 0;
            {
                let mut statement = tx
                    .prepare("SELECT sequence,entry FROM audit_server ORDER BY sequence")
                    .map_err(err)?;
                let mut rows = statement.query([]).map_err(err)?;
                while let Some(row) = rows.next().map_err(err)? {
                    through = row.get::<_, u64>(0).map_err(err)?;
                    let entry: String = row.get(1).map_err(err)?;
                    writeln!(file, "{entry}").map_err(err)?;
                }
            }
            tx.commit().map_err(err)?;
            file.sync_all().map_err(err)?;
            fs::hard_link(&temporary, target).map_err(err)?;
            fs::remove_file(&temporary).map_err(err)?;
            #[cfg(unix)]
            fs::File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(err)?;
            Ok(json!({"ok":true,"through":through,"destination":target}))
        })();
        let _ = fs::remove_file(&temporary);
        result
    }
    pub fn verify(&self) -> R<Value> {
        let mut statement = self
            .db
            .prepare("SELECT sequence,entry,hash FROM audit_server ORDER BY sequence")
            .map_err(err)?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(err)?;
        let mut previous = ZERO.to_owned();
        let mut count = 0;
        let mut producers: HashMap<String, (u64, String)> = HashMap::new();
        for row in rows {
            let (seq, raw, bound) = row.map_err(err)?;
            let mut value: Value = serde_json::from_str(&raw).map_err(err)?;
            let stored = value
                .as_object_mut()
                .ok_or_else(|| err("invalid_server_record"))?
                .remove("hash")
                .ok_or_else(|| err("invalid_server_record"))?;
            if seq != count + 1
                || value["sequence"] != seq
                || value["previous_hash"] != previous
                || stored != bound
                || hash(&value) != bound
            {
                return Err(err("chain_mismatch"));
            }
            let record: Record = serde_json::from_value(value["record"].clone()).map_err(err)?;
            record.validate()?;
            if value["source_hash"] != record.hash || value["source_sequence"] != record.sequence {
                return Err(err("source_binding_mismatch"));
            }
            let binding: Binding = serde_json::from_value(value["binding"].clone()).map_err(err)?;
            binding.validate()?;
            let key = hash(&json!([binding, value["producer"]]));
            let (prior, prior_hash) = producers.entry(key).or_insert((0, ZERO.into()));
            if record.sequence != *prior + 1 || record.previous_hash != *prior_hash {
                return Err(err("source_chain_mismatch"));
            }
            *prior = record.sequence;
            *prior_hash = record.hash;
            previous = bound;
            count = seq;
        }
        Ok(json!({"ok":true,"verified":count,"tip":previous}))
    }
}

fn redact(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .filter(|(k, _)| {
                    !matches!(
                        k.as_str(),
                        "thinking"
                            | "reasoning"
                            | "redacted_thinking"
                            | "encrypted_content"
                            | "base_instructions"
                            | "reasoning_content"
                    )
                })
                .map(|(k, v)| {
                    let name = k.to_ascii_lowercase();
                    let clean = if matches!(
                        name.as_str(),
                        "authorization"
                            | "password"
                            | "api_key"
                            | "apikey"
                            | "access_token"
                            | "refresh_token"
                            | "cookie"
                            | "set-cookie"
                            | "private_key"
                    ) {
                        json!({"redacted":true,"sha256":hash(v)})
                    } else {
                        redact(v)
                    };
                    (k.clone(), clean)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .filter(|v| {
                    !matches!(
                        v["type"].as_str(),
                        Some("thinking" | "reasoning" | "redacted_thinking")
                    )
                })
                .map(redact)
                .collect(),
        ),
        other => other.clone(),
    }
}
fn configuration(state: &Path) -> R<Option<Value>> {
    let path = state.join("state.sqlite");
    if !path.exists() {
        return Ok(None);
    }
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
    let ready: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
            [],
            |r| r.get(0),
        )
        .map_err(err)?;
    if !ready {
        return Ok(None);
    }
    let configured: Option<String> = db
        .query_row("SELECT value FROM meta WHERE key='sync_config'", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(err)?;
    configured
        .map(|s| serde_json::from_str(&s).map_err(err))
        .transpose()
}
fn context(state: &Path, store: &Store) -> R<(Binding, bool)> {
    if let Some(c) = configuration(state)? {
        return Ok((
            Binding {
                project: c["project"]
                    .as_str()
                    .ok_or_else(|| err("invalid_binding"))?
                    .into(),
                authority: c["authority"]
                    .as_str()
                    .ok_or_else(|| err("invalid_binding"))?
                    .into(),
                epoch: c["epoch"].as_u64().ok_or_else(|| err("invalid_binding"))?,
                device: c["device"]
                    .as_str()
                    .ok_or_else(|| err("invalid_binding"))?
                    .into(),
            },
            c["role"] == "client",
        ));
    }
    Ok((
        Binding {
            project: format!("local-{}", store.producer),
            authority: "local".into(),
            epoch: 1,
            device: "local".into(),
        },
        false,
    ))
}
fn flush(state: &Path, store: &Store) -> R<()> {
    let (binding, remote) = context(state, store)?;
    if !remote {
        store.flush_local(&binding)?;
    }
    Ok(())
}

pub fn handles(op: &str) -> bool {
    op.starts_with("audit_")
}
pub fn dispatch(state: &Path, request: &Value) -> R<Value> {
    let store = Store::open(state)?;
    let (binding, remote) = context(state, &store)?;
    match request["op"].as_str().unwrap_or("") {
        "audit_record" => {
            let record = &request["record"];
            let id = record["event_id"]
                .as_str()
                .ok_or_else(|| err("event_id_required"))?;
            let metadata = json!({"origin":"agent_reported","agent":record["agent"],"session_id":record["session_id"],"workspace":record["workspace"],"operation_id":record["operation_id"],"action":record["action"],"phase":record["phase"],"client_time":record["client_time"]});
            for field in ["agent", "session_id", "workspace", "action", "phase"] {
                if metadata[field]
                    .as_str()
                    .is_none_or(|s| s.is_empty() || s.len() > 1024)
                {
                    return Err(err("invalid_action_metadata"));
                }
            }
            let through = store.capture(id, &metadata, &record["payload"])?;
            flush(state, &store)?;
            let mut result = store.status(&binding, remote)?;
            result["through"] = json!(through);
            Ok(result)
        }
        "audit_status" => {
            mirror(state, &store)?;
            flush(state, &store)?;
            let mut status = store.status(&binding, remote)?;
            let collection = match fs::read(state.join("audit-collector-status.json")) {
                Ok(bytes) if bytes.len() <= 1024 * 1024 => {
                    let mut value: Value = serde_json::from_slice(&bytes).map_err(err)?;
                    let fresh = value["checked_at"].as_f64().is_some_and(|t| {
                        now() as f64 / 1000.0 - t < 60.0 && t <= now() as f64 / 1000.0 + 5.0
                    });
                    value["fresh"] = json!(fresh);
                    value["healthy"] = json!(fresh && value["ok"] == true);
                    value
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    json!({"healthy":false,"status":"not_configured"})
                }
                _ => json!({"healthy":false,"status":"unreadable"}),
            };
            status["complete"] = json!(status["synced"] == true && collection["healthy"] == true);
            status["collection"] = collection;
            Ok(status)
        }
        "audit_log" => store.log(
            request["cursor"].as_u64().unwrap_or(0),
            request["limit"].as_u64().unwrap_or(16),
        ),
        "audit_verify" => store.verify(),
        "audit_batch" => Ok(json!({"ok":true,"binding":binding,"batch":store.batch(&binding)?})),
        "audit_ingest" | "audit_transport" => {
            let c = configuration(state)?.ok_or_else(|| err("authority_required"))?;
            let target: Binding =
                serde_json::from_value(request["binding"].clone()).map_err(err)?;
            if c["role"] != "authority"
                || target.project != binding.project
                || target.authority != binding.authority
                || target.epoch != binding.epoch
                || !c["peers"]
                    .as_array()
                    .is_some_and(|p| p.iter().any(|v| v == &target.device))
            {
                return Err(err("authenticated_binding_mismatch"));
            }
            if request["op"] == "audit_transport" {
                let id = request["event_id"]
                    .as_str()
                    .ok_or_else(|| err("event_id_required"))?;
                let metadata = json!({"origin":"server","action":"transport_request","phase":request["phase"],"authenticated_device":target.device,"certificate_sha256":request["certificate_sha256"],"correlation_id":request["correlation_id"]});
                store.capture(id, &metadata, &request["payload"])?;
                flush(state, &store)?;
                return Ok(json!({"ok":true}));
            }
            let batch: Batch = serde_json::from_value(request["batch"].clone()).map_err(err)?;
            let receipt = store.ingest(
                &target,
                request["certificate_sha256"].as_str().unwrap_or(""),
                &batch,
                "agent_reported",
            )?;
            Ok(json!({"ok":true,"receipt":receipt}))
        }
        "audit_ack" => {
            let receipt: Receipt =
                serde_json::from_value(request["receipt"].clone()).map_err(err)?;
            if !remote {
                return Err(err("client_required"));
            }
            store.acknowledge(&binding, &receipt)?;
            store.status(&binding, remote)
        }
        "audit_export" => store.export(Path::new(
            request["destination"]
                .as_str()
                .ok_or_else(|| err("destination_required"))?,
        )),
        _ => Err(err("unknown_operation")),
    }
}

pub(crate) fn archive_delivery_ready(state: &Path, operation: &str) -> R<bool> {
    let store = Store::open(state)?;
    let (binding, _) = context(state, &store)?;
    store.archive_ready(&binding, operation)
}

pub fn execute(state: &Path, request: &Value, action: impl FnOnce() -> R<Value>) -> R<Value> {
    let started = std::time::Instant::now();
    let op = request["op"].as_str().unwrap_or("");
    if op == "sync_binding_status" {
        return action();
    }
    let store = Store::open(state)?;
    let quiet = matches!(
        op,
        "integrate"
            | "validation_claim"
            | "backup_tick"
            | "sync_status"
            | "sync_pending"
            | "coordination_pending"
            | "coordination_export"
            | "recovery_status"
            | "sync_export_history"
            | "sync_export_lookup"
    );
    let invocation = random_id()?;
    let metadata = |phase: &str| json!({"origin":"server","action":crate::vocabulary::public_operation(op),"phase":phase,"elapsed_ms":started.elapsed().as_millis(),"correlation_id":invocation,"session_id":std::env::var("WIPSTASH_SESSION_ID").ok(),"agent":std::env::var("WIPSTASH_AGENT_CLIENT").ok(),"workspace":request["workspace"],"operation_id":request["operation_id"]});
    if !quiet {
        store.capture(
            &format!("{invocation}-start"),
            &metadata("started"),
            request,
        )?;
        flush(state, &store)?;
    }
    let result = action();
    if !quiet {
        let outcome = match &result {
            Ok(v) => v.clone(),
            Err(e) => crate::engine::error_response(e),
        };
        store.capture(&format!("{invocation}-end"),&metadata(if outcome["ok"]==true{"completed"}else{"failed"}),&outcome).map_err(|_|"audit_recording_failed: the action may have completed; inspect its original operation ID".to_owned())?;
    }
    mirror(state, &store)?;
    flush(state, &store)?;
    result
}

fn mirror(state: &Path, store: &Store) -> R<()> {
    let path = state.join("state.sqlite");
    if !path.exists() {
        return Ok(());
    }
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
    db.busy_timeout(Duration::from_secs(30)).map_err(err)?;
    let cursor: u64 = store
        .db
        .query_row(
            "SELECT value FROM audit_meta WHERE key='event_cursor'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(err)?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut statement = db
        .prepare("SELECT seq,kind,data FROM events WHERE seq>?1 ORDER BY seq")
        .map_err(err)?;
    let rows = statement
        .query_map([cursor], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(err)?;
    for row in rows {
        let (seq, kind, raw) = row.map_err(err)?;
        let bound = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let data: Value = serde_json::from_str(&raw).map_err(err)?;
        store.capture(&format!("state-event-{seq}-{bound}"),&json!({"origin":"server","action":kind,"phase":"state_change","source_event_sequence":seq,"workspace":data["workspace"],"source_time":data["_occurred_at"]}),&data)?;
        store.db.execute("INSERT INTO audit_meta VALUES('event_cursor',?1) ON CONFLICT(key) DO UPDATE SET value=CAST(MAX(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",[seq.to_string()]).map_err(err)?;
    }
    db.execute(
        "ATTACH DATABASE ?1 AS audit_cache",
        [state
            .join("audit.sqlite")
            .to_str()
            .ok_or_else(|| err("invalid_path"))?],
    )
    .map_err(err)?;
    db.execute_batch("PRAGMA query_only=ON").map_err(err)?;
    let mut statement = db
        .prepare("SELECT o.id,o.request,o.result FROM operations o LEFT JOIN audit_cache.audit_operation_cache a ON a.id=o.id WHERE o.result IS NOT NULL AND (a.id IS NULL OR a.result<>o.result) ORDER BY o.rowid")
        .map_err(err)?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(err)?;
    for row in rows {
        let (id, request, result) = row.map_err(err)?;
        let bound = format!("{:x}", Sha256::digest(result.as_bytes()));
        let raw_result = result.clone();
        let request: Value = serde_json::from_str(&request).map_err(err)?;
        let result: Value = serde_json::from_str(&result).map_err(err)?;
        store.capture(&format!("op-{}",hash(&json!([id,bound]))),&json!({"origin":"server","action":crate::vocabulary::public_operation(request["op"].as_str().unwrap_or("unknown")),"phase":"recorded_result","workspace":request["workspace"],"operation_id":id}),&json!({"request":request,"result":result}))?;
        store
            .db
            .execute(
                "INSERT INTO audit_operation_cache VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET result=excluded.result",
                params![id, raw_result],
            )
            .map_err(err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            project: "demo".into(),
            authority: "central".into(),
            epoch: 1,
            device: "alice".into(),
        }
    }
    fn capture(store: &Store, id: &str, payload: Value) -> u64 {
        store
            .capture(
                id,
                &json!({"origin":"agent_reported","action":"tool_call","phase":"completed"}),
                &payload,
            )
            .unwrap()
    }
    #[test]
    fn archive_requires_prior_delivery_and_only_exempts_its_own_start() {
        let t = tempfile::tempdir().unwrap();
        let client = Store::open(&t.path().join("client")).unwrap();
        let server = Store::open(&t.path().join("server")).unwrap();
        let binding = binding();
        assert!(client.archive_ready(&binding, "close").unwrap());
        capture(&client, "earlier", json!({"command":"edit"}));
        assert!(!client.archive_ready(&binding, "close").unwrap());
        let receipt = server
            .ingest(
                &binding,
                ZERO,
                &client.batch(&binding).unwrap(),
                "agent_reported",
            )
            .unwrap();
        client.acknowledge(&binding, &receipt).unwrap();
        client.capture("start", &json!({"origin":"server","action":"workspace_close","phase":"started","operation_id":"close"}), &json!({"op":"workspace_close","operation_id":"close"})).unwrap();
        assert!(client.archive_ready(&binding, "close").unwrap());
        assert!(!client.archive_ready(&binding, "different-close").unwrap());
        capture(&client, "concurrent", json!({"command":"another edit"}));
        assert!(!client.archive_ready(&binding, "close").unwrap());
    }

    #[test]
    fn lost_ack_replays_exact_receipt_and_rejects_changed_records() {
        let t = tempfile::tempdir().unwrap();
        let client = Store::open(&t.path().join("client")).unwrap();
        let server = Store::open(&t.path().join("server")).unwrap();
        let b = binding();
        capture(&client, "one", json!({"command":"test"}));
        let batch = client.batch(&b).unwrap();
        let first = server.ingest(&b, ZERO, &batch, "agent_reported").unwrap();
        let replay = server.ingest(&b, ZERO, &batch, "agent_reported").unwrap();
        assert_eq!(
            serde_json::to_value(&first).unwrap(),
            serde_json::to_value(replay).unwrap()
        );
        assert_eq!(client.status(&b, true).unwrap()["pending"], 1);
        client.acknowledge(&b, &first).unwrap();
        assert!(client.batch(&b).unwrap().records.is_empty());
        let mut changed = batch.clone();
        changed.records[0].data["changed"] = json!(true);
        changed.records[0].hash = changed.records[0].expected_hash();
        assert!(server
            .ingest(&b, ZERO, &changed, "agent_reported")
            .unwrap_err()
            .contains("replay_conflict"));
        let mut epoch = b.clone();
        epoch.epoch = 2;
        assert!(server
            .ingest(&epoch, ZERO, &batch, "agent_reported")
            .unwrap_err()
            .contains("binding_conflict"));
        assert_eq!(server.verify().unwrap()["verified"], 1);
    }
    #[test]
    fn rejected_batch_is_atomic_and_gaps_cannot_be_acknowledged() {
        let t = tempfile::tempdir().unwrap();
        let c = Store::open(&t.path().join("c")).unwrap();
        let s = Store::open(&t.path().join("s")).unwrap();
        let b = binding();
        capture(&c, "one", json!({}));
        capture(&c, "two", json!({}));
        let batch = c.batch(&b).unwrap();
        let mut bad = batch.clone();
        bad.records[1].previous_hash = ZERO.into();
        bad.records[1].hash = bad.records[1].expected_hash();
        assert!(s.ingest(&b, ZERO, &bad, "agent_reported").is_err());
        assert_eq!(s.verify().unwrap()["verified"], 0);
        let receipt = s.ingest(&b, ZERO, &batch, "agent_reported").unwrap();
        let mut forged = receipt.clone();
        forged.binding.device = "bob".into();
        assert!(c.acknowledge(&b, &forged).is_err());
        forged = receipt.clone();
        forged.source_hash = ZERO.into();
        assert!(c.acknowledge(&b, &forged).is_err());
        c.acknowledge(&b, &receipt).unwrap();
        forged = receipt;
        forged.server_hash = ZERO.into();
        assert!(c.acknowledge(&b, &forged).is_err());
    }
    #[test]
    fn large_unicode_actions_are_preserved_and_replay_is_idempotent() {
        let t = tempfile::tempdir().unwrap();
        let c = Store::open(t.path()).unwrap();
        let b = binding();
        let payload =
            json!({"patch":"å🦀".repeat(9000),"password":"credential","reasoning":"private"});
        let id = "a".repeat(160);
        let through = capture(&c, &id, payload.clone());
        assert!(through > 2);
        assert_eq!(capture(&c, &id, payload.clone()), through);
        let mut statement =
            c.db.prepare("SELECT record FROM audit_local ORDER BY sequence")
                .unwrap();
        let rows = statement.query_map([], |r| r.get::<_, String>(0)).unwrap();
        let mut text = String::new();
        for (index, row) in rows.enumerate() {
            let record: Record = serde_json::from_str(&row.unwrap()).unwrap();
            record.validate().unwrap();
            assert_eq!(record.data["payload"]["index"], index);
            text.push_str(record.data["payload"]["text"].as_str().unwrap());
        }
        let restored: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(restored, redact(&payload));
        assert_eq!(restored["patch"], payload["patch"]);
        assert!(restored.get("reasoning").is_none());
        assert_eq!(restored["password"]["redacted"], true);
        assert_eq!(c.status(&b, true).unwrap()["recorded"], through);
    }
    #[test]
    fn local_origin_export_and_immutable_records() {
        let t = tempfile::tempdir().unwrap();
        let c = Store::open(t.path()).unwrap();
        let b = binding();
        capture(&c, "reported", json!({"output":"native output"}));
        c.capture(
            "server",
            &json!({"origin":"server"}),
            &json!({"result":"server result"}),
        )
        .unwrap();
        c.flush_local(&b).unwrap();
        let log = c.log(0, 32).unwrap();
        assert_eq!(log["records"][0]["origin"], "agent_reported");
        assert_eq!(log["records"][1]["origin"], "server");
        assert!(c.db.execute("DELETE FROM audit_server", []).is_err());
        assert!(c
            .db
            .execute("UPDATE audit_local SET event_id='changed'", [])
            .is_err());
        let path = t.path().join("export.jsonl");
        assert_eq!(c.export(&path).unwrap()["through"], 2);
        let original = fs::read(&path).unwrap();
        assert!(c.export(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(String::from_utf8(original).unwrap().lines().count(), 2);
        assert_eq!(c.verify().unwrap()["verified"], 2);
    }
    #[test]
    fn concurrent_local_delivery_never_regresses_acknowledgements() {
        let t = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let workers: Vec<_> = (0..4)
            .map(|actor| {
                let path = t.path().to_owned();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let store = Store::open(&path).unwrap();
                    let binding = binding();
                    for index in 0..8 {
                        capture(
                            &store,
                            &format!("actor-{actor}-{index}"),
                            json!({"actor":actor,"index":index}),
                        );
                        store.flush_local(&binding).unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let store = Store::open(t.path()).unwrap();
        assert_eq!(store.verify().unwrap()["verified"], 32);
        assert_eq!(store.status(&binding(), false).unwrap()["pending"], 0);
    }
    #[test]
    fn interrupted_first_database_open_does_not_block_initialization() {
        let t = tempfile::tempdir().unwrap();
        let state = t.path().join("state");
        fs::create_dir(&state).unwrap();
        drop(Connection::open(state.join("state.sqlite")).unwrap());
        let source = t.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file.txt"), "source").unwrap();
        assert_eq!(
            crate::engine::execute(&state, json!({"op":"init","source":source})).unwrap()["ok"],
            true
        );
        assert!(
            dispatch(&state, &json!({"op":"audit_verify"})).unwrap()["verified"]
                .as_u64()
                .unwrap()
                > 0
        );
    }
    #[test]
    fn status_does_not_claim_collection_without_a_healthy_collector() {
        let t = tempfile::tempdir().unwrap();
        let state = t.path();
        let status = dispatch(state, &json!({"op":"audit_status"})).unwrap();
        assert_eq!(status["synced"], true);
        assert_eq!(status["complete"], false);
        fs::write(
            state.join("audit-collector-status.json"),
            json!({"ok":true,"checked_at":now() as f64/1000.0}).to_string(),
        )
        .unwrap();
        assert_eq!(
            dispatch(state, &json!({"op":"audit_status"})).unwrap()["complete"],
            true
        );
        fs::write(
            state.join("audit-collector-status.json"),
            json!({"ok":true,"checked_at":0}).to_string(),
        )
        .unwrap();
        assert_eq!(
            dispatch(state, &json!({"op":"audit_status"})).unwrap()["complete"],
            false
        );
    }
}
