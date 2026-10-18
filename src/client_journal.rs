//! Private native journal for a serialized stdio client. This process never
//! contacts an engine, executes a command, or replays a mutation. A client holds
//! the explicit OS lock from durable intent through response persistence.
//!
//! Receipts are immutable: `op-<hex-id>.json` is the pending intent and
//! `op-<hex-id>.completed.json` is its optional exact terminal result. Reads overlay the
//! latter only after validating both records and their identical request. No
//! update can erase an intent, change an ID's request, or turn a completed result
//! back into pending. Interrupted private staging files are never completion.
//!
//! Unix fsyncs files and publication directories. Windows flushes file contents
//! and uses same-volume exclusive publication, but portable Win32 cannot promise
//! directory-entry persistence across power loss. Neither is a storage-device
//! guarantee; the protocol reports the platform distinction explicitly.
use serde::Deserialize;
use serde_json::{json, value::RawValue, Value};
use std::{
    fs::File,
    io::{self, BufRead, Write},
    path::Path,
};

// Share the exact reviewed implementation; do not maintain a second native
// security backend. Public pairing-only entry points are unused by this binary.
#[allow(dead_code)]
#[path = "../services/transport/src/pairing_files.rs"]
mod private_files;
use private_files::PrivateDirectory;

// value_json is canonical JSON text inside a JSON-RPC string. Preserving it
// avoids changing engine serde_json number features or rounding arbitrary JSON
// integers. Escaping overhead also counts against this wire limit.
pub const FRAME_MAX: usize = 10 * 1024 * 1024;
const RECORD_MAX: usize = 9 * 1024 * 1024 + 4096;
const REQUEST_MAX: usize = 1024 * 1024;
const ENDPOINT_MAX: usize = 64 * 1024;
const LOCK_NAME: &str = ".client-journal.lock";

fn failure(code: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, code)
}
fn endpoint(value: &Value) -> io::Result<()> {
    let root = value
        .as_object()
        .ok_or_else(|| failure("journal_invalid_endpoint"))?;
    let object = value["endpoint"]
        .as_object()
        .ok_or_else(|| failure("journal_invalid_endpoint"))?;
    let command = object
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(|| failure("journal_invalid_endpoint"))?;
    let cwd = object
        .get("cwd")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("journal_invalid_endpoint"))?;
    if root.len() != 2
        || value["version"] != 1
        || object.len() != 2
        || command.is_empty()
        || command
            .iter()
            .any(|v| v.as_str().is_none_or(|s| s.contains('\0')))
        || !command[0]
            .as_str()
            .is_some_and(|s| Path::new(s).is_absolute())
        || !Path::new(cwd).is_absolute()
        || cwd.contains('\0')
        || serde_json::to_vec(value)?.len() > ENDPOINT_MAX
    {
        return Err(failure("journal_invalid_endpoint"));
    }
    Ok(())
}
fn operation_name(name: &str) -> io::Result<&str> {
    let id = name
        .strip_suffix(".json")
        .ok_or_else(|| failure("journal_invalid_name"))?;
    if id.is_empty()
        || id.len() > 100
        || id == "endpoint"
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(failure("journal_invalid_name"));
    }
    Ok(id)
}
fn storage_name(id: &str, completed: bool) -> String {
    // Encode every byte so case-insensitive filesystems and DOS device names
    // cannot alias otherwise distinct operation IDs. API names stay readable.
    let encoded: String = id.bytes().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "op-{encoded}{}.json",
        if completed { ".completed" } else { "" }
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u8,
    request: Box<RawValue>,
    state: String,
    #[serde(default, deserialize_with = "optional_raw")]
    result: Option<Box<RawValue>>,
}
fn optional_raw<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Box<RawValue>>, D::Error> {
    Box::<RawValue>::deserialize(deserializer).map(Some)
}
impl Receipt {
    fn request(&self) -> &str {
        self.request.get()
    }
    fn completed(&self) -> bool {
        self.state == "completed"
    }
}

#[derive(Deserialize)]
struct RequestIdentity {
    operation_id: String,
    op: String,
}
#[derive(Deserialize)]
struct ResultIdentity {
    ok: bool,
}
fn receipt(id: &str, text: &str, completed: Option<bool>) -> io::Result<Receipt> {
    let record: Receipt =
        serde_json::from_str(text).map_err(|_| failure("journal_invalid_receipt"))?;
    match (record.state.as_str(), &record.result) {
        ("pending", None) => {}
        ("completed", Some(result)) => {
            let result: ResultIdentity = serde_json::from_str(result.get())
                .map_err(|_| failure("journal_invalid_result"))?;
            let _ = result.ok;
        }
        _ => return Err(failure("journal_invalid_receipt")),
    }
    let identity: RequestIdentity = serde_json::from_str(record.request())
        .map_err(|_| failure("journal_invalid_request_identity"))?;
    if record.version != 1
        || identity.operation_id != id
        || identity.op.is_empty()
        || completed.is_some_and(|expected| expected != record.completed())
        || record.request().len() > REQUEST_MAX
    {
        return Err(failure("journal_invalid_receipt"));
    }
    Ok(record)
}

struct Journal {
    // Drop the file before the directory/Windows ancestor pins.
    lock: File,
    directory: PrivateDirectory,
    locked: bool,
    poisoned: bool,
}
impl Journal {
    fn open(path: &Path) -> io::Result<Self> {
        let directory = PrivateDirectory::open(path)?;
        let lock = match directory.open_lock(LOCK_NAME) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match directory.create(LOCK_NAME, b"") {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                directory.open_lock(LOCK_NAME)?
            }
            Err(error) => return Err(error),
        };
        if lock.metadata()?.len() != 0 {
            return Err(failure("journal_invalid_lock_file"));
        }
        Ok(Self {
            lock,
            directory,
            locked: false,
            poisoned: false,
        })
    }
    fn healthy(&self) -> io::Result<()> {
        if self.poisoned {
            Err(failure("journal_io_uncertain_reopen_required"))
        } else {
            Ok(())
        }
    }
    fn acquire(&mut self) -> io::Result<()> {
        self.healthy()?;
        if self.locked {
            return Err(failure("journal_already_locked"));
        }
        fs2::FileExt::try_lock_exclusive(&self.lock)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "journal_busy"))?;
        self.locked = true;
        Ok(())
    }
    fn release(&mut self) -> io::Result<()> {
        if !self.locked {
            return Err(failure("journal_not_locked"));
        }
        fs2::FileExt::unlock(&self.lock)?;
        self.locked = false;
        Ok(())
    }
    fn require_lock(&self) -> io::Result<()> {
        self.healthy()?;
        if self.locked {
            Ok(())
        } else {
            Err(failure("journal_lock_required"))
        }
    }
    fn load(&self, name: &str) -> io::Result<Option<String>> {
        match self.directory.read(name, RECORD_MAX) {
            Ok(bytes) => {
                let value =
                    String::from_utf8(bytes).map_err(|_| failure("journal_corrupt_record"))?;
                // Ignore the single storage newline, preserving all JSON bytes.
                let value = value.strip_suffix('\n').unwrap_or(&value).to_owned();
                let _: Box<RawValue> =
                    serde_json::from_str(&value).map_err(|_| failure("journal_corrupt_record"))?;
                Ok(Some(value))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn binding(&self) -> io::Result<Option<String>> {
        let value = self.load("endpoint.json")?;
        if let Some(value) = &value {
            endpoint(&serde_json::from_str(value)?)?;
        }
        Ok(value)
    }
    fn read(&self, name: &str) -> io::Result<Option<String>> {
        self.require_lock()?;
        if name == "endpoint.json" {
            return self.binding();
        }
        let id = operation_name(name)?;
        if self.binding()?.is_none() {
            return Err(failure("journal_endpoint_required"));
        }
        let pending = self.load(&storage_name(id, false))?;
        let complete = self.load(&storage_name(id, true))?;
        if let Some(value) = &pending {
            receipt(id, value, Some(false))?;
        }
        if let Some(value) = &complete {
            let complete_record = receipt(id, value, Some(true))?;
            let pending_text = pending
                .as_ref()
                .ok_or_else(|| failure("journal_completed_intent_mismatch"))?;
            let pending_record = receipt(id, pending_text, Some(false))?;
            if pending_record.request() != complete_record.request() {
                return Err(failure("journal_completed_intent_mismatch"));
            }
        }
        Ok(complete.or(pending))
    }
    fn write(&mut self, name: &str, value: &str) -> io::Result<()> {
        self.write_using(name, value, |directory, name, bytes| {
            directory.create(name, bytes)
        })
    }
    fn write_using(
        &mut self,
        name: &str,
        value: &str,
        publish: impl FnOnce(&PrivateDirectory, &str, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        self.require_lock()?;
        let destination = if name == "endpoint.json" {
            endpoint(&serde_json::from_str(value)?)?;
            if let Some(existing) = self.binding()? {
                return if existing == value {
                    Ok(())
                } else {
                    Err(failure("journal_endpoint_mismatch"))
                };
            }
            name.to_owned()
        } else {
            let id = operation_name(name)?;
            let incoming = receipt(id, value, None)?;
            let existing = self.read(name)?;
            if let Some(existing) = &existing {
                let existing_record = receipt(id, existing, None)?;
                if existing_record.request() != incoming.request() {
                    return Err(failure("journal_idempotency_mismatch"));
                }
                if existing == value {
                    return Ok(());
                }
                if existing_record.completed() {
                    return Err(failure("journal_completed_receipt_immutable"));
                }
            }
            if incoming.completed() {
                if existing.is_none() {
                    return Err(failure("journal_pending_intent_required"));
                }
                storage_name(id, true)
            } else {
                storage_name(id, false)
            }
        };
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(b'\n');
        if bytes.len() > RECORD_MAX {
            return Err(failure("journal_record_too_large"));
        }
        if let Err(error) = publish(&self.directory, &destination, &bytes) {
            // Publication may have happened before a sync failure. A caller must
            // reopen and reconcile; it cannot dispatch on an uncertain ack.
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    fn dispatch(&mut self, method: &str, params: &Value) -> io::Result<Value> {
        let params = params
            .as_object()
            .ok_or_else(|| failure("journal_invalid_params"))?;
        match method {
            "journal/info" if params.is_empty() => Ok(json!({
                "protocolVersion": 1,
                "platform": if cfg!(windows) { "windows" } else if cfg!(target_os = "macos") { "macos" } else if cfg!(target_os = "linux") { "linux" } else { "unsupported" },
                "durability": if cfg!(windows) { "file_flush_no_directory_power_loss_guarantee" } else { "file_and_directory_fsync" },
                "receiptFormat": "immutable_pending_completed_overlay_v1",
            })),
            "journal/lock" if params.is_empty() => {
                self.acquire()?;
                Ok(json!({"locked": true}))
            }
            "journal/unlock" if params.is_empty() => {
                self.release()?;
                Ok(json!({"locked": false}))
            }
            "journal/read" if params.len() == 1 => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| failure("journal_invalid_params"))?;
                match self.read(name)? {
                    Some(value) => Ok(json!({"found": true, "value_json": value})),
                    None => Ok(json!({"found": false})),
                }
            }
            "journal/write" if params.len() == 2 => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| failure("journal_invalid_params"))?;
                let value = params
                    .get("value_json")
                    .and_then(Value::as_str)
                    .ok_or_else(|| failure("journal_invalid_params"))?;
                self.write(name, value)?;
                Ok(json!({"written": true}))
            }
            _ => Err(failure("journal_unknown_method_or_params")),
        }
    }
}

fn response(journal: &mut Journal, request: Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request["jsonrpc"] != "2.0"
        || !(id.is_i64() || id.is_u64())
        || !request["method"].is_string()
    {
        return json!({"jsonrpc": "2.0", "id": Value::Null, "error": {"code": -32600, "message": "journal_invalid_request"}});
    }
    match journal.dispatch(request["method"].as_str().unwrap(), &request["params"]) {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": error.to_string()}})
        }
    }
}

/// Blocking bounded JSON-RPC2 over private stdio only. EOF drops the OS lock.
pub fn serve(path: &Path, mut input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let mut journal = Journal::open(path)?;
    loop {
        // take() limits allocation even when a peer never sends a newline.
        let mut frame = Vec::new();
        let count = std::io::Read::take(&mut input, (FRAME_MAX + 1) as u64)
            .read_until(b'\n', &mut frame)?;
        if count == 0 {
            return Ok(());
        }
        if count > FRAME_MAX || frame.last() != Some(&b'\n') {
            return Err(failure("journal_oversized_or_incomplete_frame"));
        }
        let reply = match serde_json::from_slice(&frame) {
            Ok(request) => response(&mut journal, request),
            Err(_) => {
                json!({"jsonrpc": "2.0", "id": Value::Null, "error": {"code": -32700, "message": "journal_invalid_json"}})
            }
        };
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        if bytes.len() > FRAME_MAX {
            return Err(failure("journal_response_too_large"));
        }
        output.write_all(&bytes)?;
        output.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use private_files::PublishPoint;
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap().join("journal");
        (root, path)
    }
    fn binding() -> String {
        json!({"version": 1, "endpoint": {
            "command": [std::env::current_exe().unwrap(), "--state", "synthetic", "mcp"],
            "cwd": std::env::current_dir().unwrap(),
        }})
        .to_string()
    }
    fn pending(id: &str) -> String {
        json!({"version": 1, "state": "pending", "request": {
            "op": "checkpoint", "operation_id": id, "workspace": "synthetic", "expected_generation": 0,
        }}).to_string()
    }
    fn complete(id: &str) -> String {
        let mut value: Value = serde_json::from_str(&pending(id)).unwrap();
        value["state"] = "completed".into();
        value["result"] = json!({"ok": true, "state": "saved", "nested": {"result": "exact"}});
        value.to_string()
    }
    fn bound(path: &Path) -> Journal {
        let mut journal = Journal::open(path).unwrap();
        journal.acquire().unwrap();
        journal.write("endpoint.json", &binding()).unwrap();
        journal
    }
    #[test]
    fn pending_and_exact_completion_survive_restart_without_execution() {
        let (_root, path) = fixture();
        let mut first = bound(&path);
        first.write("save-1.json", &pending("save-1")).unwrap();
        drop(first);
        let mut second = bound(&path);
        assert_eq!(second.read("save-1.json").unwrap(), Some(pending("save-1")));
        second.write("save-1.json", &complete("save-1")).unwrap();
        second.write("save-1.json", &complete("save-1")).unwrap();
        drop(second);
        let third = bound(&path);
        assert_eq!(third.read("save-1.json").unwrap(), Some(complete("save-1")));
        assert_eq!(
            std::fs::read_to_string(path.join(storage_name("save-1", false))).unwrap(),
            pending("save-1") + "\n"
        );
    }
    #[test]
    fn exclusive_lock_serializes_clients_and_drop_releases_it() {
        let (_root, path) = fixture();
        let first = bound(&path);
        let mut second = Journal::open(&path).unwrap();
        assert_eq!(second.acquire().unwrap_err().to_string(), "journal_busy");
        assert!(second.read("endpoint.json").is_err());
        drop(first);
        second.acquire().unwrap();
        second.release().unwrap();
        let mut third = Journal::open(&path).unwrap();
        third.acquire().unwrap();
        assert!(second.acquire().is_err());
    }
    #[test]
    fn no_access_without_lock_or_binding() {
        let (_root, path) = fixture();
        let mut journal = Journal::open(&path).unwrap();
        assert!(journal.read("endpoint.json").is_err());
        assert!(journal.write("endpoint.json", &binding()).is_err());
        journal.acquire().unwrap();
        assert!(journal.write("save.json", &pending("save")).is_err());
        assert!(!path.join(storage_name("save", false)).exists());
    }
    #[test]
    fn endpoint_binding_cannot_change() {
        let (_root, path) = fixture();
        let mut journal = bound(&path);
        let mut changed: Value = serde_json::from_str(&binding()).unwrap();
        changed["endpoint"]["command"][2] = "different-state".into();
        assert_eq!(
            journal
                .write("endpoint.json", &changed.to_string())
                .unwrap_err()
                .to_string(),
            "journal_endpoint_mismatch"
        );
        assert_eq!(journal.read("endpoint.json").unwrap(), Some(binding()));
    }
    #[test]
    fn identity_and_completed_receipt_are_immutable() {
        let (_root, path) = fixture();
        let mut journal = bound(&path);
        journal.write("save.json", &pending("save")).unwrap();
        let changed =
            pending("save").replace("\"expected_generation\":0", "\"expected_generation\":0.0");
        assert_ne!(changed, pending("save"));
        assert_eq!(
            journal
                .write("save.json", &changed)
                .unwrap_err()
                .to_string(),
            "journal_idempotency_mismatch"
        );
        assert!(journal.write("other.json", &pending("save")).is_err());
        assert!(journal.write("new.json", &complete("new")).is_err());
        journal.write("save.json", &complete("save")).unwrap();
        assert!(journal.write("save.json", &pending("save")).is_err());
        assert!(journal
            .write("save.json", &complete("save").replace("exact", "changed"))
            .is_err());
        assert_eq!(journal.read("save.json").unwrap(), Some(complete("save")));
    }
    #[test]
    fn raw_json_preserves_huge_numbers_and_float_identity() {
        let (_root, path) = fixture();
        let mut journal = bound(&path);
        let request = r#"{"op":"checkpoint","operation_id":"big","integer":12345678901234567890123456789012345678901234567890,"float":-0.0}"#;
        let pending = format!("{{\"version\":1,\"state\":\"pending\",\"request\":{request}}}");
        journal.write("big.json", &pending).unwrap();
        assert_eq!(journal.read("big.json").unwrap(), Some(pending));
        let completed = format!("{{\"version\":1,\"state\":\"completed\",\"request\":{request},\"result\":{{\"ok\":true,\"number\":999999999999999999999999999999999999999999999999999999}}}}");
        journal.write("big.json", &completed).unwrap();
        assert_eq!(journal.read("big.json").unwrap(), Some(completed));
    }
    #[test]
    fn operation_ids_do_not_alias_on_case_insensitive_or_dos_filesystems() {
        let (_root, path) = fixture();
        let mut journal = bound(&path);
        for id in ["A", "a", "CON", "LPT1", "nul", "mixed_CASE-1"] {
            let name = format!("{id}.json");
            journal.write(&name, &pending(id)).unwrap();
            journal.write(&name, &complete(id)).unwrap();
            assert_eq!(journal.read(&name).unwrap(), Some(complete(id)));
            assert!(path.join(storage_name(id, false)).is_file());
        }
        assert_ne!(storage_name("A", false), storage_name("a", false));
    }
    #[test]
    fn invalid_names_and_receipts_never_create_files() {
        let (_root, path) = fixture();
        let mut journal = bound(&path);
        for name in [
            "../escape.json",
            "nested/file.json",
            "nested\\file.json",
            "endpoint.completed.json",
            "id:stream.json",
            "a.completed.json",
            ".lock",
            "",
            "/absolute.json",
        ] {
            assert!(journal.read(name).is_err(), "accepted {name}");
            assert!(
                journal.write(name, &pending("save")).is_err(),
                "accepted {name}"
            );
        }
        for value in [
            "{}",
            "null",
            "[]",
            "{",
            r#"{"version":1,"state":"pending","request":{"op":"checkpoint","operation_id":"save"},"result":null}"#,
        ] {
            assert!(
                journal.write("save.json", value).is_err(),
                "accepted {value}"
            );
        }
        assert!(journal
            .write("endpoint.json", &pending("endpoint"))
            .is_err());
        assert!(!path.join(storage_name("save", false)).exists());
    }
    #[test]
    fn corrupt_existing_records_are_never_overwritten() {
        let (_root, path) = fixture();
        let mut journal = bound(&path);
        journal
            .directory
            .create(&storage_name("bad", false), b"{\"partial\":")
            .unwrap();
        assert!(journal.read("bad.json").is_err());
        assert!(journal.write("bad.json", &pending("bad")).is_err());
        assert_eq!(
            journal
                .directory
                .read(&storage_name("bad", false), 100)
                .unwrap(),
            b"{\"partial\":"
        );
        journal
            .directory
            .create(&storage_name("orphan", true), complete("orphan").as_bytes())
            .unwrap();
        assert!(journal.read("orphan.json").is_err());
    }
    #[test]
    fn injected_partial_writes_never_ack_or_publish_partial_receipts() {
        for point in [
            PublishPoint::BeforeWrite,
            PublishPoint::AfterPartialWrite,
            PublishPoint::AfterSync,
            PublishPoint::BeforePublish,
            PublishPoint::AfterPublish,
        ] {
            let (_root, path) = fixture();
            let mut journal = bound(&path);
            assert!(journal
                .write_using("save.json", &pending("save"), |directory, name, bytes| {
                    directory.create_fault(name, bytes, point)
                })
                .is_err());
            assert!(journal.write("other.json", &pending("other")).is_err());
            drop(journal);
            let restarted = bound(&path);
            let saved = restarted.read("save.json").unwrap();
            assert_eq!(
                saved,
                if point == PublishPoint::AfterPublish {
                    Some(pending("save"))
                } else {
                    None
                }
            );
            for entry in std::fs::read_dir(&path).unwrap() {
                private_files::validate_private_file(&entry.unwrap().path()).unwrap();
            }
        }
    }
    #[test]
    fn completion_fault_keeps_pending_identity_for_reconciliation() {
        for point in [
            PublishPoint::BeforeWrite,
            PublishPoint::AfterPartialWrite,
            PublishPoint::AfterSync,
            PublishPoint::BeforePublish,
            PublishPoint::AfterPublish,
        ] {
            let (_root, path) = fixture();
            let mut journal = bound(&path);
            journal.write("save.json", &pending("save")).unwrap();
            assert!(journal
                .write_using("save.json", &complete("save"), |directory, name, bytes| {
                    directory.create_fault(name, bytes, point)
                })
                .is_err());
            drop(journal);
            let restarted = bound(&path);
            assert_eq!(
                restarted.read("save.json").unwrap(),
                Some(if point == PublishPoint::AfterPublish {
                    complete("save")
                } else {
                    pending("save")
                })
            );
        }
    }
    #[test]
    fn bounded_protocol_keeps_ids_and_releases_lock_on_eof() {
        let (_root, path) = fixture();
        let requests = [
            json!({"jsonrpc":"2.0","id":1,"method":"journal/info","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"journal/lock","params":{}}),
            json!({"jsonrpc":"2.0","id":3,"method":"journal/write","params":{"name":"endpoint.json","value_json":binding()}}),
            json!({"jsonrpc":"2.0","id":4,"method":"journal/read","params":{"name":"endpoint.json"}}),
        ];
        let input = requests
            .iter()
            .map(|value| value.to_string() + "\n")
            .collect::<String>();
        let mut output = Vec::new();
        serve(&path, io::Cursor::new(input), &mut output).unwrap();
        let replies: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 4);
        for (i, reply) in replies.iter().enumerate() {
            assert_eq!(reply["id"], i + 1);
            assert!(reply.get("error").is_none(), "{reply}");
        }
        assert_eq!(replies[3]["result"]["value_json"], binding());
        bound(&path); // EOF released the held OS lock.
        let oversized = vec![b'x'; FRAME_MAX + 1];
        assert!(serve(&path, io::Cursor::new(oversized), Vec::new()).is_err());
        assert!(serve(&path, io::Cursor::new(b"{}"), Vec::new()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_permissions_symlinks_and_lock_hardlinks_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (root, path) = fixture();
        let journal = bound(&path);
        drop(journal);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Journal::open(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = root.path().canonicalize().unwrap().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(Journal::open(&alias).is_err());
        std::fs::hard_link(path.join(LOCK_NAME), path.join("lock-alias")).unwrap();
        assert!(Journal::open(&path).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_receipt_is_not_read_or_overwritten() {
        use std::os::unix::fs::symlink;
        let (_root, path) = fixture();
        let mut journal = bound(&path);
        symlink(
            path.join("endpoint.json"),
            path.join(storage_name("save", false)),
        )
        .unwrap();
        assert!(journal.read("save.json").is_err());
        assert!(journal.write("save.json", &pending("save")).is_err());
        assert_eq!(journal.read("endpoint.json").unwrap(), Some(binding()));
    }
}
