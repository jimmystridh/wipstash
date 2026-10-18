//! Explicit trusted-file exchange between independently stored peers. No authentication or network I/O.
use super::*;
use crate::replication::{self, Authority, Envelope, Event, Id, PeerIdentity, ReplayStore};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Config {
    project: String,
    authority: String,
    epoch: u64,
    device: String,
    role: String,
    peers: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    project: String,
    authority: String,
    epoch: u64,
    device: String,
    operation: String,
    kind: String,
    head: String,
    base: Option<String>,
    proposal: Option<String>,
    intent: Option<String>,
    envelope: Option<Envelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<Receipt>,
    payload_len: u64,
    payload_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    recipient: String,
    authority_proposal: String,
    revision: u64,
    state: String,
    integration_head: Option<String>,
    evidence: String,
    repaired: bool,
}
fn config(db: &Connection) -> R<Option<Config>> {
    let text: Option<String> = sql(db
        .query_row("SELECT value FROM meta WHERE key='sync_config'", [], |r| {
            r.get(0)
        })
        .optional())?;
    text.map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .transpose()
}
fn pending_config(db: &Connection) -> R<Option<Config>> {
    let text: Option<String> = sql(db
        .query_row(
            "SELECT value FROM meta WHERE key='sync_client_pending'",
            [],
            |r| r.get(0),
        )
        .optional())?;
    text.map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .transpose()
}
/// Only template-free, empty bare initialization artifacts may be resumed.
/// Never run Git against an unvalidated local config or follow a symlink.
fn validate_pending_client_repo(root: &Path) -> R<()> {
    match fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("io_error: {e}")),
        Ok(m) if !m.is_dir() || m.file_type().is_symlink() => {
            return Err("client_initialization_not_pristine".into());
        }
        Ok(_) => (),
    }
    let mut directories = vec![PathBuf::new()];
    while let Some(relative) = directories.pop() {
        for entry in io(fs::read_dir(root.join(&relative)))? {
            let entry = io(entry)?;
            let path = relative.join(entry.file_name());
            let meta = io(fs::symlink_metadata(entry.path()))?;
            if meta.file_type().is_symlink() {
                return Err("client_initialization_not_pristine".into());
            }
            if meta.is_dir()
                && [
                    "objects",
                    "objects/info",
                    "objects/pack",
                    "refs",
                    "refs/heads",
                    "refs/tags",
                ]
                .iter()
                .any(|p| path == Path::new(p))
            {
                directories.push(path);
            } else if meta.is_file() && path == Path::new("HEAD") && meta.len() <= 256 {
                let head = io(fs::read_to_string(entry.path()))?;
                let branch = head
                    .trim_end_matches('\n')
                    .strip_prefix("ref: refs/heads/")
                    .ok_or("client_initialization_not_pristine")?;
                ident(branch).map_err(|_| "client_initialization_not_pristine".to_string())?;
            } else if meta.is_file() && path == Path::new("config") && meta.len() <= 4096 {
                let text = io(fs::read_to_string(entry.path()))?;
                let mut core = false;
                for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
                    if line == "[core]" && !core {
                        core = true;
                        continue;
                    }
                    let Some((key, value)) = line.split_once('=') else {
                        return Err("client_initialization_not_pristine".into());
                    };
                    let allowed = match key.trim() {
                        "repositoryformatversion" => value.trim() == "0",
                        "bare" => value.trim() == "true",
                        "filemode" | "symlinks" | "ignorecase" | "precomposeunicode" => {
                            matches!(value.trim(), "true" | "false")
                        }
                        _ => false,
                    };
                    if !core || !allowed {
                        return Err("client_initialization_not_pristine".into());
                    }
                }
                if !core {
                    return Err("client_initialization_not_pristine".into());
                }
            } else {
                return Err("client_initialization_not_pristine".into());
            }
        }
    }
    Ok(())
}
fn required(db: &Connection) -> R<Config> {
    config(db)?.ok_or_else(|| "sync_not_configured".into())
}
pub(super) fn is_client(db: &Connection) -> R<bool> {
    Ok(config(db)?.is_some_and(|c| c.role == "client"))
}
fn schema(db: &Connection) -> R<()> {
    sql(db.execute_batch("CREATE TABLE IF NOT EXISTS sync_exports(operation TEXT PRIMARY KEY,request_digest TEXT NOT NULL,manifest TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS sync_exports_head_sequence ON sync_exports(json_extract(manifest,'$.envelope.sequence')) WHERE json_extract(manifest,'$.kind')='head';
    CREATE TABLE IF NOT EXISTS sync_proposal_origins(proposal TEXT PRIMARY KEY,device TEXT NOT NULL,source_proposal TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sync_remote_status(proposal TEXT PRIMARY KEY,revision INTEGER NOT NULL,digest TEXT NOT NULL,receipt TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sync_imports(device TEXT NOT NULL,operation TEXT NOT NULL,digest TEXT NOT NULL,result TEXT NOT NULL,PRIMARY KEY(device,operation));"))
}
fn binding(c: &Config) -> R<Authority> {
    Ok(Authority {
        project: Id::try_from(c.project.clone())?,
        authority: Id::try_from(c.authority.clone())?,
        epoch: c.epoch,
    })
}
pub(super) fn configure(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let c = Config {
        project: field(r, "project")?.into(),
        authority: field(r, "authority")?.into(),
        epoch: r["epoch"].as_u64().ok_or("invalid_epoch")?,
        device: field(r, "device")?.into(),
        role: field(r, "role")?.into(),
        peers: serde_json::from_value(r["peers"].clone()).map_err(|_| "invalid_peers")?,
    };
    for id in [&c.project, &c.authority, &c.device]
        .into_iter()
        .chain(c.peers.iter())
    {
        ident(id)?;
    }
    if c.epoch == 0
        || c.epoch > i64::MAX as u64
        || c.peers.is_empty()
        || c.peers.len() > 100
        || !matches!(c.role.as_str(), "client" | "authority")
    {
        return Err("invalid_sync_config".into());
    }
    if let Some(old) = config(db)? {
        if old != c {
            return Err("authority_binding_mismatch: sync binding and role are immutable".into());
        }
        return status(state, db);
    }
    let initialized: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='authority')",
        [],
        |r| r.get(0),
    ))?;
    let pending = pending_config(db)?;
    if pending.as_ref().is_some_and(|old| old != &c) {
        return Err("authority_binding_mismatch: pending client binding is immutable".into());
    }
    if c.role == "client" && initialized {
        return Err("client_requires_empty_state".into());
    }
    if c.role == "authority" && !initialized {
        return Err("project_not_initialized: init authority source first".into());
    }
    if c.role == "client" {
        let repo = state.join("coordinator.git");
        if pending.is_none() {
            match fs::symlink_metadata(&repo) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(format!("io_error: {e}")),
                Ok(_) => return Err("client_requires_empty_state".into()),
            }
            // Durable intent precedes every filesystem side effect. Exact retries
            // can resume this binding, but never adopt arbitrary existing repos.
            sql(db.execute(
                "INSERT INTO meta(key,value) VALUES('sync_client_pending',?1)",
                [serde_json::to_string(&c).map_err(|e| e.to_string())?],
            ))?;
        }
        validate_pending_client_repo(&repo)?;
        Git::init(&repo)?;
        validate_pending_client_repo(&repo)?;
    }
    schema(db)?;
    // A persisted binding is the only way incoming artifacts select a project/epoch.
    let tx = sql(db.unchecked_transaction())?;
    sql(tx.execute(
        "INSERT INTO meta(key,value) VALUES('sync_config',?1)",
        [serde_json::to_string(&c).map_err(|e| e.to_string())?],
    ))?;
    if c.role == "client" {
        sql(tx.execute(
            "INSERT INTO meta(key,value) VALUES('authority',?1)",
            [&c.authority],
        ))?;
        sql(tx.execute("DELETE FROM meta WHERE key='sync_client_pending'", []))?;
    }
    sql(tx.commit())?;
    status(state, db)
}
/// Explicit local bootstrap. Legacy sync_configure still requires nonempty peers.
/// Repeated initialization never removes peers or changes an existing binding.
pub(super) fn initialize_authority(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    only_fields(
        r,
        &[
            "op",
            "operation_id",
            "project",
            "authority",
            "epoch",
            "device",
        ],
    )?;
    let c = Config {
        project: field(r, "project")?.into(),
        authority: field(r, "authority")?.into(),
        epoch: r["epoch"].as_u64().ok_or("invalid_epoch")?,
        device: field(r, "device")?.into(),
        role: "authority".into(),
        peers: Vec::new(),
    };
    for id in [&c.project, &c.authority, &c.device] {
        ident(id)?;
    }
    if c.epoch == 0 || c.epoch > i64::MAX as u64 {
        return Err("invalid_sync_config".into());
    }
    if pending_config(db)?.is_some() {
        return Err("authority_binding_mismatch: client initialization pending".into());
    }
    let exists = if let Some(old) = config(db)? {
        if old.role != "authority" {
            return Err("authority_required".into());
        }
        if old.project != c.project
            || old.authority != c.authority
            || old.epoch != c.epoch
            || old.device != c.device
        {
            return Err("authority_binding_mismatch: sync binding and role are immutable".into());
        }
        true
    } else {
        false
    };
    schema(db)?;
    let tx = sql(db.unchecked_transaction())?;
    if !exists {
        sql(tx.execute(
            "INSERT INTO meta(key,value) VALUES('sync_config',?1)",
            [serde_json::to_string(&c).map_err(|e| e.to_string())?],
        ))?;
        event(
            &tx,
            "sync_authority_initialized",
            &json!({"operation_id":field(r,"operation_id")?}),
        )?;
    }
    let result = status(state, &tx)?;
    finish(&tx, field(r, "operation_id")?, &result)?;
    sql(tx.commit())?;
    Ok(result)
}
fn only_fields(r: &Value, allowed: &[&str]) -> R<()> {
    if r.as_object()
        .ok_or("invalid_request")?
        .keys()
        .any(|k| !allowed.contains(&k.as_str()))
    {
        return Err("invalid_request: unexpected field".into());
    }
    Ok(())
}
/// Monotonic artifact-source authorization, not authentication or a transport ACL.
/// Removed/retired transport identities retain their core peer labels and history.
/// The managed enrollment layer must reject reuse and own explicit rotations.
pub(super) fn add_peer(db: &Connection, r: &Value) -> R<Value> {
    only_fields(r, &["op", "operation_id", "peer"])?;
    let mut c = required(db)?;
    if c.role != "authority" {
        return Err("authority_required".into());
    }
    let peer = field(r, "peer")?;
    ident(peer)?;
    if peer == c.device {
        return Err("peer_identity_collision: peer is the local device".into());
    }
    let existing = c.peers.iter().any(|p| p == peer);
    if !existing {
        if c.peers.len() >= 100 {
            return Err("peer_limit_reached".into());
        }
        c.peers.push(peer.into());
    }
    let result = json!({"ok":true,"state":"peer_pinned","peer":peer,
        "already_present":existing,"config":c,"transport_access_granted":false});
    let tx = sql(db.unchecked_transaction())?;
    if !existing {
        sql(tx.execute(
            "UPDATE meta SET value=?1 WHERE key='sync_config'",
            [serde_json::to_string(&c).map_err(|e| e.to_string())?],
        ))?;
        event(
            &tx,
            "sync_peer_added",
            &json!({"peer":peer,"operation_id":field(r,"operation_id")?}),
        )?;
    }
    finish(&tx, field(r, "operation_id")?, &result)?;
    sql(tx.commit())?;
    Ok(result)
}
/// Inspect without creating state, changing permissions, or replaying recovery.
/// Immutable SQLite avoids even WAL/shm creation. Pending journals fail closed
/// instead of silently inspecting an older main-file snapshot.
pub(super) fn binding_status(state: &Path) -> R<Value> {
    let unconfigured = || json!({"ok":true,"state":"unconfigured","initialized":false,"config":null,"pending_config":null,"workspace_roots":[]});
    match fs::symlink_metadata(state) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(unconfigured()),
        Err(e) => return Err(format!("io_error: {e}")),
        Ok(m) if !m.is_dir() || m.file_type().is_symlink() => {
            return Err("invalid_state_path".into());
        }
        Ok(_) => (),
    }
    let path = state.join("state.sqlite");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if io(fs::read_dir(state))?.next().is_none() {
                return Ok(unconfigured());
            }
            return Err("incomplete_state: database missing".into());
        }
        Err(e) => return Err(format!("io_error: {e}")),
        Ok(m) if !m.is_file() || m.file_type().is_symlink() => {
            return Err("invalid_state_database".into());
        }
        Ok(_) => (),
    }
    let lock = io(OpenOptions::new().read(true).open(state.join("state.lock")))?;
    fs2::FileExt::lock_shared(&lock).map_err(|e| e.to_string())?;
    for name in ["state.sqlite-wal", "state.sqlite-journal"] {
        match fs::symlink_metadata(state.join(name)) {
            Ok(m) if m.len() != 0 || !m.is_file() || m.file_type().is_symlink() => {
                return Err(
                    "binding_inspection_requires_recovery: pending database journal".into(),
                );
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("io_error: {e}")),
        }
    }
    let absolute = io(path.canonicalize())?;
    let mut uri = String::from("file:");
    for byte in absolute.to_str().ok_or("invalid_state_path")?.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-_.:".contains(&byte) {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?immutable=1");
    let db = sql(Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    ))?;
    let initialized: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='authority')",
        [],
        |row| row.get(0),
    ))?;
    let c = config(&db)?;
    if c.is_some() && !initialized {
        return Err("incomplete_state: binding without authority metadata".into());
    }
    let pending = pending_config(&db)?;
    // Bound both row count and individual allocation. Never silently omit invalid
    // registrations: callers use this list to keep private pairing files out of
    // publishable workspaces. Do not canonicalize or inspect live workspace data.
    let mut stmt = sql(db.prepare(
        "SELECT CASE WHEN typeof(path)='text' AND length(CAST(path AS BLOB)) BETWEEN 1 AND 4096 THEN path END FROM workspaces ORDER BY id LIMIT 1001",
    ))?;
    let mut workspace_roots = Vec::new();
    for row in sql(stmt.query_map([], |row| row.get::<_, Option<String>>(0)))? {
        let root = sql(row)?.ok_or("invalid_workspace_root")?;
        let path = Path::new(&root);
        if !path.is_absolute()
            || root.contains('\0')
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("invalid_workspace_root".into());
        }
        if workspace_roots.len() >= 1000 {
            return Err("workspace_root_limit_exceeded".into());
        }
        workspace_roots.push(root);
    }
    Ok(
        json!({"ok":true,"state":if c.is_some(){"configured"}else{"unconfigured"},"initialized":initialized,"config":c,"pending_config":pending,"workspace_roots":workspace_roots}),
    )
}
pub(super) fn status(state: &Path, db: &Connection) -> R<Value> {
    let c = required(db)?;
    let replay_path = state.join("sync-replay.sqlite");
    let cursor = if c.role == "client" && replay_path.exists() {
        Some(ReplayStore::open(sql(Connection::open(replay_path))?, binding(&c)?)?.cursor()?)
    } else {
        None
    };
    Ok(
        json!({"ok":true,"state":"configured","config":c,"head":coordinator(state).head(HEAD).ok(),"cursor":cursor,"transport":"trusted_directory_exchange","authenticated":false,"warning":"Identity labels and checksums are not authentication. Import only artifacts from a separately trusted source."}),
    )
}
fn write_new(path: &Path, bytes: &[u8]) -> R<()> {
    let mut file = io(OpenOptions::new().create_new(true).write(true).open(path))?;
    io(file.write_all(bytes))?;
    io(file.sync_all())
}
fn read_bounded(path: &Path, limit: usize) -> R<Vec<u8>> {
    let meta = io(fs::symlink_metadata(path))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        return Err("invalid_artifact_file: size or file type".into());
    }
    let mut out = Vec::new();
    io(io(fs::File::open(path))?
        .take(limit as u64 + 1)
        .read_to_end(&mut out))?;
    if out.len() > limit {
        return Err("artifact_too_large".into());
    }
    Ok(out)
}
fn destination(r: &Value, state: &Path, db: &Connection) -> R<PathBuf> {
    let p = PathBuf::from(field(r, "destination")?);
    if !p.is_absolute() {
        return Err("invalid_artifact_path: absolute destination required".into());
    }
    let parent = io(p.parent().ok_or("invalid_artifact_path")?.canonicalize())?;
    let p = parent.join(p.file_name().ok_or("invalid_artifact_path")?);
    if p.starts_with(io(state.canonicalize())?) {
        return Err("invalid_artifact_path: destination overlaps state".into());
    }
    let mut stmt = sql(db.prepare("SELECT path FROM workspaces"))?;
    for root in sql(stmt.query_map([], |row| row.get::<_, String>(0)))? {
        let root = PathBuf::from(sql(root)?);
        if p.starts_with(&root) || root.starts_with(&p) {
            return Err("invalid_artifact_path: destination overlaps workspace".into());
        }
    }
    Ok(p)
}
pub(super) fn export(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let c = required(db)?;
    schema(db)?;
    let op = field(r, "operation_id")?;
    ident(op)?;
    let destination = destination(r, state, db)?;
    let request_digest = digest(r);
    let saved: Option<(String, String)> = sql(db
        .query_row(
            "SELECT request_digest,manifest FROM sync_exports WHERE operation=?1",
            [op],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    let (m, bytes) = if let Some((d, text)) = saved {
        if d != request_digest && r["op"] != "sync_reexport" {
            return Err("idempotency_mismatch".into());
        }
        let m: Manifest = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let git = if m.kind == "head" || m.kind == "receipt" {
            coordinator(state)
        } else {
            let wid: String = sql(db.query_row(
                "SELECT workspace FROM proposals WHERE id=?1",
                [m.proposal.as_ref().ok_or("invalid_manifest")?],
                |row| row.get(0),
            ))?;
            local(state, &wid)
        };
        let bytes = if m.kind == "receipt" {
            Vec::new()
        } else {
            crate::transfer::export(&git, std::slice::from_ref(&m.head))?
        };
        (m, bytes)
    } else {
        if r["op"] == "sync_reexport" {
            return Err("export_not_found".into());
        }
        let kind = field(r, "kind")?;
        let (git, head, base, proposal, intent, envelope, receipt) = match kind {
            "head" if c.role == "authority" => {
                let git = coordinator(state);
                let head = git.head(HEAD)?;
                let sequence: i64=sql(db.query_row("SELECT COALESCE(MAX(json_extract(manifest,'$.envelope.sequence')),0)+1 FROM sync_exports WHERE json_extract(manifest,'$.kind')='head'",[],|row|row.get(0)))?;
                let envelope = Envelope {
                    version: 1,
                    project: Id::try_from(c.project.clone())?,
                    authority: Id::try_from(c.authority.clone())?,
                    epoch: c.epoch,
                    device: Id::try_from(c.device.clone())?,
                    sequence: sequence as u64,
                    operation: Id::try_from(op.to_string())?,
                    event: Event::HeadAdvanced { head: head.clone() },
                };
                (git, head, None, None, None, Some(envelope), None)
            }
            "proposal" if c.role == "client" => {
                let p = field(r, "proposal")?;
                ident(p)?;
                let (wid, head, base, intent, phase): (String, String, String, String, String) =
                    sql(db.query_row(
                        "SELECT workspace,commit_oid,base,intent,state FROM proposals WHERE id=?1",
                        [p],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ))
                        },
                    ))?;
                if phase != "local_queued" {
                    return Err("proposal_not_exportable".into());
                }
                (
                    local(state, &wid),
                    head,
                    Some(base),
                    Some(p.into()),
                    Some(intent),
                    None,
                    None,
                )
            }
            "receipt" if c.role == "authority" => {
                let authority_proposal = field(r, "proposal")?;
                ident(authority_proposal)?;
                let (recipient, source_proposal): (String, String) = sql(db.query_row(
                    "SELECT device,source_proposal FROM sync_proposal_origins WHERE proposal=?1",
                    [authority_proposal],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ))?;
                let (head, base): (String, String) = sql(db.query_row(
                    "SELECT commit_oid,base FROM proposals WHERE id=?1",
                    [authority_proposal],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ))?;
                let observed = super::proposal_status(db, authority_proposal)?;
                let revision:i64=sql(db.query_row("SELECT COALESCE(MAX(json_extract(manifest,'$.receipt.revision')),0)+1 FROM sync_exports WHERE json_extract(manifest,'$.receipt.authority_proposal')=?1",[authority_proposal],|row|row.get(0)))?;
                let receipt = Receipt {
                    recipient,
                    authority_proposal: authority_proposal.into(),
                    revision: revision as u64,
                    state: field(&observed, "state")?.into(),
                    integration_head: observed["head"].as_str().map(str::to_owned),
                    evidence: field(&observed, "evidence")?.into(),
                    repaired: observed["details"]["repaired"] == true,
                };
                validate_receipt(&receipt)?;
                (
                    coordinator(state),
                    head,
                    Some(base),
                    Some(source_proposal),
                    None,
                    None,
                    Some(receipt),
                )
            }
            _ => return Err("sync_role_mismatch".into()),
        };
        let bytes = if kind == "receipt" {
            Vec::new()
        } else {
            crate::transfer::export(&git, std::slice::from_ref(&head))?
        };
        if bytes.len() > replication::MAX_OBJECT_BYTES {
            return Err("object_too_large".into());
        }
        let m = Manifest {
            version: 1,
            project: c.project.clone(),
            authority: c.authority.clone(),
            epoch: c.epoch,
            device: c.device.clone(),
            operation: op.into(),
            kind: kind.into(),
            head,
            base,
            proposal,
            intent,
            envelope,
            receipt,
            payload_len: bytes.len() as u64,
            payload_sha256: format!("{:x}", Sha256::digest(&bytes)),
        };
        if serde_json::to_vec(&m).map_err(|e| e.to_string())?.len()
            > replication::MAX_ENVELOPE_BYTES
        {
            return Err("manifest_too_large".into());
        }
        // Reserve event identity before writing the transferable artifact. Retry reconstructs it.
        sql(db.execute(
            "INSERT INTO sync_exports VALUES(?1,?2,?3)",
            params![
                op,
                request_digest,
                serde_json::to_string(&m).map_err(|e| e.to_string())?
            ],
        ))?;
        (m, bytes)
    };
    if bytes.len() as u64 != m.payload_len
        || format!("{:x}", Sha256::digest(&bytes)) != m.payload_sha256
    {
        return Err("export_content_changed".into());
    }
    let manifest = serde_json::to_vec(&m).map_err(|e| e.to_string())?;
    if destination.exists() {
        if read_bounded(
            &destination.join("manifest.json"),
            replication::MAX_ENVELOPE_BYTES,
        )? != manifest
            || read_bounded(
                &destination.join("objects.json"),
                replication::MAX_OBJECT_BYTES,
            )? != bytes
        {
            return Err("artifact_destination_exists".into());
        }
    } else {
        let staging = destination.with_file_name(format!(
            ".wipstash-export-{}",
            digest(&json!({"state":state,"operation":op}))
        ));
        if staging.exists() {
            return Err("export_staging_exists: inspect incomplete artifact and choose a new destination/operation".into());
        }
        io(fs::create_dir(&staging))?;
        write_new(&staging.join("objects.json"), &bytes)?;
        write_new(&staging.join("manifest.json"), &manifest)?;
        #[cfg(unix)]
        io(fs::File::open(&staging).and_then(|f| f.sync_all()))?;
        io(fs::rename(&staging, &destination))?;
        #[cfg(unix)]
        io(fs::File::open(destination.parent().unwrap()).and_then(|f| f.sync_all()))?;
    }
    Ok(
        json!({"ok":true,"state":"exported","destination":destination,"head":m.head,"kind":m.kind,"sequence":m.envelope.map(|e|e.sequence),"authenticated":false}),
    )
}

pub(super) fn import(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    if r["confirm_trusted_source"] != true {
        return Err("trusted_source_confirmation_required: artifacts are not authenticated; confirm their separately trusted origin".into());
    }
    let c = required(db)?;
    schema(db)?;
    let source = PathBuf::from(field(r, "source")?);
    let bytes = read_bounded(
        &source.join("manifest.json"),
        replication::MAX_ENVELOPE_BYTES,
    )?;
    let m: Manifest =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid_manifest: {e}"))?;
    if m.version != 1 {
        return Err("unsupported_protocol".into());
    }
    for id in [&m.project, &m.authority, &m.device, &m.operation] {
        ident(id)?;
    }
    if m.project != c.project {
        return Err("wrong_project".into());
    }
    if m.authority != c.authority || m.epoch != c.epoch {
        return Err("authority_fenced".into());
    }
    if !c.peers.contains(&m.device) {
        return Err("wrong_device: sender not in pinned peers".into());
    }
    if m.head.len() != 40
        || !m
            .head
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid_object_id".into());
    }
    let raw = read_bounded(&source.join("objects.json"), replication::MAX_OBJECT_BYTES)?;
    let payload = replication::verify_payload(raw.as_slice(), m.payload_len, &m.payload_sha256)?;
    let md = digest(&serde_json::to_value(&m).map_err(|e| e.to_string())?);
    let existing: Option<(String, String)> = sql(db
        .query_row(
            "SELECT digest,result FROM sync_imports WHERE device=?1 AND operation=?2",
            params![m.device, m.operation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    if let Some((old, result)) = existing {
        if old != md {
            return Err("replay_conflict".into());
        }
        let mut result: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
        result["duplicate"] = json!(true);
        if m.kind != "head" {
            return Ok(result);
        }
    }
    match m.kind.as_str() {
        "head" if c.role == "client" => {
            if m.base.is_some() || m.proposal.is_some() || m.intent.is_some() || m.receipt.is_some()
            {
                return Err("invalid_manifest".into());
            }
            let envelope = m.envelope.as_ref().ok_or("invalid_manifest")?;
            let encoded = serde_json::to_vec(envelope).map_err(|e| e.to_string())?;
            let decoded = replication::decode(&encoded)?;
            if decoded.project != Id::try_from(m.project.clone())?
                || decoded.authority != Id::try_from(m.authority.clone())?
                || decoded.device != Id::try_from(m.device.clone())?
                || decoded.epoch != m.epoch
                || decoded.operation != Id::try_from(m.operation.clone())?
                || !matches!(&decoded.event, Event::HeadAdvanced{head} if head==&m.head)
            {
                return Err("invalid_manifest: envelope mismatch".into());
            }
            let git = coordinator(state);
            let prepared =
                crate::transfer::prepare(&git, payload.as_bytes(), std::slice::from_ref(&m.head))?;
            let old = git.head(HEAD).ok();
            let mut replay = ReplayStore::open(
                sql(Connection::open(state.join("sync-replay.sqlite")))?,
                binding(&c)?,
            )?;
            let peer = PeerIdentity {
                project: Id::try_from(c.project.clone())?,
                authority: Id::try_from(c.authority.clone())?,
                device: Id::try_from(m.device.clone())?,
                may_replicate: true,
            };
            let preflight = replay.check(&peer, &encoded)?;
            if preflight == replication::Admission::Applied {
                if let Some(old) = &old {
                    if !first_parent_contains(prepared.git(), &m.head, old)? {
                        return Err(
                            "stale_head: authority head must fast-forward the public cache".into(),
                        );
                    }
                }
            }
            prepared.install(&git)?;
            let admission = replay.receive(&peer, &encoded)?;
            // Replay database is the durable intent. Retry completes a crash after receive.
            // Use its latest head, never the old event head, for delayed duplicate delivery.
            let latest = replay.cached_head()?.ok_or("missing_replay_head")?;
            git.set_ref(HEAD, &latest, old.as_deref())?;
            let result = json!({"ok":true,"state":"cached","head":latest,"sequence":replay.cursor()?,"duplicate":admission==replication::Admission::Duplicate,"files_changed":false,"authenticated":false});
            sql(db.execute(
                "INSERT OR REPLACE INTO sync_imports VALUES(?1,?2,?3,?4)",
                params![m.device, m.operation, md, result.to_string()],
            ))?;
            Ok(result)
        }
        "proposal" if c.role == "authority" => {
            if m.envelope.is_some() || m.receipt.is_some() {
                return Err("invalid_manifest".into());
            }
            let p = m.proposal.as_ref().ok_or("invalid_manifest")?;
            ident(p)?;
            let base = m.base.as_ref().ok_or("invalid_manifest")?;
            let intent = m.intent.as_ref().ok_or("invalid_manifest")?;
            if intent.len() > 4096 {
                return Err("invalid_manifest: intent too large".into());
            }
            let git = coordinator(state);
            let head = git.head(HEAD)?;
            let history = String::from_utf8(git.run(&["rev-list", "--first-parent", &head], None)?)
                .map_err(|e| e.to_string())?;
            if !history.lines().any(|h| h == base) {
                return Err("unknown_public_base".into());
            }
            let prepared =
                crate::transfer::prepare(&git, payload.as_bytes(), std::slice::from_ref(&m.head))?;
            let parents = String::from_utf8(
                prepared
                    .git()
                    .run(&["show", "-s", "--format=%P", &m.head], None)?,
            )
            .map_err(|e| e.to_string())?;
            if parents.trim() != base {
                return Err("invalid_proposal_parent".into());
            }
            let message = String::from_utf8(
                prepared
                    .git()
                    .run(&["show", "-s", "--format=%B", &m.head], None)?,
            )
            .map_err(|e| e.to_string())?;
            if message.trim() != format!("proposal {p}") {
                return Err("invalid_proposal_identity".into());
            }
            let id = format!(
                "remote-{}",
                digest(&json!({"device":m.device,"proposal":p}))
            );
            let existing: Option<(String, String, String, String)> = sql(db
                .query_row(
                    "SELECT commit_oid,base,intent,state FROM proposals WHERE id=?1",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional())?;
            if let Some((commit, b, i, _)) = &existing {
                if commit != &m.head || b != base || i != intent {
                    return Err("idempotency_mismatch: proposal identity already accepted with other content".into());
                }
            }
            prepared.install(&git)?;
            git.set_ref(&format!("refs/wipstash/proposals/{id}"), &m.head, None)?;
            let result = json!({"ok":true,"state":existing.as_ref().map(|e|e.3.as_str()).unwrap_or("coordinator_accepted"),"proposal":id,"source_proposal":p,"head":m.head,"duplicate":existing.is_some(),"authenticated":false});
            sql(db.execute_batch("BEGIN IMMEDIATE"))?;
            sql(db.execute("INSERT OR IGNORE INTO proposals(id,workspace,checkpoint,commit_oid,base,intent,state) VALUES(?1,?2,?3,?4,?5,?6,'coordinator_accepted')",params![id,format!("remote-{}",m.device),p,m.head,base,intent]))?;
            sql(db.execute(
                "INSERT OR IGNORE INTO sync_proposal_origins VALUES(?1,?2,?3)",
                params![id, m.device, p],
            ))?;
            sql(db.execute(
                "INSERT INTO sync_imports VALUES(?1,?2,?3,?4)",
                params![m.device, m.operation, md, result.to_string()],
            ))?;
            if existing.is_none() {
                event(
                    db,
                    "remote_proposal_accepted",
                    &json!({"proposal":id,"device":m.device,"source_proposal":p}),
                )?;
            }
            sql(db.execute_batch("COMMIT"))?;
            Ok(result)
        }
        "receipt" if c.role == "client" => import_receipt(db, &c, &m, &md, payload.as_bytes()),
        _ => Err("sync_role_mismatch".into()),
    }
}

/// Bounded pages. All-export cursors are row IDs; head cursors are authority sequences.
pub(super) fn export_history(db: &Connection, r: &Value) -> R<Value> {
    required(db)?;
    schema(db)?;
    let heads = match r.get("kind") {
        None => false,
        Some(Value::String(kind)) if kind == "head" => true,
        _ => return Err("invalid_history_kind".into()),
    };
    let cursor_kind = if heads { "head_sequence" } else { "export_row" };
    if r.get("cursor_kind")
        .is_some_and(|v| v.as_str() != Some(cursor_kind))
    {
        return Err("history_cursor_kind".into());
    }
    let after = match r.get("after") {
        None => 0,
        Some(v) => v
            .as_u64()
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("invalid_history_cursor")?,
    };
    let limit = match r.get("limit") {
        None => 128,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=256).contains(n))
            .ok_or("invalid_history_limit")?,
    };
    if after > 0 {
        let query = if heads {
            "SELECT EXISTS(SELECT 1 FROM sync_exports WHERE json_extract(manifest,'$.kind')='head' AND json_extract(manifest,'$.envelope.sequence')=?1)"
        } else {
            "SELECT EXISTS(SELECT 1 FROM sync_exports WHERE rowid=?1)"
        };
        let exists: bool = sql(db.query_row(query, [after as i64], |row| row.get(0)))?;
        if !exists {
            return Err("unknown_history_cursor".into());
        }
    }
    let query = if heads {
        "SELECT json_extract(manifest,'$.envelope.sequence'),operation,manifest FROM sync_exports WHERE json_extract(manifest,'$.kind')='head' AND json_extract(manifest,'$.envelope.sequence')>?1 ORDER BY json_extract(manifest,'$.envelope.sequence') LIMIT ?2"
    } else {
        "SELECT rowid,operation,manifest FROM sync_exports WHERE rowid>?1 ORDER BY rowid LIMIT ?2"
    };
    let mut stmt = sql(db.prepare(query))?;
    let mut exports = Vec::new();
    let mut next = after;
    let mut has_more = false;
    for row in sql(
        stmt.query_map(params![after as i64, (limit + 1) as i64], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        }),
    )? {
        let (cursor, operation, text) = sql(row)?;
        if exports.len() == limit as usize {
            has_more = true;
            break;
        }
        let m: Manifest = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        next = cursor;
        exports.push(json!({"operation_id":operation,"kind":m.kind,"head":m.head,"sequence":m.envelope.map(|e|e.sequence)}));
    }
    Ok(
        json!({"ok":true,"exports":exports,"cursor_kind":cursor_kind,"after":after,"next_cursor":next,"has_more":has_more}),
    )
}

pub(super) fn export_lookup(db: &Connection, r: &Value) -> R<Value> {
    required(db)?;
    schema(db)?;
    let operation = field(r, "operation_id")?;
    let found: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sync_exports WHERE operation=?1)",
        [operation],
        |row| row.get(0),
    ))?;
    Ok(json!({"ok":true,"exists":found}))
}

fn first_parent_contains(git: &Git, head: &str, ancestor: &str) -> R<bool> {
    let history = String::from_utf8(git.run(&["rev-list", "--first-parent", head], None)?)
        .map_err(|e| e.to_string())?;
    Ok(history.lines().any(|h| h == ancestor))
}
pub(super) fn recover_head(state: &Path, db: &Connection) -> R<()> {
    let Some(c) = config(db)? else { return Ok(()) };
    let path = state.join("sync-replay.sqlite");
    if c.role != "client" || !path.exists() {
        return Ok(());
    }
    let replay = ReplayStore::open(sql(Connection::open(path))?, binding(&c)?)?;
    let Some(latest) = replay.cached_head()? else {
        return Ok(());
    };
    let git = coordinator(state);
    git.tree(&latest)
        .map_err(|e| format!("sync_recovery_required: admitted objects missing: {e}"))?;
    let old = git.head(HEAD).ok();
    if old.as_ref() == Some(&latest) {
        return Ok(());
    }
    if let Some(old) = &old {
        if !first_parent_contains(&git, &latest, old)? {
            return Err("sync_recovery_required: public cache diverged".into());
        }
    }
    git.set_ref(HEAD, &latest, old.as_deref())
}

fn valid_oid(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn terminal(s: &str) -> bool {
    matches!(s, "integrated" | "already_included" | "cancelled")
}
fn validate_receipt(r: &Receipt) -> R<()> {
    ident(&r.recipient)?;
    ident(&r.authority_proposal)?;
    if r.revision == 0
        || r.revision > i64::MAX as u64
        || !matches!(
            r.state.as_str(),
            "coordinator_accepted"
                | "quarantined"
                | "integrated"
                | "already_included"
                | "cancelled"
        )
        || !matches!(
            r.evidence.as_str(),
            "unchecked" | "checks_executed" | "agent_resolved_unchecked"
        )
    {
        return Err("invalid_receipt".into());
    }
    if r.integration_head.as_ref().is_some_and(|h| !valid_oid(h))
        || (matches!(r.state.as_str(), "integrated" | "already_included")
            != r.integration_head.is_some())
    {
        return Err("invalid_receipt: integration head".into());
    }
    Ok(())
}
fn import_receipt(db: &Connection, c: &Config, m: &Manifest, md: &str, payload: &[u8]) -> R<Value> {
    if !payload.is_empty() || m.intent.is_some() || m.envelope.is_some() {
        return Err("invalid_receipt".into());
    }
    let receipt = m.receipt.as_ref().ok_or("invalid_receipt")?;
    validate_receipt(receipt)?;
    if receipt.recipient != c.device {
        return Err("wrong_receipt_recipient".into());
    }
    let proposal = m.proposal.as_ref().ok_or("invalid_receipt")?;
    ident(proposal)?;
    let base = m.base.as_ref().ok_or("invalid_receipt")?;
    if !valid_oid(base) {
        return Err("invalid_receipt".into());
    }
    let authority_id = format!(
        "remote-{}",
        digest(&json!({"device":c.device,"proposal":proposal}))
    );
    if authority_id != receipt.authority_proposal {
        return Err("receipt_proposal_mismatch".into());
    }
    let (commit, local_base, local_state): (String, String, String) = sql(db.query_row(
        "SELECT commit_oid,base,state FROM proposals WHERE id=?1",
        [proposal],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ))?;
    if commit != m.head || local_base != *base || local_state != "local_queued" {
        return Err("receipt_proposal_mismatch".into());
    }
    let exported:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM sync_exports WHERE json_extract(manifest,'$.kind')='proposal' AND json_extract(manifest,'$.proposal')=?1)",[proposal],|row|row.get(0)))?;
    if !exported {
        return Err("receipt_proposal_not_exported".into());
    }
    let existing: Option<(i64, String, String)> = sql(db
        .query_row(
            "SELECT revision,digest,receipt FROM sync_remote_status WHERE proposal=?1",
            [proposal],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional())?;
    if let Some((revision, old_digest, old)) = existing {
        if receipt.revision < revision as u64 {
            return Err("stale_receipt".into());
        }
        if receipt.revision == revision as u64 && old_digest != md {
            return Err("replay_conflict".into());
        }
        let old: Receipt = serde_json::from_str(&old).map_err(|e| e.to_string())?;
        if terminal(&old.state)
            && (old.state != receipt.state
                || old.integration_head != receipt.integration_head
                || old.evidence != receipt.evidence
                || old.repaired != receipt.repaired)
        {
            return Err("terminal_receipt_regression".into());
        }
    }
    let result = json!({"ok":true,"state":"receipt_recorded","proposal":proposal,"remote_observation":receipt,"files_changed":false,"authenticated":false});
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    sql(db.execute("INSERT INTO sync_remote_status VALUES(?1,?2,?3,?4) ON CONFLICT(proposal) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,receipt=excluded.receipt",params![proposal,receipt.revision as i64,md,serde_json::to_string(receipt).map_err(|e|e.to_string())?]))?;
    sql(db.execute(
        "INSERT INTO sync_imports VALUES(?1,?2,?3,?4)",
        params![m.device, m.operation, md, result.to_string()],
    ))?;
    event(
        db,
        "remote_proposal_observed",
        &json!({"proposal":proposal,"state":receipt.state,"revision":receipt.revision}),
    )?;
    sql(db.execute_batch("COMMIT"))?;
    Ok(result)
}
pub(super) fn observed_status(db: &Connection, proposal: &str) -> R<Option<Value>> {
    if !is_client(db)? {
        return Ok(None);
    }
    schema(db)?;
    let receipt: Option<String> = sql(db
        .query_row(
            "SELECT receipt FROM sync_remote_status WHERE proposal=?1",
            [proposal],
            |row| row.get(0),
        )
        .optional())?;
    receipt
        .map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .transpose()
}
pub(super) fn check_cancel(db: &Connection, proposal: &str) -> R<()> {
    if !is_client(db)? {
        return Ok(());
    }
    schema(db)?;
    let exported:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM sync_exports WHERE json_extract(manifest,'$.kind')='proposal' AND json_extract(manifest,'$.proposal')=?1)",[proposal],|row|row.get(0)))?;
    if exported || observed_status(db, proposal)?.is_some() {
        return Err("remote_cancel_unsupported: exported proposal may already be accepted by authority; local cancellation cannot recall it".into());
    }
    Ok(())
}

/// Local transport authorization lookup; never accepted from a remote request.
pub(super) fn proposal_origin(db: &Connection, proposal: &str) -> R<Option<Value>> {
    if config(db)?.is_none_or(|c| c.role != "authority") {
        return Ok(None);
    }
    let row: Option<(String, String)> = sql(db
        .query_row(
            "SELECT device,source_proposal FROM sync_proposal_origins WHERE proposal=?1",
            [proposal],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    Ok(row.map(|(device, source)| json!({"device":device,"source_proposal":source})))
}

/// Published local proposals only; private checkpoints never enter the transport queue.
pub(super) fn pending(db: &Connection, r: &Value) -> R<Value> {
    if required(db)?.role != "client" {
        return Err("client_required".into());
    }
    schema(db)?;
    let after = r
        .get("after")
        .map_or(Some(0), Value::as_u64)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or("invalid_pending_cursor")?;
    let limit = r
        .get("limit")
        .map_or(Some(128), Value::as_u64)
        .filter(|n| (1..=256).contains(n))
        .ok_or("invalid_pending_limit")?;
    let mut stmt = sql(db.prepare("SELECT p.rowid,p.id FROM proposals p WHERE p.rowid>?1 AND p.state='local_queued' AND NOT EXISTS(SELECT 1 FROM sync_proposal_origins o WHERE o.proposal=p.id) ORDER BY p.rowid LIMIT ?2"))?;
    let mut rows = Vec::new();
    let mut next = after;
    let mut more = false;
    for row in sql(
        stmt.query_map(params![after as i64, (limit + 1) as i64], |row| {
            Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
        }),
    )? {
        let (cursor, id) = sql(row)?;
        if rows.len() == limit as usize {
            more = true;
            break;
        }
        next = cursor;
        rows.push(json!({"proposal":id}));
    }
    Ok(json!({"ok":true,"proposals":rows,"next_cursor":next,"has_more":more}))
}
/// Atomic under the engine lock: polling unchanged heads never creates a new sequence.
pub(super) fn export_current_head(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    if required(db)?.role != "authority" {
        return Err("authority_required".into());
    }
    schema(db)?;
    let head = coordinator(state).head(HEAD)?;
    let exists: bool = sql(db.query_row("SELECT EXISTS(SELECT 1 FROM sync_exports WHERE json_extract(manifest,'$.kind')='head' AND json_extract(manifest,'$.head')=?1)",[&head], |row|row.get(0)))?;
    if exists {
        return Ok(json!({"ok":true,"exported":false,"head":head}));
    }
    let operation = format!("daemon-head-{}", digest(&json!(head)));
    let result = export(
        state,
        db,
        &json!({"op":"sync_export","kind":"head","operation_id":operation,"destination":field(r,"destination")?}),
    )?;
    Ok(json!({"ok":true,"exported":true,"head":head,"export":result}))
}

#[cfg(test)]
mod history_tests {
    use super::*;

    fn history_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);")
            .unwrap();
        db.execute("INSERT INTO meta VALUES('sync_config',?1)", [json!({"project":"p","authority":"a","epoch":1,"device":"a","role":"authority","peers":[]}).to_string()]).unwrap();
        schema(&db).unwrap();
        for n in 1..=300 {
            // Interleaved non-head rows must not become head-sequence cursors.
            for kind in ["receipt", "head"] {
                let manifest = json!({"version":1,"project":"p","authority":"a","epoch":1,"device":"a","operation":format!("{kind}-{n}"),"kind":kind,"head":"abc","base":null,"proposal":null,"intent":null,"envelope": if kind == "head" { json!({"version":1,"project":"p","authority":"a","epoch":1,"device":"a","operation":format!("head-{n}"),"sequence":n,"event":{"kind":"head_advanced","head":"abc"}}) } else { Value::Null },"payload_len":0,"payload_sha256":"abc"});
                db.execute(
                    "INSERT INTO sync_exports VALUES(?1,'digest',?2)",
                    params![format!("{kind}-{n}"), manifest.to_string()],
                )
                .unwrap();
            }
        }
        db
    }
    #[test]
    fn bounded_history_and_exact_lookup() {
        let db = history_db();
        let mut cursor = 0;
        let mut count = 0;
        loop {
            let page = export_history(
                &db,
                &json!({"kind":"head","cursor_kind":"head_sequence","after":cursor,"limit":73}),
            )
            .unwrap();
            let entries = page["exports"].as_array().unwrap();
            assert!(entries.len() <= 73);
            for entry in entries {
                cursor += 1;
                assert_eq!(entry["sequence"], cursor);
                count += 1;
            }
            assert_eq!(page["next_cursor"], cursor);
            if page["has_more"] == false {
                break;
            }
        }
        assert_eq!(count, 300);
        assert_eq!(
            export_lookup(&db, &json!({"operation_id":"head-299"})).unwrap()["exists"],
            true
        );
        assert_eq!(
            export_lookup(&db, &json!({"operation_id":"missing"})).unwrap()["exists"],
            false
        );
        let all = export_history(&db, &json!({})).unwrap();
        assert_eq!(all["exports"].as_array().unwrap().len(), 128);
        assert_eq!(all["cursor_kind"], "export_row");
        assert_eq!(all["next_cursor"], 128);
        let request = json!({"kind":"head","after":72,"limit":73});
        assert_eq!(
            export_history(&db, &request).unwrap(),
            export_history(&db, &request).unwrap()
        );
        assert!(export_history(
            &db,
            &json!({"kind":"head","cursor_kind":"export_row","after":1})
        )
        .is_err());
        for request in [
            json!({"after":-1}),
            json!({"after":"1"}),
            json!({"limit":0}),
            json!({"limit":257}),
            json!({"kind":"head","after":301}),
            json!({"after":601}),
        ] {
            assert!(export_history(&db, &request).is_err());
        }
    }
}
