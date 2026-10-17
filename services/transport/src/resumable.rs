//! Durable, authenticated transfer staging. Chunk acknowledgements only attest to
//! durable transport storage, never source acceptance. No automatic expiration:
//! operators must preserve this root (and its quota) across service restarts.
use crate::{error, fingerprint, Artifact, Result, MANIFEST_MAX, PAYLOAD_MAX};
#[cfg(not(windows))]
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(not(windows))]
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

#[cfg(any(windows, test))]
mod sqlite;
#[cfg(windows)]
mod windows_path;
#[cfg(windows)]
pub use sqlite::Store;

/// Windows keeps its database in the existing trusted staging directory.
pub fn storage_root(staging: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        staging.to_path_buf()
    }
    #[cfg(not(windows))]
    {
        staging.join("resumable")
    }
}

pub const CHUNK_MAX: usize = 256 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub certificate: String,
    pub device: String,
    pub project: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub transfer_id: String,
    pub committed_offset: u64,
    pub payload_len: u64,
    pub payload_sha256: String,
    /// Only populated after the trusted core has successfully imported the artifact.
    pub import_result: Option<Value>,
    pub retention: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    offset: u64,
    len: u64,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    binding: Binding,
    manifest: Vec<u8>,
    status: Status,
    chunks: Vec<Chunk>,
}
#[cfg(not(windows))]
pub struct Store {
    root: PathBuf,
}
/// Derive the opaque identifier without mutating storage, for retry-aware admission.
pub fn transfer_id(binding: &Binding, manifest: &[u8]) -> Result<String> {
    Ok(fingerprint(&serde_json::to_vec(&(1, binding, manifest))?))
}
#[cfg(not(windows))]
impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        check_ancestors(root)?;
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        sync_dir(root)?;
        if let Some(parent) = root.parent() {
            sync_dir(parent)?;
        }
        Ok(Self {
            root: fs::canonicalize(root)?,
        })
    }
    fn lock(&self) -> Result<File> {
        check_ancestors(&self.root.join("lock"))?;
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join("lock"))?;
        f.lock_exclusive()?;
        Ok(f)
    }
    fn dir(&self, id: &str) -> Result<PathBuf> {
        if id.len() != 64
            || !id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(error("transfer_id"));
        }
        let dir = self.root.join(id);
        check_ancestors(&dir)?;
        Ok(dir)
    }
    fn read(&self, binding: &Binding, id: &str) -> Result<Record> {
        let dir = self.dir(id)?;
        check_ancestors(&dir.join("record.json"))?;
        let file = File::open(dir.join("record.json"))?;
        if file.metadata()?.len() > (MANIFEST_MAX * 8 + 2 * 1024 * 1024) as u64 {
            return Err(error("transfer_record_bound"));
        }
        let bound = (MANIFEST_MAX * 8 + 2 * 1024 * 1024) as u64;
        let mut bytes = Vec::new();
        file.take(bound + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > bound {
            return Err(error("transfer_record_bound"));
        }
        let record: Record = serde_json::from_slice(&bytes)?;
        if record.version != 1 || record.binding != *binding || record.status.transfer_id != id {
            return Err(error("transfer_binding"));
        }
        let manifest: Value = serde_json::from_slice(&record.manifest)?;
        if record.manifest.len() > MANIFEST_MAX
            || fingerprint(&serde_json::to_vec(&(1, binding, &record.manifest))?) != id
            || record.status.committed_offset > record.status.payload_len
            || record.status.payload_len > PAYLOAD_MAX as u64
            || manifest["payload_len"].as_u64() != Some(record.status.payload_len)
            || manifest["payload_sha256"].as_str() != Some(&record.status.payload_sha256)
        {
            return Err(error("transfer_record"));
        }
        Ok(record)
    }
    fn write(&self, dir: &Path, record: &Record) -> Result<()> {
        let mut temp = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer(&mut temp, record)?;
        temp.as_file().sync_all()?;
        temp.persist(dir.join("record.json"))?;
        sync_dir(dir)?;
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
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(error("artifact_identity"));
        }
        let id = transfer_id(binding, manifest)?;
        let _lock = self.lock()?;
        let dir = self.dir(&id)?;
        if dir.exists() {
            let existing = self.read(binding, &id)?;
            if existing.manifest != manifest {
                return Err(error("transfer_manifest_changed"));
            }
            if existing.status.import_result.is_some() {
                self.cleanup_payload(&id)?;
            }
            return Ok(existing.status);
        }
        let record = Record {
            version: 1,
            binding: binding.clone(),
            manifest: manifest.to_vec(),
            chunks: Vec::new(),
            status: Status {
                transfer_id: id,
                committed_offset: 0,
                payload_len: length,
                payload_sha256: digest.into(),
                import_result: None,
                retention: "durable_until_explicit_operator_cleanup_no_automatic_expiry".into(),
            },
        };
        let tmp = tempfile::Builder::new()
            .prefix("init-")
            .tempdir_in(&self.root)?;
        File::create(tmp.path().join("payload"))?.sync_all()?;
        self.write(tmp.path(), &record)?;
        fs::rename(tmp.path(), &dir)?;
        sync_dir(&self.root)?;
        Ok(record.status)
    }
    /// Revalidate retained authority identity before exposing any cached status or
    /// accepting chunks. A staging directory may outlive an authority epoch.
    pub fn validate_authority(
        &self,
        binding: &Binding,
        id: &str,
        authority: &str,
        epoch: u64,
    ) -> Result<()> {
        let _lock = self.lock()?;
        let record = self.read(binding, id)?;
        let manifest: Value = serde_json::from_slice(&record.manifest)?;
        if manifest["authority"].as_str() != Some(authority)
            || manifest["epoch"].as_u64() != Some(epoch)
        {
            return Err(error("artifact_identity"));
        }
        Ok(())
    }
    pub fn status(&self, binding: &Binding, id: &str) -> Result<Status> {
        let _lock = self.lock()?;
        let record = self.read(binding, id)?;
        if record.status.import_result.is_some() {
            self.cleanup_payload(id)?;
        }
        Ok(record.status)
    }
    pub fn chunk(&self, binding: &Binding, id: &str, offset: u64, bytes: &[u8]) -> Result<Status> {
        if bytes.is_empty() || bytes.len() > CHUNK_MAX {
            return Err(error("chunk_bound"));
        }
        let _lock = self.lock()?;
        let mut record = self.read(binding, id)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| error("chunk_bound"))?;
        if end > record.status.payload_len || offset > record.status.committed_offset {
            return Err(error("chunk_offset"));
        }
        let dir = self.dir(id)?;
        if record.status.import_result.is_some() {
            if record.chunks.iter().any(|c| {
                c.offset == offset && c.len == bytes.len() as u64 && c.sha256 == fingerprint(bytes)
            }) {
                return Ok(record.status);
            }
            return Err(error("chunk_changed"));
        }
        check_ancestors(&dir.join("payload"))?;
        let mut payload = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("payload"))?;
        if payload.metadata()?.len() < record.status.committed_offset {
            return Err(error("transfer_corrupt"));
        }
        if offset < record.status.committed_offset {
            if end > record.status.committed_offset {
                return Err(error("chunk_overlap"));
            }
            payload.seek(SeekFrom::Start(offset))?;
            let mut prior = vec![0; bytes.len()];
            payload.read_exact(&mut prior)?;
            if prior != bytes {
                return Err(error("chunk_changed"));
            }
            return Ok(record.status);
        }
        if record.status.import_result.is_some() {
            return Err(error("transfer_complete"));
        }
        // Preserve enough receipt slots to finish with maximum-sized chunks;
        // tiny chunks cannot consume the journal budget and strand durable data.
        let remaining_chunks = (record.status.payload_len - end).div_ceil(CHUNK_MAX as u64);
        if record.chunks.len() as u64 + 1 + remaining_chunks > 4096 {
            return Err(error("chunk_count_bound"));
        }
        // Any tail beyond the durable journal offset was never acknowledged.
        payload.set_len(offset)?;
        payload.seek(SeekFrom::Start(offset))?;
        payload.write_all(bytes)?;
        payload.sync_all()?;
        record.status.committed_offset = end;
        record.chunks.push(Chunk {
            offset,
            len: bytes.len() as u64,
            sha256: fingerprint(bytes),
        });
        self.write(&dir, &record)?;
        Ok(record.status)
    }
    pub fn artifact(&self, binding: &Binding, id: &str) -> Result<Artifact> {
        let _lock = self.lock()?;
        let record = self.read(binding, id)?;
        if record.status.committed_offset != record.status.payload_len {
            return Err(error("transfer_incomplete"));
        }
        let path = self.dir(id)?.join("payload");
        check_ancestors(&path)?;
        let file = File::open(path)?;
        if file.metadata()?.len() != record.status.payload_len {
            return Err(error("transfer_corrupt"));
        }
        let mut objects = Vec::with_capacity(record.status.payload_len as usize);
        file.take(PAYLOAD_MAX as u64 + 1)
            .read_to_end(&mut objects)?;
        let a = Artifact {
            manifest: record.manifest,
            objects,
        };
        a.validate()?;
        Ok(a)
    }
    /// Call only after successful trusted-core sync_import, never after chunk ack.
    /// A crash before this journal write safely retries the core's idempotent import.
    pub fn complete(&self, binding: &Binding, id: &str, import_result: Value) -> Result<Status> {
        if import_result.is_null() {
            return Err(error("transfer_result_null"));
        }
        let _lock = self.lock()?;
        let mut record = self.read(binding, id)?;
        if record.status.committed_offset != record.status.payload_len {
            return Err(error("transfer_incomplete"));
        }
        if let Some(prior) = &record.status.import_result {
            if prior != &import_result {
                return Err(error("transfer_result_changed"));
            }
            self.cleanup_payload(id)?;
            return Ok(record.status);
        }
        if serde_json::to_vec(&import_result)?.len() > 1024 * 1024 {
            return Err(error("transfer_result_bound"));
        }
        record.status.import_result = Some(import_result);
        self.write(&self.dir(id)?, &record)?;
        self.cleanup_payload(id)?;
        Ok(record.status)
    }
    fn cleanup_payload(&self, id: &str) -> Result<()> {
        let dir = self.dir(id)?;
        match fs::remove_file(dir.join("payload")) {
            Ok(()) => sync_dir(&dir)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}

/// Resumable client adapter. Request bodies/IDs remain identical across lost-ack
/// retries; an incomplete transfer never yields a successful import result.
pub async fn upload<F, Fut>(artifact: &Artifact, mut request: F) -> Result<Status>
where
    F: FnMut(String, String, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(String, Vec<u8>)>>,
{
    artifact.validate()?;
    async fn call<F, Fut>(request: &mut F, method: &str, path: &str, body: &[u8]) -> Result<Status>
    where
        F: FnMut(String, String, Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Result<(String, Vec<u8>)>>,
    {
        let bytes = crate::retry_request(|| {
            let response = request(method.into(), path.into(), body.to_vec());
            async move {
                let (_, bytes) = response.await?;
                Ok(bytes)
            }
        })
        .await?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(error("transfer_response_bound"));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    let mut status = call(&mut request, "POST", "/v1/transfers", &artifact.manifest).await?;
    let id = status.transfer_id.clone();
    let digest = fingerprint(&artifact.objects);
    let check = |status: &Status| -> Result<()> {
        if status.transfer_id != id
            || id.len() != 64
            || !id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || status.payload_len != artifact.objects.len() as u64
            || status.payload_sha256 != digest
            || status.committed_offset > status.payload_len
            || (status.import_result.is_some() && status.committed_offset != status.payload_len)
        {
            return Err(error("transfer_response_mismatch"));
        }
        Ok(())
    };
    check(&status)?;
    if status.import_result.is_some() {
        return Ok(status);
    }
    let path = format!("/v1/transfers/{id}");
    while status.committed_offset < status.payload_len {
        let offset = status.committed_offset as usize;
        let end = (offset + CHUNK_MAX).min(artifact.objects.len());
        status = call(
            &mut request,
            "PUT",
            &format!("{path}/{offset}"),
            &artifact.objects[offset..end],
        )
        .await?;
        check(&status)?;
        if status.committed_offset != end as u64 {
            return Err(error("transfer_offset_mismatch"));
        }
    }
    status = call(&mut request, "POST", &format!("{path}/finish"), b"").await?;
    check(&status)?;
    if status.import_result.is_none() {
        return Err(error("transfer_not_imported"));
    }
    Ok(status)
}

// Reject symlinks, including configured ancestors. This does not claim protection
// against malicious same-account processes racing filesystem replacement.
#[cfg(not(windows))]
fn check_ancestors(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(error("absolute_transfer_root_required"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        ) {
            return Err(error("transfer_path"));
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(m) if m.file_type().is_symlink() || (!m.is_file() && !m.is_dir()) => {
                return Err(error("transfer_symlink"))
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
#[cfg(all(not(unix), not(windows)))]
fn sync_dir(_path: &Path) -> Result<()> {
    Err(error("resumable_directory_durability_unsupported"))
}
/// Distinguishes an absent transfer from corruption, permissions, and I/O errors.
pub fn is_missing(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

// SQLite updates may rewrite the retained BLOB and its rollback journal. Charge
// full payload capacity, not only the arriving chunk. Physical high-water files
// remain counted by the shared storage scanner after logical payload deletion.
pub(crate) fn append_admission(status: &Status, incoming: usize) -> u64 {
    #[cfg(windows)]
    {
        status.payload_len + RECORD_BOUND as u64 + incoming as u64
    }
    #[cfg(not(windows))]
    {
        let _ = status;
        incoming as u64 + 512 * 1024
    }
}
#[cfg(any(windows, test))]
const RECORD_BOUND: usize = MANIFEST_MAX * 8 + 2 * 1024 * 1024;

pub(crate) fn needs_bootstrap(root: &Path) -> bool {
    #[cfg(windows)]
    {
        matches!(fs::symlink_metadata(root.join("resumable-v1.sqlite3")), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    }
    #[cfg(not(windows))]
    {
        !root.exists()
    }
}

#[cfg(windows)]
pub(crate) fn validate_storage_root(root: &Path) -> Result<()> {
    windows_path::check(root)
}
