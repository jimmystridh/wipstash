use super::{fail, id, Result};
use crate::{engine, git::Git};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub version: u32,
    pub root: PathBuf,
    pub state: PathBuf,
    pub workspace: String,
    pub profile: Option<String>,
}

pub struct Context {
    pub repo: Repository,
    _lock: File,
}

pub fn data_home() -> Result<PathBuf> {
    let path = match std::env::var_os("WIP_DATA_HOME") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .ok_or("home_not_configured")?,
        )
        .join(".local/share/wip"),
    };
    private_dir(&path)?;
    path.canonicalize().map_err(fail)
}

pub fn config_home() -> Result<PathBuf> {
    let path = match std::env::var_os("WIP_CONFIG_HOME") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .ok_or("home_not_configured")?,
        )
        .join(".config/wip"),
    };
    private_dir(&path)?;
    path.canonicalize().map_err(fail)
}

pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(fail)?;
    for ancestor in path.ancestors() {
        if fs::symlink_metadata(ancestor)
            .map_err(fail)?
            .file_type()
            .is_symlink()
        {
            return Err("unsafe_metadata_path: symbolic links are not allowed".into());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(fail)?;
    }
    Ok(())
}

pub fn read_json(path: &Path) -> Result<Value> {
    let meta = fs::symlink_metadata(path).map_err(fail)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 * 1024 {
        return Err("invalid_metadata_file".into());
    }
    serde_json::from_slice(&fs::read(path).map_err(fail)?).map_err(fail)
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().ok_or("invalid_metadata_path")?;
    private_dir(parent)?;
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("invalid_metadata_file".into());
        }
    }
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(fail)?;
    serde_json::to_writer(&mut file, value).map_err(fail)?;
    file.write_all(b"\n").map_err(fail)?;
    file.as_file().sync_all().map_err(fail)?;
    file.persist(path).map_err(fail)?;
    #[cfg(unix)]
    File::open(parent).map_err(fail)?.sync_all().map_err(fail)?;
    Ok(())
}

pub fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(fail)?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("invalid_path".into());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    if normalized.exists() {
        normalized.canonicalize().map_err(fail)
    } else {
        let parent = normalized
            .parent()
            .ok_or("invalid_path")?
            .canonicalize()
            .map_err(fail)?;
        Ok(parent.join(normalized.file_name().ok_or("invalid_path")?))
    }
}

impl Context {
    pub fn discover(directory: &Path) -> Result<Self> {
        let directory = directory.canonicalize().map_err(fail)?;
        for root in directory.ancestors() {
            if root.join(".wip").exists() {
                private_dir(&root.join(".wip"))?;
                let repo: Repository =
                    serde_json::from_value(read_json(&root.join(".wip/repo.json"))?)
                        .map_err(fail)?;
                if repo.version != 1
                    || repo.root != root
                    || !repo.state.is_absolute()
                    || repo.state.starts_with(root)
                    || root.starts_with(&repo.state)
                {
                    return Err("repository_binding_mismatch: restore the originally registered directory path".into());
                }
                let lock = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(root.join(".wip/cli.lock"))
                    .map_err(fail)?;
                lock.try_lock_exclusive()
                    .map_err(|_| "repository_busy: another wip command is running".to_string())?;
                let context = Self { repo, _lock: lock };
                context.workspace()?;
                return Ok(context);
            }
        }
        Err("not_a_wip_repository: run wip init, clone or attach".into())
    }

    pub fn install(repo: Repository) -> Result<Value> {
        if repo.root.join(".wip").exists() {
            return Err("repository_already_configured".into());
        }
        let db = Connection::open(repo.state.join("state.sqlite")).map_err(fail)?;
        let path: String = db
            .query_row(
                "SELECT path FROM workspaces WHERE id=?1",
                [&repo.workspace],
                |r| r.get(0),
            )
            .map_err(fail)?;
        if Path::new(&path) != repo.root {
            return Err("workspace_path_mismatch".into());
        }
        let binding = raw(&repo.state, json!({"op":"sync_status"}));
        if binding["config"]["role"] == "client" && repo.profile.is_none() {
            return Err("remote_profile_required: attach with the imported profile matching this client state".into());
        }
        if let Some(profile) = &repo.profile {
            if super::remote::workstation(profile)?.state != repo.state {
                return Err("profile_state_mismatch".into());
            }
        }
        write_json(&repo.root.join(".wip/repo.json"), &repo)?;
        Ok(
            json!({"ok":true,"workspace":repo.workspace,"path":repo.root,"state":repo.state,"profile":repo.profile}),
        )
    }

    pub fn workspace(&self) -> Result<(u64, String)> {
        let db = Connection::open(self.repo.state.join("state.sqlite")).map_err(fail)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(fail)?;
        let (path, generation, version): (String, u64, String) = db
            .query_row(
                "SELECT w.path,w.generation,COALESCE((SELECT c.commit_oid FROM proposals p JOIN checkpoints c ON c.id=p.checkpoint WHERE p.workspace=w.id ORDER BY c.generation DESC LIMIT 1),CASE WHEN EXISTS(SELECT 1 FROM resolution_sessions WHERE workspace=w.id) OR EXISTS(SELECT 1 FROM conflict_reviews WHERE workspace=w.id) THEN COALESCE(w.checkpoint,w.base) ELSE w.base END) FROM workspaces w WHERE w.id=?1",
                [&self.repo.workspace],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(fail)?;
        if Path::new(&path) != self.repo.root {
            return Err("workspace_path_mismatch".into());
        }
        Ok((generation, self.git().tree(&version)?))
    }
    pub fn git(&self) -> Git {
        Git::open(
            &self
                .repo
                .state
                .join("locals")
                .join(&self.repo.workspace)
                .join("objects.git"),
        )
    }
    pub fn call(&self, value: Value) -> Value {
        super::execute(&self.repo.state, value)
    }
    pub fn mutation(&self, mut value: Value) -> Result<Value> {
        if value
            .get("workspace")
            .is_some_and(|v| v != &json!(self.repo.workspace))
        {
            return Err(
                "workspace_context_mismatch: run the command from the intended clone".into(),
            );
        }
        if value.get("workspace").is_none() {
            value["workspace"] = json!(self.repo.workspace);
        }
        if value.get("operation_id").is_none() {
            value["operation_id"] = json!(id("op"));
        }
        let operation = value["operation_id"]
            .as_str()
            .ok_or("invalid_operation_id")?;
        if operation.len() > 100
            || !operation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("invalid_operation_id".into());
        }
        let path = self
            .repo
            .state
            .join("cli-operations")
            .join(format!("{operation}.json"));
        if path.exists() {
            if read_json(&path)? != value {
                return Err(
                    "idempotency_mismatch: retained request differs; inspect wip operation show"
                        .into(),
                );
            }
        } else {
            write_json(&path, &value)?;
        }
        Ok(self.call(value))
    }
    pub fn generation_request(&self, op: &str) -> Result<Value> {
        Ok(
            json!({"op":op,"workspace":self.repo.workspace,"expected_generation":self.workspace()?.0}),
        )
    }
    pub fn confirmed_operation(&self, operation: &str) -> Result<Option<Value>> {
        let db = Connection::open(self.repo.state.join("state.sqlite")).map_err(fail)?;
        let receipt: Option<Option<String>> = db
            .query_row(
                "SELECT receipt FROM coordination_outbox WHERE id=?1",
                [operation],
                |r| r.get(0),
            )
            .optional()
            .map_err(fail)?;
        receipt
            .flatten()
            .map(|text| {
                let receipt: Value = serde_json::from_str(&text).map_err(fail)?;
                let mut result = crate::vocabulary::response(receipt["result"].clone());
                result["operation_id"] = json!(operation);
                result["authority_receipt_verified"] = json!(true);
                Ok(result)
            })
            .transpose()
    }
    pub fn has_pending_coordination(&self) -> Result<bool> {
        let db = Connection::open(self.repo.state.join("state.sqlite")).map_err(fail)?;
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM coordination_outbox WHERE receipt IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(fail)
    }
    pub fn relative_paths(&self, paths: &[PathBuf], cwd: &Path) -> Result<Vec<String>> {
        paths
            .iter()
            .map(|path| {
                let full = if path.is_absolute() {
                    path.clone()
                } else {
                    cwd.join(path)
                };
                let mut normalized = PathBuf::new();
                for part in full.components() {
                    match part {
                        Component::CurDir => {}
                        Component::ParentDir => {
                            normalized.pop();
                        }
                        other => normalized.push(other.as_os_str()),
                    }
                }
                let rel = normalized
                    .strip_prefix(&self.repo.root)
                    .map_err(|_| "path_outside_repository")?;
                if rel.as_os_str().is_empty() {
                    return Ok(".".into());
                }
                if rel
                    .components()
                    .any(|p| matches!(p,Component::Normal(n) if n.eq_ignore_ascii_case(".wip")))
                {
                    return Err("reserved_metadata_path".into());
                }
                Ok(rel.to_str().ok_or("unsupported_path")?.replace('\\', "/"))
            })
            .collect()
    }
}

pub fn local_init(path: &Path) -> Result<Value> {
    let root = absolute(path)?;
    if root.join(".wip").exists() {
        return Err("repository_already_configured".into());
    }
    fs::create_dir_all(&root).map_err(fail)?;
    let state = data_home()?.join("repos").join(id("repo"));
    private_dir(&state)?;
    let initialized = super::execute(&state, json!({"op":"init","source":root}));
    if initialized["ok"] != true {
        return Ok(initialized);
    }
    let workspace = id("workspace");
    let opened = super::execute(
        &state,
        json!({"op":"clone","workspace":workspace,"path":root,"existing":true,"operation_id":id("init")}),
    );
    if opened["ok"] != true {
        return Ok(opened);
    }
    Context::install(Repository {
        version: 1,
        root,
        state,
        workspace,
        profile: None,
    })
}

pub fn raw(state: &Path, value: Value) -> Value {
    engine::execute(state, value).unwrap_or_else(|e| engine::error_response(&e))
}
