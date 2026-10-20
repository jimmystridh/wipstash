use super::{
    context::{self, Context, Repository},
    fail, id, Result,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use wipstash_transport::{daemon::Worker, settings::ClientConfig, Workstation};

pub async fn native(values: &[String]) -> Result<Value> {
    if values.first().map(String::as_str) == Some("serve") {
        wipstash_transport::pairing_cli::run(values)
            .await
            .map_err(fail)?;
        return Ok(json!({"ok":true,"state":"stopped"}));
    }
    let mut arguments = values.to_vec();
    if arguments
        .first()
        .is_some_and(|s| matches!(s.as_str(), "setup" | "join"))
        && !arguments.iter().any(|s| s == "--engine")
    {
        arguments.extend([
            "--engine".into(),
            std::env::current_exe()
                .map_err(fail)?
                .to_str()
                .ok_or("unsupported_path")?
                .into(),
        ]);
    }
    let output = tokio::process::Command::new(std::env::current_exe().map_err(fail)?)
        .arg("--pairing")
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .output()
        .await
        .map_err(fail)?;
    Ok(
        json!({"ok":output.status.success(),"operator_output":String::from_utf8_lossy(&output.stdout),"error":if output.status.success(){Value::Null}else{json!({"code":"native_operator_failed","message":String::from_utf8_lossy(&output.stderr)})}}),
    )
}

fn name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid_profile_name".into());
    }
    Ok(())
}
fn profile_path(profile: &str) -> Result<PathBuf> {
    name(profile)?;
    Ok(context::config_home()?
        .join("profiles")
        .join(format!("{profile}.json")))
}

pub fn add(profile: &str, source: &Path, default: bool) -> Result<Value> {
    let mut value = context::read_json(source)?;
    let _: ClientConfig = serde_json::from_value(value.clone()).map_err(fail)?;
    let path = profile_path(profile)?;
    if path.exists() {
        return Err(
            "profile_exists: use a fresh profile name; existing bindings are preserved".into(),
        );
    }
    value["engine"] = json!(std::env::current_exe().map_err(fail)?);
    context::write_json(&path, &value)?;
    if default {
        context::write_json(
            &context::config_home()?.join("default.json"),
            &json!({"profile":profile}),
        )?;
    }
    Ok(
        json!({"ok":true,"profile":profile,"endpoint":value["https_endpoint"],"device":value["device"],"default":default}),
    )
}
pub fn list() -> Result<Value> {
    let directory = context::config_home()?.join("profiles");
    let mut profiles = Vec::new();
    if directory.exists() {
        for entry in fs::read_dir(directory).map_err(fail)? {
            let path = entry.map_err(fail)?.path();
            if path.extension().is_some_and(|s| s == "json") {
                let value = context::read_json(&path)?;
                profiles.push(json!({"name":path.file_stem().and_then(|s|s.to_str()),"endpoint":value["https_endpoint"],"device":value["device"],"state":value["state"]}));
            }
        }
    }
    profiles.sort_by_key(|v| v["name"].as_str().unwrap_or("").to_owned());
    Ok(json!({"ok":true,"profiles":profiles}))
}
pub fn select(source: &str, explicit: Option<&str>) -> Result<String> {
    if let Some(profile) = explicit {
        let value = context::read_json(&profile_path(profile)?)?;
        if source.starts_with("https://") && value["https_endpoint"] != source {
            return Err("profile_endpoint_mismatch".into());
        }
        return Ok(profile.into());
    }
    if !source.contains("://") && profile_path(source)?.exists() {
        return Ok(source.into());
    }
    let default = context::config_home()?.join("default.json");
    if default.exists() {
        let value = context::read_json(&default)?;
        if let Some(profile) = value["profile"].as_str() {
            let config = context::read_json(&profile_path(profile)?)?;
            if config["https_endpoint"] == source {
                return Ok(profile.into());
            }
        }
    }
    let candidates = list()?["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["endpoint"] == source)
        .filter_map(|v| v["name"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if candidates.len() == 1 {
        return Ok(candidates[0].clone());
    }
    Err("credentials_required: import a private device profile with wip remote add NAME --config FILE, then clone with --profile NAME".into())
}

pub fn workstation(profile: &str) -> Result<Workstation> {
    let mut value = context::read_json(&profile_path(profile)?)?;
    value["engine"] = json!(std::env::current_exe().map_err(fail)?);
    let config: ClientConfig = serde_json::from_value(value).map_err(fail)?;
    config.connect().map_err(fail)
}
pub async fn refresh(context: &Context) -> Result<Value> {
    let Some(profile) = &context.repo.profile else {
        return Ok(json!({"ok":true,"remote":false}));
    };
    let workstation = workstation(profile)?;
    if workstation.state != context.repo.state {
        return Err("profile_state_mismatch".into());
    }
    tokio::time::timeout(Duration::from_secs(120), async {
        let history = workstation.catch_up().await.map_err(fail)?;
        let coordination = workstation.flush_coordination().await.map_err(fail)?;
        Ok(json!({"ok":true,"history":history,"coordination":coordination}))
    })
    .await
    .map_err(|_| "remote_timeout: inspect retained operations before retrying".to_owned())?
}
pub async fn sync(context: &Context) -> Result<Value> {
    let Some(profile) = &context.repo.profile else {
        return Ok(context::raw(
            &context.repo.state,
            json!({"op":"integrate","max_proposals":32}),
        ));
    };
    let workstation = workstation(profile)?;
    if workstation.state != context.repo.state {
        return Err("profile_state_mismatch".into());
    }
    tokio::time::timeout(Duration::from_secs(180), async {
        let mut worker = Worker::open(
            workstation.engine.clone(),
            workstation.state.clone(),
            workstation,
        )
        .await
        .map_err(fail)?;
        let mut result = worker.once().await.map_err(fail)?;
        result["pending"] = json!(
            result["failures"].as_u64().unwrap_or(0) > 0
                || result["audit"]["pending"].as_u64().unwrap_or(0) > 0
                || result["coordination"]["pending"] == true
        );
        Ok(result)
    })
    .await
    .map_err(|_| "remote_timeout: pending operations and exact retry IDs are retained".to_owned())?
}

pub async fn clone(source: &str, target: &Path, explicit: Option<&str>) -> Result<Value> {
    let root = context::absolute(target)?;
    if root.exists() && fs::read_dir(&root).map_err(fail)?.next().is_some() {
        return Err("clone_destination_not_empty".into());
    }
    let (state, profile) = if Path::new(source).exists() {
        let origin = Context::discover(Path::new(source))?;
        (origin.repo.state.clone(), origin.repo.profile.clone())
    } else {
        let profile = select(source, explicit)?;
        let station = workstation(&profile)?;
        let binding = super::execute(
            &station.state,
            json!({"op":"sync_configure","project":station.project,"authority":station.authority,"epoch":station.epoch,"device":station.device,"role":"client","peers":[station.authority_device]}),
        );
        if binding["ok"] != true {
            return Ok(binding);
        }
        station.catch_up().await.map_err(fail)?;
        (station.state, Some(profile))
    };
    let workspace = id("workspace");
    let request =
        json!({"op":"clone","workspace":workspace,"path":root,"operation_id":id("clone")});
    context::write_json(
        &state.join("cli-operations").join(format!(
            "{}.json",
            request["operation_id"].as_str().unwrap()
        )),
        &request,
    )?;
    let result = super::execute(&state, request);
    if result["ok"] != true {
        return Ok(result);
    }
    Context::install(Repository {
        version: 1,
        root,
        state,
        workspace,
        profile,
    })
}
