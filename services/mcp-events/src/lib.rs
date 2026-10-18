//! Optional MCP 2026-07-28 connection; trusted local stdio stays separate.
pub mod auth;
pub mod callback;
pub mod config;
pub mod events;
pub(crate) mod github;
pub mod http;
pub mod source;
use auth::{AuthStore, Principal};
use events::{EventService, ProjectAccess, SanitizedTransition};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
pub const PROTOCOL_VERSION: &str = "2026-07-28";
struct Access {
    auth: Arc<AuthStore>,
    projects: BTreeMap<String, PathBuf>,
}
impl ProjectAccess for Access {
    fn has_project_access(&self, p: &str, project: &str) -> bool {
        self.project_grant_epoch(p, project).is_some()
    }
    fn has_any_project_access(&self, p: &str) -> bool {
        self.projects
            .keys()
            .any(|project| self.has_project_access(p, project))
    }
    fn project_grant_epoch(&self, p: &str, project: &str) -> Option<i64> {
        if !self.projects.contains_key(project) {
            return None;
        }
        self.auth.project_grant_epoch(p, project).ok().flatten()
    }
    fn event_is_current(&self, e: &SanitizedTransition) -> bool {
        if e.name != "action_required" {
            return true;
        }
        let Some(path) = self.projects.get(&e.project) else {
            return false;
        };
        let Ok(s) = source::Source::new(BTreeMap::from([(e.project.clone(), path.clone())])) else {
            return false;
        };
        s.still_relevant(&source::Transition {
            id: e.id.clone(),
            name: e.name.clone(),
            project: e.project.clone(),
            workspace: e.workspace.clone(),
            proposal: e.proposal.clone(),
            occurred_at: e.occurred_at,
            status: e.status.clone(),
        })
    }
}
pub fn project_access(
    auth: Arc<AuthStore>,
    projects: BTreeMap<String, PathBuf>,
) -> Arc<dyn ProjectAccess> {
    Arc::new(Access { auth, projects })
}
pub struct App {
    auth: Arc<AuthStore>,
    events: Arc<EventService>,
    source: Mutex<source::Source>,
}
impl App {
    pub fn new(
        auth: Arc<AuthStore>,
        events: Arc<EventService>,
        projects: BTreeMap<String, PathBuf>,
    ) -> Result<Self, String> {
        Ok(Self {
            auth,
            events,
            source: Mutex::new(source::Source::new(projects)?),
        })
    }
    pub fn poll(&self, now: i64) {
        if now < 0 {
            return;
        }
        let es = match self.source.lock() {
            Ok(mut s) => s.poll(now),
            Err(_) => return,
        };
        for e in es {
            self.events.ingest(
                SanitizedTransition {
                    id: e.id,
                    name: e.name,
                    project: e.project,
                    workspace: e.workspace,
                    proposal: e.proposal,
                    occurred_at: e.occurred_at,
                    status: e.status,
                },
                (now as u64).saturating_mul(1000),
            );
        }
    }
    pub async fn deliver(&self, now: i64) {
        if now >= 0 {
            self.events.tick((now as u64).saturating_mul(1000)).await;
        }
    }
    pub async fn tick(&self, now: i64) {
        self.poll(now);
        self.deliver(now).await;
    }
    pub async fn rpc(&self, p: &Principal, request: Value, now: i64) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        if !request.is_object()
            || request["jsonrpc"] != "2.0"
            || !request["method"].is_string()
            || !(id.is_null() || id.is_string() || id.is_i64() || id.is_u64())
        {
            return rpc_error(id, -32600, "Invalid request");
        }
        if !request.as_object().is_some_and(|o| o.contains_key("id")) {
            return Value::Null;
        }
        if now < 0 {
            return rpc_error(id, -32603, "Clock unavailable");
        }
        let owner = p.owner_id();
        if !self.auth.has_any_project_access(&owner).unwrap_or(false) {
            return rpc_error(id, -32001, "Access denied");
        }
        let method = request["method"].as_str().unwrap_or_default();
        let params = request.get("params").cloned().unwrap_or(json!({}));
        if !params.is_object() {
            return rpc_error(id, -32602, "Invalid parameters");
        }
        let result = match method {
            "server/discover" => Ok(
                json!({"resultType":"complete","supportedVersions":[PROTOCOL_VERSION],"serverInfo":{"name":"wipstash-mcp-events","version":env!("CARGO_PKG_VERSION")},"capabilities":{"tools":{},"events":{}},"instructions":"Read-only status and best-effort alerts. Recheck current status before acting. Receipt never authorizes adoption, publication, integration or workspace edits."}),
            ),
            "tools/list" => Ok(json!({"resultType":"complete","tools":[status_tool()]})),
            "tools/call" => self.tool(p, &params),
            "events/list" | "events/subscribe" | "events/unsubscribe" => {
                if method != "events/list" {
                    let project = params["arguments"]["project_id"]
                        .as_str()
                        .unwrap_or_default();
                    if !p.projects.iter().any(|s| s == project) {
                        return rpc_error(id, -32001, "Access denied");
                    }
                }
                match self
                    .events
                    .rpc(&owner, method, params, (now as u64).saturating_mul(1000))
                    .await
                {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        let mut error = rpc_error(id, e.code, e.message);
                        if let Some(reason) = e.reason {
                            error["error"]["data"] = json!({"reason":reason});
                        }
                        return error;
                    }
                }
            }
            _ => return rpc_error(id, -32601, "Method not found"),
        };
        match result {
            Ok(v) => json!({"jsonrpc":"2.0","id":id,"result":v}),
            Err(message) => rpc_error(id, -32602, &message),
        }
    }
    fn tool(&self, p: &Principal, params: &Value) -> Result<Value, String> {
        if params["name"] != "wipstash_status"
            || params.as_object().is_some_and(|o| {
                o.keys()
                    .any(|k| !["name", "arguments", "_meta"].contains(&k.as_str()))
            })
        {
            return Err("Unknown tool or invalid parameters".into());
        }
        let a = params["arguments"].as_object().ok_or("Invalid arguments")?;
        if a.keys()
            .any(|k| !["project_id", "workspace_id", "proposal_id"].contains(&k.as_str()))
        {
            return Err("Invalid arguments".into());
        }
        let project = a
            .get("project_id")
            .and_then(Value::as_str)
            .ok_or("project_id required")?;
        if !p.projects.iter().any(|s| s == project)
            || !self
                .auth
                .has_project_access(p.github_user_id, project)
                .unwrap_or(false)
        {
            return Err("Access denied".into());
        }
        let workspace = optional_string(a.get("workspace_id"))?;
        let proposal = optional_string(a.get("proposal_id"))?;
        if workspace.is_some() && proposal.is_some() {
            return Err("Choose one filter".into());
        }
        let source = self.source.lock().map_err(|_| "Source unavailable")?;
        let mut result = source.status(project, workspace, proposal)?;
        result["delivery"] = json!({"degraded":self.events.health()["degraded"],"possible_restart_gap":self.events.health()["possible_restart_gap"],"source_degraded":source.degraded,"best_effort":true,"buffer_seconds":300,"historical_replay":false,"restart_may_lose_buffer":true});
        Ok(
            json!({"resultType":"complete","content":[{"type":"text","text":result.to_string()}],"structuredContent":result,"isError":false}),
        )
    }
}
fn optional_string(v: Option<&Value>) -> Result<Option<&str>, String> {
    match v {
        None => Ok(None),
        Some(v) => v.as_str().map(Some).ok_or("Invalid filter".into()),
    }
}
fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn status_tool() -> Value {
    json!({"name":"wipstash_status","description":"Recheck sanitized current proposal status for a permitted project. No source, paths, diffs, private WIP or raw check logs. Alerts are past observations; recheck before any separately authorized action.","inputSchema":{"type":"object","properties":{"project_id":{"type":"string"},"workspace_id":{"type":"string"},"proposal_id":{"type":"string"}},"required":["project_id"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}})
}
#[cfg(test)]
mod tests {
    use super::*;
    use auth::{AuthConfig, GithubUserId, RegisteredClient};
    use callback::{CallbackError, CallbackFuture, CallbackRequest, CallbackTransport};
    struct NoNetwork;
    impl CallbackTransport for NoNetwork {
        fn post(&self, _: CallbackRequest) -> CallbackFuture<'_> {
            Box::pin(async { Err(CallbackError::Connect) })
        }
    }
    fn app() -> (App, Arc<AuthStore>, Principal, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        std::fs::File::create(d.path().join("state.lock")).unwrap();
        let c = rusqlite::Connection::open(d.path().join("state.sqlite")).unwrap();
        c.execute_batch("CREATE TABLE events(seq INTEGER PRIMARY KEY,kind TEXT,data TEXT); CREATE TABLE proposals(id TEXT,workspace TEXT,state TEXT); INSERT INTO proposals VALUES('p1','w1','quarantined');").unwrap();
        let u = GithubUserId::new(123).unwrap();
        let auth = Arc::new(
            AuthStore::in_memory(AuthConfig {
                issuer: "https://service.example".into(),
                resource: "https://service.example/mcp".into(),
                clients: vec![RegisteredClient {
                    client_id: "https://chatgpt.com/oauth/client.json".into(),
                    name: "ChatGPT".into(),
                    redirect_uris: vec!["https://chatgpt.com/oauth/callback".into()],
                }],
                administrators: Default::default(),
            })
            .unwrap(),
        );
        auth.grant_project_local(u, "project1", 1000).unwrap();
        let projects = BTreeMap::from([("project1".into(), d.path().to_path_buf())]);
        let ed = d.path().canonicalize().unwrap().join("private-events");
        wipstash_transport::pairing_files::ensure_private_dir(&ed).unwrap();
        let events = Arc::new(
            EventService::open(
                ed.join("events.sqlite"),
                project_access(auth.clone(), projects.clone()),
                Arc::new(NoNetwork),
                10,
            )
            .unwrap(),
        );
        let p = Principal {
            github_user_id: u,
            client_id: "https://chatgpt.com/oauth/client.json".into(),
            resource: "https://service.example/mcp".into(),
            projects: vec!["project1".into()],
        };
        (
            App::new(auth.clone(), events, projects).unwrap(),
            auth,
            p,
            d,
        )
    }
    #[tokio::test]
    async fn only_read_status_tool_exists_and_engine_mutations_are_rejected() {
        let (a, _, p, _d) = app();
        let v = a
            .rpc(
                &p,
                json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
                1000,
            )
            .await;
        assert_eq!(v["result"]["tools"].as_array().unwrap().len(), 1);
        for m in ["publish", "integrate", "adopt", "command_run", "initialize"] {
            let v = a
                .rpc(&p, json!({"jsonrpc":"2.0","id":2,"method":m}), 1000)
                .await;
            assert_eq!(v["error"]["code"], -32601);
            assert!(a.rpc(&p,json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":m,"arguments":{"project_id":"project1"}}}),1000).await["error"].is_object());
        }
    }
    #[tokio::test]
    async fn status_cross_project_and_revocation_fail_closed() {
        let (a, auth, p, _d) = app();
        let r = |project: &str| json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wipstash_status","arguments":{"project_id":project}}});
        assert!(a.rpc(&p, r("project1"), 1000).await["result"].is_object());
        assert!(a.rpc(&p, r("other"), 1000).await["error"].is_object());
        auth.revoke_project_local(p.github_user_id, "project1", 1001)
            .unwrap();
        assert!(a.rpc(&p, r("project1"), 1001).await["error"].is_object());
    }
    #[tokio::test]
    async fn discover_pins_version_and_notifications_do_not_mutate() {
        let (a, _, p, _d) = app();
        assert_eq!(
            a.rpc(
                &p,
                json!({"jsonrpc":"2.0","id":1,"method":"server/discover"}),
                1000
            )
            .await["result"]["supportedVersions"],
            json!(["2026-07-28"])
        );
        assert_eq!(
            a.rpc(
                &p,
                json!({"jsonrpc":"2.0","method":"events/subscribe","params":{}}),
                1000
            )
            .await,
            Value::Null
        );
    }
    #[tokio::test]
    async fn callback_failure_preserves_openai_error_reason() {
        use base64::Engine;
        let (a, _, p, _d) = app();
        let secret = format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode([7u8; 32])
        );
        let v=a.rpc(&p,json!({"jsonrpc":"2.0","id":1,"method":"events/subscribe","params":{"name":"action_required","arguments":{"project_id":"project1"},"delivery":{"mode":"webhook","url":"https://callback.example/events","secret":secret}}}),1000).await;
        assert_eq!(v["error"]["code"], -32015);
        assert_eq!(v["error"]["data"]["reason"], "connect_failed");
    }
}

#[cfg(test)]
mod auth_pressure_tests;
