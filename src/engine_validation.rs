use super::*;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

pub(super) fn schema(db: &Connection) -> R<()> {
    sql(db.execute_batch("CREATE TABLE IF NOT EXISTS validation_jobs(
 id TEXT PRIMARY KEY,head TEXT NOT NULL,tree TEXT NOT NULL,proposal TEXT,policy_hash TEXT NOT NULL,
 policy TEXT NOT NULL,state TEXT NOT NULL,queued INTEGER NOT NULL,started INTEGER,finished INTEGER,
 attempt INTEGER NOT NULL DEFAULT 0,token TEXT,evidence TEXT,UNIQUE(head,policy_hash));
 CREATE INDEX IF NOT EXISTS validation_queue ON validation_jobs(state,queued);
 CREATE TABLE IF NOT EXISTS repair_incidents(
 id TEXT PRIMARY KEY,signature TEXT NOT NULL,policy_hash TEXT NOT NULL,check_id TEXT NOT NULL,
 first_job TEXT NOT NULL,last_job TEXT NOT NULL,state TEXT NOT NULL,device TEXT NOT NULL,
 workspace TEXT NOT NULL,source_commit TEXT,expires INTEGER NOT NULL,revision INTEGER NOT NULL,
 acknowledged INTEGER,created INTEGER NOT NULL,closed INTEGER,attribution TEXT NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS one_open_repair ON repair_incidents(signature) WHERE state='open';
 CREATE TABLE IF NOT EXISTS repair_resolutions(incident TEXT PRIMARY KEY,job_id TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS operation_timings(
 seq INTEGER PRIMARY KEY,recorded_at_ms INTEGER NOT NULL,operation TEXT NOT NULL,workspace TEXT,timing TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS repair_declines(incident TEXT NOT NULL,device TEXT NOT NULL,workspace TEXT NOT NULL,until_ms INTEGER NOT NULL,PRIMARY KEY(incident,device,workspace));
"))?;
    let migrated: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='repair_pickup_v1')",
        [],
        |r| r.get(0),
    ))?;
    let initialized: bool = sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='authority')",
        [],
        |r| r.get(0),
    ))?;
    if !migrated && initialized {
        sql(db.execute("UPDATE repair_incidents SET expires=0,revision=revision+1 WHERE state='open' AND acknowledged IS NULL",[]))?;
        sql(db.execute("INSERT INTO meta VALUES('repair_pickup_v1','1')", []))?;
    }
    Ok(())
}

pub(super) fn policy(db: &Connection) -> R<Value> {
    let text: Option<String> = sql(db
        .query_row("SELECT value FROM meta WHERE key='policy'", [], |r| {
            r.get(0)
        })
        .optional())?;
    text.map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .unwrap_or_else(|| Ok(json!({})))
}

pub(super) fn enqueue(state: &Path, db: &Connection, proposal: Option<&str>, head: &str) -> R<()> {
    let policy = policy(db)?;
    crate::policy::validate_policy(&policy)?;
    let hash = digest(&policy);
    let id = format!("validation-{}", digest(&json!([head, hash])));
    if sql(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM validation_jobs WHERE id=?1)",
        [&id],
        |r| r.get::<_, bool>(0),
    ))? {
        return Ok(());
    }
    let tree = coordinator(state).tree(head)?;
    let checks = policy["checks"].as_array().map_or(0, Vec::len);
    let phase = if checks == 0 { "unchecked" } else { "queued" };
    // Only waiting work is coalesced. A running exact-tree check always finishes.
    sql(db.execute(
        "UPDATE validation_jobs SET state='superseded',finished=?1 WHERE state='queued'",
        [now_ms()],
    ))?;
    sql(db.execute("INSERT INTO validation_jobs(id,head,tree,proposal,policy_hash,policy,state,queued) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![id,head,tree,proposal,hash,policy.to_string(),phase,now_ms()]))?;
    event(
        db,
        "validation_queued",
        &json!({"job_id":id,"proposal":proposal,"head":head,"tree":tree,"policy_sha256":hash,"state":phase}),
    )
}

fn job(db: &Connection, id: &str) -> R<Value> {
    sql(db.query_row("SELECT id,head,tree,proposal,policy_hash,state,queued,started,finished,attempt,evidence FROM validation_jobs WHERE id=?1", [id], |r| {
        let raw: Option<String> = r.get(10)?;
        Ok(json!({"job_id":r.get::<_,String>(0)?,"head":r.get::<_,String>(1)?,"candidate_tree":r.get::<_,String>(2)?,
            "proposal":r.get::<_,Option<String>>(3)?,"policy_sha256":r.get::<_,String>(4)?,"job_state":r.get::<_,String>(5)?,
            "queued_at_ms":r.get::<_,i64>(6)?,"started_at_ms":r.get::<_,Option<i64>>(7)?,"finished_at_ms":r.get::<_,Option<i64>>(8)?,
            "attempt":r.get::<_,i64>(9)?,"details":raw.and_then(|s|serde_json::from_str::<Value>(&s).ok())}))
    }))
}

fn describe(mut j: Value) -> Value {
    let phase = j["job_state"].as_str().unwrap_or("");
    let mut validation = match phase {
        "queued" | "running" => {
            json!({"state":"pending","reason":"background_checks","checks_total":0})
        }
        "superseded" => {
            json!({"state":"unchecked","reason":"superseded_before_testing","checks_total":0})
        }
        "unchecked" => {
            json!({"state":"unchecked","reason":"no_configured_checks","checks_total":0})
        }
        _ => feedback::validation(
            Some(&j["details"]),
            "integrated",
            None,
            j["details"]["proposal"].as_str(),
            false,
        ),
    };
    for key in [
        "job_id",
        "head",
        "candidate_tree",
        "policy_sha256",
        "queued_at_ms",
        "started_at_ms",
        "finished_at_ms",
        "attempt",
        "job_state",
    ] {
        validation[key] = j[key].take();
    }
    if let (Some(start), Some(queued)) = (
        validation["started_at_ms"].as_i64(),
        validation["queued_at_ms"].as_i64(),
    ) {
        validation["queue_wait_ms"] = json!((start - queued).max(0));
    }
    if let (Some(end), Some(start)) = (
        validation["finished_at_ms"].as_i64(),
        validation["started_at_ms"].as_i64(),
    ) {
        validation["duration_ms"] = json!((end - start).max(0));
    }
    validation["failure_kind"] = j["details"]["failure_kind"].clone();
    validation["checks"] = json!(j["details"]["checks"].as_array().into_iter().flatten().map(|c|json!({"id":c["id"],"success":c["success"],"duration_ms":c["duration_ms"],"timed_out":c["timed_out"]})).collect::<Vec<_>>());
    validation["semantic_correctness_claimed"] = json!(false);
    validation
}

pub(super) fn for_proposal(db: &Connection, id: &str) -> R<Option<Value>> {
    let id: Option<String> = sql(db.query_row("SELECT j.id FROM validation_jobs j JOIN proposals p ON p.head=j.head WHERE p.id=?1 ORDER BY j.rowid DESC LIMIT 1",[id],|r|r.get(0)).optional())?;
    id.map(|id| job(db, &id).map(describe)).transpose()
}

pub(super) fn remote_proposal(db: &Connection, id: &str) -> R<Option<Value>> {
    let c = cached(db)?;
    let device = coordination::device(db)?;
    Ok(c["commits"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|v| v["origin"]["device"] == device && v["origin"]["source_proposal"] == id)
        })
        .map(|v| {
            let mut evidence = v["validation"].clone();
            evidence["scope"] = json!("authority_observation");
            evidence["remote_cache"] = json!(true);
            evidence["stale"] = c["stale"].clone();
            evidence["fetched_at"] = c["fetched_at"].clone();
            evidence
        }))
}

fn cached(db: &Connection) -> R<Value> {
    let row: Option<(i64, String)> = sql(db
        .query_row(
            "SELECT fetched,data FROM coordination_cache WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    let Some((fetched, raw)) = row else {
        return Ok(
            json!({"repairs":[],"repo_health":{"state":"unknown"},"stale":true,"confirmed":false}),
        );
    };
    let mut v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    v["stale"] = json!(coordination::now().saturating_sub(fetched) > 30);
    v["fetched_at"] = json!(fetched);
    v["remote_cache"] = json!(true);
    v["authority_contact_verified"] = json!(false);
    Ok(v)
}

pub(super) fn health(db: &Connection) -> R<Value> {
    if sync::is_client(db)? {
        let c = cached(db)?;
        let mut health = c["repo_health"].clone();
        if !health.is_object() {
            health = json!({"state":"unknown"});
        }
        for key in [
            "stale",
            "fetched_at",
            "remote_cache",
            "authority_contact_verified",
        ] {
            health[key] = c[key].clone();
        }
        return Ok(health);
    }
    let hash = digest(&policy(db)?);
    // The engine stores the latest shared head when scheduling; no filesystem reads are needed here.
    let head: Option<String> = sql(db
        .query_row(
            "SELECT value FROM meta WHERE key='validation_head'",
            [],
            |r| r.get(0),
        )
        .optional())?;
    let id: Option<String> = sql(db
        .query_row(
            "SELECT id FROM validation_jobs WHERE head=?1 AND policy_hash=?2",
            params![head, hash],
            |r| r.get(0),
        )
        .optional())?;
    let mut health = if let Some(id) = id {
        describe(job(db, &id)?)
    } else {
        json!({"state":"pending","head":head,"reason":"validation_not_scheduled","semantic_correctness_claimed":false})
    };
    let verified:Option<String>=sql(db.query_row("SELECT head FROM validation_jobs WHERE state='passed' AND policy_hash=?1 ORDER BY finished DESC,rowid DESC LIMIT 1",[hash],|r|r.get(0)).optional())?;
    health["last_verified_head"] = json!(verified);
    health["release_ready"] = json!(health["state"] == "passed");
    health["sharing_policy"] = json!("share_then_check");
    let mut q=sql(db.prepare("SELECT id,check_id,device,workspace,source_commit,expires,revision FROM repair_incidents WHERE state='open' ORDER BY rowid LIMIT 17"))?;
    let mut summaries=sql(q.query_map([],|r|Ok(json!({"incident_id":r.get::<_,String>(0)?,"check_id":r.get::<_,String>(1)?,"owner":{"device":r.get::<_,String>(2)?,"workspace":r.get::<_,String>(3)?,"source_commit_id":r.get::<_,Option<String>>(4)?},"expires_at_ms":r.get::<_,i64>(5)?,"revision":r.get::<_,i64>(6)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
    health["repairs_truncated"] = json!(summaries.len() > 16);
    summaries.truncate(16);
    health["repairs"] = json!(summaries);
    Ok(health)
}

pub(super) fn schedule_head(
    state: &Path,
    db: &Connection,
    proposal: Option<&str>,
    head: &str,
) -> R<()> {
    enqueue(state, db, proposal, head)?;
    sql(db.execute("UPDATE repair_incidents SET state='superseded',closed=?2,revision=revision+1 WHERE state='open' AND policy_hash<>?1",params![digest(&policy(db)?),now_ms()]))?;
    sql(db.execute("INSERT INTO meta VALUES('validation_head',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[head]))?;
    Ok(())
}

fn owner(db: &Connection, proposal: &str) -> R<(String, String, String)> {
    if let Some(origin) = sync::proposal_origin(db, proposal)? {
        return Ok((
            field(&origin, "device")?.into(),
            String::new(),
            field(&origin, "source_proposal")?.into(),
        ));
    }
    let workspace: String = sql(db.query_row(
        "SELECT workspace FROM proposals WHERE id=?1",
        [proposal],
        |r| r.get(0),
    ))?;
    Ok((coordination::device(db)?, workspace, proposal.into()))
}

pub(super) fn repairs(db: &Connection, cursor: u64, limit: u64) -> R<Value> {
    if cursor > i64::MAX as u64 || !(1..=32).contains(&limit) {
        return Err("invalid_page".into());
    }
    if sync::is_client(db)? {
        let c = cached(db)?;
        let all = c["repairs"].as_array().cloned().unwrap_or_default();
        let start = (cursor as usize).min(all.len());
        let end = (start + limit as usize).min(all.len());
        return Ok(
            json!({"ok":true,"repairs":&all[start..end],"next_cursor":end,"has_more":end<all.len(),"stale":c["stale"],"fetched_at":c["fetched_at"],"remote_cache":true,"authority_contact_verified":false}),
        );
    }
    server_repairs(db, cursor, limit, false)
}

fn server_repairs(db: &Connection, cursor: u64, limit: u64, active_only: bool) -> R<Value> {
    let mut q=sql(db.prepare("SELECT rowid,id,check_id,state,device,workspace,source_commit,expires,revision,acknowledged,created,closed,attribution,first_job,last_job FROM repair_incidents WHERE rowid>?1 AND (?3=0 OR state='open') ORDER BY rowid LIMIT ?2"))?;
    let rows=sql(q.query_map(params![cursor,limit+1,active_only],|r|Ok(json!({"cursor":r.get::<_,i64>(0)?,"incident_id":r.get::<_,String>(1)?,"check_id":r.get::<_,String>(2)?,"state":r.get::<_,String>(3)?,
        "owner":{"device":r.get::<_,String>(4)?,"workspace":r.get::<_,String>(5)?,"source_commit_id":r.get::<_,Option<String>>(6)?},
        "expires_at_ms":r.get::<_,i64>(7)?,"revision":r.get::<_,i64>(8)?,"acknowledged_at_ms":r.get::<_,Option<i64>>(9)?,"created_at_ms":r.get::<_,i64>(10)?,"closed_at_ms":r.get::<_,Option<i64>>(11)?,"attribution":r.get::<_,String>(12)?,"first_job_id":r.get::<_,String>(13)?,"last_job_id":r.get::<_,String>(14)?}))))?;
    let mut items = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    let more = items.len() > limit as usize;
    items.truncate(limit as usize);
    for item in &mut items {
        let first = job(db, field(item, "first_job_id")?)?;
        item["first_observed_head"] = first["head"].clone();
        item["assignment_policy"] = json!("next_active_caller");
        item["assignment_state"] = json!(if item["owner"]["workspace"] == "" {
            "available"
        } else if item["acknowledged_at_ms"].is_number() {
            "acknowledged"
        } else {
            "offered"
        });
        item["origin"] = json!(first["proposal"]
            .as_str()
            .map(|p| owner(db, p))
            .transpose()?
            .map(|(d, w, p)| json!({"device":d,"workspace":w,"commit_id":p})));
        item["claimable"] = json!(
            item["state"] == "open" && item["expires_at_ms"].as_i64().unwrap_or(0) <= now_ms()
        );
        let last = job(db, field(item, "last_job_id")?)?;
        item["head"] = last["head"].clone();
        item["validation"] = describe(last.clone());
        let check = last["details"]["checks"]
            .as_array()
            .and_then(|a| a.iter().find(|c| c["id"] == item["check_id"]))
            .cloned();
        item["failure"] = json!(check);
        item["repair_elapsed_ms"] = json!(
            item["closed_at_ms"].as_i64().unwrap_or_else(now_ms)
                - item["created_at_ms"].as_i64().unwrap_or(0)
        );
        item["time_to_acknowledgement_ms"] = json!(item["acknowledged_at_ms"]
            .as_i64()
            .map(|ack| ack - item["created_at_ms"].as_i64().unwrap_or(ack)));
        let resolved: Option<String> = sql(db
            .query_row(
                "SELECT job_id FROM repair_resolutions WHERE incident=?1",
                [field(item, "incident_id")?],
                |r| r.get(0),
            )
            .optional())?;
        item["resolved_job_id"] = json!(resolved);
    }
    Ok(
        json!({"ok":true,"next_cursor":items.last().map(|v|&v["cursor"]).cloned().unwrap_or(json!(cursor)),"repairs":items,"has_more":more,"confirmed":true,"server_time_ms":now_ms()}),
    )
}

pub(super) fn export(db: &Connection) -> R<Vec<Value>> {
    let mut all = Vec::new();
    let mut cursor = 0;
    loop {
        let page = server_repairs(db, cursor, 32, true)?;
        all.extend(
            page["repairs"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["state"] == "open")
                .cloned(),
        );
        if all.len() > 256 {
            return Err("repair_export_bound".into());
        }
        if page["has_more"] != true {
            break;
        }
        cursor = page["next_cursor"].as_u64().unwrap();
    }
    Ok(all)
}

pub(super) fn decorate(db: &Connection, r: &Value, v: &mut Value) -> R<()> {
    v["repo_health"] = health(db)?;
    let device = coordination::device(db)?;
    let workspace = r["workspace"].as_str().map(str::to_owned).or_else(|| {
        r["proposal"].as_str().and_then(|p| {
            db.query_row("SELECT workspace FROM proposals WHERE id=?1", [p], |r| {
                r.get::<_, String>(0)
            })
            .ok()
        })
    });
    let Some(workspace) = workspace else {
        return Ok(());
    };
    v["comment_notices"] = coordination::comment_notices(db, &workspace)?;
    v["local_test_scope"] =
        json!("local workspace only; server checks validate the combined shared head");
    let all = if sync::is_client(db)? {
        cached(db)?["repairs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        export(db)?
    };
    let mut notices = Vec::new();
    let context_limit = if r["detail"] == true { 256 } else { 16 };
    v["failure_context_truncated"] = json!(all.len() > context_limit);
    for (index, mut incident) in all.into_iter().enumerate() {
        if incident["state"] == "open" {
            let first_head = incident["first_observed_head"].as_str();
            let observed_head = v["head"]
                .as_str()
                .or_else(|| v["validation"]["head"].as_str());
            let known_before = if let (Some(first), Some(head)) = (first_head, observed_head) {
                first!=head && sql(db.query_row("SELECT EXISTS(SELECT 1 FROM validation_jobs a JOIN validation_jobs b ON b.head=?2 WHERE a.head=?1 AND a.state='failed' AND a.finished<=b.queued AND a.policy_hash=b.policy_hash)",params![first,head],|r|r.get::<_,bool>(0)))?
            } else {
                false
            };
            let context = json!({"incident_id":incident["incident_id"],"check_id":incident["check_id"],"owner":incident["owner"],"first_observed_head":incident["first_observed_head"],"attribution":incident["attribution"],"check_already_failing_before_this_head":known_before,"caused_by_this_commit":"not_established","message":if known_before{"This check was already recorded failing before this head was shared. See the assigned incident; responsibility for causing it is not established."}else{"The combined shared version has an open check incident. Investigation ownership does not establish which change caused it."}});
            if v.get("failure_context").is_none() {
                v["failure_context"] = json!([]);
            }
            if index < context_limit {
                v["failure_context"].as_array_mut().unwrap().push(context);
            }
        }
        if incident["state"] != "open" || incident["owner"]["device"] != device {
            continue;
        }
        let owned = if incident["owner"]["workspace"] == workspace {
            true
        } else if incident["owner"]["workspace"] == "" {
            incident["owner"]["source_commit_id"]
                .as_str()
                .is_some_and(|p| {
                    db.query_row("SELECT workspace FROM proposals WHERE id=?1", [p], |r| {
                        r.get::<_, String>(0)
                    })
                    .is_ok_and(|w| w == workspace)
                })
        } else {
            false
        };
        if !owned || incident["acknowledged_at_ms"].is_number() {
            continue;
        }
        incident["action"] = json!("acknowledge");
        incident["requires_repair_claim"] =
            json!(incident["expires_at_ms"].as_i64().unwrap_or(0) <= now_ms());
        incident["message"]=json!("A background-check repair is offered to this active workspace. Acknowledge within 30 seconds to hold the lease, or release for another agent. Assignment is investigation responsibility, not blame or additional task authorization.");
        if r["detail"] != true {
            incident.as_object_mut().unwrap().retain(|k, _| {
                matches!(
                    k.as_str(),
                    "incident_id"
                        | "check_id"
                        | "owner"
                        | "revision"
                        | "expires_at_ms"
                        | "action"
                        | "requires_repair_claim"
                        | "message"
                        | "first_observed_head"
                        | "head"
                        | "attribution"
                )
            });
        }
        notices.push(incident);
    }
    v["notices"] = json!(notices);
    v["notices_observed_at_ms"] = json!(now_ms());
    Ok(())
}

pub(super) fn pickup(db: &Connection, r: &Value, actor: &str) -> R<Value> {
    let wid = field(r, "workspace")?;
    ident(wid)?;
    let busy:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM repair_incidents WHERE state='open' AND device=?1 AND workspace=?2 AND expires>?3)",params![actor,wid,now_ms()],|r|r.get(0)))?;
    if busy {
        return Ok(
            json!({"ok":true,"confirmed":true,"assigned":false,"reason":"already_assigned"}),
        );
    }
    let candidate:Option<(String,u64)>=sql(db.query_row("SELECT id,revision FROM repair_incidents WHERE state='open' AND expires<=?1 AND policy_hash=?2 AND (?3 IS NULL OR id=?3) AND NOT EXISTS(SELECT 1 FROM repair_declines d WHERE d.incident=repair_incidents.id AND d.device=?4 AND d.workspace=?5 AND d.until_ms>?1) ORDER BY created,rowid LIMIT 1",params![now_ms(),digest(&policy(db)?),r["incident_id"].as_str(),actor,wid],|r|Ok((r.get(0)?,r.get(1)?))).optional())?;
    let Some((id, revision)) = candidate else {
        return Ok(
            json!({"ok":true,"confirmed":true,"assigned":false,"reason":"no_available_repair"}),
        );
    };
    if r.get("expected_revision").is_some_and(|v| *v != revision) {
        return Err("repair_revision_mismatch".into());
    }
    let expires = now_ms() + 30_000;
    let n=sql(db.execute("UPDATE repair_incidents SET device=?2,workspace=?3,expires=?4,acknowledged=NULL,revision=revision+1 WHERE id=?1 AND state='open' AND revision=?5 AND expires<=?6",params![id,actor,wid,expires,revision,now_ms()]))?;
    if n != 1 {
        return Err("repair_revision_mismatch".into());
    }
    event(
        db,
        "repair_offered",
        &json!({"incident_id":id,"device":actor,"workspace":wid,"revision":revision+1,"expires_at_ms":expires,"assignment":"next_active_caller"}),
    )?;
    Ok(
        json!({"ok":true,"confirmed":true,"assigned":true,"incident_id":id,"revision":revision+1,"expires_at_ms":expires,"action":"acknowledge","message":"A repair is offered to this active workspace for 30 seconds. Acknowledge to hold the repair lease, or release to let another agent take it. Assignment grants no additional task authorization."}),
    )
}

pub(super) fn poll(state: &Path, r: &Value) -> R<()> {
    let Some(wid) = r["workspace"].as_str() else {
        return Ok(());
    };
    if r["accept_repairs"] == false
        || !matches!(
            r["op"].as_str(),
            Some(
                "status"
                    | "updates"
                    | "task_list"
                    | "validation_status"
                    | "repair_list"
                    | "task_claim"
                    | "commit"
            )
        )
    {
        return Ok(());
    }
    if r["limit"].as_u64().is_some_and(|n| !(1..=32).contains(&n)) {
        return Ok(());
    }
    if !state.join("state.sqlite").exists() {
        return Ok(());
    }
    let db = sql(Connection::open(state.join("state.sqlite")))?;
    sql(db.busy_timeout(Duration::from_secs(5)))?;
    if !db
        .query_row(
            "SELECT value='2' FROM meta WHERE key='observation_schema'",
            [],
            |r| r.get::<_, bool>(0),
        )
        .unwrap_or(false)
    {
        return Ok(());
    }
    let _lock = observation::coordination_fence(state)?;
    if let Some(id) = r["operation_id"].as_str() {
        let replay: bool = sql(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1)",
            [id],
            |r| r.get(0),
        ))?;
        if replay {
            return Ok(());
        }
    }
    if ws(&db, wid).is_err() || lifecycle::ensure_open(&db, wid).is_err() {
        return Ok(());
    }
    if sync::is_client(&db)? {
        let cache = cached(&db)?;
        if cache["stale"] == true {
            return Ok(());
        }
        let Some(incident) = cache["repairs"].as_array().and_then(|a| {
            a.iter()
                .find(|v| v["state"] == "open" && v["claimable"] == true)
        }) else {
            return Ok(());
        };
        let id = format!(
            "pickup-{}",
            digest(&json!([
                coordination::device(&db)?,
                wid,
                incident["incident_id"],
                incident["revision"]
            ]))
        );
        let request = json!({"op":"repair_pickup","workspace":wid,"incident_id":incident["incident_id"],"expected_revision":incident["revision"],"operation_id":id});
        sql(db.execute(
            "INSERT OR IGNORE INTO coordination_outbox VALUES(?1,?2,NULL)",
            params![id, request.to_string()],
        ))?;
    } else {
        sql(db.execute_batch("BEGIN IMMEDIATE"))?;
        let result = pickup(&db, &json!({"workspace":wid}), &coordination::device(&db)?);
        match result {
            Ok(_) => {
                sql(db.execute_batch("COMMIT"))?;
            }
            Err(e) => {
                let _ = db.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    Ok(())
}

pub(super) fn validate_update(r: &Value) -> R<()> {
    ident(field(r, "workspace")?)?;
    ident(field(r, "operation_id")?)?;
    ident(field(r, "incident_id")?)?;
    if !matches!(
        r["action"].as_str(),
        Some("acknowledge" | "claim" | "renew" | "release")
    ) || r["expected_revision"].as_u64().is_none()
    {
        return Err("invalid_request: repair update requires action and expected_revision".into());
    }
    if !r
        .get("lease_seconds")
        .map_or(Some(300), Value::as_u64)
        .is_some_and(|n| (15..=3600).contains(&n))
    {
        return Err("invalid_request: lease_seconds must be 15 through 3600".into());
    }
    Ok(())
}

pub(super) fn update(db: &Connection, r: &Value, actor: &str) -> R<Value> {
    validate_update(r)?;
    let id = field(r, "incident_id")?;
    let workspace = field(r, "workspace")?;
    let action = field(r, "action")?;
    let (state, device, owned, expiry, revision): (String, String, String, i64, u64) = sql(db
        .query_row(
            "SELECT state,device,workspace,expires,revision FROM repair_incidents WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional())?
    .ok_or("repair_not_found")?;
    if state != "open" {
        return Err("repair_closed: checks already resolved this incident".into());
    }
    if r["expected_revision"] != revision {
        return Err("repair_revision_mismatch".into());
    }
    if action == "claim" {
        if expiry > now_ms() {
            return Err("repair_already_owned: an active repair lease exists".into());
        }
    } else {
        if device != actor || (!owned.is_empty() && owned != workspace) {
            return Err("repair_owner_mismatch".into());
        }
        if expiry <= now_ms() {
            return Err("repair_lease_expired: claim the repair before editing".into());
        }
    }
    let expires = if action == "release" {
        now_ms()
    } else {
        now_ms() + 1000 * r["lease_seconds"].as_i64().unwrap_or(300)
    };
    let acknowledged = if matches!(action, "claim" | "acknowledge") {
        Some(now_ms())
    } else {
        None
    };
    sql(db.execute("UPDATE repair_incidents SET device=?2,workspace=?3,expires=?4,revision=revision+1,acknowledged=CASE WHEN ?5='release' THEN NULL ELSE COALESCE(?6,acknowledged) END WHERE id=?1",params![id,if action=="release"{""}else{actor},if action=="release"{""}else{workspace},expires,action,acknowledged]))?;
    if action == "release" {
        sql(db.execute("INSERT INTO repair_declines VALUES(?1,?2,?3,?4) ON CONFLICT(incident,device,workspace) DO UPDATE SET until_ms=excluded.until_ms",params![id,actor,workspace,now_ms()+60_000]))?;
    }
    event(
        db,
        "repair_updated",
        &json!({"incident_id":id,"workspace":workspace,"device":actor,"action":action,"revision":revision+1,"expires_at_ms":expires}),
    )?;
    Ok(
        json!({"ok":true,"confirmed":true,"incident_id":id,"revision":revision+1,"expires_at_ms":expires,"action":action}),
    )
}

fn claim(state: &Path, db: &Connection) -> R<Value> {
    // Caller holds validation-worker.lock, including across evaluation. Its release
    // after a crash proves no other cooperative validation worker is still running.
    let interrupted = sql(db.execute(
        "UPDATE validation_jobs SET state='queued',token=NULL,queued=?1,started=NULL,finished=NULL WHERE state='running'",
        [now_ms()],
    ))?;
    if interrupted > 0 {
        event(
            db,
            "validation_interrupted",
            &json!({"requeued":interrupted,"delivery":"at_least_once"}),
        )?;
    }
    let head = coordinator(state).head(HEAD)?;
    let proposal:Option<String>=sql(db.query_row("SELECT id FROM proposals WHERE head=?1 AND state IN ('integrated','already_included') ORDER BY rowid LIMIT 1",[&head],|r|r.get(0)).optional())?;
    schedule_head(state, db, proposal.as_deref(), &head)?;
    let id:Option<String>=sql(db.query_row("SELECT id FROM validation_jobs WHERE state='queued' OR (state='failed' AND (json_extract(evidence,'$.failure_kind')='infrastructure' OR EXISTS(SELECT 1 FROM json_each(validation_jobs.evidence,'$.checks') WHERE json_extract(value,'$.reason')='evaluation_budget_exhausted')) AND attempt<3 AND finished<?1 AND head=?2 AND policy_hash=?3) ORDER BY queued DESC,rowid DESC LIMIT 1",params![now_ms()-10_000,head,digest(&policy(db)?)],|r|r.get(0)).optional())?;
    let Some(id) = id else {
        return Ok(json!({"ok":true,"state":"idle"}));
    };
    let token = digest(&json!([id, now_ms(), std::process::id()]));
    sql(db.execute("UPDATE validation_jobs SET queued=CASE WHEN state='failed' THEN finished+10000 ELSE queued END,state='running',started=?2,finished=NULL,attempt=attempt+1,token=?3 WHERE id=?1",params![id,now_ms(),token]))?;
    let mut j = job(db, &id)?;
    j["policy"] = serde_json::from_str(&sql(db.query_row(
        "SELECT policy FROM validation_jobs WHERE id=?1",
        [&id],
        |r| r.get::<_, String>(0),
    ))?)
    .map_err(|e| e.to_string())?;
    j["token"] = json!(token);
    j["ok"] = json!(true);
    event(db, "validation_started", &j)?;
    Ok(j)
}

fn complete(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    let id = field(r, "job_id")?;
    let j = job(db, id)?;
    let token: Option<String> = sql(db.query_row(
        "SELECT token FROM validation_jobs WHERE id=?1",
        [id],
        |r| r.get(0),
    ))?;
    if j["job_state"] != "running" || token.as_deref() != r["token"].as_str() {
        return Err("stale_validation_result".into());
    }
    let d = &r["details"];
    if d["candidate_tree"] != j["candidate_tree"] || d["policy_sha256"] != j["policy_sha256"] {
        return Err("validation_evidence_mismatch".into());
    }
    let outcome = feedback::validation(Some(d), "integrated", None, d["proposal"].as_str(), false);
    let phase = outcome["state"]
        .as_str()
        .ok_or("invalid_validation_outcome")?;
    sql(db.execute_batch("BEGIN IMMEDIATE"))?;
    let result = (|| {
        sql(db.execute(
            "UPDATE validation_jobs SET state=?2,evidence=?3,finished=?4 WHERE id=?1",
            params![id, phase, d.to_string(), now_ms()],
        ))?;
        let current = coordinator(state).head(HEAD)?;
        let current_policy = digest(&policy(db)?);
        let applicable = j["head"] == current && j["policy_sha256"] == current_policy;
        // A delayed green result can never resolve a newer untested/red head.
        if applicable {
            if let Some(checks) = d["checks"].as_array() {
                for c in checks {
                    if c["success"] == true && c["checkout_unchanged"] == true {
                        let mut q=sql(db.prepare("SELECT id FROM repair_incidents WHERE state='open' AND policy_hash=?1 AND check_id=?2"))?;
                        let resolved = sql(q
                            .query_map(params![current_policy, c["id"].as_str()], |r| {
                                r.get::<_, String>(0)
                            }))?
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .map_err(|e| e.to_string())?;
                        sql(db.execute("UPDATE repair_incidents SET state='resolved',closed=?3,revision=revision+1 WHERE state='open' AND policy_hash=?1 AND check_id=?2",params![current_policy,c["id"].as_str(),now_ms()]))?;
                        for incident in resolved {
                            sql(db.execute(
                                "INSERT INTO repair_resolutions VALUES(?1,?2)",
                                params![incident, id],
                            ))?;
                            event(
                                db,
                                "repair_resolved",
                                &json!({"incident_id":incident,"job_id":id,"head":current,"check_id":c["id"]}),
                            )?;
                        }
                    }
                }
            }
        }
        if phase == "failed"
            && d["failure_kind"] != "infrastructure"
            && j["policy_sha256"] == current_policy
        {
            for c in d["checks"].as_array().into_iter().flatten().filter(|c| {
                (c["success"] != true || c["checkout_unchanged"] != true)
                    && c["failure_kind"] != "infrastructure"
            }) {
                let check = field(c, "id")?;
                let signature = digest(&json!([current_policy, check]));
                let existing: Option<String> = sql(db
                    .query_row(
                        "SELECT id FROM repair_incidents WHERE signature=?1 AND state='open'",
                        [&signature],
                        |r| r.get(0),
                    )
                    .optional())?;
                if let Some(existing) = existing {
                    sql(db.execute(
                        "UPDATE repair_incidents SET last_job=?2 WHERE id=?1",
                        params![existing, id],
                    ))?;
                    continue;
                }
                // Do not resurrect a historical failure already fixed by a newer verified head.
                let newer_passed:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM validation_jobs WHERE head=?1 AND policy_hash=?2 AND state='passed')",params![current,current_policy],|r|r.get(0)))?;
                if newer_passed {
                    continue;
                }
                let proposal = j["proposal"].as_str();
                let (device, workspace, source) = proposal
                    .map(|p| owner(db, p))
                    .transpose()?
                    .unwrap_or((String::new(), String::new(), String::new()));
                let parent: Option<String> = proposal
                    .map(|p| {
                        sql(db
                            .query_row("SELECT old FROM promotions WHERE proposal=?1", [p], |r| {
                                r.get::<_, String>(0)
                            })
                            .optional())
                    })
                    .transpose()?
                    .flatten();
                let verified_parent:bool=sql(db.query_row("SELECT EXISTS(SELECT 1 FROM validation_jobs WHERE head=?1 AND policy_hash=?2 AND state='passed')",params![parent,current_policy],|r|r.get(0)))?;
                let attribution = if verified_parent {
                    "first_failing_commit_after_verified_parent"
                } else {
                    "investigator_only_unverified_commit_range"
                };
                let incident = format!("repair-{}", digest(&json!([signature, id])));
                sql(db.execute("INSERT INTO repair_incidents VALUES(?1,?2,?3,?4,?5,?5,'open','','',?6,0,1,NULL,?7,NULL,?8)",params![incident,signature,current_policy,check,id,source,now_ms(),attribution]))?;
                event(
                    db,
                    "repair_opened",
                    &json!({"incident_id":incident,"job_id":id,"check_id":check,"origin_device":device,"origin_workspace":workspace,"assignment":"next_active_caller","attribution":attribution}),
                )?;
            }
        }
        event(
            db,
            "validation_finished",
            &json!({"job_id":id,"head":j["head"],"state":phase,"applies_to_current_head":applicable,"duration_ms":now_ms()-j["started_at_ms"].as_i64().unwrap_or(now_ms()),"details":d}),
        )?;
        Ok(
            json!({"ok":true,"validation":describe(job(db,id)?),"applies_to_current_head":applicable}),
        )
    })();
    match result {
        Ok(v) => {
            sql(db.execute_batch("COMMIT"))?;
            Ok(v)
        }
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

pub(super) fn dispatch(state: &Path, db: &Connection, r: &Value) -> R<Value> {
    match field(r, "op")? {
        "validation_claim" => claim(state, db),
        "validation_complete" => complete(state, db, r),
        "repair_list" => {
            let mut v = repairs(
                db,
                r["cursor"].as_u64().unwrap_or(0),
                r["limit"].as_u64().unwrap_or(16),
            )?;
            if sync::is_client(db)? {
                v["commands"] =
                    coordination::list(db, r["workspace"].as_str(), 0, 16)?["commands"].clone();
            }
            Ok(v)
        }
        "validation_status" => {
            let mut v = json!({"ok":true,"repo_health":health(db)?});
            if let Some(head) = r["head"].as_str() {
                if sync::is_client(db)? {
                    return Err("authority_required: exact-head validation lookup requires authority evidence".into());
                }
                let hash = digest(&policy(db)?);
                let id: Option<String> = sql(db
                    .query_row(
                        "SELECT id FROM validation_jobs WHERE head=?1 AND policy_hash=?2",
                        params![head, hash],
                        |r| r.get(0),
                    )
                    .optional())?;
                let recorded = id.map(|id| job(db, &id)).transpose()?;
                v["details"] = recorded
                    .as_ref()
                    .map(|j| j["details"].clone())
                    .unwrap_or(Value::Null);
                v["validation"] = recorded.map(describe).unwrap_or(
                    json!({"state":"unchecked","head":head,"reason":"no_exact_commit_evidence"}),
                );
                v["release_ready"] = json!(v["validation"]["state"] == "passed");
            }
            if r["include_timings"] == true {
                let mut q=sql(db.prepare("SELECT recorded_at_ms,operation,workspace,timing FROM operation_timings ORDER BY seq DESC LIMIT 32"))?;
                v["operation_timings"]=json!(sql(q.query_map([],|r|Ok(json!({"recorded_at_ms":r.get::<_,i64>(0)?,"operation":r.get::<_,String>(1)?,"workspace":r.get::<_,Option<String>>(2)?,"timing":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(Value::Null)}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?);
                let mut q =
                    sql(db.prepare("SELECT id FROM validation_jobs ORDER BY rowid DESC LIMIT 32"))?;
                let ids = sql(q.query_map([], |r| r.get::<_, String>(0)))?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(|e| e.to_string())?;
                v["recent_checks"] = json!(ids
                    .iter()
                    .map(|id| job(db, id).map(describe))
                    .collect::<R<Vec<_>>>()?);
            }
            Ok(v)
        }
        _ => Err("unsupported_validation_operation".into()),
    }
}

pub(super) fn timing(
    db: &Connection,
    r: &Value,
    wait_ms: u128,
    dispatch_ms: u128,
    total_ms: u128,
    v: &mut Value,
) -> R<()> {
    if (r["op"] == "integrate" && v["outcomes"].as_array().is_some_and(Vec::is_empty))
        || (r["op"] == "validation_claim" && v["state"] == "idle")
        || (r["op"] == "backup_tick"
            && matches!(v["state"].as_str(), Some("not_configured" | "complete")))
    {
        return Ok(());
    }
    let mut timing = v
        .get("timing")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or(json!({}));
    timing["lock_wait_ms"] = json!(wait_ms);
    timing["dispatch_ms"] = json!(dispatch_ms);
    timing["engine_elapsed_ms"] = json!(total_ms);
    if let Some(blocker) = v.get("lock_blocker_observed_before_wait") {
        timing["blocker_observed_before_wait"] = blocker.clone();
    }
    v["timing"] = timing.clone();
    sql(db.execute("INSERT INTO operation_timings(recorded_at_ms,operation,workspace,timing) VALUES(?1,?2,?3,?4)",params![now_ms(),field(r,"op")?,r["workspace"].as_str(),timing.to_string()]))?;
    Ok(())
}

pub(super) fn tick(state: &Path) -> R<Value> {
    let lock = io(OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("validation-worker.lock")))?;
    if fs2::FileExt::try_lock_exclusive(&lock).is_err() {
        return Ok(json!({"ok":true,"state":"worker_busy"}));
    }
    let j = execute(state, json!({"op":"validation_claim"}))?;
    if j["ok"] != true || j["job_id"].is_null() {
        return Ok(j);
    }
    let details = evaluate_claim(state, &j)?;
    execute(
        state,
        json!({"op":"validation_complete","job_id":j["job_id"],"token":j["token"],"details":details}),
    )
}

pub(super) fn evaluate_claim(state: &Path, j: &Value) -> R<Value> {
    let started = Instant::now();
    let mut check_policy = j["policy"].clone();
    check_policy
        .as_object_mut()
        .ok_or("invalid_policy")?
        .remove("repair");
    let head = field(j, "head")?;
    let mut details=crate::policy::evaluate(state,&coordinator(state),head,head,field(j,"candidate_tree")?,false,&[],&check_policy)
        .map(|e|e.details).unwrap_or_else(|e|json!({"head":head,"proposal":head,"candidate_tree":j["candidate_tree"],"evaluation_error":e,"checks":[],"failure_kind":"infrastructure"}));
    details["policy_sha256"] = j["policy_sha256"].clone();
    details["policy"] = j["policy"].clone();
    details["duration_ms"] = json!(started.elapsed().as_millis());
    if let Some(checks) = details["checks"].as_array() {
        let infrastructure = checks.iter().any(|c| c["failure_kind"] == "infrastructure");
        let code_failure = checks
            .iter()
            .any(|c| c["failure_kind"].is_string() && c["failure_kind"] != "infrastructure");
        details["has_infrastructure_failure"] = json!(infrastructure);
        if infrastructure && !code_failure {
            details["failure_kind"] = json!("infrastructure");
        }
    }
    Ok(details)
}

pub(super) fn start(state: PathBuf) {
    std::thread::spawn(move || loop {
        if let Err(e) = tick(&state) {
            eprintln!("background validation: {e}");
        }
        std::thread::sleep(Duration::from_secs(1));
    });
}
