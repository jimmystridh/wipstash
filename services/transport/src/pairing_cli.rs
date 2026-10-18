//! Guided, restartable pairing. No credential is accepted in command arguments.
use crate::{error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, io::Read, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

const FILE_MAX: u64 = 128 * 1024;

fn private_directory(path: &Path, create: bool) -> Result<()> {
    if create { crate::pairing_files::ensure_private_dir(path)?; }
    else { crate::pairing_files::validate_private_dir(path)?; }
    Ok(())
}
fn read_private(path: &Path) -> Result<Vec<u8>> {
    Ok(crate::pairing_files::read_private_file(path, FILE_MAX as usize)?)
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > FILE_MAX { return Err(error("profile_file_bound")); }
    crate::pairing_files::create_private_file(path, bytes)?;
    Ok(())
}
fn write_same(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if read_private(path)? != bytes { return Err(error("existing_profile_file_conflicts")); }
        return Ok(());
    }
    write_private(path, bytes)
}
fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> { write_same(path, &serde_json::to_vec_pretty(value)?) }
fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    // Never print a serde error that might include supplied secret material.
    serde_json::from_slice(&read_private(path)?).map_err(|_| error("invalid_private_profile_document"))
}
fn now() -> Result<i64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs().try_into()?) }
struct Flags(BTreeMap<String, String>);
impl Flags {
    fn parse(args: &[String], allowed: &[&str]) -> Result<Self> {
        let mut map = BTreeMap::new(); let mut i = 0;
        while i < args.len() {
            let name = &args[i];
            if !allowed.contains(&name.as_str()) { return Err(error("unknown_pairing_option; run help")); }
            let value = if matches!(name.as_str(), "--invite-stdin" | "--online") { String::from("true") } else { i += 1; args.get(i).filter(|s| !s.starts_with("--")).cloned().ok_or_else(|| error("missing_pairing_option_value"))? };
            if map.insert(name.clone(), value).is_some() { return Err(error("duplicate_pairing_option")); }
            i += 1;
        }
        Ok(Self(map))
    }
    fn get(&self, name: &str) -> Result<&str> { self.0.get(name).map(String::as_str).ok_or_else(|| error("required_pairing_option_missing; run help")) }
    fn or<'a>(&'a self, name: &str, default: &'a str) -> &'a str { self.0.get(name).map(String::as_str).unwrap_or(default) }
    fn has(&self, name: &str) -> bool { self.0.contains_key(name) }
}

use crate::pairing::{AuthorityBinding, Invite, InviteScope, InvitePurpose, PairingStore, RedeemRequest, RecoveryChallengeRequest, RecoveryRequest, EnrollmentResponse, random_id, recovery_message};
use crate::pairing_crypto::{generate_bootstrap, generate_local_csr, sign_recovery, validate_enrollment_response};
use crate::enrollment::EnrollmentClient;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    version: u32, role: String, engine: PathBuf, state: PathBuf,
    project: String, authority: String, epoch: u64, device: String,
    authority_device: String, scope: InviteScope,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinIntent { version: u32, invite_id: String, request_id: String, csr_der: Vec<u8>, key_pem: String, scope: InviteScope }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteIntent { device: String, operation_id: String }
fn default_engine() -> Result<PathBuf> { Ok(std::env::current_exe()?.with_file_name(if cfg!(windows) { "wipstash.exe" } else { "wipstash" })) }
fn engine_path(f: &Flags) -> Result<PathBuf> { let p = f.0.get("--engine").map(PathBuf::from).unwrap_or(default_engine()?); if !p.is_absolute() { return Err(error("absolute_engine_path_required")); } Ok(p) }
fn binding_matches(config: &Value, p: &Profile) -> bool {
    config["project"] == p.project && config["authority"] == p.authority && config["epoch"] == p.epoch && config["device"] == p.device && config["role"] == p.role && (p.role != "client" || config["peers"] == json!([p.authority_device]))
}
async fn check_binding(p: &Profile, allow_fresh: bool) -> Result<Value> {
    let status = crate::run_engine(&p.engine, &p.state, json!({"op":"sync_binding_status"})).await?;
    if !status["pending_config"].is_null() && !binding_matches(&status["pending_config"], p) { return Err(error("pending_engine_binding_conflicts")); }
    if status["state"] == "unconfigured" && allow_fresh && status["initialized"] == false { return Ok(status); }
    if !binding_matches(&status["config"], p) { return Err(error("existing_engine_binding_conflicts")); }
    Ok(status)
}
fn directory(f: &Flags) -> Result<PathBuf> { Ok(PathBuf::from(f.get("--directory")?)) }
async fn setup(f: Flags) -> Result<()> {
    let dir = directory(&f)?;
    private_directory(&dir, true)?;
    if dir.join("profile.json").exists() {
        let p: Profile = load(&dir.join("profile.json"))?;
        if p.role != "authority" { return Err(error("profile_is_not_authority")); }
        for (flag, expected) in [("--project",p.project.as_str()),("--authority",p.authority.as_str()),("--device",p.device.as_str()),("--server-name",p.scope.sync_server_name.as_str())] {
            if f.0.get(flag).is_some_and(|v| v != expected) { return Err(error("existing_setup_options_conflict")); }
        }
        for (flag, expected) in [("--engine",p.engine.clone()),("--state",p.state.clone())] { if f.0.get(flag).is_some_and(|v| Path::new(v) != expected) { return Err(error("existing_setup_paths_conflict")); } }
        for (flag, expected) in [("--epoch",p.epoch.to_string()),("--enrollment-address",p.scope.enrollment_address.to_string()),("--sync-address",p.scope.sync_address.to_string())] { if f.0.get(flag).is_some_and(|v| v != &expected) { return Err(error("existing_setup_options_conflict")); } }

        check_binding(&p, false).await?;
        println!("Authority profile already exists. Use status or device invite."); return Ok(());
    }
    let engine = engine_path(&f)?;
    let state = PathBuf::from(f.get("--state")?);
    if !state.is_absolute() { return Err(error("absolute_state_path_required")); }
    let project = f.get("--project")?.to_owned(); let authority = f.get("--authority")?.to_owned(); let device = f.get("--device")?.to_owned();
    if [&project,&authority,&device].iter().any(|id| !crate::valid_id(id)) { return Err(error("invalid_binding_identifier")); }
    let epoch: u64 = f.or("--epoch", "1").parse().map_err(|_| error("invalid_epoch"))?;
    let server_name = f.or("--server-name", "localhost").to_owned();
    let enrollment_address: std::net::SocketAddr = f.or("--enrollment-address", "127.0.0.1:7444").parse().map_err(|_| error("invalid_enrollment_address"))?;
    let sync_address: std::net::SocketAddr = f.or("--sync-address", "127.0.0.1:7443").parse().map_err(|_| error("invalid_sync_address"))?;
    if enrollment_address == sync_address { return Err(error("enrollment_and_sync_require_separate_addresses")); }
    if epoch == 0 || epoch > i64::MAX as u64 || enrollment_address.port()==0 || sync_address.port()==0 || enrollment_address.ip().is_unspecified() || sync_address.ip().is_unspecified() || rustls::pki_types::ServerName::try_from(server_name.clone()).is_err() { return Err(error("invalid_authority_endpoint_or_epoch")); }
    if f.0.get("--source").is_some_and(|v| !Path::new(v).is_absolute()) { return Err(error("absolute_source_path_required")); }

    // Validate the existing binding BEFORE generating authority secrets.
    let mut status = crate::run_engine(&engine, &state, json!({"op":"sync_binding_status"})).await?;
    if !status["pending_config"].is_null() { return Err(error("pending_client_initialization_conflicts_with_authority_setup")); }
    if status["initialized"] == false && !f.has("--source") { return Err(error("authority_source_required; rerun setup with --source ABSOLUTE_SOURCE to explicitly import the initial public head")); }
    save(&dir.join("setup-intent.json"), &json!({"engine":engine,"state":state,"project":project,"authority":authority,"device":device,"epoch":epoch,"server_name":server_name,"enrollment_address":enrollment_address,"sync_address":sync_address,"source":f.0.get("--source")}))?;
    if status["initialized"] == false {
        let source=PathBuf::from(f.get("--source").map_err(|_| error("authority_source_required; rerun setup with --source ABSOLUTE_SOURCE to explicitly import the initial public head"))?);
        if !source.is_absolute() { return Err(error("absolute_source_path_required")); }
        println!("Importing the explicitly selected source as the authority's initial public head.");
        crate::run_engine(&engine,&state,json!({"op":"init","source":source})).await?;
        status=crate::run_engine(&engine,&state,json!({"op":"sync_binding_status"})).await?;
    }
    if status["state"] != "unconfigured" && !(status["config"]["project"] == project && status["config"]["authority"] == authority && status["config"]["epoch"] == epoch && status["config"]["device"] == device && status["config"]["role"] == "authority") { return Err(error("existing_engine_binding_conflicts")); }
    // One durable bootstrap bundle avoids generating a different CA after partial installation.
    #[derive(Serialize,Deserialize)] struct Bootstrap { ca_pem:String, ca_key_pem:String, ca_der:Vec<u8>, server_pem:String, server_key_pem:String, server_der:Vec<u8> }
    let bootstrap_path = dir.join("bootstrap.json");
    let b: Bootstrap = if bootstrap_path.exists() { load(&bootstrap_path)? } else {
        let m = generate_bootstrap(&[server_name.clone()], now()?)?;
        let b = Bootstrap { ca_pem:m.ca_pem, ca_key_pem:m.ca_key_pem, ca_der:m.ca_certificate_der, server_pem:m.server_pem, server_key_pem:m.server_key_pem, server_der:m.server_certificate_der };
        save(&bootstrap_path, &b)?; b
    };
    let pin = crate::fingerprint(&b.server_der);
    let scope = InviteScope { project:project.clone(), authority:authority.clone(), epoch, authority_device:device.clone(), client_device:String::from("reserved"), purpose:InvitePurpose::New, enrollment_address, enrollment_server_name:server_name.clone(), enrollment_leaf_pin:pin.clone(), sync_address, sync_server_name:server_name, sync_leaf_pin:pin, ca_certificate_der:b.ca_der, certificate_lifetime_secs:30*24*3600 };
    let p = Profile { version:1, role:"authority".into(), engine, state, project, authority, epoch, device:device.clone(), authority_device:device, scope };
    for (name, content) in [("ca.pem",b.ca_pem),("ca-key.pem",b.ca_key_pem),("server.pem",b.server_pem),("server-key.pem",b.server_key_pem)] { write_same(&dir.join(name), content.as_bytes())?; }
    private_directory(&dir.join("staging"), true)?;
    let store = PairingStore::open(&dir.join("pairing.sqlite"))?;
    store.initialize(&AuthorityBinding { project:p.project.clone(), authority:p.authority.clone(), epoch:p.epoch, authority_device:p.device.clone() })?;
    if status["state"] == "unconfigured" {
        crate::run_engine(&p.engine,&p.state,json!({"op":"sync_initialize_authority","operation_id":format!("setup-{}",crate::fingerprint(&serde_json::to_vec(&p)?)),"project":p.project,"authority":p.authority,"epoch":p.epoch,"device":p.device})).await?;
    }
    save(&dir.join("service.json"), &json!({"engine":p.engine,"state":p.state,"staging":dir.join("staging"),"project":p.project,"authority":p.authority,"epoch":p.epoch,"device":p.device,"acl":{"managed":dir.join("pairing.sqlite")},"ca":dir.join("ca.pem"),"certificate":dir.join("server.pem"),"key":dir.join("server-key.pem"),"listen":p.scope.sync_address}))?;
    save(&dir.join("profile.json"), &p)?;
    println!("Authority profile ready. No listeners started. Run remote serve --directory PATH, then remote device invite --directory PATH --device NAME --out PRIVATE_FILE.");
    Ok(())
}

async fn device_command(command: &str, f: Flags) -> Result<()> {
    let dir = directory(&f)?; private_directory(&dir, false)?;
    let p: Profile = load(&dir.join("profile.json"))?;
    if p.role != "authority" { return Err(error("device_management_requires_authority")); }
    let status = check_binding(&p, false).await?;
    let store = if command == "list" { PairingStore::open_existing(&dir.join("pairing.sqlite"))? } else { PairingStore::open(&dir.join("pairing.sqlite"))? };
    match command {
        "list" => { for d in store.list()? { println!("{}\t{}\tgeneration {}",d.device,d.state,d.generation); } }
        "cancel-invite" => { store.cancel_pending_invite(f.get("--device")?)?; println!("Pending invitations cancelled. Existing device authorization is unchanged; you can explicitly issue a replacement invitation."); }
        "revoke" => { store.revoke(f.get("--device")?, now()?)?; println!("Device revoked. Subsequent requests are denied, including existing connections; admitted work may finish."); }
        "invite" | "rotate" => {
            let device = f.get("--device")?;
            if !crate::valid_id(device) || device == p.device { return Err(error("invalid_client_device")); }
            let out = PathBuf::from(f.get("--out")?);
            private_directory(out.parent().ok_or_else(|| error("invite_output_parent_required"))?, false)?;
            if out.exists() { return Err(error("invitation_output_already_exists")); }
            let current = now()?;
            let ttl: i64 = f.or("--expires-in", "900").parse().map_err(|_| error("invalid_invite_expiry"))?;
            if !(60..=86400).contains(&ttl) { return Err(error("invite_expiry_must_be_60_to_86400_seconds")); }
            let invitation = if command == "rotate" {
                let generation = f.get("--generation")?.parse().map_err(|_| error("expected_generation_required"))?;
                store.rotate_invite(device,generation,current+ttl,current)?
            } else {
                let intent_path = dir.join(format!("invite-intent-{}.json",device));
                let intent: InviteIntent = if intent_path.exists() { let x: InviteIntent=load(&intent_path)?; if x.device != device { return Err(error("invite_intent_conflicts")); } x } else {
                    if status["config"]["peers"].as_array().is_some_and(|peers| peers.iter().any(|peer| peer == device)) { return Err(error("existing_peer_requires_explicit_rotation_or_migration")); }
                    let x = InviteIntent { device:device.into(), operation_id:random_id()? }; save(&intent_path,&x)?; x
                };
                crate::run_engine(&p.engine,&p.state,json!({"op":"sync_add_peer","operation_id":intent.operation_id,"peer":device})).await?;
                store.reserve_device(device)?;
                let mut scope = p.scope.clone(); scope.client_device=device.into();
                store.create_invite(scope,current+ttl,current)?
            };
            // Never emit invite secret on stdout. Only this protected, explicit destination.
            write_private(&out,&serde_json::to_vec(&invitation)?).map_err(|_| error("invitation_output_incomplete; inspect the protected output; use device cancel-invite --device NAME before explicitly reissuing a lost invitation"))?;
            println!("Invitation saved to protected file. Share the complete file through a trusted private channel. It expires in {} seconds. Access: client for project {}, device {}.",ttl,p.project,device);
        }
        _ => return Err(error("unknown_device_command")),
    }
    Ok(())
}
fn pem_certificate(der: &[u8]) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded=String::new();
    for c in der.chunks(3) {
        let n=((c[0] as u32)<<16)|((c.get(1).copied().unwrap_or(0) as u32)<<8)|c.get(2).copied().unwrap_or(0) as u32;
        encoded.push(B64[((n>>18)&63) as usize] as char); encoded.push(B64[((n>>12)&63) as usize] as char);
        encoded.push(if c.len()>1 {B64[((n>>6)&63) as usize] as char} else {'='}); encoded.push(if c.len()>2 {B64[(n&63) as usize] as char} else {'='});
    }
    let mut pem=String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) { pem.push_str(std::str::from_utf8(chunk).unwrap()); pem.push('\n'); }
    pem.push_str("-----END CERTIFICATE-----\n"); pem
}
async fn join(f: Flags) -> Result<()> {
    let dir=directory(&f)?; private_directory(&dir,true)?;
    if f.has("--invite-file") == f.has("--invite-stdin") { return Err(error("choose_exactly_one_invite_file_or_stdin")); }
    let invitation: Invite = if f.has("--invite-file") { load(Path::new(f.get("--invite-file")?))? } else {
        let mut input=Vec::new(); std::io::stdin().take(FILE_MAX+1).read_to_end(&mut input)?;
        if input.len() as u64>FILE_MAX { return Err(error("invitation_bound")); }
        serde_json::from_slice(&input).map_err(|_| error("invalid_invitation"))?
    };
    let scope=&invitation.scope;
    scope.validate()?;
    if invitation.invite_id.len()!=64 || invitation.secret.len()!=64 || !invitation.invite_id.bytes().chain(invitation.secret.bytes()).all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(error("invalid_invitation")); }
    if invitation.version != 1 || scope.epoch == 0 || [&scope.project,&scope.authority,&scope.authority_device,&scope.client_device].iter().any(|id| !crate::valid_id(id)) { return Err(error("invalid_invitation_scope")); }
    let p=Profile { version:1, role:"client".into(), engine:engine_path(&f)?, state:PathBuf::from(f.get("--state")?),project:scope.project.clone(),authority:scope.authority.clone(),epoch:scope.epoch,device:scope.client_device.clone(),authority_device:scope.authority_device.clone(),scope:scope.clone() };
    if !p.state.is_absolute() { return Err(error("absolute_state_path_required")); }
    let status=check_binding(&p,true).await?;
    if dir.join("profile.json").exists() { let existing:Profile=load(&dir.join("profile.json"))?; if serde_json::to_value(&existing)? != serde_json::to_value(&p)? { return Err(error("existing_profile_conflicts")); } }
    println!("Pairing device {} with authority {}, project {} (client access). Trust depends on how you received the invitation.",p.device,p.authority,p.project);
    save(&dir.join("join-profile-intent.json"),&p)?;
    let intent_path=dir.join("join-intent.json");
    let intent:JoinIntent=if intent_path.exists() { let i:JoinIntent=load(&intent_path)?; if i.invite_id != invitation.invite_id || serde_json::to_value(&i.scope)? != serde_json::to_value(scope)? { return Err(error("unfinished_join_is_for_different_invitation")); } i } else {
        if invitation.expires_at <= now()? { return Err(error("invitation_expired_before_join")); }
        let local=generate_local_csr()?;
        let i=JoinIntent { version:1,invite_id:invitation.invite_id.clone(),request_id:random_id()?,csr_der:local.csr_der,key_pem:local.key_pem,scope:scope.clone() };
        save(&intent_path,&i)?; i
    };
    crate::pairing_crypto::validate_local_key_csr(&intent.key_pem,&intent.csr_der)?;
    // Exact key, CSR, request ID and invitation identity are durable BEFORE any network.
    let response_path=dir.join("issued-response.json");
    let response:EnrollmentResponse=if response_path.exists() { load(&response_path)? } else {
        let mut roots=rustls::RootCertStore::empty(); roots.add(rustls::pki_types::CertificateDer::from(scope.ca_certificate_der.clone()))?;
        let client=EnrollmentClient::new(roots,scope.enrollment_server_name.clone(),scope.enrollment_leaf_pin.clone())?;
        let request=RedeemRequest { version:1,invite_id:intent.invite_id.clone(),secret:invitation.secret.clone(),request_id:intent.request_id.clone(),csr_der:intent.csr_der.clone() };
        let response=match client.enroll(scope.enrollment_address,&request,scope).await {
            Ok(response)=>response,
            Err(_)=> {
                let challenge_request=RecoveryChallengeRequest { version:1,invite_id:intent.invite_id.clone(),request_id:intent.request_id.clone(),csr_der:intent.csr_der.clone() };
                let challenge=client.challenge(scope.enrollment_address,&challenge_request).await.map_err(|_| error("join_incomplete; durable key and request retained; retry the same invitation"))?;
                let signature=sign_recovery(&intent.key_pem,&recovery_message(&challenge_request,&challenge)?)?;
                let recovery=RecoveryRequest { version:1,invite_id:intent.invite_id.clone(),request_id:intent.request_id.clone(),csr_der:intent.csr_der.clone(),challenge,signature };
                client.recover(scope.enrollment_address,&recovery,scope).await.map_err(|_| error("join_recovery_incomplete; retain profile and retry same invitation"))?
            }
        };
        validate_enrollment_response(&response,&intent.csr_der,scope,&intent.request_id,now()?)?;
        save(&response_path,&response)?; response
    };
    validate_enrollment_response(&response,&intent.csr_der,scope,&intent.request_id,now()?)?;
    write_same(&dir.join("client-key.pem"),intent.key_pem.as_bytes())?;
    write_same(&dir.join("client.pem"),pem_certificate(&response.certificate_der).as_bytes())?;
    write_same(&dir.join("ca.pem"),pem_certificate(&response.ca_certificate_der).as_bytes())?;
    private_directory(&dir.join("staging"),true)?;
    save(&dir.join("client.json"),&json!({"engine":p.engine,"state":p.state,"staging":dir.join("staging"),"ca":dir.join("ca.pem"),"certificate":dir.join("client.pem"),"key":dir.join("client-key.pem"),"server_name":scope.sync_server_name,"authority_fingerprint":scope.sync_leaf_pin,"address":scope.sync_address,"project":p.project,"authority":p.authority,"epoch":p.epoch,"device":p.device,"authority_device":p.authority_device}))?;
    if status["state"] == "unconfigured" { crate::run_engine(&p.engine,&p.state,json!({"op":"sync_configure","project":p.project,"authority":p.authority,"epoch":p.epoch,"device":p.device,"role":"client","peers":[p.authority_device]})).await?; }
    check_binding(&p,false).await?;
    save(&dir.join("profile.json"),&p)?;
    println!("Credential issued and installed; engine binding configured. Checking authenticated connectivity…");
    verify_connection(&dir,&p).await?;
    if !dir.join("connection-verified.json").exists() { save(&dir.join("connection-verified.json"),&json!({"request_id":intent.request_id,"verified_at":now()?}))?; }
    println!("Pairing complete. Authenticated read-only connectivity verified. No proposals uploaded or heads adopted.");
    Ok(())
}
async fn verify_connection(dir:&Path,p:&Profile)->Result<()> {
    let client=crate::Client::from_files(&dir.join("ca.pem"),&dir.join("client.pem"),&dir.join("client-key.pem"),p.scope.sync_server_name.clone(),p.scope.sync_leaf_pin.clone())?;
    tokio::time::timeout(std::time::Duration::from_secs(15),client.request(p.scope.sync_address,"GET","/v1/history",Vec::new())).await.map_err(|_| error("connectivity_timeout; credentials retained"))?.map_err(|e| {
        let safe=e.to_string();
        match safe.as_str() {
            "authority_pin_mismatch"=>error("connectivity_authority_pin_mismatch; credentials retained"),
            "remote_rejected"=>error("connectivity_remote_rejected; check device revocation and project authorization"),
            _=>error("connectivity_unverified; check address, TLS name and certificate validity; credentials retained"),
        }
    })?;
    Ok(())
}
async fn serve(f:Flags)->Result<()> {
    let dir=directory(&f)?; private_directory(&dir,false)?;
    let p:Profile=load(&dir.join("profile.json"))?;
    if p.role != "authority" { return Err(error("serve_requires_authority_profile")); }
    check_binding(&p,false).await?;
    let config:crate::Config=load(&dir.join("service.json"))?;
    let ca=String::from_utf8(read_private(&dir.join("ca.pem"))?).map_err(|_| error("invalid_ca_pem"))?;
    let key=zeroize::Zeroizing::new(String::from_utf8(read_private(&dir.join("ca-key.pem"))?).map_err(|_| error("invalid_ca_key"))?);
    let issuer=crate::pairing_crypto::Issuer::from_pem(&ca,&key,now()?)?;
    let enrollment=std::sync::Arc::new(crate::enrollment::EnrollmentService::new(PairingStore::open(&dir.join("pairing.sqlite"))?,issuer,crate::certs(&dir.join("server.pem"))?,crate::KeySource::File(dir.join("server-key.pem")).load()?)?);
    let mut worker=crate::daemon::AuthorityWorker::open_with_limits(config.engine.clone(),config.state.clone(),config.staging.clone(),config.limits.clone()).await?;
    let service=crate::Service::new(config).await?;
    println!("Starting separate enrollment TLS and mandatory-mTLS sync listeners. Press Ctrl-C to stop.");
    tokio::select! { r=service.serve()=>r, r=worker.run()=>r, r=enrollment.serve(p.scope.enrollment_address)=>r, _=tokio::signal::ctrl_c()=>Ok(()) }
}
async fn inspect(f:Flags,doctor:bool)->Result<()> {
    let dir=directory(&f)?; private_directory(&dir,false)?;
    if !dir.join("profile.json").exists() {
        for (file, message) in [("join-intent.json","Join pending: original key, CSR and request are retained. Retry the SAME invitation and directory."),("bootstrap.json","Authority setup pending: bootstrap credentials retained. Retry the same setup options."),("setup-intent.json","Authority setup intent recorded; credential creation not completed.")] {
            if dir.join(file).exists() { let _:Value=load(&dir.join(file))?; println!("{}",message); if dir.join("issued-response.json").exists() { let _:Value=load(&dir.join("issued-response.json"))?; println!("Issuance response recorded; local installation may be incomplete."); } return Ok(()); }
        }
        return Err(error("no_pairing_profile_or_restart_intent"));
    }
    let p:Profile=load(&dir.join("profile.json"))?;
    println!("{} profile: project {}, authority {}, device {}, epoch {}",p.role,p.project,p.authority,p.device,p.epoch);
    if doctor {
        // Do not open the store, launch engine, enroll, create files, or run recovery.
        let names: &[&str]=if p.role=="authority" { &["ca.pem","ca-key.pem","server.pem","server-key.pem","service.json","pairing.sqlite"] } else { &["ca.pem","client.pem","client-key.pem","client.json","join-intent.json","issued-response.json"] };
        for name in names {
            crate::pairing_files::validate_private_file(&dir.join(name))?;
        }
        println!("Local profile files and protection checked without mutation. Live engine binding was not checked.");
        if f.has("--online") {
            if p.role != "client" { return Err(error("doctor_online_requires_client_profile")); }
            verify_connection(&dir,&p).await?;
            println!("Authenticated read-only connectivity verified now. No files or credentials changed.");
        } else { println!("Network connectivity and current remote authorization were not checked; use doctor --online for a live read-only check."); }
    } else {
        println!("Credential installation: {}. Prior read-only connection check: {}.",if p.role=="authority"||dir.join("issued-response.json").exists(){"recorded"}else{"incomplete"},if dir.join("connection-verified.json").exists(){"recorded (not a live check)"}else{"not recorded"});
    }
    Ok(())
}
const HELP:&str="Guided pairing (absolute paths required):\n  wipstash remote setup --directory PRIVATE_DIR --state ENGINE_STATE --project NAME --authority NAME --device NAME [--source INITIAL_SOURCE] [--engine ENGINE] [--epoch 1] [--server-name localhost] [--enrollment-address 127.0.0.1:7444] [--sync-address 127.0.0.1:7443]\n  wipstash remote serve --directory PRIVATE_DIR\n  wipstash remote device invite --directory PRIVATE_DIR --device NAME --out PRIVATE_FILE [--expires-in 900]\n  wipstash remote join --directory PRIVATE_DIR --state ENGINE_STATE (--invite-file PRIVATE_FILE | --invite-stdin) [--engine ENGINE]\n  wipstash remote device list --directory PRIVATE_DIR\n  wipstash remote device revoke --directory PRIVATE_DIR --device NAME\n  wipstash remote device cancel-invite --directory PRIVATE_DIR --device NAME\n  wipstash remote device rotate --directory PRIVATE_DIR --device NAME --generation N --out PRIVATE_FILE\n  wipstash remote status --directory PRIVATE_DIR\n  wipstash remote doctor --directory PRIVATE_DIR [--online]\nInvitations are secrets: never paste them into command arguments. Transfer invitation files privately. No automatic publishing, adoption, service installation or IdP setup.";
/// Dispatch guided commands; false preserves legacy serve/worker/client syntax.
pub async fn run(args:&[String])->Result<bool> {
    let Some(command)=args.first().map(String::as_str) else { return Ok(false); };
    if matches!(command,"help"|"--help"|"-h") { println!("{}",HELP); return Ok(true); }
    let common=&["--directory"];
    match command {
        "setup"=>setup(Flags::parse(&args[1..],&["--directory","--engine","--state","--source","--project","--authority","--device","--epoch","--server-name","--enrollment-address","--sync-address"])?).await?,
        "join"=>join(Flags::parse(&args[1..],&["--directory","--engine","--state","--invite-file","--invite-stdin"])?).await?,
        "device"=>{let sub=args.get(1).ok_or_else(||error("device_subcommand_required"))?; let allowed:&[&str]=match sub.as_str(){"list"=>common,"revoke"|"cancel-invite"=>&["--directory","--device"],"invite"=>&["--directory","--device","--out","--expires-in"],"rotate"=>&["--directory","--device","--generation","--out","--expires-in"],_=>return Err(error("unknown_device_subcommand"))}; device_command(sub,Flags::parse(&args[2..],allowed)?).await?;},
        "status"=>inspect(Flags::parse(&args[1..],common)?,false).await?,
        "doctor"=>inspect(Flags::parse(&args[1..],&["--directory","--online"])?,true).await?,
        "serve" if args.get(1).map(String::as_str)==Some("--directory")=>serve(Flags::parse(&args[1..],common)?).await?,
        _=>return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn arguments_never_accept_secret_flags() {
        for option in ["--token","--secret","--invite","--key"] { assert!(Flags::parse(&[option.into(),"sensitive".into()], &["--invite-file"]).is_err()); }
        assert!(Flags::parse(&["--invite-file".into(),"a".into(),"--invite-file".into(),"b".into()], &["--invite-file"]).is_err());
    }
    #[test] fn pem_encodes_canonical_bytes() { assert_eq!(pem_certificate(&[0,1,2]),"-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n"); }
    fn synthetic_profile() -> Profile {
        Profile { version:1,role:"client".into(),engine:"/synthetic/engine".into(),state:"/synthetic/state".into(),project:"p".into(),authority:"a".into(),epoch:1,device:"d".into(),authority_device:"ad".into(),scope:InviteScope { project:"p".into(),authority:"a".into(),epoch:1,authority_device:"ad".into(),client_device:"d".into(),purpose:InvitePurpose::New,enrollment_address:"127.0.0.1:7444".parse().unwrap(),enrollment_server_name:"localhost".into(),enrollment_leaf_pin:"0".repeat(64),sync_address:"127.0.0.1:7443".parse().unwrap(),sync_server_name:"localhost".into(),sync_leaf_pin:"1".repeat(64),ca_certificate_der:vec![1,2,3],certificate_lifetime_secs:3600 } }
    }
    #[test] fn binding_requires_exact_role_identity_epoch_and_peer() {
        let p=synthetic_profile();
        let c=json!({"project":"p","authority":"a","epoch":1,"device":"d","role":"client","peers":["ad"]});
        assert!(binding_matches(&c,&p));
        for (field,value) in [("epoch",json!(2)),("role",json!("authority")),("device",json!("other")),("project",json!("other")),("authority",json!("other")),("peers",json!(["ad","unexpected"]))] { let mut changed=c.clone(); changed[field]=value; assert!(!binding_matches(&changed,&p)); }
    }
    #[cfg(unix)]
    #[test] fn exact_join_material_survives_restart_and_refuses_new_profile() {
        use std::os::unix::fs::PermissionsExt;
        let temp=tempfile::tempdir().unwrap(); fs::set_permissions(temp.path(),fs::Permissions::from_mode(0o700)).unwrap();
        let p=synthetic_profile();
        let intent=JoinIntent { version:1,invite_id:"a".repeat(64),request_id:"b".repeat(64),csr_der:vec![7,8,9],key_pem:"synthetic-only-key".into(),scope:p.scope.clone() };
        save(&temp.path().join("join-intent.json"),&intent).unwrap();
        let resumed:JoinIntent=load(&temp.path().join("join-intent.json")).unwrap();
        assert_eq!(resumed.request_id,intent.request_id);assert_eq!(resumed.csr_der,intent.csr_der);assert_eq!(resumed.key_pem,intent.key_pem);
        save(&temp.path().join("join-profile-intent.json"),&p).unwrap();
        let mut changed=p;changed.state="/synthetic/different-state".into();
        assert!(save(&temp.path().join("join-profile-intent.json"),&changed).is_err());
    }
    #[cfg(unix)]
    #[test] fn journal_is_create_only_private_and_restartable() {
        use std::os::unix::fs::PermissionsExt;
        let temp=tempfile::tempdir().unwrap(); fs::set_permissions(temp.path(),fs::Permissions::from_mode(0o700)).unwrap();
        let path=temp.path().join("intent.json");
        let expected=json!({"request_id":"synthetic-request","csr_der":[1,2,3],"key":"synthetic-only"});
        save(&path,&expected).unwrap(); assert_eq!(load::<Value>(&path).unwrap(),expected);
        save(&path,&expected).unwrap(); assert!(save(&path,&json!({"request_id":"replacement"})).is_err());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode()&0o777,0o600);
        assert!(write_private(&path,b"replacement").is_err());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn doctor_is_read_only_for_pending_join() {
        use std::os::unix::fs::PermissionsExt;
        let temp=tempfile::tempdir().unwrap();fs::set_permissions(temp.path(),fs::Permissions::from_mode(0o700)).unwrap();
        let path=temp.path().join("join-intent.json");save(&path,&json!({"synthetic":"pending"})).unwrap();
        let before=read_private(&path).unwrap();
        inspect(Flags::parse(&["--directory".into(),temp.path().to_str().unwrap().into()],&["--directory"]).unwrap(),true).await.unwrap();
        assert_eq!(read_private(&path).unwrap(),before);assert_eq!(fs::read_dir(temp.path()).unwrap().count(),1);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn conflicting_engine_binding_rejects_before_key_or_network() {
        use std::os::unix::fs::PermissionsExt;
        let temp=tempfile::tempdir().unwrap();fs::set_permissions(temp.path(),fs::Permissions::from_mode(0o700)).unwrap();
        let engine=temp.path().join("synthetic-engine");
        fs::write(&engine,b"#!/bin/sh\nprintf '%s\\n' '{\"ok\":true,\"state\":\"configured\",\"initialized\":true,\"config\":{\"project\":\"wrong-project\"}}'\n").unwrap();
        fs::set_permissions(&engine,fs::Permissions::from_mode(0o700)).unwrap();
        let profile=synthetic_profile();let invitation=Invite { version:1,invite_id:"a".repeat(64),secret:"b".repeat(64),expires_at:now().unwrap()+900,scope:profile.scope };
        let invite=temp.path().join("invite");save(&invite,&invitation).unwrap();
        let dest=temp.path().join("client");
        let flags=Flags::parse(&["--directory".into(),dest.to_str().unwrap().into(),"--state".into(),temp.path().join("state").to_str().unwrap().into(),"--engine".into(),engine.to_str().unwrap().into(),"--invite-file".into(),invite.to_str().unwrap().into()],&["--directory","--state","--engine","--invite-file"]).unwrap();
        let failure=join(flags).await.unwrap_err().to_string();assert_eq!(failure,"existing_engine_binding_conflicts");
        assert!(!dest.join("join-intent.json").exists());assert!(!dest.join("client-key.pem").exists());
    }
    #[cfg(unix)]
    #[test] fn symlinks_and_public_invites_are_rejected() {
        use std::os::unix::fs::{symlink,PermissionsExt};
        let temp=tempfile::tempdir().unwrap(); fs::set_permissions(temp.path(),fs::Permissions::from_mode(0o700)).unwrap();
        let real=temp.path().join("real");write_private(&real,b"synthetic").unwrap();
        let link=temp.path().join("link");symlink(&real,&link).unwrap();assert!(read_private(&link).is_err());
        fs::set_permissions(&real,fs::Permissions::from_mode(0o644)).unwrap();assert!(read_private(&real).is_err());
    }
}
