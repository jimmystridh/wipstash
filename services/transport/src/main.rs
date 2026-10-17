use serde::Deserialize;
use serde_json::Value;
use std::{net::SocketAddr, path::PathBuf};
use wipstash_transport::daemon::{AuthorityWorker, Worker};
use wipstash_transport::{Client, Config, KeySource, Result, Service, Workstation};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    engine: PathBuf,
    state: PathBuf,
    staging: PathBuf,
    ca: PathBuf,
    certificate: PathBuf,
    key: KeySource,
    server_name: String,
    authority_fingerprint: String,
    address: SocketAddr,
    project: String,
    authority: String,
    epoch: u64,
    device: String,
    authority_device: String,
}
#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum Operation {
    #[serde(rename = "upload")]
    Upload {
        proposal: String,
        operation_id: String,
    },
    #[serde(rename = "download")]
    Download {
        kind: String,
        operation_id: String,
        proposal: Option<String>,
    },
    #[serde(rename = "catch_up")]
    CatchUp,
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "serve" {
        let config: Config = serde_json::from_slice(&std::fs::read(&args[2])?)?;
        let mut worker = AuthorityWorker::open_with_limits(
            config.engine.clone(),
            config.state.clone(),
            config.staging.clone(),
            config.limits.clone(),
        )
        .await?;
        let service = Service::new(config).await?;
        return tokio::select! { result = service.serve() => result, result = worker.run() => result };
    }
    let background = args.len() == 3 && args[1] == "worker";
    if !background && (args.len() != 4 || args[1] != "client") {
        return Err("usage: wipstash-transport serve /absolute/service.json | worker /absolute/client.json | client /absolute/client.json '<JSON operation>'".into());
    }
    let c: ClientConfig = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    let client = Client::from_key_source(
        &c.ca,
        &c.certificate,
        &c.key,
        c.server_name,
        c.authority_fingerprint,
    )?;
    let w = Workstation {
        client,
        address: c.address,
        engine: c.engine,
        state: c.state,
        staging: c.staging,
        project: c.project,
        authority: c.authority,
        epoch: c.epoch,
        device: c.device,
        authority_device: c.authority_device,
    };
    if background {
        let mut worker = Worker::open(w.engine.clone(), w.state.clone(), w).await?;
        return worker.run().await;
    }
    let result: Value = match serde_json::from_str::<Operation>(&args[3])? {
        Operation::Upload {
            proposal,
            operation_id,
        } => w.upload(&proposal, &operation_id).await?,
        Operation::Download {
            kind,
            operation_id,
            proposal,
        } => {
            w.download(&kind, &operation_id, proposal.as_deref())
                .await?
        }
        Operation::CatchUp => w.catch_up().await?,
    };
    println!("{}", result);
    Ok(())
}

#[cfg(test)]
mod key_configuration_tests {
    use super::*;
    #[test]
    fn client_configuration_accepts_exactly_one_source_without_lookup() {
        let mut value = serde_json::json!({
            "engine":"/synthetic/engine", "state":"/synthetic/state",
            "staging":"/synthetic/staging", "ca":"/synthetic/ca",
            "certificate":"/synthetic/cert", "key":"/synthetic/key",
            "server_name":"localhost", "authority_fingerprint":"synthetic",
            "address":"127.0.0.1:12345", "project":"p", "authority":"a",
            "epoch":1, "device":"d", "authority_device":"ad"
        });
        assert!(serde_json::from_value::<ClientConfig>(value.clone()).is_ok());
        value["key"] = serde_json::json!({"native_vault":"wipstash/test-tls"});
        assert!(serde_json::from_value::<ClientConfig>(value.clone()).is_ok());
        value["key_file"] = serde_json::json!("/synthetic/fallback");
        assert!(serde_json::from_value::<ClientConfig>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove("key_file");
        let text = serde_json::to_string(&value).unwrap();
        let duplicate = text.replacen('{', r#"{"key":"/synthetic/fallback","#, 1);
        assert!(serde_json::from_str::<ClientConfig>(&duplicate).is_err());
    }
}
