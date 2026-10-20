use serde::Deserialize;
use serde_json::Value;
use wipstash_transport::daemon::{AuthorityWorker, Worker};
use wipstash_transport::{Config, Result, Service};

use wipstash_transport::settings::ClientConfig;
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
    #[serde(rename = "audit_flush")]
    AuditFlush,
    #[serde(rename = "coordination_flush")]
    CoordinationFlush,
    #[serde(rename = "catch_up")]
    CatchUp,
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "cloud-route" {
        use base64::Engine;
        use tokio::io::AsyncReadExt;
        let config: Config = serde_json::from_slice(&std::fs::read(&args[2])?)?;
        let mut input = Vec::new();
        tokio::io::stdin()
            .take((wipstash_transport::WIRE_MAX * 2) as u64)
            .read_to_end(&mut input)
            .await?;
        let value: Value = serde_json::from_slice(&input)?;
        let decode = |field: &str| -> Result<Vec<u8>> {
            Ok(base64::engine::general_purpose::STANDARD
                .decode(value[field].as_str().ok_or("missing_field")?)?)
        };
        let service = Service::new(config).await?;
        let result = service
            .route(
                &decode("certificate")?,
                value["method"].as_str().ok_or("missing_method")?,
                value["path"].as_str().ok_or("missing_path")?,
                &decode("body")?,
            )
            .await;
        let result = match result {
            Ok((kind, bytes)) => {
                serde_json::json!({"ok":true,"content_type":kind,"body":base64::engine::general_purpose::STANDARD.encode(bytes)})
            }
            Err(e) => serde_json::json!({"ok":false,"error":e.to_string()}),
        };
        println!("{result}");
        return Ok(());
    }
    if wipstash_transport::pairing_cli::run(&args[1..]).await? {
        return Ok(());
    }
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
    let w = c.connect()?;
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
        Operation::AuditFlush => w.flush_audit().await?,
        Operation::CoordinationFlush => w.flush_coordination().await?,
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
