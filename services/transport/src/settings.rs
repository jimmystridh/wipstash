use crate::{Client, KeySource, Result, Workstation};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub engine: PathBuf,
    pub state: PathBuf,
    pub staging: PathBuf,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: KeySource,
    pub server_name: String,
    pub authority_fingerprint: String,
    pub address: SocketAddr,
    pub project: String,
    pub authority: String,
    pub epoch: u64,
    pub device: String,
    pub authority_device: String,
    #[serde(default)]
    pub https_endpoint: Option<String>,
}

impl ClientConfig {
    pub fn connect(self) -> Result<Workstation> {
        let mut client = Client::from_key_source(
            &self.ca,
            &self.certificate,
            &self.key,
            self.server_name,
            self.authority_fingerprint,
        )?;
        if let Some(endpoint) = self.https_endpoint {
            client.cloud = Some(crate::cloud::HttpsClient::new(
                endpoint,
                &self.certificate,
                &self.key,
            )?);
        }
        Ok(Workstation {
            client,
            address: self.address,
            engine: self.engine,
            state: self.state,
            staging: self.staging,
            project: self.project,
            authority: self.authority,
            epoch: self.epoch,
            device: self.device,
            authority_device: self.authority_device,
        })
    }
}
