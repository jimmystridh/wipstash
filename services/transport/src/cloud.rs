//! Explicit HTTPS mode for managed TLS frontends. Native mTLS remains unchanged.
use crate::{certs, error, fingerprint, KeySource, Result, OUTPUT_MAX, WIRE_MAX};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature,
};
use serde_json::json;
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct HttpsClient {
    endpoint: String,
    certificate: Vec<u8>,
    signer: signature::EcdsaKeyPair,
    http: reqwest::Client,
}

impl HttpsClient {
    pub fn new(endpoint: String, certificate: &Path, key: &KeySource) -> Result<Self> {
        let url = reqwest::Url::parse(&endpoint)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || endpoint.ends_with('/')
        {
            return Err(error("invalid_https_endpoint"));
        }
        let key = key.load()?;
        let rustls::pki_types::PrivateKeyDer::Pkcs8(key) = key else {
            return Err(error("cloud_requires_p256_pkcs8"));
        };
        let signer = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            key.secret_pkcs8_der(),
            &SystemRandom::new(),
        )
        .map_err(|_| error("cloud_requires_p256_pkcs8"))?;
        let certificates = certs(certificate)?;
        if certificates.len() != 1 {
            return Err(error("one_client_certificate_required"));
        }
        Ok(Self {
            endpoint,
            certificate: certificates[0].as_ref().to_vec(),
            signer,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(90))
                .https_only(true)
                .build()?,
        })
    }

    pub async fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        if body.len() > WIRE_MAX
            || method.len() > 16
            || path.len() > 512
            || !path.starts_with("/v1/")
        {
            return Err(error("client_request_bound"));
        }
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| error("randomness_unavailable"))?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let nonce = fingerprint(&nonce);
        let message = serde_json::to_vec(&json!([
            "wipstash-cloudrun-v1",
            self.endpoint,
            method,
            path,
            timestamp,
            nonce,
            fingerprint(body)
        ]))?;
        let signature = self
            .signer
            .sign(&SystemRandom::new(), &message)
            .map_err(|_| error("cloud_signature_failed"))?;
        let mut response = self
            .http
            .post(format!("{}/rpc", self.endpoint))
            .json(&json!({
                "certificate": STANDARD.encode(&self.certificate), "method": method, "path":path,
                "timestamp":timestamp,"nonce":nonce,"signature":STANDARD.encode(signature.as_ref()),
                "body":STANDARD.encode(body)
            }))
            .send()
            .await?;
        if matches!(response.status().as_u16(), 429 | 503) {
            return Err(Box::new(crate::RetryableStatus {
                delay: Duration::from_secs(1),
            }));
        }
        if !response.status().is_success() {
            return Err(error("remote_rejected"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > OUTPUT_MAX {
                return Err(error("response_bound"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_insecure_or_ambiguous_endpoints_before_loading_credentials() {
        for endpoint in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com/a",
            "https://example.com/?x",
            "https://example.com/",
        ] {
            assert!(HttpsClient::new(
                endpoint.into(),
                Path::new("missing"),
                &KeySource::File("missing".into())
            )
            .is_err());
        }
    }
}
