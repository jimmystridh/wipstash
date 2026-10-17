//! Synthetic fixtures only: these tests never call NativeVault::read.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use wipstash_platform::vault::{CredentialKey, CredentialVault, Secret, VaultError};

struct FailedVault {
    failure: VaultError,
    reads: AtomicUsize,
}
impl CredentialVault for FailedVault {
    fn read(&self, key: &CredentialKey) -> std::result::Result<Secret, VaultError> {
        assert_eq!(key.as_str(), "wipstash/test-tls");
        self.reads.fetch_add(1, Ordering::SeqCst);
        Err(self.failure.clone())
    }
}
fn failed(failure: VaultError) -> FailedVault {
    FailedVault {
        failure,
        reads: AtomicUsize::new(0),
    }
}
#[test]
fn exclusive_key_configuration_and_legacy_file_shape() {
    let file: KeySource = serde_json::from_str(r#""/synthetic/key.pem""#).unwrap();
    assert!(matches!(file, KeySource::File(_)));
    let vault: KeySource = serde_json::from_str(r#"{"native_vault":"wipstash/test-tls"}"#).unwrap();
    assert!(matches!(vault, KeySource::NativeVault { .. }));
    for invalid in [
        r#"null"#,
        r#"[]"#,
        r#"{}"#,
        r#"{"file":"key.pem"}"#,
        r#"{"native_vault":""}"#,
        r#"{"native_vault":"bad id"}"#,
        r#"{"native_vault":"wipstash/test-tls","file":"key.pem"}"#,
        r#"{"native_vault":"wipstash/test-tls","fallback":"key.pem"}"#,
        r#"{"native_vault":"one","native_vault":"two"}"#,
    ] {
        assert!(
            serde_json::from_str::<KeySource>(invalid).is_err(),
            "{invalid}"
        );
    }
}
#[test]
fn vault_failures_remain_failures_without_file_fallback() {
    let source: KeySource =
        serde_json::from_str(r#"{"native_vault":"wipstash/test-tls"}"#).unwrap();
    for failure in [
        VaultError::Unavailable,
        VaultError::Locked,
        VaultError::NotFound,
        VaultError::Ambiguous,
        VaultError::InvalidSecret,
    ] {
        let vault = failed(failure.clone());
        let err = source.load_with_vault(&vault).unwrap_err();
        assert_eq!(err.downcast_ref::<VaultError>(), Some(&failure));
        assert_eq!(vault.reads.load(Ordering::SeqCst), 1);
    }
    let vault = failed(VaultError::Unavailable);
    let invalid = KeySource::NativeVault {
        native_vault: "bad id".into(),
    };
    assert!(invalid.load_with_vault(&vault).is_err());
    assert_eq!(vault.reads.load(Ordering::SeqCst), 0);
}
#[test]
fn bounded_single_key_parser_and_file_source() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = generated.key_pair.serialize_pem();
    assert!(parse_private_key(pem.as_bytes()).is_ok());
    let double = format!("{pem}{pem}");
    assert_eq!(
        parse_private_key(double.as_bytes())
            .unwrap_err()
            .to_string(),
        "ambiguous_private_key"
    );
    for invalid in [
        Vec::new(),
        vec![0; TLS_KEY_MAX + 1],
        b"not a PEM key".to_vec(),
        b"-----BEGIN PRIVATE KEY-----\n!invalid!\n-----END PRIVATE KEY-----".to_vec(),
        generated.cert.pem().into_bytes(),
    ] {
        assert!(parse_private_key(&invalid).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-key.pem");
    std::fs::write(&path, &pem).unwrap();
    let vault = failed(VaultError::Unavailable);
    let source = KeySource::File(path.clone());
    assert!(source.load_with_vault(&vault).is_ok());
    assert_eq!(vault.reads.load(Ordering::SeqCst), 0);
    std::fs::write(&path, vec![0; TLS_KEY_MAX + 1]).unwrap();
    assert!(source.load_with_vault(&vault).is_err());
    assert_eq!(vault.reads.load(Ordering::SeqCst), 0);
    let cert_path = dir.path().join("synthetic-cert.pem");
    std::fs::write(&cert_path, vec![0; TLS_CERT_MAX + 1]).unwrap();
    assert!(certs(&cert_path).is_err());
}
#[test]
fn parsed_synthetic_keys_build_both_tls_roles_and_legacy_client() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = generated.key_pair.serialize_pem();
    let cert = generated.cert.der().clone();
    let mut trust = RootCertStore::empty();
    trust.add(cert.clone()).unwrap();
    assert!(server_tls(
        trust.clone(),
        vec![cert.clone()],
        parse_private_key(pem.as_bytes()).unwrap()
    )
    .is_ok());
    assert!(client_tls(
        trust,
        vec![cert.clone()],
        parse_private_key(pem.as_bytes()).unwrap()
    )
    .is_ok());
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("synthetic-cert.pem");
    let key_path = dir.path().join("synthetic-key.pem");
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, pem).unwrap();
    assert!(Client::from_files(
        &cert_path,
        &cert_path,
        &key_path,
        "localhost".into(),
        fingerprint(cert.as_ref())
    )
    .is_ok());
}

#[test]
fn server_configuration_accepts_exactly_one_source() {
    let base = serde_json::json!({
        "engine":"/synthetic/engine", "state":"/synthetic/state",
        "staging":"/synthetic/staging", "project":"p", "authority":"a",
        "epoch":1, "device":"d", "acl":"/synthetic/acl",
        "ca":"/synthetic/ca", "certificate":"/synthetic/cert",
        "key":"/synthetic/key", "listen":"127.0.0.1:12345"
    });
    assert!(serde_json::from_value::<Config>(base.clone()).is_ok());
    let mut native = base.clone();
    native["key"] = serde_json::json!({"native_vault":"wipstash/test-tls"});
    assert!(serde_json::from_value::<Config>(native.clone()).is_ok());
    native["key_file"] = serde_json::json!("/synthetic/fallback");
    assert!(serde_json::from_value::<Config>(native).is_err());
    let text = serde_json::to_string(&base).unwrap();
    let duplicate = text.replacen('{', r#"{"key":{"native_vault":"wipstash/test-tls"},"#, 1);
    assert!(serde_json::from_str::<Config>(&duplicate).is_err());
}
