//! Managed authorization must be bound to this exact coordinator before service start.
use super::*;

#[tokio::test]
async fn managed_authority_binding_mismatch_fails_before_engine_launch() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    pairing_files::ensure_private_dir(&root).unwrap();
    let state = root.join("state");
    let staging = root.join("staging");
    pairing_files::ensure_private_dir(&state).unwrap();
    pairing_files::ensure_private_dir(&staging).unwrap();
    let managed = root.join("pairing.sqlite");
    let store = pairing::PairingStore::open(&managed).unwrap();
    store
        .initialize(&pairing::AuthorityBinding {
            project: "project".into(),
            authority: "authority".into(),
            epoch: 1,
            authority_device: "coordinator".into(),
        })
        .unwrap();
    let config = Config {
        engine: root.join("engine-must-not-run"),
        state,
        staging,
        project: "project".into(),
        authority: "authority".into(),
        epoch: 2,
        device: "coordinator".into(),
        acl: AclSource::Managed { managed },
        ca: root.join("unused-ca"),
        certificate: root.join("unused-cert"),
        key: root.join("unused-key").into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        limits: Limits::default(),
    };
    match Service::new(config).await {
        Ok(_) => panic!("mismatched managed authority must not start"),
        Err(error) => assert_eq!(error.to_string(), "managed_authority_binding_mismatch"),
    }
}
