//! Synthetic, offline pressure tests. Each worker owns a separate SQLite
//! connection; barriers create contention without listeners or process killing.
use crate::auth::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::digest;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
    time::{Duration, Instant},
};

const NOW: i64 = 1_800_000_000;
const RESOURCE: &str = "https://wipstash.example/mcp";
const CLIENT: &str = "https://chatgpt.example/client.json";
const REDIRECT: &str = "https://chatgpt.example/callback";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const WORKERS: usize = 8;
const ROUNDS: usize = 96;
// The original 45-second Linux-derived limit was not a cross-platform SLO:
// macOS CI reached only 51/96 rounds before it stopped scheduling. Preserve
// that observation threshold in logs, but give this correctness workload a
// separate cooperative scheduling deadline. It cannot interrupt a blocked
// operation/barrier/join; the CI job retains its outer timeout. Never reduce
// work or SQLite durability.
const PERFORMANCE_REFERENCE: Duration = Duration::from_secs(45);
const LIVENESS_BUDGET: Duration = Duration::from_secs(300);

fn user(id: u64) -> GithubUserId {
    GithubUserId::new(id).unwrap()
}
fn identity(id: u64) -> VerifiedGithubIdentity {
    // The same crate-private synthetic identity boundary used by auth unit tests.
    VerifiedGithubIdentity::from_github_user(id, format!("pressure-{id}")).unwrap()
}
fn config() -> AuthConfig {
    AuthConfig {
        issuer: "https://wipstash.example".into(),
        resource: RESOURCE.into(),
        clients: vec![RegisteredClient {
            client_id: CLIENT.into(),
            name: "Synthetic pressure client".into(),
            redirect_uris: vec![REDIRECT.into()],
        }],
        administrators: [user(1)].into_iter().collect(),
    }
}
fn private_path() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let private = root.path().canonicalize().unwrap().join("private");
    wipstash_transport::pairing_files::ensure_private_dir(&private).unwrap();
    (root, private.join("auth.sqlite"))
}
fn code(store: &AuthStore, id: u64, project: &str) -> String {
    let start = store
        .begin_authorization(
            AuthorizationRequest {
                client_id: CLIENT.into(),
                redirect_uri: REDIRECT.into(),
                resource: RESOURCE.into(),
                state: "synthetic-pressure-state".into(),
                code_challenge: URL_SAFE_NO_PAD
                    .encode(digest::digest(&digest::SHA256, VERIFIER.as_bytes()).as_ref()),
                code_challenge_method: "S256".into(),
                projects: vec![project.into()],
            },
            NOW,
        )
        .unwrap();
    let callback = store
        .take_github_callback(&start.state, &start.browser_binding, NOW)
        .unwrap();
    let consent = store
        .complete_github_login(callback, identity(id), NOW)
        .unwrap();
    store
        .approve_consent(
            &consent.flow_id,
            &start.browser_binding,
            &consent.csrf_token,
            NOW,
        )
        .unwrap()
        .code
}
fn exchange(code: &str) -> CodeExchange {
    CodeExchange {
        code: code.into(),
        client_id: CLIENT.into(),
        redirect_uri: REDIRECT.into(),
        resource: RESOURCE.into(),
        code_verifier: VERIFIER.into(),
    }
}
fn refresh(token: &str) -> RefreshExchange {
    RefreshExchange {
        refresh_token: token.into(),
        client_id: CLIENT.into(),
        resource: RESOURCE.into(),
    }
}
fn tokens(store: &AuthStore, id: u64, project: &str) -> TokenPair {
    store
        .exchange_code(exchange(&code(store, id, project)), NOW)
        .unwrap()
}

/// Panics are caught inside each worker so the other participants can leave
/// their barriers and every thread is joined before an assertion can fail.
fn race<I, O, F>(
    phase: &str,
    path: &Path,
    inputs: Vec<I>,
    started: Instant,
    operation: F,
) -> Vec<Vec<O>>
where
    I: Send + Sync + 'static,
    O: Send + 'static,
    F: Fn(&AuthStore, &I) -> O + Send + Sync + 'static,
{
    let phase_started = Instant::now();
    eprintln!(
        "AUTH_PRESSURE_PHASE_START phase={phase} total_elapsed_ms={}",
        started.elapsed().as_millis()
    );
    let stores: Vec<_> = (0..WORKERS)
        .map(|_| AuthStore::open(path, config()).unwrap())
        .collect();
    let barrier = Arc::new(Barrier::new(WORKERS));
    let stop = Arc::new(AtomicBool::new(false));
    let inputs = Arc::new(inputs);
    let operation = Arc::new(operation);
    let expected = inputs.len();
    let handles: Vec<_> = stores
        .into_iter()
        .map(|store| {
            let barrier = Arc::clone(&barrier);
            let stop = Arc::clone(&stop);
            let inputs = Arc::clone(&inputs);
            let operation = Arc::clone(&operation);
            thread::spawn(move || {
                let mut results = Vec::with_capacity(inputs.len());
                let mut panicked = false;
                for input in inputs.iter() {
                    if started.elapsed() >= LIVENESS_BUDGET {
                        stop.store(true, Ordering::SeqCst);
                    }
                    barrier.wait();
                    // Snapshot stop while no worker can enter its operation:
                    // a panic after the second barrier cannot split this phase.
                    let stopping = stop.load(Ordering::SeqCst);
                    barrier.wait();
                    if stopping {
                        break;
                    }
                    match catch_unwind(AssertUnwindSafe(|| operation(&store, input))) {
                        Ok(result) => results.push(result),
                        Err(_) => {
                            panicked = true;
                            stop.store(true, Ordering::SeqCst);
                        }
                    }
                }
                (panicked, results)
            })
        })
        .collect();
    // Collect all joins before inspecting any outcome, including panic paths.
    let joined: Vec<_> = handles.into_iter().map(|handle| handle.join()).collect();
    let mut outcomes = Vec::with_capacity(WORKERS);
    for (worker, joined) in joined.into_iter().enumerate() {
        let (panicked, results) = joined.expect("pressure worker join failed");
        eprintln!("AUTH_PRESSURE_WORKER phase={phase} worker={worker} completed_rounds={} expected_rounds={expected} phase_elapsed_ms={} total_elapsed_ms={}", results.len(), phase_started.elapsed().as_millis(), started.elapsed().as_millis());
        assert!(!panicked, "authorization operation panicked under pressure");
        assert_eq!(results.len(), expected, "pressure liveness budget exhausted in {phase}; elapsed={:?}, required rounds={expected}", started.elapsed());
        outcomes.push(results);
    }
    eprintln!("AUTH_PRESSURE_PHASE_OK phase={phase} rounds={expected} workers={WORKERS} phase_elapsed_ms={} total_elapsed_ms={}", phase_started.elapsed().as_millis(), started.elapsed().as_millis());
    outcomes
}

fn assert_invalid_token(result: AuthResult<Principal>) {
    assert!(matches!(result, Err(AuthError::InvalidToken)));
}
fn assert_invalid_grant<T>(result: AuthResult<T>) {
    assert!(matches!(result, Err(AuthError::InvalidGrant)));
}

#[test]
fn auth_pressure_separate_connections_keep_single_use_and_revocation_after_restart() {
    let started = Instant::now();
    let (_root, path) = private_path();
    let store = AuthStore::open(&path, config()).unwrap();
    let invitations: Vec<_> = (0..ROUNDS)
        .map(|round| {
            let id = 100 + round as u64;
            let invite = store
                .issue_invitation_local(user(id), "alpha", NOW)
                .unwrap();
            (id, invite.token)
        })
        .collect();
    let saved_invitations = invitations.clone();
    let redeemed = race(
        "invitation-redemption",
        &path,
        invitations,
        started,
        |store, (id, token)| store.redeem_invitation(&identity(*id), token, NOW),
    );
    for round in 0..ROUNDS {
        let winners = redeemed
            .iter()
            .filter(|worker| matches!(&worker[round], Ok(project) if project == "alpha"))
            .count();
        assert_eq!(winners, 1, "invite round {round} had {winners} winners");
        for result in redeemed.iter().map(|worker| &worker[round]) {
            assert!(matches!(result, Ok(_) | Err(AuthError::InvalidGrant)));
        }
    }

    store.grant_project_local(user(7), "alpha", NOW).unwrap();
    let codes: Vec<_> = (0..ROUNDS).map(|_| code(&store, 7, "alpha")).collect();
    let saved_codes = codes.clone();
    let exchanged = race(
        "authorization-code-exchange",
        &path,
        codes,
        started,
        |store, code| store.exchange_code(exchange(code), NOW),
    );
    let mut code_winners = Vec::new();
    for round in 0..ROUNDS {
        let winners: Vec<_> = exchanged
            .iter()
            .filter_map(|worker| worker[round].as_ref().ok())
            .collect();
        assert_eq!(winners.len(), 1, "code round {round} was not single-use");
        let winner = winners[0];
        // A valid replay must also revoke the winning code's derived family.
        assert_invalid_token(store.authenticate_access(&winner.access_token, RESOURCE, NOW));
        assert_invalid_grant(store.rotate_refresh(refresh(&winner.refresh_token), NOW));
        code_winners.push((winner.access_token.clone(), winner.refresh_token.clone()));
        for result in exchanged.iter().map(|worker| &worker[round]) {
            assert!(matches!(result, Ok(_) | Err(AuthError::InvalidGrant)));
        }
    }

    let originals: Vec<_> = (0..ROUNDS).map(|_| tokens(&store, 7, "alpha")).collect();
    let refresh_inputs: Vec<_> = originals.iter().map(|p| p.refresh_token.clone()).collect();
    let rotated = race(
        "refresh-rotation",
        &path,
        refresh_inputs,
        started,
        |store, token| store.rotate_refresh(refresh(token), NOW + 1),
    );
    let mut refresh_winners = Vec::new();
    for (round, original) in originals.iter().enumerate() {
        let winners: Vec<_> = rotated
            .iter()
            .filter_map(|worker| worker[round].as_ref().ok())
            .collect();
        assert_eq!(winners.len(), 1, "refresh round {round} was not single-use");
        let winner = winners[0];
        assert_ne!(winner.refresh_token, original.refresh_token);
        assert_invalid_token(store.authenticate_access(&original.access_token, RESOURCE, NOW + 1));
        assert_invalid_token(store.authenticate_access(&winner.access_token, RESOURCE, NOW + 1));
        assert_invalid_grant(store.rotate_refresh(refresh(&winner.refresh_token), NOW + 1));
        refresh_winners.push((winner.access_token.clone(), winner.refresh_token.clone()));
        for result in rotated.iter().map(|worker| &worker[round]) {
            assert!(matches!(result, Ok(_) | Err(AuthError::RefreshReuse)));
        }
    }
    drop(store);

    // Persisted replay markers survive a real close/reopen and normal pruning.
    let reopened = AuthStore::open(&path, config()).unwrap();
    reopened.prune_expired(NOW + 2).unwrap();
    for (id, invite) in saved_invitations {
        assert_invalid_grant(reopened.redeem_invitation(&identity(id), &invite, NOW + 2));
        assert!(reopened.has_project_access(user(id), "alpha").unwrap());
    }
    for code in saved_codes {
        assert_invalid_grant(reopened.exchange_code(exchange(&code), NOW + 2));
    }
    for original in &originals {
        assert!(matches!(
            reopened.rotate_refresh(refresh(&original.refresh_token), NOW + 2),
            Err(AuthError::RefreshReuse)
        ));
    }
    for (access, token) in code_winners.iter().chain(&refresh_winners) {
        assert_invalid_token(reopened.authenticate_access(access, RESOURCE, NOW + 2));
        assert_invalid_grant(reopened.rotate_refresh(refresh(token), NOW + 2));
    }

    // Three explicit visibility phases avoid classifying a read that overlaps
    // revocation as stale: all rejected calls start after the revoke commits.
    let live = tokens(&reopened, 7, "alpha");
    let stale_code = code(&reopened, 7, "alpha");
    let stale_invite = reopened
        .issue_invitation_local(user(7), "alpha", NOW)
        .unwrap();
    let epoch = reopened.project_grant_epoch("7", "alpha").unwrap().unwrap();
    let live_access = live.access_token.clone();
    let accepted = race(
        "live-access",
        &path,
        vec![(); ROUNDS],
        started,
        move |store, _| store.authenticate_access(&live_access, RESOURCE, NOW + 3),
    );
    assert!(accepted.iter().flatten().all(Result::is_ok));
    reopened
        .revoke_project_local(user(7), "alpha", NOW + 3)
        .unwrap();
    assert!(!reopened.has_any_project_access("7").unwrap());
    let dead_access = live.access_token.clone();
    let denied = race(
        "revoked-access",
        &path,
        vec![(); ROUNDS],
        started,
        move |store, _| store.authenticate_access(&dead_access, RESOURCE, NOW + 3),
    );
    assert!(denied
        .iter()
        .flatten()
        .all(|r| matches!(r, Err(AuthError::InvalidToken))));
    reopened
        .grant_project_local(user(7), "alpha", NOW + 4)
        .unwrap();
    assert!(reopened.project_grant_epoch("7", "alpha").unwrap().unwrap() > epoch);
    drop(reopened);
    let restarted = AuthStore::open(&path, config()).unwrap();
    let fresh = tokens(&restarted, 7, "alpha");
    let dead_access = live.access_token.clone();
    let dead_refresh = live.refresh_token.clone();
    let current_access = fresh.access_token.clone();
    let mixed = race(
        "regrant-and-restart",
        &path,
        vec![(); ROUNDS],
        started,
        move |store, _| {
            (
                store.authenticate_access(&dead_access, RESOURCE, NOW + 4),
                store.rotate_refresh(refresh(&dead_refresh), NOW + 4),
                store.authenticate_access(&current_access, RESOURCE, NOW + 4),
                store.exchange_code(exchange(&stale_code), NOW + 4),
                store.redeem_invitation(&identity(7), &stale_invite.token, NOW + 4),
            )
        },
    );
    for (old_access, old_refresh, new_access, old_code, old_invite) in mixed.into_iter().flatten() {
        assert_invalid_token(old_access);
        assert_invalid_grant(old_refresh);
        assert!(new_access.is_ok());
        assert!(matches!(
            old_code,
            Err(AuthError::AccessDenied | AuthError::InvalidGrant)
        ));
        assert_invalid_grant(old_invite);
    }

    // Read-only persisted invariants, independent of the AuthStore read API.
    let db =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let duplicate_grants: i64 = db.query_row(
        "SELECT count(*) FROM (SELECT github_user_id,project,count(*) AS n FROM auth_grants GROUP BY github_user_id,project HAVING n>1)",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(duplicate_grants, 0);
    let integrity: String = db
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert!(
        started.elapsed() < LIVENESS_BUDGET,
        "pressure test exceeded 300-second liveness guard"
    );
    if started.elapsed() > PERFORMANCE_REFERENCE {
        eprintln!("AUTH_PRESSURE_PERFORMANCE_REFERENCE_EXCEEDED reference_seconds=45 elapsed_ms={}; correctness completion is not a throughput guarantee", started.elapsed().as_millis());
    }
    eprintln!(
        "AUTH_PRESSURE_OK workers={WORKERS} rounds={ROUNDS} contested_calls={} visibility_calls={} elapsed_ms={}",
        WORKERS * ROUNDS * 3,
        WORKERS * ROUNDS * 7,
        started.elapsed().as_millis()
    );
}
