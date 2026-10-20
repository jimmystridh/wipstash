# Current agent workflow coverage

`uv run --no-project python tests/cli.py` exercises the installed interface: exact staging, unstaging, discovery, independent clones, shared commits, conflict review, task comments, lifecycle, audit and process-crash recovery. Build both binaries with `cargo build --bins` first. `WIP_BINARY` selects a release CLI. No model sessions, MCP connections or client services are started.

`uv run --no-project python tests/async_validation.py` checks background validation through real CLI processes: sharing while a check is held open, exact-head evidence, owner-only notices, inherited-failure deduplication, atomic repair handoff, stale leases, worker restart, coalescing and bounded infrastructure retries. `--artifacts PATH` retains measured operation timings. See [the background validation contract](../docs/BACKGROUND-VALIDATION.md).

`python tests/shared_commit.py` exercises the only current agent save/share action: `wip commit`. It uses real CLI subprocesses, Git and SQLite with four isolated scripted actors. It covers rejection of removed split actions, one-call integration, concurrent commits, required checks, public conflict resolution, private adoption reconciliation, duplicate/lost replies and crash recovery without recapturing newer files. Use `--binary PATH --artifacts PATH` to retain a sanitized summary.

Reports and fixture campaigns below that describe checkpoint/publish/integrate concern lower-level storage primitives or historical revisions. They are not an alternative current agent workflow. The native ergonomics CI job runs the current single-commit suite.

# Independent adversarial integration tests

Run from the repository root after building:

    cargo build
    python3 tests/adversarial.py

`--binary PATH` selects a binary; `--artifacts PATH` selects an evidence directory.

These tests launch real `wipstash` subprocesses against Git objects and persisted local state. The four actors are deterministic Python-scripted personas in distinct directories, with concurrent checkpoint and publication processes. They are **not** real Codex or Claude Code agent sessions, separate operating-system users, separate devices, or an authenticated network deployment.

The checked-in fixture matches the proposed adversarial fixture, with exact-byte hashes in `fixtures/manifest.json`. Synthetic excluded canaries are not real credentials. Tests retain every CLI request, response, exit status and timing, plus fixture/store state for diagnosis. No GitHub destination is configured.

Assertions cover disjoint concurrent proposals, same-line conflict quarantine and unrelated progress, immutable broken-source publication, no implicit adoption, sanitized public object reachability, operation identity binding/retries, stale generations, dirty adoption conflict, private/excluded file preservation, binary/CRLF/executable-bit round trips, and actual process termination at promotion/adoption failpoints.

A successful run establishes only the exercised local prototype behavior. It does not establish power-loss durability, storage-loss recovery, native macOS/Windows compatibility, authenticated remote isolation, arbitrary external writer containment, autonomous model conflict repair, or GitHub backup/restore. Fault hooks explicitly exit the process; they are not power failures. Retained-state restart is required before recovery assertions.


## Native guided pairing acceptance (CI only)

`pairing_live_ci.py` is separate from the local adversarial harness. It runs the
actual engine and transport CLIs with disposable synthetic credentials, four
independent device profiles, isolated enrollment/sync loopback listeners, online
diagnosis, pending invitation cancellation, revocation, certificate replacement
and an owned server restart. It checks preserved device identity and source state,
no implicit publication/adoption, and excluded-marker absence from public objects.
The actors share one runner; they are not four physical machines or AI sessions.

Only execute on an authorized native GitHub Actions runner. The script requires
both the runner-provided `GITHUB_ACTIONS=true` and explicit
`WIPSTASH_PAIRING_LIVE_CI=1`; outside that guard it exits 2 without running the
scenario. Do not spoof the CI guard to run sockets locally.

```sh
cargo build --locked
cargo build --locked --manifest-path services/transport/Cargo.toml
WIPSTASH_PAIRING_LIVE_CI=1 python tests/pairing_live_ci.py --artifacts evidence/pairing-live
```

Defaults select `target/debug/wipstash` and
`services/transport/target/debug/wipstash-transport` (with `.exe` on Windows).
`--binary` and `--transport` override them. Only retain `summary.json` and
`safe-stderr.txt` as artifacts. Never upload the temporary profile/state tree,
private keys, invitation bodies or raw command output.

## Real TLS resumable upload-fault campaign (CI only)

`services/transport/tests/live_tls_ci.rs` is an ignored integration test with an
owned real loopback mTLS listener and four scripted identities using the legacy
file-ACL path. It is distinct from guided pairing. Its assertions cover certificate
and ACL denials, cross-device upload isolation, durable partial transfer restart,
exact chunk/final acknowledgment replay, application delay, a pre-send drop and a
post-commit lost acknowledgment, deliberate publication, public-object privacy and
preserved private worktrees. The campaign passed on Linux at functional commit
`1488774be3582fb0322de74f1071245ced08f114`; see the exact evidence below.
The earlier fixture `sequence_gap` failure is superseded by the corrected run.

The test is ignored by ordinary `cargo test`. Explicit execution requires both
`GITHUB_ACTIONS=true` and `WIPSTASH_LIVE_TLS_CI=1`. The checked-in native workflow
opts in on Linux only. Compilation on any other runner, when performed, does not
execute the ignored test. On authorized GitHub CI, after building the root engine:

```sh
WIPSTASH_LIVE_TLS_CI=1 \
WIPSTASH_LIVE_TLS_ARTIFACT_DIR="$PWD/evidence/live-tls" \
cargo test --locked --manifest-path services/transport/Cargo.toml \
  --test live_tls_ci four_devices_live_tls_restart_and_faults -- --ignored --nocapture
```

`WIPSTASH_ENGINE` optionally supplies the built root engine path. The optional
artifact directory receives only `summary.json` and a bounded `server.log`;
credential/config/state directories are not copied. Do not run the ignored child
server test directly or bypass the guards. No local socket execution is claimed.
Application-level injected faults are not a real WAN impairment or power failure.

## Evidence checkpoints

Feature checkpoint `42a40025b4d8c3d6b0bfd7bd6b59a597562d5735` passed native
Linux/macOS/Windows, real-CLI guided pairing over loopback TLS, browser interception
and real-HTTP browser runs (53 API requests each), and strict Clippy. Later enrollment
response-bound checks passed too. These supersede historical “native never ran”
and “no listener tested” statements, while the original local adversarial harness
remains narrower evidence on its own.

Functional commit `1488774be3582fb0322de74f1071245ced08f114` passed [native CI 39095243418](https://github.com/jimmystridh/wipstash/actions/runs/39095243418), with Linux, macOS, Windows and browser jobs green, and [bootstrap CI 39095243492](https://github.com/jimmystridh/wipstash/actions/runs/39095243492). The formatter patch was empty.

Real-TLS artifact `12124098556` passed: four device identities, two owned server restarts, a retained offset of 262,144 bytes, eight upload attempts, one pre-send drop, one post-commit lost acknowledgment, one cross-device rejection, six certificate/ACL rejections and two integrated publications. Every stored public Git blob, including unreachable objects, was audited.

At this functional checkpoint, main was still `112f8e7`; release publication requires passing CI on the final cleanup revision. This evidence is revision-specific and does not establish deployed multi-host WAN operation or completion of the full production specification. Preserve exact revisions and CI results; passing functional CI does not certify later edits. See [SCOPE.md](../docs/SCOPE.md) for remaining model-workflow, writer containment, full Windows adoption, real vault, multi-host WAN, GitHub/fresh-host recovery, physical power-loss and performance gates.

Central audit contracts: `cargo test --locked audit::tests`, `uv run --no-project python tests/audit_collector.py`, and the transport security/daemon suites exercise integrity, lost acknowledgements, device binding, native history scoping and persisted retries. The native collector tests use synthetic histories and the real engine; they do not start model sessions.


## Concurrent-agent feedback regressions

`uv run --no-project python tests/agent_experience.py` exercises explicit save/share stages, the README baseline failure, prepared reviews, successful resolution reuse, binary/rename/deletion conflicts, combined-candidate checks, four concurrent advisory claims, leases/expiry, safe archive/reopen, generated-file visibility and crash recovery. Set `WIPSTASH_EXPERIENCE_ARTIFACTS` to save scenario metrics. `native_agent_experience.py --run-native --artifacts ABSOLUTE_NEW_PATH` is a separate opt-in test using installed Codex, Claude Code, OpenCode and Pi model accounts; its isolated fixture and normal CLI access never change global settings. See [the collaboration contracts](../docs/AGENT-COLLABORATION.md).
