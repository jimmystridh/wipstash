# Scope, evidence and release gates

## What this release is

This is a Rust local-first vertical slice of the **Bot workspace collaboration specification v1.1 (17 October 2026)** and accompanying **Wipstash implementation plan (17 October 2026)**. Those documents define the target, not features automatically provided by this repository. Their target is a native macOS/Windows/Linux collaboration service for real Codex and Claude Code clients across LAN/WAN, with authenticated authority, reliable writer coordination, confined repair and asynchronous GitHub recovery.

The implementation here is a **cooperative local-first prototype with selected native Linux/macOS/Windows and real loopback TLS acceptance evidence**. One process-shared lock serializes the local engine. One state directory holds SQLite, the coordinator object store, per-workspace private object stores and adoption staging. Workspace directories are ordinary directories outside that state directory. Separate authority/client stores exchange explicit source artifacts. A separate mTLS transport service adds certificate-authenticated admission, per-request project/device ACL checks and bounded resumable uploads. Guided pairing adds managed SQLite authorization, an isolated TLS enrollment endpoint and protected current-account credential files. Native CI has exercised four independent scripted device identities over actual loopback TLS, including join, revocation, rotation and retained-state server restart. This is one runner per scenario, not a deployed multi-host LAN/WAN boundary; see [PAIRING.md](PAIRING.md). Do not deploy this as a production coordinator or use it as your only recovery mechanism.

## Specification vs implementation vs verification

“Implemented” describes code, not a guarantee for untested environments. Tests verify only their fixtures and failure points. Exact final commands, results and counts must be supplied with the final run evidence; this document deliberately does not invent a pass count.

| Target requirement | Current implementation | Verification boundary |
|---|---|---|
| Isolated private WIP; save broken source | Separate directories and private Git stores, explicit checkpoints, default empty check policy | Real Linux CLI/storage fixtures; four scripted actors, not four AI agents or separate users |
| Deliberate publication/integration/adoption | Immutable selected checkpoint export; Git merge; serialized promotion; explicit adopt and update queries | Harness exercises public history, disjoint concurrent proposals, conflicts and unchanged live files before adoption |
| Private ancestry isolation | Public export parents are public base, not private checkpoint chain; fixed exclusions | Synthetic privacy canaries and reachable object inspection; no generic secret scanner |
| Enforced coherent capture and writer leases | Global cooperative engine lock, double capture, generation checks, optional `command_run` | No native agent interception or enforceable lease against external editors; double scan cannot prove coherence |
| Autonomous integration | `worker` loop plus explicit `integrate`; conflicts quarantine and unrelated proposals continue | Local process/storage fixtures plus service worker code; deployed service behavior remains unverified |
| Per-operation command lifecycle | Unix process group cleanup, command timeout, durable pre-launch intent/generation and explicit recovery fence | Escaped descendants can survive; recovery requires caller assertion that writers stopped, not proof of containment |
| Crash recovery | Promotion intent/CAS journal and adoption staging/rollback/finalization | Named process termination failpoints; retained storage restart, not power loss or lost disk |
| Optional checks/repair | Validated trusted argv workers, candidate checkouts, bounded execution/output, durable repair reservations and explicit evidence | Scripted worker fixtures and confined-or-unavailable dispatch; actual model repair and live sandbox execution remain unverified |
| Agent publication-conflict handback | Actionable task, isolated public-snapshot checkout and explicit checkpoint/resubmission, bounded lineage and stale-tip checks; see [CONFLICTS.md](CONFLICTS.md) | New conflict-handback verification pending; real Codex/Claude resolution sessions remain unverified |
| Explicit private conflict resolution | `resolve_adoption` binds candidate, target, generation and current checkpoint | Local explicit-caller resolution only; not automatic private editing |
| Local history/diff inspection | Separate read-only SQLite/Git API and Dioxus WASM UI, loopback only, no engine mutation calls | Synthetic four-workspace/API tests and bounded diff/SSR checks; browser interception and real-HTTP browser CI each passed 53 tests at the feature checkpoint below; deployed acceptance is separate |
| Agent access | JSON CLI/stdin plus bounded MCP lifecycle, typed workflow tools and generic tool | Scripted protocol tests, Codex configuration parsing and Claude Code 2.1.302 stdio handshake/tool discovery; model-driven workflows remain unverified |
| OS-local IPC | Unix socket implementation with 0600 socket permissions | Historical cloud bind attempt was denied with `EPERM`; native platform CI now exercises selected IPC contracts. No cloud-local listener execution is claimed |
| Offline save/replay | Missing coordinator-store detection; local queued proposals and cached heads | Local outage fixtures plus delayed/dropped/replayed artifacts between independent client/authority states; no actual network outage |
| Authenticated LAN/WAN and authority epochs | Typed admission, durable replay/epoch binding and quarantined public source exchange wired to independent client/authority engines | Artifact origin remains operator-asserted on the filesystem path; the separate mTLS service binds certificate identity and rechecks ACL/revocation. In-memory contracts plus native CI real-loopback guided pairing, managed revocation/rotation and restart; no deployed multi-host pairing, remote fencing or migration drill; see NETWORK.md |
| GitHub asynchronous backup | Local bare-repository backup plus separate durable asynchronous GitHub replication library and worker integration | Local/injected transport tests; real GitHub credential, namespace, branch-policy and fresh-host restore acceptance remain open |
| Disaster recovery | Read-only `backup_verify_restore`; separate `restore` reconstructs a public subset in new empty state | Version 2 retains public intent, ownership, eligibility, operation identity, queue and replay metadata. Execution is fenced until explicit `recovery_activate`; private WIP is excluded and operator assertion is not remote fencing |
| Native cross-platform support | Native lifecycle/IPC/vault adapters, strict portable paths and native CI definition | Linux, macOS and Windows CI passed native process/MCP/policy contracts and transport/backup builds; actual native vault access, broader filesystem behavior and installer acceptance remain unvalidated |
| Platform credential storage | Platform vault adapters and allowlisted Git credential-helper integration | Guided pairing uses protected current-account files (Unix modes / Windows DACLs); native vault retrieval with real credentials and deployed remote authentication remain open |
| Retention and garbage collection | Pins retained; separate conservative loose-object collector and storage admission | 32 storage-service tests reported; no automatic pin expiry, transactional reservation, whole-store reclamation or power-loss guarantee |
| Power-loss durability | SQLite WAL/FULL, explicit Git fsync and staged file/directory syncs on Unix | No controlled power-loss, filesystem corruption or storage-loss validation |

## Safety and operational limits

### Cooperative writers are a hard precondition

Stop unmanaged writers before capture and adoption. Generation tokens cover operations performed through this engine; native edits can occur without advancing them. A clean double capture is not an enforced freeze and can observe an intermediate logical edit. The broker serializes managed operations but is not a native agent adapter. Stopping the parent does not reliably terminate every descendant. Do not describe this profile as safe against arbitrary concurrent writers.

The cooperative local profile uses the same OS account and storage trust boundary. An authority label alone is not authentication. State directory permissions and socket permissions do not implement per-device/project authorization or secure shared hosting. The separate mTLS service supplies certificate-backed identity and ACL admission; its deployment still requires independent acceptance. Public and private object separation prevents accidental ancestry export through the intended path, not a same-account attacker reading local files.

### File representation

The Git backend preserves blob bytes without source-project filters, and tests cover binary data, CRLF and executable bits on Linux. Its supported path subset is ASCII only. Symlinks, special files, unsupported entries, case-fold collisions and Windows-reserved/nonportable names are rejected rather than normalized. This restrictive policy does not establish native Windows or macOS compatibility. Submodules, LFS payload synchronization and arbitrary filesystem metadata are not supported release features.

Fixed exclusions include `.git`, `.env` variants, common credentials/key names, dependency/build/cache directories and agent metadata/transcript directories. Inspect `src/git.rs` for the authoritative list. Exclusion is based on names, not content. An allowed file containing a secret is still captured; initial import and deliberately published trees can disclose it. Excluded local files are not private checkpoint backups.

### Integration and policy

Clean Git merges are structural combinations, not compilation or semantic correctness. Unchecked is the default and intentional. Optional checks must be configured explicitly. A generic top-level `evidence:"unchecked"` field in some status/envelope responses is not a detailed policy transcript; inspect per-candidate/proposal details for executed checks and repair provenance.

Optional check commands and explicitly trusted commands run as the current OS user. Clearing environment and using temporary checkouts do not confine filesystem/network access. Repair defaults to confined execution and refuses to launch if the backend is unavailable; only an explicitly selected `trusted_unsandboxed` profile bypasses confinement. Process groups reduce ordinary runaway children but cannot contain deliberate escapes or survive every parent crash. Repair launches reserve their configured time before execution in a durable SQLite ledger keyed by the public proposal commit, with at most two attempts and 600 reserved seconds. Interrupted attempts remain charged. This bounds configured repair retries across restarts, not total process-tree resource consumption or hostile-worker activity. Policy definitions are validated before persistence. Confined real-agent execution remains a release gate.

### Recovery is narrower than durability marketing

Failpoints terminate the process (`WIPSTASH_FAULT`, exit 86) and are for disposable test fixtures. Retained Git/SQLite/staging files are required for replay. They do not emulate a power cut or guarantee ordered durable writes on every filesystem. Concurrent uncooperative writes during rollback can invalidate the cooperative model. No filesystem/disk-loss recovery claim follows from a successful process-crash test.

The public backup manifest is versioned. Version 2 includes published proposal intent, public ownership, original eligibility and queue order, public operation/idempotency records, replay metadata and policy identity. Verification is read-only; `restore` imports verified roots into new empty state and reconstructs public recovery metadata. Unresolved proposals initially enter `recovery_quarantined`. `recovery_activate` requires explicit review, confirmation that the old authority has stopped, the exact original sync binding and a matching configured policy before eligible public work can resume. Legacy version 1 recovery cannot reconstruct that eligibility and requires review and republishing.

This is public recovery, not a copy of the entire coordinator: private checkpoints/workspaces, private operation history, credentials and executable policy are excluded. A crash between staged-repository rename and the SQLite restore commit may leave an orphan repository; restore fails closed for inspection. Activation is operator-mediated fencing, not proof that a remote authority has stopped, authenticated migration or zero-loss recovery. The local engine's `remote_kind:"local_simulation"` and `state:"complete"` do not claim GitHub protection. The separate asynchronous GitHub component still needs real remote and fresh-host acceptance. Keep an independent backup of valuable original work.

### Performance and availability

All state operations contend on one engine lock, including commands/checks/repair and integration. The design's low-latency/LAN objectives have not been established as performance guarantees. There is no horizontal scaling or automatic failover guarantee. Service/client workers and durable outbox/resumable transfer retries exist, but deployment supervision, backlog behavior and actual WAN availability require acceptance testing. Local worker backoff alone is not network evidence.

## Reproduction and evidence interpretation

From a clean checkout with prerequisites installed:

```sh
cargo build --locked
cargo test --locked
python3 tests/adversarial.py
```

The adversarial harness saves timestamped requests, responses, exit statuses, timings and disposable state under its artifacts directory. Preserve that directory and the exact source revision with any reported result. Record `rustc --version`, `cargo --version`, `git --version`, Python version and OS/filesystem. `rust-toolchain.toml` pins the tested Rust 1.99.1 environment, not a declared MSRV. Tests with four actors use deterministic Python scripts and concurrent subprocesses; report them that way.

The README's small example demonstrates the distinction between publication and adoption. Worker, policy, backup and MCP smoke tests provide additional local evidence only when run and their output retained. Do not extrapolate a suite beyond its recorded OS and revision, or to model-driven product workflows, deployed multi-host network authentication, real remote credentials or lost-storage recovery. The historical cloud Unix-socket denial remains distinct from successful native CI contracts.

## Concrete work remaining before target v1

1. Demonstrate actual Codex/Claude integrations and a verified, enforceable writer coordination contract; contain detached descendants and recover ownership safely after process death.
2. Extend the passing native Linux/macOS/Windows process and build CI to broader filesystem/IPC acceptance. Validate full Windows adoption and open-file/case-rename/reparse-point hazards, real native vault access and installer behavior.
3. Extend the passing real-loopback guided pairing and certificate lifecycle checks to a permitted multi-host deployment; extend the passing real-TLS resumable upload-fault campaign to deployment quota and multi-machine failure drills. Authenticated fenced migration remains open.
4. Make model repair confined and auditable, with confined execution and exact resolution/check provenance; retain the implemented durable retry/budget accounting; verify malicious repository/worker behavior.
5. Complete and validate asynchronous GitHub worker integration with an approved namespace and credential flow; run a fresh-host recovery drill using version 2 public metadata and explicit activation.
6. Validate the conservative loose-object collector against all pending-operation/recovery roots; establish retention policy, storage-pressure/capacity behavior and explicit loss windows without evicting acknowledged work.
7. Validate power-loss/disk-full/corruption behavior separately from process termination. Measure latency and backlog against the design goals on stated environments.
8. Complete real same-LAN/hosted and mixed-agent end-to-end release drills before claiming the original specification complete.

The local loop is useful engineering evidence. It is not a substitute for these missing contracts or a finished production system.

## Hardening references

See [client adapter contract](CLIENTS.md), [storage boundary](STORAGE.md) and [transport foundation](TRANSPORT.md). These documents distinguish code present from environments and workflows actually exercised. The final gap-closure evidence report records the tested source and binary; intermediate counts are not release evidence.

## Source-exchange addition

[SOURCE-SYNC.md](SOURCE-SYNC.md) describes independent authority/client state, bounded exact public-object quarantine, deliberate source exchange, ordered catch-up, and explicit adoption. Identity labels/checksums and an operator provenance assertion are not network authentication. Importing source artifacts does not imply TCP/TLS, hosted service, automatic transport, authenticated device identity or complete production replication. The source-sync evidence report supersedes earlier statements that replication was metadata-only.

## Confined repair dispatch

Repair now defaults to `execution_profile: "confined"`. A missing/unavailable backend keeps the proposal quarantined; it does not fall back to ordinary subprocess execution. The explicit `trusted_unsandboxed` profile is for unsafe development fixtures and is never enabled automatically. The Linux bubblewrap implementation has contract tests, but its single live probe was blocked by the cloud environment (NETLINK_ROUTE permission); live confinement remains unverified here. See `crates/repair-runner/README.md`. Optional check commands are still trusted execution and are not thereby sandboxed.

## Verified native baseline

[Commit 0f0b284](https://github.com/jimmystridh/wipstash/commit/0f0b2841627bfbdee1370867b284b6a1705253d6) passed [Linux, macOS and Windows CI](https://github.com/jimmystridh/wipstash/actions/runs/39080367426). Each OS ran process, MCP and policy contracts and compiled transport/backup. All five SQLite consumers on all three OSes printed bundled SQLite 3.51.3 and passed runtime/checked-integer guards. This includes the upstream WAL-reset fix; it does not establish power-loss or deployed-network acceptance. Linux also ran the full suites and strict Clippy.


## Guided pairing feature evidence (18 October 2026)

Feature checkpoint `42a40025b4d8c3d6b0bfd7bd6b59a597562d5735` passed native Linux, macOS and Windows CI, the actual CLI four-device loopback setup/join/revoke/rotate/server-restart scenario, browser interception and real-HTTP browser runs (53 API requests each), and strict Clippy. Later enrollment response-bound checks also passed. These results supersede older statements that native tests or a listening service had never run. They do not certify all later source changes or the full original specification.

Functional commit `1488774be3582fb0322de74f1071245ced08f114` passed [native CI 39095243418](https://github.com/jimmystridh/wipstash/actions/runs/39095243418), with Linux, macOS, Windows and browser jobs green, and [bootstrap CI 39095243492](https://github.com/jimmystridh/wipstash/actions/runs/39095243492). The formatter patch was empty.

Real-TLS artifact `12124098556` passed: four device identities, two owned server restarts, a retained offset of 262,144 bytes, eight upload attempts, one pre-send drop, one post-commit lost acknowledgment, one cross-device rejection, six certificate/ACL rejections and two integrated publications. Every stored public Git blob, including unreachable objects, was audited. The earlier Unix fixture-permission and `sequence_gap` failures are superseded by this successful corrected run.

These results apply to the named functional commit and artifacts. Any later release revision needs its own passing CI; this evidence does not establish deployed multi-host WAN operation or completion of the full production specification.

All pairing credentials and grants in this evidence are disposable synthetic test fixtures. No real user credentials, native credential-vault provisioning or public endpoint deployment is claimed. See [NETWORK.md](NETWORK.md) and the [test harness guide](../tests/README.md) for the distinct live-CI guards and remaining gates.
