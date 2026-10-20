# Agent feedback acceptance — 2026-10-19

This report predates asynchronous validation. Its required-check gating observations describe that earlier build. The current share-then-check and repair-ownership contract is documented in [BACKGROUND-VALIDATION.md](BACKGROUND-VALIDATION.md).

This records validation of the current working-tree implementation. No source-repo Git commit or push was made. The desktop release, source patch, test logs, native session evidence and exact binary hashes are retained under the installation's `evidence/improvements` directory and submitted to its private central audit.

The implementation adds explicit save/submission/sharing outcomes, common prepared conflict review, reusable successful resolution checkouts, incoming summaries, server task claims with advisory overlap warnings, remote claim delivery and workspace reports, safe archive/reopen, and explicit Init ignore presets. See [the operational contract](AGENT-COLLABORATION.md).

## Observed results

- Core: 199 tests passed, including source isolation, repeated head movement, saved-request recovery, private ancestry exclusion and backup/restore contracts.
- Authenticated transport: 116 tests passed; two existing opt-in live-CI campaigns remained ignored. Real local mTLS tests covered claims, ownership, exact replay after a lost acknowledgement, offline truth, inventory reports, successive remote Commits and incoming messages. Durable worker backoff survived restart.
- Feedback regressions: 13 passed through real MCP, Git and SQLite. The README baseline reproduction saved files without falsely reporting shared, named the conflict, and opened prepared inputs/result without a comparison Clone. Rename, binary and deletion cases, rejected markers, stale original files, resolution reuse, process-exit recovery, claims/expiry, active-session leases, archive/reopen and explicit ignores passed.
- An independent combined-candidate test demonstrated that two changes could pass separately while their integrated result failed. The authority retained failure evidence and refused to advance shared; a corrected review then passed and shared.
- Native Codex, Claude Code, OpenCode and Pi sessions each edited one assigned file and reached shared with server checks passing. Four initial workspaces, four Commit attempts, zero comparison Clones and zero resolution attempts were observed. Advisory overlap counts were 0, 1, 2 and 3. Peer files never appeared in another live directory.
- The running desktop demo passed 50 Python tests, JavaScript syntax validation and 6 JavaScript tests under three required server checks. Its checked tree was `02f66effbdb52db20325b4c5863ef6b65b573923`. A no-change Commit verified actual policy enforcement and returned `shared:true`, `state:already_included`, and `validation.state:passed`. The validation workspace was archived without deleting files or history.

The native run completed in 154.923 seconds. Pi used a per-run `openai/gpt-6.1-sol` override because its configured default was rejected by the provider; global model preferences were preserved. Earlier attempts exposed a provider configuration failure and macOS process-launch delays. Those failures are retained alongside the successful reruns. The successful native result is separate from deterministic scripted-client evidence.

## Limits

These are local macOS results with isolated fixtures and real loopback mTLS, plus the running local demo. They do not establish deployed multi-host acceptance, cross-platform release readiness, sustained contention fairness, large-refactor scalability, arbitrary editor containment or automatic semantic correctness. Claims expose intended work; the native exercise's assigned tasks do not prove that claims alone prevent duplicate effort. Existing client sessions need to reconnect MCP to use the new schemas and implementation.

## Follow-up: responsive coordination and active repair pickup

The follow-up keeps Commit → shared with asynchronous checks. It adds metadata-only MCP Status, independent coordination reads/short transactions, capture preparation outside the repo lock with durable exact-request intent, unlocked delivery of prepared backup pairs, public diffs, targeted task/repair comments, honest failure-context summaries, strict page bounds and certain argument-error guidance. Startup instructions, the launch authorization option and the source-control skill describe the same workflow. The next eligible workspace receives a 30-second repair offer; acknowledgement holds a five-minute lease, and origin remains separate from investigation ownership. Existing acknowledged leases are preserved.

Validation artifacts for this follow-up live under the installation’s `evidence/feedback-v2` directory. The verified core run passed 187 unit tests and 12 auxiliary tests. Subsequent observation/recovery changes were exercised by the release workflow suites and focused replay/cache tests. Real MCP release fixtures cover 23 async/concurrency/repair cases and 14 sharing/crash-recovery cases. The four-client feedback suite passed 13 cases. The extended real mTLS scenario verifies queued pickup grants no lease, authenticated ownership acknowledgement, identity rejection, comment author identity and remote comment delivery. These are scripted clients; native model sessions were not rerun for this follow-up.

The lock-held fixture keeps the repository lock continuously held while three clients each perform Status, Task List and a claim. All three groups complete before the lock is released; measured client durations are retained in `async-validation.json`. This is a bounded contention regression, not a fleet-capacity benchmark or WAN latency claim.

Initial validation exposed and corrected an offline-cache fallback, fresh-state restore markers, early generation rejection that bypassed durable error recording, recovery skipped by fast reads, and an integration cursor causing `SQLITE_BUSY_SNAPSHOT` under independent timing writes. A deterministic paused-Git test now covers that snapshot collision. Earlier failing logs remain with the passing results. Some initial native tests also used macOS’s symlinked temporary path; canonical `TMPDIR=/private/tmp` was used for the verified core run without weakening path checks.

Repository locks still serialize source promotion and some workspace operations. Metadata-only Status does not inspect files; null is not clean. Backup preparation still uses the repository fence. Remote comments expose their latest-128 cache window while authority history remains retained. Existing MCP sessions need reconnection to load the new code and schemas. These changes do not establish multi-host production acceptance or sandbox untrusted check commands.
