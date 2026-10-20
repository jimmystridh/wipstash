# Background validation

The agent flow remains **edit → add → Commit → shared**. Conflict-free commits reach shared without waiting for checks. Get Latest never edits working files; Merge remains deliberate. Textual conflicts retain the existing isolated review flow. Checks can discover that shared code is broken after other agents have already built on it.

## Evidence and scheduling

Every authority sharing operation durably schedules an immutable head/tree and policy hash alongside the promotion. Recovery schedules a missing job for a recovered head. The core worker/daemon and transport authority worker run validation independently of promotion and backup. A process-held validation lock permits one cooperative check worker per repo. The state lock is held only to claim or record a job; checkout materialization and check commands run outside it.

The newest waiting head replaces older waiting jobs during a burst. Running jobs finish. A replaced job is `unchecked` with reason `superseded_before_testing`; a later pass never invents evidence for an untested intermediate commit. A restarted worker retries an interrupted check job with an incremented attempt. Checks are trusted repeatable commands, not exactly-once side effects. Their isolated checkouts never replace agents' live files. Old automatic repair commands are not executed by background validation; fixes come from the assigned agent.

`validation` describes one commit and policy. `repo_health` describes the current shared head under current policy, including the last verified head. Delayed results remain historical evidence and cannot mark a newer head green or close its repair. A policy change requires fresh checks and supersedes repairs for the old policy. No configured checks means `unchecked`, never passed.

`wip check --head EXACT_HEAD --json` returns `release_ready:true` only for passing evidence on that exact commit under current policy. Deployment callers must use that exact version. This is an eligibility query, not a deployment command or automatic enforcement in an external deployment system.

## One repair owner

Failing checks open a durable repair incident. Repeated failures of the same check under the same policy update the existing open incident, preserving its owner. The next eligible workspace to call after the failure receives a 30-second offer. Acknowledgement acquires the normal five-minute lease. The original committer remains recorded as origin; assignment follows availability, not blame. Competing offers are serialized and compare the incident revision atomically. A workspace with an active assignment receives no additional incident. Ignored offers expire, release allows handoff, and a releasing workspace has a one-minute automatic-pickup cooldown (it may still explicitly claim). Observation calls can opt out with `accept_repairs:false`. Remote clients queue an identity-bound pickup for the authority; queued requests never grant ownership. Attribution identifies a first failing commit only when its exact parent was verified; otherwise the owner is an investigator for an unverified range, not a proven culprit. Infrastructure failures retain diagnostics without assigning a code repair owner and retry at most three times, with ten seconds between attempts.

Status, Get Latest and other new workspace operation replies carry unacknowledged repair offers. Other workspaces receive repo health and can read repair history without being told to fix the same issue. Operation replays and operation-status lookups remain their original immutable replies; their notices may be historical.

`wip repair acknowledge|renew|release|claim INCIDENT_ID --revision REVISION` uses the current workspace and a retained operation ID. The actions are:

- `acknowledge`: accept the active assignment and stop repeated notices.
- `renew`: extend the owned active lease.
- `release`: make the incident available for handoff.
- `claim`: atomically acquire a released or expired assignment.

Lease duration is 15–3600 seconds, default 300. Wrong owners, stale revisions, active competing leases and closed incidents reject without granting ownership. Agents must stop repair edits after expiry until they hold a new confirmed lease. These leases coordinate cooperative agents; native file tools are not intercepted. A normal Commit shares the fix, and passing checks on the current shared head close the incident. There is no second publishing action and no automatic shared rollback.

Remote updates use the authenticated coordination outbox and identity-bound receipts. Queued replies grant no lease. `repair_list.commands` distinguishes pending, confirmed success and confirmed rejection. Remote owner notices map the server's source commit ID to the submitting device's actual local workspace. Cached observations expose staleness and never claim fresh server contact.

## Timing and audit

`wip check --timings --json` returns recent lock-wait, dispatch and engine durations plus validation queue wait, check durations, attempts and immutable commit/policy identities. Repair records include creation, acknowledgement, lease changes and elapsed time. Server audit records retain validation start/results, diagnostic output, ownership changes and monotonic elapsed time on request completion.

Engine timing excludes final audit delivery and CLI serialization. Audit completion elapsed time includes initial audit setup and recording before the final delivery; neither is a client-observed round trip. Tests also measure actual client elapsed time. Idle integration/validation/backup polling is excluded from timing records to avoid filling the journal with empty worker ticks.

Private timing records use a separate authority table and the action audit; reading status does not create a public backup revision. Idle integration reads the last scheduled head without spawning Git. Local backup validation still checks every historical manifest, while reusing the exact reachable commit set for each immutable public root within that validation. This avoids repeated Git ancestry processes without skipping history or changing backup contents.

Run the contract regressions with:

```sh
cargo build --locked
uv run --no-project python tests/async_validation.py --artifacts /absolute/evidence/path
uv run --no-project python tests/shared_commit.py
uv run --no-project python tests/agent_experience.py
```

## Responsive coordination and check hygiene

`wip status --quick` requests metadata only (`inspect_files:false`); unknown live-file state is null, never falsely clean. Explicit file inspection remains available. Metadata reads use a committed SQLite read transaction without the repository lock. Short coordination mutations use their own mutex and SQLite transactions; archive/reopen joins that mutex. Local capture runs under a workspace fence before the repository lock, with durable capture intent and immutable pinned data. Aborted capture is never silently repeated against new files. Integration still serializes shared-head mutation. Backup validates and transfers its prepared immutable pair outside the repository lock, then reacquires it before recording completion. Backup preparation still uses the existing repository fence.

The lock-owner diagnostic records PID, operation, workspace, operation ID and acquisition time, without command arguments or credentials. It is a diagnostic observation, not proof of an active process after a crash. Recorded lock wait excludes pre-lock capture work. On-demand public diffs are bounded to 16 KiB and never read private workspace commits.

An administrator can set `preset:"python"` on a configured check. It adds `PYTHONDONTWRITEBYTECODE=1` to the cleared check environment, including ordinary child processes. It does not rewrite existing policy automatically. Check-mutation evidence lists up to 100 added, modified or deleted paths, including ignored files; aggregate integrity checks remain enforced. Required test runtimes and command authorization are unchanged.

Task and repair comments are private server coordination records, with authenticated authors, operation IDs, targeted workspace mentions, and audit events. Comments do not grant a lease or establish reading/agreement. Authority listing retains the full sequence; workstation caches expose their latest-128 window explicitly.

Read cursors used to enumerate queued source work and interrupted promotions/merges are fully consumed before Git work or database writes. Independent metadata/timing writers can otherwise invalidate a WAL read snapshot and prevent its upgrade to a writer (`SQLITE_BUSY_SNAPSHOT`, extended code 517). The gated integration regression performs real metadata writes while Git merge is paused, then requires successful integration. See [SQLite’s result-code reference](https://www.sqlite.org/rescode.html#busy_snapshot).
