# Background peer synchronization

The transport binary has two long-running modes:

- `wipstash-transport serve /absolute/service.json`: mutually authenticated HTTPS service plus an authority integration worker.
- `wipstash-transport worker /absolute/client.json`: outbound-only workstation worker using the existing certificate and pinned authority configuration.

The existing one-shot `client ...` upload, download and catch-up commands remain available. Starting workers does not create credentials, configure an OS service, open an inbound workstation port, or change system settings. Operators supply existing explicit configuration. Stop the process normally to stop coordination.

## Explicit publication boundary

Only an explicit engine `publish` creates eligible source work. `sync_pending` reads published local proposals in bounded row-cursor pages; it does not enumerate private checkpoints or native working files. A worker never checkpoints, publishes, adopts, or resolves adoption. Receiving a new public head changes the verified public cache, not an agent's working directory. Local cancellation stops pending uploads; it does not retract an already accepted remote proposal.

The authority worker runs the existing integration policy. The default remains `checks=[]`; it does not silently add validation commands or repair execution. Conflicts quarantine their proposal while independent proposals continue. Configured repair execution remains subject to the engine's confinement policy.

## Durable delivery and polling

Each state has a lifetime OS file lock, `transport-worker.lock`, preventing duplicate background workers. A process crash releases the lock. `transport-outbox.json` is written with file fsync, atomic rename, and directory fsync. It binds the exact immutable synchronization configuration and records the source proposal ID, stable export operation ID, authority acknowledgement mapping, retry state, and terminal observation. Export identities are durable before requests leave the process. Lost responses and restarts reuse retained engine artifacts under the same ID; retries never invent a new operation.

Upload acknowledgements and receipt observations must match the expected proposal. The production adapter verifies project, authority, epoch, authority device, and receipt recipient before engine import. Heads use the engine's durable verified sequence cursor and retained history pagination. Transport errors are isolated per proposal and do not suppress unrelated head polling.

A pass handles at most 128 due outbox entries, ordered by due time for fairness. Failed entries use persisted exponential backoff capped at 256 seconds; normal polling is every five seconds. The client transport also bounds each individual network retry. The outbox rejects additional entries at 10,000 tracked proposals rather than deleting or forgetting replay identities. It refuses malformed, oversized or differently bound journals. Operator review is required when that capacity is reached; there is no destructive automatic cleanup. Published/exported graphs remain pinned by the existing engine retention rules.

`POST /v1/current-receipt` derives an immutable cache identity from the actual relevant authority observation. Repeated unchanged polls reexport the same receipt and revision. A changed state/evidence/head produces a new immutable observation. Quarantine remains pollable because explicit operator retry can change it; integrated, already-included and cancelled receipts stop normal polling.

The authority uses `sync_export_current_head` under the engine lock. An already-retained current head produces no new sequence event, including when an explicit earlier export retained it. A worker tick may integrate several proposals and publish their resulting public head as one availability event. Intermediate integration commits and proposal events remain retained and the exported graph includes their ancestors. Availability announcements do not force clients to adopt every intermediate tree.

## Verification

`services/transport/tests/daemon.rs` runs separate real authority/client engine stores behind an injectable in-memory transport. It exercises initial catch-up, explicit publication, lock exclusion, response loss after successful import, restart with unchanged operation IDs, persisted retry timing, immutable receipt polling, integration/head deduplication, and preservation of post-publish native edits. No socket binding or live credentials are needed for this test. The production adapter uses the same mTLS client and artifact verification as one-shot operations.

## Integration deadlines and blocked entries

Background integration requests `max_proposals=1` and allows 660 seconds for that candidate, covering the policy's 600-second budget plus cleanup grace. Explicit engine integration remains unbounded in proposal count by default; callers may set a validated batch size from 1 through 32. HTTP engine operations retain their shorter 60-second deadline. While an integration owns the engine state lock, HTTP operations can fail or time out and clients back off using their unchanged request identity. This is a documented head-of-line limitation of the current single-state engine lock, not a parallel integration claim.

Recognized schema, identity, binding and acknowledgement rejections mark that outbox entry blocked for operator review. They do not get automatically resent. Ambiguous connection/response loss retains the exact operation and artifact and retries with persisted bounded backoff. Generic remote failures that do not reveal whether the engine committed are treated conservatively as ambiguous. No retry manufactures a new ID or rereads native source files.

Authority integration and head export each perform storage admission using the service's configured limits, including the free-space reserve. Admission conservatively budgets artifact growth and entries. Quota pressure pauses the worker with bounded backoff while the HTTP service remains available. These are cooperative preflight checks, not atomic reservations or an absolute cap against concurrent/unmanaged writers or unexpectedly large integration output.

## Autonomous local snapshot refresh

After an operator explicitly configures an existing local bare backup destination with `backup_flush`, the core worker and transport authority worker automatically call `backup_tick`. The transport worker does this after each source-coordination attempt, including failed promotion or export. It uses a bounded asynchronous engine subprocess (60 seconds), a five-second successful cadence and capped exponential error backoff. Backup errors are reported separately and do not reverse or conceal successful source integration. With no backup configured, the result remains `not_configured`; no destination, credentials or network backup is created.

The separate backup service can be explicitly configured with `public_source` pointing at that local public bare snapshot. Its watcher verifies the refreshed snapshot, deduplicates enqueueing and drains one remote job per cycle. This connects autonomous local snapshot refresh to the separate network worker without putting network access or credentials in the engine. Publication advances the configured local snapshot and the watcher discovers it without a fresh user enqueue.

The core `worker` checks `recovery_status` at startup and exits clearly when activation is required. It integrates at most one proposal each iteration. Operators must review and explicitly activate recovered authorities before either worker starts processing them.
