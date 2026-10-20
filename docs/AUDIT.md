# Central action audit

The Wipstash authority is the system of record for source-control actions and agent activity. Working files remain in each agent's own directory. Commit is still the single action that saves and shares source; collecting an audit record does not commit source or change anyone's files.

## What is recorded

Each state directory has a private `audit.sqlite`. Core actions record a start before execution and a completed or failed outcome afterward, with timestamps, correlation IDs, workspace and operation IDs, request and result. Committed state events and completed operation results are also mirrored into the audit. This recovers committed evidence after an interrupted process when a subsequent engine invocation observes its committed state. Read-only binding inspection and idle worker polls do not generate a new record on every pass; audit reads do not audit themselves.

An optional one-shot native collector reads persisted Codex, Claude Code, OpenCode and Pi session histories. It records tool calls, arguments, edits/patches, results, errors and visible session activity. Only history segments whose recorded working directory exactly matches a registered workspace in this project are included. Resumed sessions can enter or leave the project; scope transitions are reported without copying unrelated history. A separate workspace per concurrent agent is still required. Native actions outside those directories, activity a client never persists, edits by other programs and intermediate OpenCode revisions overwritten before observation are outside this evidence boundary. A start without a result is evidence of uncertainty, not success.

A central entry distinguishes:

- `origin: server`: Wipstash performed or observed the action on the authority.
- `origin: agent_reported`: a workstation or native history collector reported it. The authenticated device and certificate fingerprint identify the sender; they do not prove the report's contents. Session IDs and client timestamps are reported claims. Server sequence and receipt time are assigned by the authority.

Explicit native collection reports its coverage and failures to the audit. Missing, stale, truncated or invalid histories are visible as collection errors. No client hooks or additional model calls are needed.

## Delivery and integrity

Records enter a durable local SQLite outbox before acknowledgement to the collector. Connected CLI commands upload bounded batches to `POST /v1/audit` using the existing mutual TLS connection, certificate ACL, project binding and authority pin. The server commits the batch before returning a receipt bound to the project, authority, epoch, device, producer, final source sequence/hash and central sequence/hash. The client advances its delivery cursor only after validating that receipt. Offline delivery and lost replies leave the records pending; retransmission is deduplicated. Changed replays, gaps and mismatched identities are rejected atomically. Retry backoff survives process restarts; explicit `wip sync` requests an immediate bounded retry.

Each producer has a hash chain; the authority adds its own ordered hash chain. Database triggers reject record updates and deletion. Verification checks both chains. These checks detect inconsistency; they do not prevent a privileged machine owner from replacing databases and recomputing history. Protect the server's private state and retain independent exports or database backups.

Records and delivery receipts are retained after acknowledgement. There is no automatic audit deletion. Payloads up to 16 MiB are split into ordered, hash-bound UTF-8 JSON parts rather than silently truncated. Parts carry a payload SHA-256, byte count, index and total; reconstruct by joining their `text` fields in index order and checking the hash. Oversized records fail visibly and keep the collector cursor unchanged.

Structured credential fields such as passwords, API keys, authorization and cookies are replaced by hash-bound redaction markers. Private reasoning and system/developer instructions are omitted from native collection. This is not a general scanner for credentials embedded in arbitrary shell text or output. Audit data is private operational evidence, separate from public source exports and GitHub backups; public backup/restore does not restore this audit database. Back it up separately.

## Optional native activity collection

Normal CLI use records Wip actions and delivers them during connected commands. No collector or client worker is installed. Native edits and other shell commands outside `wip` are not automatically observed. To import persisted model activity explicitly, run one bounded scan in the owned clone:

```sh
wip audit collect --collector /absolute/path/to/wipstash-audit-collector.py
wip sync
```

The CLI invokes the collector through `uv` with `--once`, its own executable and the clone's existing state. Cursors remain in `audit-collector.sqlite`; historical source directories and matching rules are preserved. `wip audit import --file FILE` imports explicitly prepared records. Collection is agent-reported evidence, and zero matching sessions proves no coverage beyond that scan.

## Inspect and export

```sh
wip audit status --json
wip audit log --limit 16 --json
wip audit verify --json
```

Online Audit Log reads the authority's central history through an authenticated request; `--offline` reads the local history. `wip audit verify` verifies the local producer and locally stored server chains. A trusted operator uses `wip admin audit_verify --state ABS_SERVER_STATE --params '{}'` to verify the authority's full database. Audit evidence is returned verbatim, including original historical field names, so its stored hashes remain verifiable. `synced` means locally recorded evidence has a durable authority receipt. CLI `complete` is explicitly scoped to `wip_actions`; optional native coverage is reported separately under `native_activity` and is never implied by complete Wip delivery.

Trusted operators can export a consistent server snapshot:

```sh
wip admin audit_export --state /absolute/server/state --params '{"destination":"/absolute/private/audit.jsonl"}'
```

Pages are in central sequence order; pass `next_cursor` for the next page. Export takes a consistent read snapshot, fsyncs its JSONL output, and installs it without replacing an existing destination. Preserve the audit database and independent exports in private server backups. They can contain source patches, command text and output.

For custom activity, write a JSON record and use `wip audit record --file FILE`, followed by `wip sync`. Supply a stable `event_id`, `agent`, `session_id`, `workspace`, `action`, `phase` and `payload`; optional `operation_id` correlates it with source control. Reuse an event ID only for identical content. Native collector cursors acknowledge durable local storage; `audit_status` separately proves authority delivery.
