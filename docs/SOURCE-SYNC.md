# Independent peer source exchange

`engine_sync.rs` connects the public Git object model to independent authority/client state directories using explicit filesystem artifacts. It is application-layer transfer, **not an authenticated network service**. No listener, TCP/TLS, pairing, account authorization, remote credential store, or automatic transport is involved. Identity labels and SHA-256 checksums do not authenticate a sender. `sync_import` requires `confirm_trusted_source:true`: the operator must establish artifact provenance separately. Only use this with trusted participants in the cooperative prototype profile.

## State model

- Authority: initialize a source once, configure a pinned project/authority/epoch/device and peer allowlist, import proposals, run the existing `worker` loop or `integrate`, and export public heads.
- Client: configure a fresh state without `init`, import the authority's head artifacts, then open a workspace. Its `coordinator.git` is a **local public cache**, not a second authority. `status`/`updates` identify that distinction and do not infer remote availability from a local directory.
- Configuration is immutable, including role and peers. There is no migration/revocation/epoch-rotation API. A client cannot initialize, restore into, integrate, configure authority policy, retry authority proposals, or run authority backup operations on its cache.
- `checkpoint` remains private and works without transport. `publish` on a client creates a deliberate public-base-parented proposal, always locally queued. It does not pretend the authority accepted it. Export/import below is the separate acceptance step.
- Receiving a head only installs verified public objects and advances the local cache. `updates` can prefetch into workspace-private storage. Neither changes live workspace files, generation, or adopted base. Only explicit `adopt` or explicit conflict-resolution workflows do so.

## Exact CLI examples

All commands are JSON arguments to `wipstash --state /absolute/state`. The artifact parent directory must already exist, and each new artifact destination must be absent. Export destinations cannot overlap state or any registered workspace.

Authority setup:

```json
{"op":"init","source":"/projects/source"}
{"op":"sync_configure","project":"demo","authority":"central","epoch":1,"device":"central-device","role":"authority","peers":["alice-device","bob-device"]}
{"op":"sync_export","kind":"head","destination":"/exchange/head-1","operation_id":"head-1"}
```

Fresh Alice client setup (separate state and files):

```json
{"op":"sync_configure","project":"demo","authority":"central","epoch":1,"device":"alice-device","role":"client","peers":["central-device"]}
{"op":"sync_import","source":"/exchange/head-1","confirm_trusted_source":true}
{"op":"open","workspace":"alice","path":"/work/alice","operation_id":"open-alice"}
```

After cooperative editing, deliberate proposal transfer:

```json
{"op":"checkpoint","workspace":"alice","expected_generation":0,"operation_id":"cp-1"}
{"op":"publish","workspace":"alice","checkpoint":"cp-1","intent":"Implement the selected change","operation_id":"proposal-1"}
{"op":"sync_export","kind":"proposal","proposal":"proposal-1","destination":"/exchange/alice-proposal-1","operation_id":"upload-1"}
```

On the authority:

```json
{"op":"sync_import","source":"/exchange/alice-proposal-1","confirm_trusted_source":true}
{"op":"integrate"}
{"op":"sync_export","kind":"head","destination":"/exchange/head-2","operation_id":"head-2"}
```

Proposal artifacts include the deliberately supplied intent text (up to 4096 bytes); exporting shares that text with the recipient along with the selected public source. This differs from sanitized backup metadata.

Proposal import returns `proposal`, a stable authority-side ID derived from device and source proposal ID, and `source_proposal`, the original client ID. Use the authority-side ID for `proposal_status`. The existing `worker` loop integrates accepted proposals autonomously after explicit import; it does not scan exchange directories. Conflicting proposals quarantine without blocking unrelated proposals.

On Alice, after importing every missing head event:

```json
{"op":"sync_import","source":"/exchange/head-2","confirm_trusted_source":true}
{"op":"updates","workspace":"alice"}
{"op":"adopt","workspace":"alice","target":"latest","expected_generation":1,"operation_id":"adopt-2"}
```

On a client, `latest` means the latest **locally verified cache**, never a fresh remote observation. Concurrent private edits are handled by the existing merge/adoption conflict contract. Head arrival alone is not proof that a particular proposal integrated. Import an explicit authority receipt as below to learn its observed outcome.

## Explicit proposal receipts

The authority can export an observation of an imported proposal separately from the head stream:

```json
{"op":"sync_export","kind":"receipt","proposal":"remote-AUTHORITY_PROPOSAL_HASH","destination":"/exchange/alice-receipt-1","operation_id":"receipt-1"}
```

Use the actual authority-side proposal ID from its proposal import response. Receipt export requires the origin record written by this version's proposal importer. Experimental journals created before receipt support are not backfilled; repeating an already journaled import does not add a missing origin record. Locally authored authority proposals are not remote receipt targets. On the targeted client:

```json
{"op":"sync_import","source":"/exchange/alice-receipt-1","confirm_trusted_source":true}
{"op":"proposal_status","proposal":"proposal-1"}
```

Receipts contain an allowlisted observed state, checked/unchecked evidence category, repair-applied flag, optional public integration OID, recipient identity, authority proposal identity and revision. A quarantined proposal can also carry a bounded, sanitized `resolution_task`: public snapshot identities, conflict paths, attempt/lineage metadata and next action. Check identifiers are hashed (`id_sha256`); only hash/status/count metadata is retained. Raw worker output, command/error text, policy commands, argv, local paths, opaque proposal details and private checkpoints are excluded. `conflict_paths_total`, `checks_total` and `evidence_truncated` describe bounded previews within an 8 KiB task. Previews can be empty when individual entries are too large; public root and attempt identity are retained. Use freshly recomputed `resolution_open.conflict_paths`, not a receipt preview, for the complete resolution attestation.

A receipt's manifest binds its source proposal ID, public proposal commit and public base. Ordinary receipts have an empty object payload. Resolution-task receipts carry verified public objects rooted at the proposal commit and observed current head so that a recipient can inspect the public conflict inputs. Admission still verifies recipient, proposal identity and receipt monotonicity before installing objects. Import does not advance cached `HEAD` or the ordered head-stream cursor and never mutates workspace files/generation. Import missing head events through the ordinary ordered stream before opening a resolution against the latest cache.

Receipt revisions increase per authority proposal and survive process restart. They are independent of head sequences: clients need not receive another client's receipts or earlier observations of their own proposal. New lower revisions fail as stale. The same revision with altered content fails; integrated/already-included/cancelled/superseded observations cannot regress or change terminal outcome. Exact previously imported artifacts return their original duplicate receipt without regressing current observation.

Client `proposal_status.state`, `head` and `evidence` reflect the latest imported authority observation. `local_state` retains the local transport state and `remote_observation` gives its provenance/revision. This is an explicitly delivered observation, not a live authority query or remote command. Local proposal storage is retained for replay. Once any proposal export is reserved, local `cancel` fails with `remote_cancel_unsupported`, even before acknowledgement: a local cancellation cannot recall an artifact the authority may already have accepted. Unexported local proposals can still be cancelled. There is no remote cancellation command or automatic receipt scan.

## Explicit agent resolution handback

Follow [CONFLICTS.md](CONFLICTS.md) for the MCP/CLI resolution sequence. On an independent client, `resolution_submit` creates a new locally queued proposal; export it with `sync_export(kind:"proposal")` using its returned proposal ID. The resolution metadata binds the original proposal, lineage, attempt and expected public head. The authority validates ownership and lineage, then ordinary integration remerges the replacement against the actual latest public tip and runs current policy. An otherwise-valid replacement is not rejected solely because the tip advanced during delivery. If that fresh merge or its checks fail, the successor proposal receives a new task with the retained lineage/attempt count; fetch its receipt and missing head events to continue. Locally known stale resolution checkouts still fail before submission and require a fresh checkout. Do not treat queued state as remote acceptance or retry with invented head metadata.

`sync_status`, catch-up results and transport worker tick results also expose cached `resolution_tasks` with a truncation indicator. These summaries are discovery aids; inspect detailed proposal status and receipts before acting.

Task receipts are explicit observations, not remote polling or background model invocation. New receipt public inputs do not authorize skipping ordered head events, exporting private ancestry or adopting the shared result. The original private workspace remains unchanged.

## Replay, catch-up and loss

Head exports form one contiguous authority stream, beginning with sequence 1. Every client must import all head events in order, including a fresh client joining later. A self-contained full-history object artifact does **not** authorize skipping events. Gaps, altered operation identity, and changed epochs fail closed. There is no snapshot cursor reset.

```json
{"op":"sync_export_history"}
{"op":"sync_reexport","operation_id":"head-1","destination":"/exchange/recovered-head-1"}
{"op":"sync_status"}
```

`sync_export_history` lists retained export IDs, kind, head and sequence. `sync_reexport` reconstructs the exact reserved manifest and object bytes at a new destination without advancing the sequence. Repeat for every missing sequence. Export history and public roots are retained indefinitely; no retention/GC policy exists. This is explicit operator-mediated catch-up, not an automatic discovery or download protocol.

Each export operation is request-bound and reserves its immutable manifest before artifact creation. Repeating `sync_export` with the exact same request succeeds only if an existing destination matches byte-for-byte; using the same ID for changed parameters fails. A failed destination write may reserve a sequence; `sync_reexport` can recover it. Incomplete staging directories are not automatically overwritten or deleted. There is no promise to recover a permanently lost sender database/root store.

Imports independently re-read and checksum content even on duplicate receipt. They journal canonical manifest identity by device/operation. A repeated exact import returns its original receipt with `duplicate:true`; its recorded head/sequence may be older than current state. `sync_status` shows current cached head and replay cursor. Re-exporting an already known proposal with a different export ID does not reopen a terminal proposal or re-run integration.

## Admission and crash ordering

1. Bound and parse the manifest, check local project/authority/epoch and allowlisted device, and verify payload length/checksum.
2. Build an isolated quarantine Git repository; verify exact requested roots, reachable closure, each object's identity, supported tree entries, public commit grammar and Git connectivity. No incoming ref names, hooks, filters, repository config, compressed packs, symlinks or private checkpoint ancestry are accepted.
3. Validate proposal single-parent/public-base/identity or head stream admission and first-parent fast-forward **before installing any roots in destination storage**. Rejected artifacts leave no new destination roots.
4. Install admitted objects and generated transfer pins. For proposals, the accepted proposal row and import receipt commit in one engine SQLite transaction. For heads, the dedicated replication replay journal records the head as a durable intent, then the cache ref advances, then the receipt is stored.

A crash after approved installation but before journal commit can leave inert public object pins. Retry remains required; no acceptance is acknowledged early. A crash after head replay commit but before ref advancement is completed on the next engine invocation by the replay journal, without adopting workspace files. Unexpected divergence or missing admitted objects fails closed. This is deterministic recovery logic over retained storage, not a power-loss guarantee. The global cooperative engine lock protects preflight/installation/admission from other engine invocations; it is not protection against a same-account filesystem attacker.

## Bounds and remaining gates

The effective sync payload bound is **8 MiB** and the manifest is at most 16 KiB. `objects.json` retains a historical filename but contains the transfer module's binary object container, not JSON. Full reachable public history is sent each time; larger histories fail export rather than generate artifacts receivers cannot accept. The underlying standalone transfer module permits larger artifacts, but that does not enlarge this sync API's bound. SHA-1 Git repositories only; limits also apply to object count, ancestry, paths and blob sizes. Fixed exclusions are not content-based secret detection: deliberately publishing an allowed file can disclose its contents.

No chunking/resumption, partial packs, remote queue polling, automatic receipt delivery, aggregate storage quota, retained history pagination/pruning, credential enforcement, authority migration, failover, remote fencing, TLS/revocation, GitHub service, or native cross-platform validation is provided. Local directory delivery/drop/reorder fixtures exercise actual source operations across independent stores, not TCP behavior or hostile-device security.
