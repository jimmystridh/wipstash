# Working with concurrent agents

A repo owns shared history and policy. A workspace is one agent session's local directory and saved history. Each client uses its native file tools in its own workspace. The normal source-control flow is **Clone → edit → add → Commit**, with **Get Latest → Merge** when the agent wants incoming files. Commit saves and attempts to share in one action; it never silently rewrites a working directory.

## Explain the observed state

| Field | Meaning |
| --- | --- |
| `has_unshared_changes` | Live changes or a queued/blocked Commit still need sharing. |
| `changes_since_save` | Live files differ from the last saved copy. This can be false while work is unshared. |
| `shared_changes_available` | The latest available shared tree differs from the workspace's last shared local result. |
| `workspace_mode` | Ordinary work, an open conflict review, or a pending resolution. |
| `saved_locally`, `submitted`, `shared` | Separate outcomes of a Commit attempt. Only `shared:true` establishes integration. |
| `generation_before`, `generation_after`, `generation_reason` | Whether and why the attempted action advanced local state. A failed sharing attempt can still have saved files. |

Get Latest returns an `incoming` summary of paths and change kinds plus paginated Commit messages and validation summaries. Independent clients receive messages through the authenticated coordination cache; cached observations identify their server time and do not claim fresh authority contact. Reads never install incoming files. Status bounds path previews, and task/commit listings expose pagination rather than hiding truncation.

## One review tool

A private Merge failure and a Commit baseline failure return `candidate`, exact input versions, `conflict_paths` and per-path details under `conflict.paths`. Details distinguish edits, additions, deletions, renames and binary files. A blocked submitted Commit supplies a resolution task and `commit_id`.

Call `wip conflict open` with a fresh directory path and exactly one of `--candidate` or `--commit`. The CLI retains a new workspace identity and operation ID; the original workspace is inferred. It supplies three input directories (`side_paths.base`, `.local`, `.shared`) and one editable `result_path`. No comparison Clone or generic engine tool is needed. The original directory remains intact.

The returned `completion` specifies the action:

- `resolve_merge`: accept the prepared result into the original workspace with `wip conflict resolve`, its candidate/target, original generation, review workspace and full path attestation. This changes owned local files without sharing them. A normal authorized Commit shares the result.
- `commit`: Commit the review workspace using the exact `resolution_head` as `expected_head` and every reviewed path in `resolved_conflicts`. A successfully shared resolution checkout becomes an ordinary reusable workspace.

Changed original files invalidate an old Merge review. Unreviewed markers, wrong target, wrong owner and missing path attestations are rejected. Known closed/pending resolution states are checked before saving, so rejection does not create another saved generation. A completed or durably prepared open can recover an identical request after a lost reply; a partial or edited directory that cannot be verified is preserved for inspection. Accepted Merge application uses the existing recoverable filesystem transaction.

Overlapping shared-head advances still require a new pinned review. The three-submission resolution budget remains in force. Claims and better review tools reduce investigation costs; they do not remove semantic conflicts or guarantee fairness under sustained contention.

## Declare intent on the server

`wip task claim` records a task ID, title, acceptance criteria, literal repo paths, owner/session and lease. The server reports overlapping paths or the same task ID. Claims are advisory: they do not lock files, prove agreement or authorize unrelated edits. Agents can see the intended semantics before independently implementing incompatible behavior.

`wip task renew|complete|release` renews, completes or releases an owned claim using its exact revision. Lease duration is 15–3600 seconds (default 300). The server assigns expiry; wrong owner, stale revision and expired leases are rejected. Exact retries return the original lease rather than extending it again.

Separate hosts queue declarations durably, then the same CLI invocation sends them through authenticated `/v1/coordination`. A queued declaration has `confirmed:false`; the client records confirmation only from an identity-bound receipt. `task_list.commands` distinguishes acknowledged success, acknowledged rejection and pending delivery. Cached claims expose freshness and estimated expiry. Coordination retries use durable backoff and do not block source synchronization.

The same one-shot synchronization sends bounded workspace inventory reports. The authority labels these `agent_reported`, records receipt time and staleness, and never claims to have inspected a remote disk. Local inventory retains directory paths; reports omit them. `workspace_inventory.remote_hosts` has its own cursor. Completed operations, declarations, receipts and host reports feed the central action audit; public GitHub source backup remains separate from private audit and review data.

## Checks and lifecycle

Commit shares conflict-free work without waiting for checks. A background worker validates the immutable combined shared tree outside the repo lock. Evidence binds the exact commit/tree, policy hash, results, bounded diagnostic output and timings. A shared result can be pending or failed; no checks still means `unchecked`. Two private changes can pass separately and fail together: the resulting shared failure opens one repair incident rather than a second conflict checkout. Side-messages target the assigned investigator, while all agents can inspect repo health and repair history. See [background validation and repair ownership](BACKGROUND-VALIDATION.md).

`workspace_close` archives metadata without moving/deleting the directory or private history. It requires the observed generation and confirmation that native writers have stopped. Retained historical launcher leases, active claims, unshared/pending/blocked work, open resolution work and pending delivery prevent closure. `workspace_reopen` restores normal operations in place. Launcher leases protect cooperative launched sessions; arbitrary external editors are not frozen. A session started before lease support requires explicit operator care.

Init optionally accepts `ignore_template`: `python`, `node` or `python-node`. `ignore_templates` shows the exact rules. The preset changes the initial shared tree, leaving the source directory unchanged. Status and Commit return bounded generated-file warnings separating `included_in_save` from `excluded_from_save`. Warnings never delete files; existing fixed exclusions still apply and are not secret scanning.

See [the dated acceptance results and limits](AGENT-FEEDBACK-VALIDATION.md).

## Reproduce validation

```sh
cargo build --locked
uv run --no-project python tests/agent_experience.py
uv run --no-project python tests/shared_commit.py
cargo test --locked
cargo test --locked --manifest-path services/transport/Cargo.toml
```

`WIPSTASH_EXPERIENCE_ARTIFACTS=/absolute/new-or-existing/path` saves per-scenario metrics for scripted CLI clients, including comparison Clones, review opens, Commit attempts, overlap warnings and elapsed time. These deterministic regressions cover the reported README baseline problem, binary and rename/delete conflicts, combined-candidate check failure, active leases, expired claims, recovery after process exit and lost replies. Existing core/transport suites cover repeated head contention, source delivery and idempotency; separate mTLS tests exercise remote claims, identity, cached truth, offline queues and restarted retry workers.

An opt-in native acceptance run invokes the four installed products with normal shell access to `wip` and a fresh fixture repo. It uses their model accounts, never edits global client configuration and records native outcomes separately from scripted tests:

```sh
uv run --no-project python tests/native_agent_experience.py --run-native \
  --artifacts /absolute/new/evidence/path
```

Use `--pi-model PROVIDER/MODEL` only when a test needs an available Pi model override. The summary records isolation, shared outcomes, workspace/Clone counts, Commit attempts and elapsed time. A four-client local run does not establish deployed multi-host reliability, arbitrary writer containment, large-refactor scalability or semantic correctness.
