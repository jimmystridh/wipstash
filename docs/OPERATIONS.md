# Wipstash core operations reference

Wipstash combines source capture, submission and attempted shared integration in one commit, while merge remains deliberate. It uses ordinary workspace directories, Git objects and SQLite. **This repository is a cooperative, single-machine prototype, not the complete cross-platform/networked system in the design specification.** Read [the scope and evidence boundary](SCOPE.md) and [gap-closure status](GAP-CLOSURE.md) before using it.

There are no project compilation, test or lint checks by default (`checks = []`). A commit can integrate broken source when no checks are configured. The tests below test Wipstash itself; they do not become mandatory checks on projects it manages.

## Build and test

Prerequisites: Rust/Cargo, Git with `merge-tree --write-tree` support, and Python 3 for the integration harness. `rust-toolchain.toml` pins Rust 1.99.1, the tested environment; this is not a declared minimum supported Rust version (MSRV). The full cooperative workflow is exercised on Linux; selected process, Git-path, storage and transfer contracts also run in macOS/Windows CI. Complete native merge remains unverified; no minimum supported OS version is promised yet. Git must be on PATH. The lockfile is checked in; dependencies may need downloading on the first build.

```sh
cargo build --locked
cargo test --locked
python3 tests/adversarial.py
```

The independent harness runs real CLI processes, Git and SQLite, using four deterministic scripted actors. It does **not** run real Codex or Claude Code sessions. Evidence is retained under `../tests/artifacts/<timestamp>/`; use `--binary PATH` and `--artifacts PATH` to override defaults. See [tests/README.md](../tests/README.md). Test counts and outcomes belong to the final run evidence, not an assertion in this README.

## Runnable two-workspace example

Run from the repository root. This Python example avoids shell JSON quoting and makes fresh disposable directories. Keep the printed directory to inspect the result. Nothing is pushed to a remote service.

```sh
python3 - <<'PY'
import json, pathlib, subprocess, tempfile
binary = str(pathlib.Path('target/debug/wipstash').resolve())
root = pathlib.Path(tempfile.mkdtemp(prefix='wipstash-demo-'))
state = root / 'state'
source = root / 'source'
source.mkdir()
(source / 'hello.txt').write_text('initial\n')
def request(**body):
    result = subprocess.run([binary, '--state', str(state), json.dumps(body)],
                            check=True, text=True, capture_output=True)
    reply = json.loads(result.stdout)
    print(json.dumps(reply))
    return reply
request(op='init', source=str(source))
for name in ('alice', 'bob'):
    request(op='clone', workspace=name, path=str(root/name), operation_id='open-'+name)
(root/'alice'/'hello.txt').write_text('published by alice\n')
committed = request(op='commit', workspace='alice', expected_generation=0,
                    message='Update greeting', operation_id='commit-alice')
assert committed['shared'], committed
request(op='get_latest', workspace='bob')
assert (root/'bob'/'hello.txt').read_text() == 'initial\n'
request(op='merge', workspace='bob', target='latest', expected_generation=0,
        operation_id='merge-bob')
assert (root/'bob'/'hello.txt').read_text() == 'published by alice\n'
print('Disposable demo directory:', root)
PY
```

`init` imports the allowed source tree as the initial **public** integration head. Review the source before import. Workspace directories must be absolute, empty and nonoverlapping with each other and the state directory. Keep state and workspaces outside the source tree. Stop all external writers before commit or merge; the prototype does not enforce that requirement.

See [concurrent-agent operations](AGENT-COLLABORATION.md) for prepared conflict review, advisory server claims, explicit status fields, workspace archive/reopen and Init ignore presets.

## JSON interface

```sh
./target/debug/wipstash --state /absolute/path/to/state '{"op":"status"}'
printf '%s\n' '{"op":"status"}' | ./target/debug/wipstash --state /absolute/path/to/state stdin
```

One-shot mode prints one JSON response and exits nonzero when `ok` is false. `stdin` accepts one request per line and prints one response per line. `operation_id` is a caller-chosen identifier (ASCII letters, digits, `_` or `-`, at most 100 characters). Reuse it only for the identical request; changing the body gives `idempotency_mismatch`. Workspace IDs have the same identifier restriction. An acknowledgement is not proof that project code is correct.

| `op` | Request fields in addition to `op` | Meaning |
|---|---|---|
| `init` | `source` | Import initial public source; fresh state only |
| `clone` | `workspace`, `path`, `operation_id` | Clone the project into an isolated working directory |
| `status` | optional `workspace` | Head or workspace state/generation |
| `commit` | `workspace`, `message`, `expected_generation`, `operation_id`; resolution adds `expected_head`, `resolved_conflicts` | Capture, submit and attempt shared integration in one action |
| `resolution_tasks` | `workspace` | Inspect blocked commit tasks |
| `resolution_open` | `workspace`, `commit_id`, `resolution_workspace`, `path`, `operation_id` | Open a separate resolution directory |
| `get_latest` | `workspace` | Fetch/cache shared head; never change workspace files |
| `merge` | `workspace`, `target`, `expected_generation`, `operation_id` | Reconcile live WIP with `latest` or an authoritative descendant OID |
| `resolve_merge` | `workspace`, `candidate`, `target`, `expected_generation`, `operation_id` | Accept the reviewed live merge reconciliation without sharing |
| `commit_status` | `commit_id` | Commit state and recorded details |
| `operation_status` | `operation_id` | Look up a known operation's recorded result |
| `events` | optional integer `cursor` (default 0) | Up to 1,000 events after cursor |
| `cancel` | `commit_id`, `operation_id` | Cancel queued/accepted/blocked commit |
| `retry_commit` | `commit_id`, `operation_id` | Explicitly retry a blocked commit |
| `configure` | `policy`, `operation_id` | Replace project check/repair policy |
| `command_run` | `workspace`, `expected_generation`, `argv`, optional `timeout_seconds`, `operation_id` | Cooperative command broker; durably increments generation before launch |
| `command_recover` | `workspace`, `expected_generation`, `operation_id`, `confirm_writers_stopped:true` | Explicit operator acknowledgement after stopping surviving writers; clears uncertain-command fence |
| `backup_flush` | `destination`, `operation_id` | Configure/flush to an existing local bare Git repository |
| `backup_tick` | none | Retry configured local backup if needed |
| `backup_status` | none | Report local backup watermark and lag |
| `backup_verify_restore` | `destination` | Read-only backup consistency preflight; does not restore state |
| `restore` | `destination` | Recover a public commit into a new empty state directory |

Use returned generations or query `status`. Commit capture, successful merge, explicit resolution and `command_run` advance the generation. Generation checks serialize cooperative operations; they cannot detect or exclude every native editor/background writer. `command_run`'s top-level `ok` means the request completed: inspect `execution.success`, exit code and timeout to determine whether the command succeeded.

Commit never means merge. It exports ancestry from the merged public base; internal recovery commits remain private. Initial import and committed contents are public. Filename exclusions are **not secret detection**.

Commit attempts integration immediately. Require `shared:true` before claiming it landed. A queued result remains pending for automatic processing; a blocked result needs conflict investigation. Checks run asynchronously after sharing; absent checks are `unchecked`. A recorded operation result is historical: query the commit for its current disposition and read `repo_health` and your repair notices.

Persist the exact request before dispatch. Interrupted commits reuse the completed durable commit and pinned public identity, never newer live bytes. Incomplete captures fail rather than recapturing automatically. After uncertainty, inspect `operation_status` for the original ID before choosing an action. Conflicting pins fail closed.

## Background operation

After initialization, run this in a separate terminal:

```sh
./target/debug/wipstash --state /absolute/path/to/state worker
```

The worker periodically integrates queued commits and retries the configured local backup with bounded backoff. A separate validation worker checks immutable shared code outside the state lock. Checks do not delay reads or sharing. Explicit managed workspace commands retain writer fencing. Source capture and live inspection no longer hold the repository lock; source integration remains serialized. Prepared backup transfer runs outside the repository lock. Metadata reads and brief coordination mutations use the responsive path described in BACKGROUND-VALIDATION.md. Stop the worker with Ctrl-C. It shares `daemon.lock` with `daemon`, so do not run both for one state directory. The transport authority worker also runs background validation. A missing/stopped worker leaves validation pending; it does not misreport a pass.

`daemon` implements a Unix socket server at `STATE/daemon.sock` with mode 0600 and periodic integration. Socket binding was denied with `EPERM` in the cloud test environment, so its actual request path is unverified there. No alternate network listener is provided as a workaround. The CLI and worker use the engine directly, not socket RPC; the socket daemon does not run the worker's backup retry loop. The core daemon has no Windows named-pipe implementation. A separate authenticated remote component is documented in [NETWORK.md](NETWORK.md).

## Explicit merge resolution

A dirty merge conflict returns `ok:false`, `state:"conflict"`, a `candidate` ID and exact `target` OID. It leaves the live workspace unchanged and pins a private recovery commit.

1. Retain the candidate and exact target. Stop other writers and manually edit the live workspace into the reviewed resolved result, incorporating the target changes you intend to accept.
2. Read the current generation and call `resolve_merge` with `workspace`, the original `candidate` and `target`, `expected_generation` and a fresh `operation_id`.

Resolution verifies the original base/target/generation and stable live files, records private recovery ancestry and advances the merged base without replacing your reviewed files. It does not share private edits. Use an authorized commit afterward to share them. Intervening engine mutations can stale the candidate; inspect rather than silently refreshing it.

## Background checks and agent repairs

`configure` replaces the policy. Reset to unchecked operation with:

```json
{"op":"configure","operation_id":"policy-empty","policy":{"checks":[]}}
```

An explicitly configured check uses an argv array, no implicit shell:

```json
{"op":"configure","operation_id":"policy-example","policy":{"checks":[{"id":"sample","argv":["/usr/bin/python3","-c","print('configured check')"],"required":true,"timeout_seconds":30}]}}
```

Checks run asynchronously against separate immutable shared checkouts. Commands default to 60 seconds and allow 1–600 seconds, with a ten-minute total run budget. Failures and check mutations are recorded after sharing, including advisory failures; `required` no longer gates Commit. Output retains at most 8 KiB per stream, with hashes/counts and per-check durations.

On supported Unix platforms, commands run with a cleared environment, controlled PATH (`/usr/bin:/bin`), C locale, checkout-local HOME/TMPDIR, and `WIPSTASH_HEAD`, `WIPSTASH_PROPOSAL`, `WIPSTASH_CANDIDATE_TREE` bindings. Administrator-configured commands are trusted: the checkout is **not an OS security sandbox**, and commands can access the invoking account's filesystem/network. Never configure untrusted candidate-controlled commands on a sensitive machine.

Failures have one leased repair owner. Use `repair_list` and `repair_update` to inspect, acknowledge, renew, release or claim an incident. The owner shares a fix with a normal Commit; passing checks on current shared code close the incident. New automatic repair-command policies are rejected. Legacy stored repair commands are not executed. See [background validation](BACKGROUND-VALIDATION.md).


With no checks, an accepted repair is labeled `agent_resolved_unchecked`; with configured checks, `checks_executed` means they ran, not that every advisory check passed. Inspect `commit_status.details` and individual check records. This contract records an explicit worker declaration and structural changes; even a valid report cannot prove semantic correctness.

## Local backup simulation

Create a disposable destination, then explicitly configure it:

```sh
git init --bare /absolute/path/to/backup.git
./target/debug/wipstash --state /absolute/path/to/state '{"op":"backup_flush","destination":"/absolute/path/to/backup.git","operation_id":"backup-1"}'
./target/debug/wipstash --state /absolute/path/to/state '{"op":"backup_status"}'
./target/debug/wipstash --state /absolute/path/to/state '{"op":"backup_verify_restore","destination":"/absolute/path/to/backup.git"}'
```

Only existing local bare repositories are accepted. This is not GitHub replication. The allowlisted integration, metadata and public commit refs live under `refs/heads/wipstash/`; no private recovery record refs are intentionally exported. A complete watermark requires verification of the expected ref set. Unexpected destination divergence blocks replication rather than overwriting foreign history. Later flushes must use the configured destination.

`backup_verify_restore` checks the public commit/manifest and object availability read-only. It does **not** rebuild state. To recover the supported public subset into a **new empty state directory**, use the separate command:

```sh
./target/debug/wipstash --state /absolute/path/to/new-recovered-state '{"op":"restore","destination":"/absolute/path/to/backup.git"}'
```

`restore` verifies and imports public source/commit roots, reconstructs sanitized public events and commit dispositions with public queue review commits, and initializes a standalone local authority at the backup watermark. Public commits without an integrated/cancelled record receive the conservative state `recovery_blocked`; `retry_commit` rejects that state. Their original eligibility, commit message and ownership were not exported and cannot be reconstructed; review and republish rather than treating them as automatically eligible work. Private workspaces, private recovery records, original operation identities, policy and full queue semantics are not recovered. Clone into new workspaces after recovery. A crash between installing the staged repository and committing SQLite can leave an orphan repository: subsequent restore fails closed for inspection and never automatically overwrites it.

This is a public recovery subset, not zero-loss recovery, full coordinator reconstruction or network-authority migration. Do not switch clients to it as though it were an authenticated replacement authority. A second repository on the same disk does not protect against loss of that disk. Consult [SCOPE.md](SCOPE.md) for the remaining release gates.

## Independent client/authority source exchange

See [SOURCE-SYNC.md](SOURCE-SYNC.md) for `sync_configure`, `sync_export`, `sync_import`, `sync_export_history`, and `sync_reexport`. Separate client stores can deliberately publish commit artifacts, an authority can integrate them, and clients can import verified public heads before explicitly merging. Transfers preserve private workspace/recovery record isolation. Import requires explicit confirmation of separately trusted artifact provenance. These core commands exchange filesystem artifacts. The separate [mTLS transport component](NETWORK.md) handles authenticated network transfer; deployed multi-machine acceptance remains open. Fresh clients must replay head history in order; history artifacts can be regenerated. Effective full-history transfer limit is 8 MiB.

## Standalone client setup

Use `wip` directly from each agent's own clone. Stage with `wip add PATH`, then share with `wip commit -m MESSAGE`. Source-control MCP and client services are removed. See [CLIENTS.md](CLIENTS.md) for remote profiles, the complete command surface, staging and retained-operation recovery.

Run `uv run --no-project python tests/cli.py` for actual CLI subprocess contracts. The opt-in native acceptance harness starts the four products normally in isolated CLI-configured clones. Model-driven results must be recorded separately from deterministic tests. Native edits remain cooperative.

An interrupted managed command is never replayed. Its workspace is fenced until an operator stops surviving writers and deliberately calls `command_recover`. Status reports the fence. The acknowledgement is an assertion, not an enforced process-tree guarantee. Arbitrary native writers remain outside the cooperative safety contract.

The native CI definition in `.github/workflows/native.yml` exercises selected contracts on Linux/macOS/Windows. Full Windows merge and arbitrary-writer coordination are still release gates. Read [STORAGE.md](STORAGE.md) for size/free-space/durability limits and [TRANSPORT.md](TRANSPORT.md) for the replay/admission foundation used by explicit source exchange. Separate authenticated transport and GitHub backup components exist; real remote credentials, deployed multi-machine acceptance and fresh-host recovery remain release gates.

## Action audit

See [central action audit](AUDIT.md) for the server log, native collection, durable delivery receipts, verification and private exports. Audit state is separate from public source backups.
