# Wipstash core operations reference

Wipstash separates private checkpoints, deliberate publication, shared integration and deliberate adoption. It uses ordinary workspace directories, Git objects and SQLite. **This repository is a cooperative, single-machine prototype, not the complete cross-platform/networked system in the design specification.** Read [the scope and evidence boundary](SCOPE.md) and [gap-closure status](GAP-CLOSURE.md) before using it.

There are no project compilation, test or lint checks by default (`checks = []`). Broken source can be checkpointed and published. The tests below test Wipstash itself; they do not become mandatory checks on projects it manages.

## Build and test

Prerequisites: Rust/Cargo, Git with `merge-tree --write-tree` support, and Python 3 for the integration harness. `rust-toolchain.toml` pins Rust 1.99.1, the tested environment; this is not a declared minimum supported Rust version (MSRV). The full cooperative workflow is exercised on Linux; selected process, Git-path, storage and transfer contracts also run in macOS/Windows CI. Complete native adoption remains unverified; no minimum supported OS version is promised yet. Git must be on PATH. The lockfile is checked in; dependencies may need downloading on the first build.

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
    request(op='open', workspace=name, path=str(root/name), operation_id='open-'+name)
(root/'alice'/'hello.txt').write_text('published by alice\n')
request(op='checkpoint', workspace='alice', expected_generation=0, operation_id='save-alice')
request(op='publish', workspace='alice', checkpoint='save-alice',
        intent='Update greeting', operation_id='publish-alice')
request(op='integrate')
request(op='updates', workspace='bob')
assert (root/'bob'/'hello.txt').read_text() == 'initial\n'
request(op='adopt', workspace='bob', target='latest', expected_generation=0,
        operation_id='adopt-bob')
assert (root/'bob'/'hello.txt').read_text() == 'published by alice\n'
print('Disposable demo directory:', root)
PY
```

`init` imports the allowed source tree as the initial **public** integration head. Review the source before import. Workspace directories must be absolute, empty and nonoverlapping with each other and the state directory. Keep state and workspaces outside the source tree. Stop all external writers before checkpoint or adoption; the prototype does not enforce that requirement.

## JSON interface

```sh
./target/debug/wipstash --state /absolute/path/to/state '{"op":"status"}'
printf '%s\n' '{"op":"status"}' | ./target/debug/wipstash --state /absolute/path/to/state stdin
```

One-shot mode prints one JSON response and exits nonzero when `ok` is false. `stdin` accepts one request per line and prints one response per line. `operation_id` is a caller-chosen identifier (ASCII letters, digits, `_` or `-`, at most 100 characters). Reuse it only for the identical request; changing the body gives `idempotency_mismatch`. Workspace IDs have the same identifier restriction. An acknowledgement is not proof that project code is correct.

| `op` | Request fields in addition to `op` | Meaning |
|---|---|---|
| `init` | `source` | Import initial public source; fresh state only |
| `open` | `workspace`, `path`, `operation_id` | Materialize isolated ordinary directory |
| `status` | optional `workspace` | Head or workspace state/generation |
| `checkpoint` | `workspace`, `expected_generation`, `operation_id` | Capture private WIP; checkpoint ID is operation ID |
| `publish` | `workspace`, `checkpoint`, `intent`, `operation_id` | Publish exactly the selected checkpoint; proposal ID is operation ID |
| `integrate` | none | Process queued proposals, quarantine unresolved conflicts |
| `updates` | `workspace` | Fetch/cache shared head; never change workspace files |
| `adopt` | `workspace`, `target`, `expected_generation`, `operation_id` | Reconcile live WIP with `latest` or an authoritative descendant OID |
| `resolve_adoption` | `workspace`, `candidate`, `target`, `checkpoint`, `expected_generation`, `operation_id` | Explicitly accept a manually resolved private checkpoint |
| `proposal_status` | `proposal` | Proposal disposition and recorded details |
| `operation_status` | `operation_id` | Look up a known operation's recorded result |
| `events` | optional integer `cursor` (default 0) | Up to 1,000 events after cursor |
| `cancel` | `proposal`, `operation_id` | Cancel queued/accepted/quarantined proposal |
| `retry_proposal` | `proposal`, `operation_id` | Explicitly retry a quarantined proposal |
| `configure` | `policy`, `operation_id` | Replace project check/repair policy |
| `command_run` | `workspace`, `expected_generation`, `argv`, optional `timeout_seconds`, `operation_id` | Cooperative command broker; durably increments generation before launch |
| `command_recover` | `workspace`, `expected_generation`, `operation_id`, `confirm_writers_stopped:true` | Explicit operator acknowledgement after stopping surviving writers; clears uncertain-command fence |
| `backup_flush` | `destination`, `operation_id` | Configure/flush to an existing local bare Git repository |
| `backup_tick` | none | Retry configured local backup if needed |
| `backup_status` | none | Report local backup watermark and lag |
| `backup_verify_restore` | `destination` | Read-only backup consistency preflight; does not restore state |
| `restore` | `destination` | Recover a public snapshot into a new empty state directory |

Use returned generations or query `status`. Checkpoint, successful adoption, explicit resolution and `command_run` advance the generation. Generation checks serialize cooperative operations; they cannot detect or exclude every native editor/background writer. `command_run`'s top-level `ok` means the request completed: inspect `execution.success`, exit code and timeout to determine whether the command succeeded.

Publication never means adoption. Private history is retained in each workspace's object store; publication builds export ancestry from the adopted public base rather than private checkpoint parents. Initial import and published snapshot contents are public. Exclusions are a fixed filename policy, **not secret detection**: credentials in an ordinary source file can still be published.

An interrupted publication retried with the identical request reuses its original pinned public commit, including its timestamp and object ID. The saved pin must match the selected checkpoint tree, public base, and operation identity. Conflicting export or coordinator proposal pins fail closed rather than being overwritten; private checkpoint ancestry is never used to repair a publication.

## Background operation

After initialization, run this in a separate terminal:

```sh
./target/debug/wipstash --state /absolute/path/to/state worker
```

The worker periodically integrates proposals and retries the configured local backup with bounded backoff. It uses no network endpoint. CLI requests and the worker share a state lock; long checks/commands block other state operations. Stop the worker with Ctrl-C. It shares `daemon.lock` with `daemon`, so do not run both for one state directory.

`daemon` implements a Unix socket server at `STATE/daemon.sock` with mode 0600 and periodic integration. Socket binding was denied with `EPERM` in the cloud test environment, so its actual request path is unverified there. No alternate network listener is provided as a workaround. The CLI and worker use the engine directly, not socket RPC; the socket daemon does not run the worker's backup retry loop. The core daemon has no Windows named-pipe implementation. A separate authenticated remote component is documented in [NETWORK.md](NETWORK.md).

## Explicit adoption resolution

A dirty adoption conflict returns `ok:false`, `state:"conflict"`, a `candidate` ID and exact `target` OID. It leaves the live workspace unchanged and pins a private recovery commit.

1. Save that candidate and target. Stop other writers and manually edit the live workspace into the intended resolved result, incorporating the target changes you want.
2. Create exactly one new checkpoint using the current generation and a new operation ID.
3. Call `resolve_adoption` with that checkpoint, the original candidate and exact target, the checkpoint's returned generation and a new operation ID.

Resolution requires the same adopted base, candidate target, live checkpoint tree and the expected one-generation transition. Intervening checkpoints/adoptions make it stale. This is an explicit declaration by the caller, not semantic validation or automatic conflict repair. Resolution records ancestry and advances the adopted base without replacing the manually resolved live files.

## Optional checks and repair

`configure` replaces the policy. Reset to unchecked operation with:

```json
{"op":"configure","operation_id":"policy-empty","policy":{"checks":[]}}
```

An explicitly configured check uses an argv array, no implicit shell:

```json
{"op":"configure","operation_id":"policy-example","policy":{"checks":[{"id":"sample","argv":["/usr/bin/python3","-c","print('configured check')"],"required":true,"timeout_seconds":30}]}}
```

Checks run against separate temporary candidate checkouts. `required` defaults to true; advisory command failure does not reject, but mutation of the checkout does reject even for an advisory check. Commands default to 60 seconds and allow 1–600 seconds. A candidate evaluation has a ten-minute in-process budget. Output collection is bounded to 8 KiB per stream and reports hashes/counts rather than full logs.

On supported Unix platforms, commands run with a cleared environment, controlled PATH (`/usr/bin:/bin`), C locale, checkout-local HOME/TMPDIR, and `WIPSTASH_HEAD`, `WIPSTASH_PROPOSAL`, `WIPSTASH_CANDIDATE_TREE` bindings. Administrator-configured commands are trusted: the checkout is **not an OS security sandbox**, and commands can access the invoking account's filesystem/network. Never configure untrusted candidate-controlled commands on a sensitive machine.

To opt in to repair, add `"repair":{"argv":["/absolute/path/to/trusted-worker"],"max_attempts":2,"timeout_seconds":60}` to the policy. `max_attempts` defaults to two and accepts only one or two. Repair is attempted for conflicted candidates, with each attempt starting from the original candidate tree. Repair attempts reserve their full timeout in durable SQLite before launch, keyed by public proposal commit rather than proposal ID. Republishing the identical commit shares the allowance; a genuinely new public commit receives a new budget. At most two attempts and 600 reserved seconds are available across restarts and policy/head changes; interrupted reservations are not refunded. No Codex/Claude repair worker is bundled. Repair defaults to `execution_profile: "confined"`; unavailable confinement quarantines the proposal. Explicit `execution_profile: "trusted_unsandboxed"` is an unsafe development-only opt-in used by scripted tests. `sandbox_disabled: true` can only deny execution, never manufacture a confinement guarantee. See `crates/repair-runner/README.md`.

A repair command receives the bindings above plus:

- `WIPSTASH_CONFLICT_PATHS`: a JSON array of the exact conflict paths
- `WIPSTASH_RESOLUTION_FILE`: the absolute checkout-local `.wipstash-resolution.json` report path

It must change or delete every conflict path and write this JSON object at the supplied report path:

```json
{"head":"<WIPSTASH_HEAD>","proposal":"<WIPSTASH_PROPOSAL>","input_tree":"<WIPSTASH_CANDIDATE_TREE>","resolved_paths":["<each supplied conflict path>"]}
```

The three identity fields must exactly match their environment values. `resolved_paths` must cover exactly the supplied path set without duplicates. The report must be a regular nonsymlink file of at most 65,536 bytes. Successful exit alone, an unrelated edit, a missing report, wrong identities, or incomplete path coverage cannot resolve a conflict. The report is removed before capturing the candidate tree and is not source content. The resulting tree is then evaluated by any configured checks.

With no checks, an accepted repair is labeled `agent_resolved_unchecked`; with configured checks, `checks_executed` means they ran, not that every advisory check passed. Inspect `proposal_status.details` and individual check records. This contract records an explicit worker declaration and structural changes; even a valid report cannot prove semantic correctness.

## Local backup simulation

Create a disposable destination, then explicitly configure it:

```sh
git init --bare /absolute/path/to/backup.git
./target/debug/wipstash --state /absolute/path/to/state '{"op":"backup_flush","destination":"/absolute/path/to/backup.git","operation_id":"backup-1"}'
./target/debug/wipstash --state /absolute/path/to/state '{"op":"backup_status"}'
./target/debug/wipstash --state /absolute/path/to/state '{"op":"backup_verify_restore","destination":"/absolute/path/to/backup.git"}'
```

Only existing local bare repositories are accepted. This is not GitHub replication. The allowlisted integration, metadata and public proposal refs live under `refs/heads/wipstash/`; no private checkpoint refs are intentionally exported. A complete watermark requires verification of the expected ref set. Unexpected destination divergence blocks replication rather than overwriting foreign history. Later flushes must use the configured destination.

`backup_verify_restore` checks the public snapshot/manifest and object availability read-only. It does **not** rebuild state. To recover the supported public subset into a **new empty state directory**, use the separate command:

```sh
./target/debug/wipstash --state /absolute/path/to/new-recovered-state '{"op":"restore","destination":"/absolute/path/to/backup.git"}'
```

`restore` verifies and imports public source/proposal roots, reconstructs sanitized public events and proposal dispositions with public queue review snapshots, and initializes a standalone local authority at the backup watermark. Public proposals without an integrated/cancelled record receive the conservative state `recovery_quarantined`; `retry_proposal` rejects that state. Their original eligibility, intent and ownership were not exported and cannot be reconstructed; review and republish rather than treating them as automatically eligible work. Private workspaces, private checkpoints, original operation identities, policy and full queue semantics are not recovered. Open new workspaces after recovery. A crash between installing the staged repository and committing SQLite can leave an orphan repository: subsequent restore fails closed for inspection and never automatically overwrites it.

This is a public recovery subset, not zero-loss recovery, full coordinator reconstruction or network-authority migration. Do not switch clients to it as though it were an authenticated replacement authority. A second repository on the same disk does not protect against loss of that disk. Consult [SCOPE.md](SCOPE.md) for the remaining release gates.

## Independent client/authority source exchange

See [SOURCE-SYNC.md](SOURCE-SYNC.md) for `sync_configure`, `sync_export`, `sync_import`, `sync_export_history`, and `sync_reexport`. Separate client stores can deliberately publish proposal artifacts, an authority can integrate them, and clients can import verified public heads before explicitly adopting. Transfers preserve private workspace/checkpoint isolation. Import requires explicit confirmation of separately trusted artifact provenance. These core commands exchange filesystem artifacts. The separate [mTLS transport component](NETWORK.md) handles authenticated network transfer; deployed multi-machine acceptance remains open. Fresh clients must replay head history in order; history artifacts can be regenerated. Effective full-history transfer limit is 8 MiB.

## Stdio MCP and client setup

Run `wipstash --state /absolute/path/to/state mcp`. The adapter provides bounded, flushed newline-delimited JSON-RPC, MCP initialization/ready lifecycle, typed workflow tools and the generic `wipstash` request tool. See [CLIENTS.md](CLIENTS.md) for setup examples, supported protocol, exact schemas, trust boundary and recovery behavior.

Run `python3 tests/mcp_protocol.py` for scripted protocol tests. The installed Codex CLI parsed a scratch-scoped configuration; this is not evidence of an actual model session or complete client workflow. Claude Code stdio initialization/tool discovery has since been verified; this is not a real model-driven workflow. Neither adapter registration nor MCP intercepts native file edits.

An interrupted managed command is never replayed. Its workspace is fenced until an operator stops surviving writers and deliberately calls `command_recover`. Status reports the fence. The acknowledgement is an assertion, not an enforced process-tree guarantee. Arbitrary native writers remain outside the cooperative safety contract.

The native CI definition in `.github/workflows/native.yml` exercises selected contracts on Linux/macOS/Windows. Full Windows adoption and arbitrary-writer coordination are still release gates. Read [STORAGE.md](STORAGE.md) for size/free-space/durability limits and [TRANSPORT.md](TRANSPORT.md) for the replay/admission foundation used by explicit source exchange. Separate authenticated transport and GitHub backup components exist; real remote credentials, deployed multi-machine acceptance and fresh-host recovery remain release gates.
