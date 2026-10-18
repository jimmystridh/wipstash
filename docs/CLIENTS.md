# Local Codex and Claude Code adapter

Wipstash provides a stdio MCP adapter: `wipstash --state ABSOLUTE_STATE_DIR mcp`.
It uses the same cooperative engine and OS account as the JSON CLI. This stdio adapter itself provides no network service, authentication, enforced
editor interception, or remote access. The separate authenticated peer service is
documented in NETWORK.md.
Only stdout carries newline-delimited JSON-RPC; diagnostics use stderr.

## Setup examples

Build with `cargo build --locked`. Initialize a disposable project using the CLI
before connecting a client. Keep state outside every workspace and source tree.

- `examples/clients/codex.toml`: merge the stanza into your Codex configuration.
- `examples/clients/claude.mcp.json`: merge its entry into the project's `.mcp.json`.

Replace both example absolute paths. On native Windows use `wipstash.exe` and
JSON/TOML-escaped absolute Windows paths, for example `C:\\tools\\wipstash.exe`.
Do not commit real private directory paths or credentials. Review the client
approval prompts; these examples do not disable them. The generic tool exposes
trusted engine operations including command execution and configuration, so do
not add this server to an untrusted shared client.

Official configuration references:
[Codex MCP](https://developers.openai.com/codex/mcp) and
[Claude Code MCP](https://code.claude.com/docs/en/mcp).

## Protocol contract

The adapter implements the tools-only, stdio subset of MCP revision 2025-11-25.
It returns that supported version if a client requests another revision; clients
that cannot support it must disconnect. Initialization validates client metadata,
then requires `notifications/initialized` before tool calls. Ping is available
throughout. Notifications never execute tools or receive responses. Batch arrays,
null IDs, malformed envelopes, unknown methods and malformed call envelopes have
JSON-RPC errors. Tool argument and engine errors are tool results with `isError`.
Each tool result carries both JSON text and `structuredContent`.

Frames are limited to 1 MiB, oversized frames are drained without unbounded
allocation, and each response is explicitly flushed. EOF terminates the server.
There is no pagination, progress stream, background-task capability or parallel
execution. A running engine call blocks further reads; cancellation notifications
cannot interrupt it. Configure client tool timeouts for your policy budget and
expect that a timeout/disconnect may leave an operation completed or uncertain.
This transport does not impose an engine-wide execution deadline or output cap.

Protocol references: [lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## Tools and safe workflow

Discover tools through `tools/list`; the schemas are the authoritative argument
shape. `wipstash_status`, `wipstash_updates`, `wipstash_open`,
`wipstash_checkpoint`, `wipstash_publish`, `wipstash_adopt`,
`wipstash_proposal_status`, `wipstash_resolution_tasks`,
`wipstash_resolution_open`, `wipstash_resolution_submit`, and
`wipstash_operation_status` cover ordinary work.
`wipstash` also accepts an existing JSON CLI request under `request` for other
operations, such as explicit integration and managed commands.

1. Open one isolated workspace per actor. Point each client's working directory
   at its own workspace. Merely registering MCP does not change its directory.
2. Before checkpoint/adoption, stop every native tool, shell, editor and background
   writer that can change the workspace. MCP cannot intercept these writers.
3. Use workspace status for `generation` and the selected `checkpoint` ID, or
   carry forward the generation returned by your last successful mutation when
   no other writer can have changed the workspace. Pass it as
   `expected_generation` where required. A checkpoint ID is not its Git commit
   OID. Give each new mutation a fresh `operation_id`, retaining the exact request
   before sending it. Do not silently refresh a rejected generation and retry a
   mutation: inspect the changed state and deliberately prepare a new request.
4. Checkpoint saves private WIP even if the source is broken. Publish only a
   deliberately selected checkpoint with an explicit intent, following caller
   authorization and client approval settings; this does not require a human
   approval for each already-authorized publication. Integration does
   not change another actor's working files.
5. Query updates and explicitly adopt when ready. Read `resolution_tasks` on
   status/updates and `resolution_task` on proposal status. For a quarantined
   publication, resolve in a separate checkout, checkpoint there and explicitly
   resubmit; never reset the original workspace. See [CONFLICTS.md](CONFLICTS.md)
   for the complete agent workflow and the separate adoption-conflict boundary.
6. After a timeout/disconnect, query `operation_status` for the same operation ID.
   Retry the identical request only, never reuse that ID with changed arguments.
   An uncertain managed command must not be rerun automatically. After independently
   stopping surviving writers, `command_recover` through the generic tool requires
   `confirm_writers_stopped:true` plus workspace, operation ID and current generation.
   This is an operator assertion, not proof of process-tree containment.

## Check evidence and compact state

Checks remain optional: the default policy is `checks: []`. Private checkpoints
can contain broken code. A successful publication or resolution submission means
queue admission, not passing checks or successful integration. Configured required
checks still gate promotion; this adapter never configures or runs new commands
on the user's behalf merely because a response suggests a next action.

Agent-facing responses expose a `validation` object with one of four states:

- `unchecked`: no sufficient snapshot-bound passing check evidence is available.
- `pending`: evaluation has not established an outcome for this queued candidate.
- `passed`: recorded checks affirmatively passed for the indicated candidate;
  this is not proof of arbitrary semantic correctness.
- `failed`: recorded evaluation/check evidence reports failure.

Read the evidence scope and candidate identity as well as the state. Current
policy configuration and historical evidence are different facts. A sanitized
remote receipt saying only `checks_executed` cannot establish `passed`.

Run only project-authorized local checks, and stop immediately if one fails.
Do not put a checkpoint/submission command after a test with an unconditional
shell separator. Review the complete resolved diff, including preservation of
already integrated behavior. Where authorized, configure required integration
checks as the enforcement boundary; an agent's local test is advisory unless the
project's policy actually gates promotion.

Workspace status combines the current generation/checkpoint, existing resolution
tasks and at most ten recent proposal summaries. Each summary includes validation
and a structured `next_action`; `proposals_total`, `proposals_limit` and
`proposals_truncated` make the preview boundary explicit. Query `proposal_status`
for a specific older proposal or its complete diagnostics. This avoids fetching
the same workspace/proposal state through several tools in the common case.

Structured recovery and next-action fields are guidance, never authorization.
`requires_explicit_request` means the server does not take the suggested action
automatically; an already-authorized agent can issue the call without asking a
human again. Publication and adoption remain separate explicit calls. Error responses retain
their existing `error.code` and `error.message` and add recovery guidance where
available. An operation-status replay is the original recorded response, not a
fresh observation: re-read status when current state matters.

For reliable client recovery, `operation_status` optionally accepts
`include_record: true`. A found operation returns a `recorded: true` envelope
with `state: "pending"` and `result: null`, or `state: "completed"` and the exact
recorded result. Both include the original stored `request`; verify it matches
your exact pending intent before accepting the result, since another caller may
have used the same operation ID. The nested result can itself be a failed operation. An unknown
ID returns `operation_not_found`; neither an unknown ID nor a pending result
authorizes an automatic retry. Omitting this option preserves the original
unwrapped response format.

## Durable long-lived Python client

`examples/clients/wipstash_client.py` provides a standard-library client for the
built Wipstash executable. It negotiates initialization in order, discovers tools
once per connection, and reuses that stdio connection. It runs a separate
`wipstash client-journal ABSOLUTE_DIRECTORY` subprocess for the native private
receipt store on Linux, macOS and Windows. No listener, persistent grant, editor
interception or automatic integration is added.

Put the journal outside source and all workspaces: exact requests and results
may contain private information. Its parent must exist; use a canonical absolute
path without symlink/reparse ancestors. The native store uses verified account
permissions, exclusive ownership while locked, and create-only durable records.
It refuses unsafe paths instead of repairing their permissions. On Windows it
flushes file contents but does **not** promise directory-entry durability across
power loss. Inspect `client.journal_durability` for the active guarantee.

The client bounds incoming engine responses at 8 MiB, engine request frames at
1 MiB, and escaped native-journal frames at 10 MiB. Journal string escaping can
make a response exceed the journal limit even when it fits the engine-response
limit. Oversized results fail closed and can leave the intent unresolved; they
are never truncated and marked complete. The journal binds the server argv and
working directory, so reopen it with the same endpoint configuration.

```python
from wipstash_client import WipstashClient, UncertainOperation

with WipstashClient(
    [binary, "--state", str(state), "mcp"],
    journal_dir=str(journal),
) as client:
    status = client.read("status", workspace="alice")
    if not status["ok"]:
        raise RuntimeError(status)
    save_id = client.new_operation_id("save")  # Retain this ID and request.
    request = {"op": "checkpoint", "workspace": "alice",
               "expected_generation": status["generation"],
               "operation_id": save_id}
    try:
        saved = client.mutate(request)
    except UncertainOperation:
        saved = client.reconcile(save_id)  # May remain uncertain; never replay.
    if not saved["ok"]:
        raise RuntimeError(saved)
    # Only an explicit, authorized publish call exports saved["checkpoint"].
```

Add the examples directory to your Python module path when importing. Generate a
new ID for a new action, not each retry. `mutate` durably records the exact request
before dispatch. The same ID with changed arguments rejects locally. A completed
receipt returns its saved outcome; a pending receipt only queries
`operation_status`, including after restarting the client. Neither an unknown
operation nor an uncertain managed command is automatically rerun. Backend or
transport failure can leave an uncertain outcome even if the caller saw no
success; preserve the journal and reconcile before changing anything.

`read` and `mutate` return engine `ok: false` results rather than raising for them.
Check `ok` before dependent actions. An exited `command_run` also requires
checking `execution.success`; this client does not turn a failed local check into
an integration gate. `UncertainOperation` denotes an unresolved operation;
`ProposalTimeout` denotes an expired bounded wait and retains its last status.

`wait_for_proposal(proposal, timeout=60, initial_delay=0.25, max_delay=2)` uses a
monotonic deadline and bounded backoff. It returns actionable dispositions such
as quarantine as well as successful integration; inspect the result. It never
integrates, resubmits, adopts or silently follows a replacement proposal.
An ordinary read-only client can omit `journal_dir`; mutations require it.
Operations without engine idempotency, such as `init` and `integrate`, remain
outside `mutate` and require separate explicit caller orchestration.

## Evidence and release gates

A [six-arm native coding-agent pilot](REAL-AGENT-VALIDATION.md) at
`c489e00ea284127389e29e9e9875eb6db26132b2` verified bounded local model-driven
conflict/check-failure resolution and resubmission with private WIP preserved:
45 integrated snapshots and 39 superseded predecessors, with all lineages drained.
These were genuine autonomous model agents using the CLI, not standalone Codex
CLI or Claude Code product sessions; this does not establish MCP product-client
acceptance or close writer-containment, remote and platform gates.


`cargo test --locked client::tests` checks transport/session behavior without
invoking storage. `python3 tests/mcp_protocol.py` drives the compiled executable
through actual stdin/stdout pipes, including a live flush check and EOF shutdown.
These are scripted protocol tests, not AI-agent sessions.

The installed `codex-cli 0.159.2` successfully parsed a scratch-scoped server
configuration through `codex mcp get wipstash --json` on this Linux cloud host.
That verifies configuration parsing only: it does not connect or negotiate with
Wipstash, invoke a model, or prove a product workflow. Real Codex execution was
attempted but its app-server initialization failed on a read-only filesystem in
this cloud runtime, including after documented scratch-directory overrides.

Claude Code 2.1.302 was installed in an isolated test prefix and successfully
connected to the real stdio server: project approval gating, initialization,
initialized notification and discovery of all nine tools present at that
checkpoint were observed. This is actual client protocol evidence, not a
model-driven editing session; it does not validate the later resolution tools. See
[Claude validation](../examples/clients/CLAUDE-VALIDATION.md).
No credentials or persistent user configuration were created or changed.

`.github/workflows/native.yml` defines native Linux/macOS/Windows builds, test
compilation, and protocol tests, plus Linux unit tests. Merely checking in that
workflow is not a passing CI result. Selected native Linux/macOS/Windows
contracts did pass at commits recorded in [SCOPE.md](SCOPE.md#verified-native-baseline),
including process, MCP and policy contracts; later guided-pairing evidence is
recorded there separately. This does not certify new conflict-handback changes.
Full Windows adoption, broader filesystem semantics, open-file/reparse-point
hazards, executable-bit preservation, directory durability, arbitrary process
containment, real credential-vault retrieval and installers remain open. Windows
daemon IPC is explicitly unsupported; stdio does not require a socket. A historical
Unix socket bind attempt on this cloud host was blocked by sandbox `EPERM`; no
cloud-local socket success is claimed or bypass attempted. That denial is separate
from the recorded native CI contracts.

Before claiming real-client support, retain client version and configuration,
handshake/tool-list evidence, approved actual tool-call transcripts, checkpoint /
publish / integrate / adopt outcomes, and lost-response recovery evidence from
both products. Before claiming native OS support, retain successful native CI and
filesystem/process acceptance results on each OS.
