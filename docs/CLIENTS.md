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
3. Read status for `generation`; pass it as `expected_generation` where required.
   Give every mutation a fresh `operation_id`, retaining the exact request.
4. Checkpoint saves private WIP even if the source is broken. Publish only a
   deliberately selected checkpoint with an explicit intent. Integration does
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

## Evidence and release gates

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
