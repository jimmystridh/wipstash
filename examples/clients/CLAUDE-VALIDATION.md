# Claude Code validation

Validated on the Linux cloud development host on 2026-10-17 with the actual
Anthropic CLI, **Claude Code 2.1.302**, installed from the official npm package
`@anthropic-ai/claude-code@2.1.302` into an isolated writable prefix. No model
session, sign-in, existing credential access, or real user configuration change
was performed.

## Reproduce the credential-free check

Build Wipstash first. Install the official CLI separately if needed, then run:

```sh
cargo build --locked
npm install --prefix /tmp/claude-validation --cache /tmp/claude-npm-cache \
  --no-audit --no-fund @anthropic-ai/claude-code@2.1.302
python3 tests/clients/claude_smoke.py \
  --claude /tmp/claude-validation/node_modules/.bin/claude \
  --evidence /tmp/claude-health-check.json
```

The smoke test creates synthetic source, state, project directory, HOME and
CLAUDE_CONFIG_DIR. It passes only a small environment allowlist, without
credentials. All test-created fixture/config directories are temporary. It uses
`claude mcp add --scope project --transport stdio` and a transparent stdio relay
around the real Wipstash binary to retain actual JSON-RPC messages.

Assertions and retained evidence:

- The CLI writes and reads a project `.mcp.json` entry.
- Before approval, `claude mcp get wipstash` reports `Pending approval` and does
  not launch the server.
- An explicit, per-invocation setting approves only this synthetic server.
  The subsequent health check reports `Connected`.
- The real client sends `initialize`, `notifications/initialized`, and `tools/list`.
- Wipstash responds with MCP 2025-11-25 and nine tool schemas, including status,
  checkpoint, publish, adopt, and operation-status recovery.
- Claude first probes `server/discover` using newer metadata. The current server
  rejects that pre-initialization probe with -32002. Claude then successfully
  falls back to the supported initialization sequence; no newer-protocol support
  is claimed.

The smoke runner writes wire evidence to the explicitly selected local evidence
path. Generated transcripts are not part of the public source distribution.
The smoke runner is [`tests/clients/claude_smoke.py`](../../tests/clients/claude_smoke.py).

## Remaining real-workflow gate

This proves actual Claude Code configuration, process launch, handshake and tool
discovery. It does **not** prove model-directed tool calls or the complete
checkpoint → publish → integrate → adopt workflow inside Claude Code. No paid
model session was invoked, and no authentication failure was fabricated by
attempting an unauthorized model call.

For that remaining gate, the operator must run `claude` interactively, complete
Anthropic's browser sign-in themselves with their chosen supported account, and
approve the project/server prompts. Existing approved authentication can also be
used by the operator. Do not paste credentials into this repository, copy another
client's credentials, or create a `setup-token` as a shortcut. Then approve a
bounded model-backed test on synthetic source and retain its actual tool-call
transcript, state assertions, private-checkpoint/publication/adoption outcomes,
and uncertain-response recovery. Configure each agent to work in its own isolated
workspace, with state outside the source and workspaces. Stop native writers
before checkpoint/adoption; MCP registration does not intercept native edits.

## Official references

- [Installation](https://code.claude.com/docs/en/setup)
- [MCP configuration and project approvals](https://code.claude.com/docs/en/mcp)
- [Authentication](https://code.claude.com/docs/en/authentication)
