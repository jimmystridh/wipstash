# Agent ergonomics changes and validation

18 October 2026. This report separates API behavior, deterministic transport
validation, native model-agent evidence and product-client acceptance.

## Changes

- Explicit snapshot-bound `unchecked`, `pending`, `passed` and `failed`
  validation, separate from current policy counts and integration state. No
  configured checks remains a supported default; it never becomes `passed`.
- Workspace status combines generation, selected checkpoint identity, resolution
  tasks and ten recent proposal summaries with explicit truncation. Structured
  next actions and recovery hints preserve publication/adoption decisions.
- Durable native client receipts, private permissions and exclusive locking on
  Linux/macOS/Windows. The Python client negotiates once per connection, retains
  exact requests, verifies request identity during lost-response recovery, and
  uses bounded observation backoff. It never automatically replays uncertainty.
- MCP schemas explain identity/generation/head boundaries and expose response
  evidence. Compatible-head resolution reuse already existed and is preserved.

Required integration checks still enforce the existing policy. This change does
not install a project test command or make arbitrary source semantically safe.
Private broken checkpoints remain allowed; publication and adoption remain
separate explicit calls. See [client contract](CLIENTS.md) for API examples,
size limits and the Windows directory-entry/power-loss durability boundary.

## Deterministic real-stdio comparison

The same revised binary ran two isolated copies of one four-actor fixture.
One observation recipe called status, updates, proposal status and resolution
tasks separately; the other used the compact workspace status. These are
scripted personas, not autonomous model agents. MCP connections were long-lived
and correctly sequenced. Initialization and explicit integration used the CLI.

Both runs passed with equivalent observed state and final worktrees:

- Repeated-read recipe: 63 observation requests.
- Compact-status recipe: 15 observation requests.
- Saved: 48 observation requests, or 76.19% in this fixture.
- Concurrent checkpointing and competing resolutions, stale-head/generation
  rejection, exact receipt replay and changed-request rejection passed.
- A deliberately withheld completed checkpoint reply was recovered after normal
  EOF/restart by operation status. No mutation replay, kill or crash was injected.
- Private ancestry/live-WIP canaries were absent from all public objects,
  including unreachable blobs. Explicit adoption preserved compatible WIP.
- Git and SQLite integrity and duplicate-promotion checks passed.

This is a deliberately redundant-read comparison against the **same revised
server**, not an old/new implementation throughput benchmark. It does not
establish faster model reasoning, lower token cost, latency improvements,
optimal change size, sustained fairness or production-scale performance.

Local runs configured no check commands. The guarded native-CI extension tests
required-check `pending → failed → pending → passed`, no failed-candidate
promotion, and unchanged owner files. Native execution results must be read
from the exact CI revision; local success does not establish that gate.

Initial harness attempts exposed and corrected fixture assumptions: live private
WIP must be created after selecting the public checkpoint; the existing rejection
code is `generation_mismatch`; and adoption need not leave a named checkpoint ID.
These corrections did not relax engine assertions or configure checks locally.

Evidence: [local summary](../evidence/agent-ergonomics/local-summary.json).
Frozen binary SHA-256:
`17f5b3870e01b77529f305b6a245f8095d9e936e52a53d13eb8cf384941ace89`.
Frozen Python helper SHA-256:
`a1725ad3153a06086307fa55b74c96b5d0eaf02ed85391f60424c0df8e62db36`.

## Focused local verification

Final focused Linux checks passed: 8 MCP client tests, 12 feedback tests, 19 safe
engine regressions, 24 native-journal/shared-file tests, 10 transport private-file
tests, 30 Python client tests including real engine/native-journal recovery, and
12 pressure-harness synthetic tests. Counts overlap where tests belong to more
than one filtered suite; they must not be added into a unique-test total.
Formatting, strict all-target Clippy and whitespace checks passed.

Independent review led to additional safeguards: uncertain commands and ID
collisions cannot suggest fresh-ID replay; imported peer proposals cannot suggest
invalid local-workspace actions; recovered promotions cannot reuse stale prior
candidate validation; and recovered client results must match the stored request,
not merely its operation ID. Native journal backing names encode IDs to avoid
Windows case-folding/reserved-name collisions.

macOS/Windows runtime results and full required-check execution remain separate
native CI gates. Standalone Codex/Claude model-driven product-client UX remains
unverified; earlier Codex runtime initialization was blocked by the host's
read-only filesystem. The optional ChatGPT MCP Events service remains a separate
sanitized read/notification interface, not this local mutating stdio adapter.
