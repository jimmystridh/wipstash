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

## Fresh native model-agent campaign

Three fresh autonomous native model actors independently implemented six utility
features sharing one registry hotspot. The frozen binary/helper hashes above were
used unchanged. Every one of six accepted public heads passed a fixed external
invariant oracle, preserving previously accepted behavior; there were no failed
intermediate heads or coordinator-written source fixes. This oracle audited after
promotion and was not an engine integration gate.

The campaign used seven long-lived MCP sessions and 72 actual tool calls, with
six original publications, five accepted resolution submissions and one deliberate
stale-head rejection followed by fresh-checkout recovery. Two completed replies
were deliberately withheld before client receipt completion; exact request-bound
operation recovery succeeded without duplicate mutation/promotion. All processes
closed normally by EOF. Explicit observer adoption preserved private WIP.

All 30 public blobs were canary-free, three historical private commits were absent
from the public store, and 24 original-workspace comparisons were unchanged.
Git/SQLite integrity passed. All 115 observed validation objects were honestly
unchecked because no engine checks were configured. This bounded controlled
campaign has no matched model baseline and establishes no throughput superiority
or standalone Codex/Claude product-client acceptance.

Evidence: [native model summary](../evidence/agent-ergonomics/native-model-summary.json).
The campaign exposed historical nested task/current checkout head naming ambiguity.
A separately tested follow-on adds explicit `captured_head`/`resolution_head` and
scope labels, preserving legacy aliases and exact recorded replies. The frozen
model campaign predates that patch. Legacy `checks_pending` is queue-era wording;
use structured `validation` and configured-check counts for actual check evidence.

## Native CI follow-on validation

The first native CI run of the frozen implementation exposed a Linux journal-lock
release race in the concurrent full suite and an unsupported Unix-style directory
flush in Windows adoption. Linux/macOS ergonomics jobs passed; Windows validation
and the overall delivery remained pending while these issues were repaired.
Native platform repair results must be attributed to their later exact CI SHA.

Follow-on local verification passed after the reviewed repairs: 14 feedback tests,
8 MCP tests, 15 journal tests (25 including shared private-file coverage),
13 adoption tests, 21 safe engine regressions, 30 Python helper tests and
15 pressure-harness tests. Counts overlap. The deterministic real-stdio campaign
passed again with the same 63-versus-15 observation count and equivalent state.
See [follow-on local summary](../evidence/agent-ergonomics/follow-on-local-summary.json).

Journal drop now explicitly unlocks inherited descriptors rather than waiting for
all fork/exec copies to close; a deterministic regression reproduced the old
failure and checks continued mutual exclusion. Harness SQLite probes explicitly
close their handles, and secondary cleanup errors no longer mask primary failures.
Windows adoption now uses a reviewed local-filesystem path with an explicit
[durability boundary](CLIENTS.md#windows-adoption-durability-boundary), fail-closed
readonly/reparse handling, and native-only path/sharing/recovery tests. Native CI
must still establish runtime acceptance of that follow-on on all three platforms.

The next native Windows run caught an additional real negative-test failure:
a directory rename succeeded while the adoption guard was held. Review traced
this to metadata-only access, which does not participate in Windows data-access
sharing checks; the reused private-file guard had the same pattern. A repository
search found those two implementations. The follow-on correction requests the
minimal directory-list access in both and adds native leaf/ancestor rename/removal
regressions without weakening existing assertions, DACLs or reparse checks.
The [Windows sharing algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/8c0e3f4f-0729-49f4-a14d-7f7add593819)
explains the access-mask distinction; native tests remain the acceptance gate.
