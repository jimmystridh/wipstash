# MCP Events local pressure report — 2026-10-18

## Provenance and limits

This is a newly reconstructed implementation over base
`aa10a7062946bd88fffc96737be35617e6c74b93`, after the original cloud workspace
was lost. It is not claimed byte-identical to the lost artifact. The first
reconstructed remote checkpoint is `f859acf616aa6398eb7bf5f37f419821761340fb`,
tree `c93ccdaf9f25dc4dda6f7937fdf22b867094d455`.

All measurements below are Linux cloud runs using Rust 1.99.1. No live OAuth
application, credentials, grants, invitations, HTTPS listener or ChatGPT
subscription was created. Actual GitHub/browser/ChatGPT acceptance is still a
release gate. No claim of production readiness, exactly-once delivery, or
resolution of the prior OS-level SQLite IOERR/fault-injection limitation.

## Actual four-native-agent coding campaign

Four independent native coding agents authored overlapping changes to one
synthetic Python project in isolated Wipstash workspaces: category totals,
currency totals, spending/refunds, and date ranges. They wrote their own code,
tests, checkpoints and publishes; this was not a scripted actor loop.

The coordinator opened the initial workspaces and explicitly integrated queued
proposals. The owners independently resolved returned conflicts in fresh
resolution workspaces. The coordinator deliberately advanced the public head
between three resolution checkouts and their submissions. All three stale
submissions were rejected; their owners reopened, combined the current features,
tested, checkpointed and resubmitted. The first author also continued with a
schema-version feature while peers were resolving.

- Five successful public integrations, five observed merge-conflict events.
- Final public head: `ad4ec56528286fd2d31e55ddcd5191d8be2f591d`.
- All 23 combined tests passed in a fresh final verification workspace.
- Original four report files and four post-publication private WIP markers
  remained byte-for-byte unchanged; no private paths appeared in public tree.
- SQLite integrity check passed.
- An obsolete first-draft followup was explicitly cancelled by its originating
  author through the supported API. Audit evidence remains; no quarantined
  proposals remain. No direct database/ref changes were used for cleanup.
- Integration policy checks were unconfigured. Tests were independently run by
  authors and coordinator; integration does not claim semantic correctness.

Measured actor activity spans (UTC, including coordination waits and final
verification): A 13:42:21–13:48:53; B 13:42:37–13:48:19;
C 13:42:43–13:43:57; D 13:42:55–13:49:17. These are not CPU-time or autonomous
completion latency benchmarks.

A concurrent read-only Source observer ran for 332.798 seconds, polling 15,360
times: 15 unique sanitized events (5 action-required, 5 integrated, 5 public-head
advanced), 255 busy status reads, no duplicate IDs, no false degraded state,
and verified restart without replay. Four old action events were no longer
current after resolutions. A separate cleanup observer saw no history replay.
**This observes event projection only, not a webhook chain or ChatGPT action.**

Core executable SHA-256 used by all actors:
`ded60ad5c3a533d01cf646228f03f38e7e3aa5b45941da115f5e6429233d9a51`.

## Separate synthetic pressure

- Six CLI campaigns: 270 actual CLI requests, 3,158 Source polls, 84 transitions,
  18.72 seconds total. Verified repeated-failure identity, stale resolution
  rejection, privacy, superseded/expired suppression, restart without replay,
  SQLite integrity and zero duplicate promotions.
- Auth: eight independent SQLite connections, 2,304 contested invitation/code/
  refresh calls plus 5,376 phased visibility/revocation checks, 13.765 seconds.
  Exactly one winner per contested round. Replay, regrant and reopen checks held.
- Delivery: five repetitions of five in-process mocked tests, 91,765 actions,
  9,151 callback attempts, 1,440 gated lifecycle races, 11,520 competing ticks,
  10,240 overflow observations and 160 metadata restarts. Each run took
  3.465–4.118 seconds; observed peak RSS 10,624 KiB. Signatures, pre-byte
  revocation, expiry, challenge replay rejection and bounded queues held.

These synthetic measurements are distinct from the actual agent campaign.

## Issues found and corrected

1. Normal writer-lock contention incorrectly made Source health permanently
   degraded. Contention now preserves the cursor and retries without claiming
   loss; genuine lock errors still degrade. Regression verifies catch-up.
2. Maintenance deleted consumed authorization-code replay evidence before its
   token family expired. Retain bound consumed markers through family expiry.
   Regression failed before the fix and passes after prune/restart; wrong
   verifier cannot revoke a family, valid replay revokes all derived tokens.
3. Cache hits indefinitely extended callback verification proof. Only a fresh
   successful challenge now starts a new cache window. Regression uses
   0/59/118-second subscriptions.
4. A backward wall-clock step could extend a dequeued callback past its
   monotonic five-minute budget. Pre-byte authorization and transport timeout
   now both enforce remaining monotonic lifetime. Gated regression covers it.

A fresh independent review examined OAuth bindings, grants/epochs, invitation
atomicity, subscription ownership/recreation, callback SSRF/DNS pinning and
expiry. Review and tests do not replace deployed acceptance.

## Reproduction and safe-suite scope

Run the core build before the CLI pressure test:

```sh
cargo build --locked
cargo test --locked --manifest-path services/mcp-events/Cargo.toml --all-targets
cargo clippy --locked --manifest-path services/mcp-events/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path services/mcp-events/Cargo.toml --check
```

Fresh safe regression coverage: core 100, storage 37, transport 88, backup 7.
The full new crate has 72 tests including the three added security regressions.
Executable `check-config` accepted a synthetic valid shape, rejected plaintext
issuer and public proxy binding, and created no auth/subscription databases.

Local restrictions excluded listener, process-kill and OS fault-injection paths.
The normal CI gates remain intact; local filtered runs are not substitutes for
those gates or cross-platform CI. Source-only observer and in-process mock
callbacks must not be described as real browser/network/ChatGPT verification.

### Cross-platform CI follow-up

The first cross-platform run exposed macOS test-fixture paths through symlinked
system temp ancestors. The production private-file helper correctly rejected
those paths. New fixtures now canonicalize their temporary roots, matching the
existing transport test approach; production no-follow checks are unchanged.
An additional Unix regression verifies a deliberate symlink alias is still
rejected. This adds one local Unix test; macOS verification awaits the new CI run.

The canonical-path fix removed macOS filesystem failures, but the next run
completed only 51 of 96 rounds before the auth pressure test's old 45-second
Linux-derived scheduling cutoff. This was an incomplete correctness run, not a
passed concurrency test. Eight workers, 96 rounds, every security assertion and
SQLite durability remain unchanged. The test now separates the informational
45-second performance reference from a 300-second cooperative scheduling
deadline and reports phase/worker counts in successful CI output too. The guard
cannot interrupt blocked filesystem operations or thread joins; the workflow's
outer timeout remains. A passing rerun will not establish that the observed
cross-platform performance disparity disappeared. The newly instrumented local
Linux run completed in 16.208 seconds, including setup and validation as well
as the 7,680 raced operations; macOS phase calibration awaits CI.
