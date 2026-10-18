# Wipstash real-model contention pilot

Completed 18 October 2026. Tested source: `c489e00ea284127389e29e9e9875eb6db26132b2`.

## Bottom line

Four autonomous model coding agents completed the local failed-integration → isolated repair → resubmission → continued-work loop while shared HEAD moved. Every measured proposal lineage drained without human source fixes, weakened checks, or bypassing revision bounds. This is a bounded synthetic-workload pilot, not production-scale throughput certification.

The concrete bottleneck was repeated stale-head resolution work, not integration execution. In the backlog burst one publication required seven stale reopens and waited 171.61 seconds to integrate; active integration calls had a 0.291-second p95. Observed queued depth peaked at three, so engine saturation was not established.

## Measured arms

| Arm | Correct features | Elapsed to last integration | Correct features/min | Initial publications | Successful replacements | Stale rejections | Submit → integrate p50 / p95 |
|---|---:|---:|---:|---:|---:|---:|---|
| Independent-file warm-up | 4 | 61.68s | 3.89 | 4 | 0 | 0 | 0.25s / 0.52s (n=4) |
| Original coding, one feature per publication | 12 | 165.36s | 4.35 | 12 | 12 | 7 | 19.53s / 54.58s (n=12) |
| Vetted-code reuse, three-feature batches | 12 | 49.49s | 14.55 | 4 | 3 | 3 | 15.65s / 42.11s (n=4) |
| Matched vetted-code reuse, one feature per publication | 12 | 187.67s | 3.84 | 12 | 12 | 16 | 24.41s / 74.80s (n=12) |
| Injected failed-check recovery control | 1 | 42.17s | 1.42 | 1 | 1 | 0 | 23.72s / 23.72s (n=1) |
| Vetted-code backlog burst | 12 | 172.80s | 4.17 | 12 | 11 | 22 | 61.81s / 171.61s (n=12) |

The control is deliberately injected and is not comparable productivity data. Warm-up includes sequential agent startup. Other four-agent arms used a readiness gate and shared release. Timing excludes state initialization. Nearest-rank percentiles are descriptive small-sample observations; integration timestamps are CLI-response upper bounds.

## What was actually verified

- Twelve fixed library requirements across billing, inventory, text normalization and statistics; a fixed external validator covered stated behavior and edge cases. Actors could not edit it.
- Original and matched-small selected snapshots each added exactly one required function and matching registry entry. Batch snapshots each added exactly three. This was checked from actual selected Git snapshots, not inferred from prompts.
- The matched replay and backlog burst retained AST-identical required functions relative to the vetted batch implementations.
- All 45 integrated snapshots across the six arms were independently validated; no previously accepted feature disappeared at an intermediate HEAD. The repeated arms produced 53 feature completions, covering the same 12 unique requirements, not 53 different requirements.
- Final states total 45 integrated proposals and 39 superseded predecessors; no pending, quarantined or escalated lineages remained.
- 48 stale-resolution rejections were handled separately from three genuine replacement re-quarantines. Thirteen private adoption conflicts were explicitly resolved. No revision-budget escalation occurred.
- The deliberate rounding defect was quarantined as required_checks_failed with check exit 1; a model corrected only its public resolution checkout and the successor passed with exit 0. The original bad source and live private canary stayed untouched.
- Synthetic private-history and live-WIP canaries were absent from all public Git blobs. Original workspace manifests were unchanged across 174 resolution-operation samples; all active actors’ live canaries remained present. Git object integrity and SQLite integrity checks passed, with no duplicate promotion. Git reported expected unreachable intermediate trees in conflict arms, not integrity failures.

## Backlog and same-owner overlap

Each actor published three cumulative selected snapshots in rapid succession, without adopting or waiting for prior integration. Later snapshots therefore included earlier unintegrated features relative to their old public base. Every snapshot added one new own function relative to the preceding selected private snapshot. This is a backlog test, not another independent-small-publication comparison.

The burst completed 12 correct features in 172.80 seconds, with 11 public-resolution replacements and 22 stale rejections. Billing’s last publication required seven stale reopens; inventory’s first required six. Later resolutions had same-owner module conflicts in addition to the intentionally hot single-line registry. All actors eventually drained once competing work subsided; this does not prove starvation freedom under indefinitely advancing HEAD.

2 quarantine observations had some already-identical own function code at the current head. None had all of its own function code already there. Function coverage alone is not whole-proposal equivalence; no quarantined proposal was treated as integrated based on that inference.

## Small changes versus batches

The initial coding arm and subsequent batch arm are not a valid isolated sizing comparison because the batch reused already-written code. The third arm controlled that major difference by reusing the same vetted functions one at a time. In this single matched integration-workflow comparison, batch took 49.49 seconds versus 187.67 seconds for small publications. Fixed ordering, model scheduling, adoption frequency and a deliberately pathological shared registry remain confounds. There is no plain-Git comparison and no general optimal-size result.

Wipstash does not enforce coherent task size. “Make small commits” is agent/task guidance. Its actual enforced boundaries are selected-snapshot publication, explicit generations and head binding, required-check quarantine, isolated public resolution, bounded submitted revisions, and explicit adoption. A rigid line-count cap would not solve the observed stale-head churn. Here batching coherent changes to the same hotspot reduced coordination cycles; this should be measured per workload rather than imposed as a universal rule.

## Runtime and scope

- Four native autonomous coding subagents made edits and resolved conflicts. They were not deterministic scripted personas, but they were also not standalone Codex CLI or Claude Code product sessions.
- Inherited model identifier, token counts and monetary costs were not exposed and are not estimated.
- Linux x86_64, glibc 2.41, Python 3.12.14, Git 2.52.0; the verified debug binary was built with Rust/Cargo 1.99.1 on glibc 2.39.
- CLI integration polled every 0.5 seconds. No sockets, process-kill fault injection, keys, account authentication, persistent grants, or source changes during the measured arms.
- Binary SHA256: `615cfde843bffb96db0b86093b0db98c067d2b511986ebadac4a873d5cdb9627`.
- [Exact CI run](https://github.com/jimmystridh/wipstash/actions/runs/39106512175), artifact ID 12128353944. Other CI failures at this revision are outside this pilot’s local-live-workflow result; this report does not certify the revision for release.
- No backup/restore, remote transport, Windows/macOS runtime, crash durability, arbitrary native-writer containment, realistic large-repository scaling, or sustained engine-saturation claim.

The bounded campaign is complete. Further testing should target the stale-head coordination tail and fairness with realistic workloads, rather than extrapolating an optimal publication size from this pilot.
