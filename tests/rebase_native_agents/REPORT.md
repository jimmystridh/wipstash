# AFTER genuine-native-agent campaign: fewer conflict reopens, no end-to-end speedup, semantic contract fails

## Decisive result

Four newly spawned independent native coding agents authored all 32 frozen expense-ledger features, eight waves each. The 32nd feature integrated at **14:39:38.732 UTC**, **559.130 seconds after common GO**. The complete actor-reporting and queue-drain interval was **579.245 seconds (9m 39s)**, including 20.115 seconds after the last integration. There was no integration/conflict rescue, exhausted lineage or unfinished feature. All original private work passed the exhaustive isolation audit.

The unchanged independent blind oracle **failed 8 of 5,780 assertions**, all for C1 `date_range`: no usable date must return `null`, but the new author's implementation returned `{start: null, end: null}`. This independently repeated the same semantic defect as BEFORE. Only the first four of 32 public snapshots fully passed; the remaining 28 retained that defect. All 32 feature fields were present, and no other field failed. The final author suite passed **103 tests**. Across 51 author test invocations, one initial D1 test expectation failed and was corrected before its publication. Passing native-author tests therefore did not establish semantic acceptance. Core policy checks were intentionally unconfigured.

This is a blind semantic failure, not a storage/integration failure. Both BEFORE and AFTER remain failures of the frozen domain contract. No oracle-guided repair or actor feedback occurred before the blind evidence freeze, and no recovery changes have been made in this campaign.

- Final blind public head: `d074b57187570bdbe90a12a50969c6590b3c0e7a`.
- AFTER core binary SHA256: `17f406790e388a36791228012b1b3cdc1f0fd496e1d816b58ccee264dcaf3088`.
- BEFORE preserved binary SHA256: `ded60ad5c3a533d01cf646228f03f38e7e3aa5b45941da115f5e6429233d9a51`.
- Unchanged SPEC SHA256: `46d01d465de5271b977b7c6c1e8c617564053a660672df991be5b6dcf57cba1f`.
- Unchanged independent oracle SHA256: `7688a757fcf87e128c4ddaf05673c670a361d2dd62fba1e83967671fe2034c50`.

## Conflict retry behavior and timing

| Observed native result | BEFORE | AFTER |
|---|---:|---:|
| Integrated feature waves | 32 | 32 |
| Accepted publications, including revisions | 46 | 42 |
| Accepted resolution revisions | 14 | 10 |
| Resolution openings | 31 | 18 |
| Stale resolution submissions | 17 | 8 |
| Successful captured-head submissions after compatible advance | Unsupported | 7 |
| Maximum stale reopens for one feature | 7 | 3 |
| Run start/GO → all 32 integrations | 535.638s | 559.130s |
| Full campaign including actor reporting/drain | 563.369s | 579.245s |
| Integrated features/minute | 3.408 | 3.315 |
| Accepted publications/minute | 4.899 | 4.350 |
| Root-publication → integration p95 | 53.262s | 73.813s |
| Root-publication → integration maximum | 167.092s | 123.084s |
| Peak journal-reconstructed accepted queue | 2 | 1 |
| Peak unfinished feature lineages | 4 | 3 |

Seven native resolutions exercised the new compatibility-preservation path using the normal API. All 18 resolution-submit attempts kept `expected_head` exactly equal to their own `resolution_open.current_head` and attested the full opened conflict-path set. Eight genuine stale rejections led to independent fresh checkouts; no actor disguised old bytes by replacing `expected_head`. The ten accepted revisions ultimately integrated. There were **1,646 automatic integration calls and zero integration-call errors**. The only failed actor RPC code was `stale_resolution`.

The native run had fewer reopens and a lower worst lineage delay, but its p95 lineage latency increased and the run-start/GO-to-last-integration interval was approximately 4.39% longer, and the full reporting/drain interval was 2.82% longer. **This native comparison does not show an end-to-end speedup.** Authored implementations, tests, model reasoning and schedules differ, and the launch protocol changed. The separate deterministic matched trace controls code/workload differences; its results must not be blended into this native run.

| AFTER observed duration | p50 | p95 | p99 | maximum |
|---|---:|---:|---:|---:|
| Accepted publication return → integration result | 0.115s | 0.392s | 0.938s | 1.304s |
| Nonempty integration CLI call | 0.070s | 0.283s | 0.735s | 1.045s |
| Original publication → integrated successor | 0.322s | 73.813s | 112.626s | 123.084s |
| Feature workspace-open → integration | 26.216s | 99.497s | 137.983s | 147.647s |
| Queue-residence lower bound | 0.044s | 0.258s | 0.282s | 0.289s |
| Queue-residence conservative upper bound | 0.260s | 0.444s | 0.977s | 1.345s |

Queue bounds are the same client-interval definitions as BEFORE: lower bound from publication return to integration-call start, clamped to zero for overlap; conservative upper bound from publication-request start through integration return, including service/lock overhead. Exact internal queue residence is not claimed. The analyzer and percentile formulas are byte-identical to BEFORE.

## Direct BEFORE/AFTER latency comparison

| Observed duration | BEFORE p50 | BEFORE p95 | BEFORE max | AFTER p50 | AFTER p95 | AFTER max |
|---|---:|---:|---:|---:|---:|---:|
| Accepted publication → integration outcome | 0.191s | 0.379s | 1.016s | 0.115s | 0.392s | 1.304s |
| Nonempty integration CLI | 0.079s | 0.290s | 0.800s | 0.070s | 0.283s | 1.045s |
| Root publication → integrated successor | 0.470s | 53.262s | 167.092s | 0.322s | 73.813s | 123.084s |
| Workspace open → integration | 26.866s | 81.083s | 189.477s | 26.216s | 99.497s | 147.647s |
| Queue residence lower bound | 0.074s | 0.279s | 0.295s | 0.044s | 0.258s | 0.289s |
| Queue residence conservative upper bound | 0.277s | 0.423s | 1.061s | 0.260s | 0.444s | 1.345s |

## Per-actor completion and bounded fairness

| Actor | Features integrated | Resolution openings | Stale submits | Preserved advanced-head resolutions | Maximum lineage latency |
|---|---:|---:|---:|---:|---:|
| A | 8/8 | 2 | 0 | 0 | 27.181s |
| B | 8/8 | 6 | 3 | 3 | 89.349s |
| C | 8/8 | 9 | 5 | 3 | 123.084s |
| D | 8/8 | 1 | 0 | 1 | 25.935s |

Every actor completed all eight features; no permanent starvation was observed within this bounded campaign. Actor C still experienced the longest lineage delay (123.084s) and five stale rejections across its features. These observations do not establish general fairness or saturation.

## Isolation and actual Source projection

- All **32** sealed original private-work manifests unchanged.
- **623** original checkpoint-tracked file checks unchanged, except the designated unsaved marker whose SHA256 was independently checked.
- All **32** unpublished original private-checkpoint OIDs absent from the public object store.
- Every public object enumerated: **324** objects; all **108** blobs (**520,597 bytes**) scanned with no synthetic private markers.
- No public ref tree contains private marker paths or excluded local files.
- Actual product `Source` observed **74** unique events: **10** action-required, **32** proposal-integrated and **32** public-head-advanced.
- **26,971** Source polls; **24,731** successful status reads and **2,239** ordinary lock-busy reads; no degraded state.
- Restart caused no historical replay, and all ten former action-required IDs were no longer current.

The observer was built offline against the actual candidate checkout's `wipstash_mcp_events::source::Source`, not a copied/mock library. Its SHA256 is `ef6048fb9de2637119f6d30b55c4a98ce991df9f3a219a4582b6e0673d0d638d`. Core and observer binary copies remained byte-identical through completion. Build inputs were hashed before/after observer compilation and were unchanged during that build. Later unrelated regression-test/source-checkpoint work did not replace either pinned executable.

This measures Source projection only. No HTTP webhook-to-ChatGPT delivery chain, real provider, credential, socket/listener, `command_run`, process killing, fault injection or policy change was exercised.

## Start synchronization and provenance limits

All four native actors registered readiness before a single common GO at **2026-10-18 14:30:19.602 UTC**. The first actual workspace opens were spread over **5.723s**; all were after GO. Preparation/spawn skew was **280.309s**, because actor A waited at readiness while remaining spawns were held for a separate matched benchmark. No feature implementation, author test or product CLI call occurred before GO. The observer started after all four were ready, then the same 350 ms automatic integrator released GO and ran continuously.

BEFORE had a 66-second fourth-actor launch delay plus an administrative slot rescue, without a common barrier. That difference remains explicit and is not hidden by reporting only AFTER's common-GO skew. Neither campaign had integration or conflict-resolution coaching/rescue.

Both runs use exactly the same baseline source/helpers/tests and initial public tree `d9779a88c5b6481d5c0357f52c70cd58e1d6a548`, 32 feature semantics, eight-wave ordering per actor, 350 ms integration interval, and 45-minute active plus 5-minute drain maximum. This run stopped itself earlier after all four actors were terminal and the queue drained. The observer then stopped by its graceful file sentinel. All processes exited normally.

The observer compilation ran 14:23:45.678–14:24:04.415 UTC before native GO. The separate matched timing run began at 14:24:09.432597 UTC, over five seconds after this build ended, so there was no measured overlap. Its deterministic results are documented separately.

## Reproducibility and retained evidence

The accompanying summary.json contains aggregate BEFORE/AFTER metrics, timing boundaries, per-actor fairness, privacy counts and independent oracle outcomes. harness-manifest.json fixes the contract, source/harness hashes, executable identities and run protocol. The complete raw state, private checkpoints, original/resolution workspaces, actor handoffs and command logs are retained separately and are intentionally excluded from this publication package.

Blind evidence was frozen before any recovery changes. No recovery was performed. These were genuine native model coding agents, not scripted solution actors and not standalone Codex CLI/Claude Code product sessions. The bounded workload supports compatibility-preserving retry behavior and private-work isolation, while retaining both semantic failure and timing/fairness limits. No production-readiness or cross-platform claim follows from this run.
