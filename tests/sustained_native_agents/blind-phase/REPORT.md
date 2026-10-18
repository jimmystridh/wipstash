# Sustained real-native-agent benchmark: automatic integration passes, semantic contract fails

## Decisive result

Four new independently reasoning native coding agents implemented 32 frozen expense-ledger features across eight waves each. All 32 public feature lineages integrated in **563.37 seconds (9m 23s)**, without manual integration or conflict-resolution rescue. Original private work remained intact and absent from the public object store.

However, the independently frozen semantic oracle found a genuine authored defect: C1 returned `{start: null, end: null}` when no valid dates existed; the specification required `null`. The final public tree failed **8 of 5,780 oracle assertions**, despite all **95 author tests** passing. Only the first two of 32 public snapshots fully passed; the subsequent 30 retained this defect. All 32 feature fields were present and no other field failed. This is a semantic failure of the blind campaign, not evidence of a storage or integration defect. Core policy checks were intentionally unconfigured and outcomes remained unchecked.

Blind final head: `0e3af1acb9275802d05d4eea25cff4d675b851bc`.
Core binary SHA256: `ded60ad5c3a533d01cf646228f03f38e7e3aa5b45941da115f5e6429233d9a51`.

## Automatic integration and rework

- 46 accepted publications: 32 initial features + 14 resolution revisions.
- 32 integrations, 14 quarantines subsequently superseded, 0 exhausted lineages, 0 unfinished features.
- 1,591 automatically scheduled integration calls, 0 integration-call errors.
- 31 isolated resolution openings and 17 stale-resolution submissions.
- 63 author test runs, 0 failing runs; final combined suite 95 tests.
- One actor queried a nonexistent successor after a stale submission; its `storage_error: Query returned no rows` was a protocol mistake, not SQLite IOERR.
- Throughput: 4.899 accepted publications/minute and 3.408 integrated features/minute, including model work and final evidence recording.
- Peak durable accepted queue depth 2; peak unfinished feature lineages 4.

| Observed duration | p50 | p95 | p99 | maximum |
|---|---:|---:|---:|---:|
| Accepted publication return → integration result |0.191s|0.379s|0.818s|1.016s|
| Nonempty integration CLI call |0.079s|0.290s|0.597s|0.800s|
| Original publication → final integrated successor |0.470s|53.262s|135.792s|167.092s|
| Feature workspace-open → final integration |26.866s|81.083s|158.439s|189.477s|
| Queue residence lower bound |0.074s|0.279s|0.290s|0.295s|
| Queue residence conservative upper bound |0.277s|0.423s|0.867s|1.061s|

Queue bounds use CLI call intervals, not internal admission/service timestamps. The lower bound is publication return to integration call start, clamped to zero for overlapping calls; the conservative upper bound spans publication request start through integration return and includes lock/service overhead. Exact internal queue residence is not claimed.

Actor C's second feature required seven stale reopens before its first accepted resolution revision. Its original-publication-to-integration delay was 167.092s. Every actor completed all eight features, so no permanent starvation was observed in this bounded run; the long rework tail remains important. This is churn evidence, not saturation or a general fairness guarantee.

## Isolation and Source projection

- All 32 original private-WIP manifests unchanged.
- 622 original checkpoint-tracked file checks unchanged, excluding the deliberately unsaved marker whose SHA256 was independently checked.
- All 32 unpublished private checkpoint OIDs absent from the public object store.
- All 110 public Git blobs (538,714 bytes; 336 total public objects) scanned with no synthetic private markers.
- No public ref tree contained private marker paths or excluded local files.
- Actual Source implementation observed 78 unique events: 14 action-required, 32 proposal-integrated, 32 public-head-advanced.
- 26,219 Source polls; 23,413 successful status reads and 2,805 ordinary lock-busy reads; no degraded state.
- Restart produced no historical replay; all 14 former action IDs were no longer current.

This was Source projection only. No HTTP webhook-to-ChatGPT delivery chain, real provider, credential, listener, command_run, process killing, or fault injection was exercised.

## Design and limits

The feature contract and independent oracle were frozen before launch. Actors could read requirements but not oracle implementation or results. An automatic coordinator attempted one proposal every 350ms, subject to ordinary CLI completion. The fixed upper bound was 45 active minutes plus 5 drain minutes; all work finished earlier, so the coordinator stopped itself after every actor was terminal and the queue drained.

One administrative setup intervention delayed the fourth actor's launch 66 seconds because an older native actor still occupied a slot. The automatic coordinator was not paused. Integration/conflict rescue count remained zero.

This one fixed-order workload has no randomized matched batch comparison. It does not establish optimal publication size, production scalability, broader fairness, or standalone Codex CLI/Claude Code product behavior. These were genuine native model agents, not scripted actors. The results support fast automatic queue handling and preserved private work under repeated shared-file contention, while showing that native-author tests can miss a semantic contract violation when integration checks are off.

The blind evidence is frozen. Any later oracle-guided fix is a separately measured recovery phase and cannot retroactively turn this blind result into a pass.
