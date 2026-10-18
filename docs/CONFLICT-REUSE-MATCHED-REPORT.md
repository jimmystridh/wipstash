# Matched stale-resolution benchmark

Both runs passed. All 12 paired business schedules and final content/mode oracles matched. This is deterministic scripted logical contention, not simultaneous-process stress or model-authored work.

## Provenance

- Baseline SHA256: ded60ad5c3a533d01cf646228f03f38e7e3aa5b45941da115f5e6429233d9a51
- Optimized SHA256: 17f406790e388a36791228012b1b3cdc1f0fd496e1d816b58ccee264dcaf3088
- Harness SHA256: 112174db305b81977fd6e8ee998fc2b55f636ed6b04db8ba18e1074b21cace0b
- Four actors; three modes; four rotated winner/completion orders; 5 ms fixed pre-submit think delay.
- Baseline first init: approximately 2026-10-18 14:24:09.432597 UTC; evidence directory birth is 14:24:09.420411696 UTC. Observer compilation ended at 14:24:04.415 UTC, so the known build did not overlap. See timing-provenance.json.
- Exact invocations: run-commands.txt. Raw requests/responses and synthetic fixture/store directories are retained.

## Behavioral results

| Metric | Baseline | Optimized |
|---|---:|---:|
| Original proposals completed | 48 | 48 |
| Promoted snapshots | 92 | 92 |
| Full-tree oracle passes | 92 | 92 |
| Negative guard passes | 360 | 360 |
| Stale submissions rejected | 36 | 12 |
| Fresh resolution reopens | 36 | 12 |
| Scripted resolution edits | 72 | 48 |
| Resolved edits retained without reopen | 0 | 24 |
| CLI requests | 1268 | 1172 |

All 24 disjoint/repeated resolutions were retained after optimization. All 12 overlapping resolutions still required fresh handback. Both runs verified 96 private commit/blob absence checks and 48 original-workspace preservation checks across cases. Ownership, generation, current checkpoint, live checkout, expected-head binding, and conflict attestation guards passed. Git fsck and SQLite integrity passed.

## Measured wall time

Times include scripted ordering, intervening workload and audit reads. Scheduled-workload totals exclude initial fixture/workspace setup and final audits. Quantiles are nearest rank.

| Metric (seconds) | Baseline | Optimized |
|---|---:|---:|
| Scheduled workload total | 123.829 | 101.628 |
| Publish to integration, p50 | 7.384865 | 5.794448 |
| Publish to integration, p95 | 10.857324 | 10.104096 |
| Publish to integration, max | 10.931767 | 10.926862 |
| First resolution open to integration, p50 | 6.808510 | 5.463167 |
| First resolution open to integration, p95 | 8.133251 | 7.456514 |
| First resolution open to integration, max | 8.249188 | 7.769698 |
| Accepted submit to integration, p50 | 0.026220 | 0.029637 |
| Accepted submit to integration, p95 | 0.033381 | 0.042219 |
| Accepted submit to integration, max | 0.034390 | 0.052270 |

| Mode workload total (seconds) | Baseline | Optimized |
|---|---:|---:|
| disjoint | 35.176 | 24.682 |
| overlap | 43.571 | 43.447 |
| repeated | 45.082 | 33.500 |

Original-proposal throughput was 0.387633 to 0.472309 per second. All-integration throughput was 0.742963 to 0.905259 per second.

## Per-actor completion and latency

Each actor completed 12 original proposals and 23 total integrations in both runs. Each had nine stale reopens before versus three after, retaining six resolved edits. Equal bounded offered-work completion Jain index was 1.0 in both runs; this construction does not establish scheduler fairness or starvation resistance.

| Actor | Publish p50 before/after (s) | Publish p95 before/after (s) | Throughput before/after (proposals/s) |
|---|---:|---:|---:|
| A | 7.577 / 5.515 | 10.703 / 10.927 | 0.096908 / 0.118077 |
| B | 6.899 / 5.456 | 10.353 / 10.104 | 0.096908 / 0.118077 |
| C | 7.279 / 5.794 | 10.888 / 10.127 | 0.096908 / 0.118077 |
| D | 7.264 / 5.632 | 10.932 / 9.995 | 0.096908 / 0.118077 |

## Limits

One fixed-order local before/after sample with rotated actors. The aggregate scheduled workload was about 17.9% shorter, but this does not guarantee a speedup or isolate all cache/host effects. Overlap mode was essentially unchanged. Accepted-submit-to-integration p95 increased from about 33 ms to 42 ms; the benefit observed here is fewer reopen/re-edit cycles, not universally lower call latency.

No real human/model resolution cost is simulated beyond a 5 ms delay. No simultaneous lock/storage races, required-policy process execution, native agent quality, sustained fairness, saturation, cross-platform, multi-host, or SQLITE_IOERR explanation/fix is established. The prior IOERR limitation remains.

The initial baseline-smoke failure was a harness assumption that rejected CLI operations exit 0; corrected to expect exit 1. Its evidence remains intact. Smoke outputs are separate from the matched v1 pair, which uses an identical saved harness hash.
