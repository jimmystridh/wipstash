# Resolution materialization: bounded reuse and timing evidence

## Observed failure and evidence limit

[Windows job 117748630803](https://github.com/jimmystridh/wipstash/actions/runs/39152432153/job/117748630803), at commit `72f0e41fea1df64d68300e09b90bb296a6a911fa`, passed all five conflict-stress cases for seed 731927. Seed 991337 then hit the existing 40-second subprocess limit during the third wave's concurrent resolution preparation; its other four cases passed. This was a `resolution_open` timeout, distinct from the submission barrier and the workflow job's total time budget.

The engine holds its existing exclusive state lock throughout dispatch. A new resolution reads and materializes four public views: the merged checkout and its base/current/proposal inputs. The final SQLite transaction begins after this work. Repeated Git object reads therefore lengthen both the active request and other actors' lock waits.

The failed run did not retain the timed-out request's captured diagnostic phases, so its exact lock-wait/materialization split is unknown. The results below establish the repeated-work cost and local improvement; they do not prove that the Windows timeout is resolved. Native Windows stress must pass at the new revision.

## Narrow change and preserved boundaries

- A materializer borrows one Git repository and retains only checksum-verified, immutable blob bytes during one resolution request.
- Cache admission is optional, capped at 64 MiB and 10,000 entries. A full cache falls back to verified reads. No cache survives a request.
- Root and subtree objects are verified afresh for every view. Paths, modes, exclusions, collisions, snapshot entry/byte limits, destination capacity, create-new writes, and file/directory durability checks remain in place.
- Each occurrence of a cached blob still counts toward that view's 64 MiB snapshot limit. Shared buffers avoid duplicating retained bytes; cache storage is an additional bounded resource, not a relaxation of snapshot admission.
- Within a request, later changes to an already-read blob cannot alter its retained verified bytes. A fresh request reads and verifies the backing object again.
- Ownership, public/private ancestry, expected-head/generation fences, state locking, CAS, recovery comparisons, and journal boundaries are unchanged. The frozen `src/engine.rs` file is unchanged.
- The 40-second request limit, 30-second submission barrier, native-CI guards, and test assertions are unchanged.

## Measurements

The deterministic unit fixture has four views, each containing 12 files across seven directories, with one changed file per view. Identical byte output and executable modes are checked.

| Measurement | Fresh contexts | Shared context |
| --- | ---: | ---: |
| Git subprocesses for four materializations | 296 | 164 |
| Verified blob reads | 48 reads | 15 reads |
| Reused verified blob reads | 0 | 33 |

This is a 44.6% subprocess reduction. Counts are asserted; elapsed times are observational only.

A separate disposable Linux comparison used the preserved pre-change binary and the optimized binary, three trials each, with three concurrent `resolution_open` requests and the same 12-file fixture. The timing driver set no subprocess timeout. It used no policy commands, fault injection, listeners, process killing, or CI-environment spoofing, and checked that original private workspaces stayed unchanged.

| Measurement | Baseline | Optimized |
| --- | ---: | ---: |
| Median three-actor wave | 1.733 s | 0.857 s |
| Longest measured state-lock wait | 1,214 ms | 574 ms |
| Longest request | 1.772 s | 0.885 s |
| Dispatch range | 473–655 ms | 263–306 ms |
| Materialization range | Not instrumented | 228–265 ms |

Median local wave duration improved 50.5%. These are Linux development measurements, not Windows timing guarantees. [Sanitized observations and binary hashes](../tests/benchmarks/resolution-materialization/summary.json) retain the paired lock/dispatch phases and the optimized materialization phases.

## Verification and future timeout evidence

Passing focused checks:

- 20 Git tests, including four new materializer regressions
- 9 existing resolution ownership, stale-head, generation, privacy, and policy-refusal contracts
- 10 synthetic scheduling/timing harness tests
- Core build

Run the deterministic checks with:

```sh
cargo test --locked --bin wipstash git::tests::materializer_ -- --nocapture
cargo test --locked --bin wipstash git::tests::
cargo test --locked --bin wipstash engine::regression_tests::resolution_
python tests/test_agent_conflict_stress_harness.py
```

The native contract job includes the materializer tests on Linux, macOS, and Windows. New opt-in phase markers use the existing `WIPSTASH_SQLITE_DIAGNOSTICS=1` flag. Stress summaries retain at most 1,000 resolution timing records with fixed phase labels and numeric durations only. They retain partial phases when completion is absent and never infer a completed lock wait from an unfinished request. Raw stderr, request arguments, process IDs, paths, object IDs, and file contents are excluded. Timeout recording rethrows the same exception without retrying or changing its limit; captured bytes are decoded safely so ordinary scratch log serialization still works.
