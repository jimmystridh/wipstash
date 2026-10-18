# Separate oracle-guided recovery: pass

This phase began only after the complete blind campaign, semantic failure, metrics and evidence were frozen. It records **one external oracle-feedback intervention** and does not change the blind result.

## Repair and verification

The original calendar actor was told the precise C1 requirement: date_range must be null when no valid dates exist. It received no oracle source. In a new isolated workspace from the blind final public head, it corrected the implementation and an author test that had encoded the wrong shape, then added regression coverage for empty, missing, blank, invalid-only and mixed-valid dates.

- Before the fix: 97 author tests ran with 5 failing assertions.
- After the fix: all 97 author tests passed.
- One new publication integrated automatically, with no conflict or resolution revision.
- The unchanged independently frozen oracle then passed **170 invocations, 5,780 assertions, zero failures** across all 32 features.

Recovery proposal: `actor-c-recovery-1-publish`.
Recovery public head: `edde8a17cbadaca02faeb411de2f0d35a4769838`.
Oracle SHA256 remains `7688a757fcf87e128c4ddaf05673c670a361d2dd62fba1e83967671fe2034c50`.

## Separate timing

- Workspace-open request to integrated result: **60.856 seconds**.
- Accepted publication return to integrated result: **0.345 seconds**.
- Automatic recovery runner: **108.605 seconds**, including setup and feedback idle time.
- 311 integration calls at a requested 350 ms cadence; zero integration errors.
- One external semantic-feedback intervention; zero manual integrations or conflict rescues.

The recovery coordinator used separate logs and a 10-minute active plus 2-minute drain upper bound. It stopped itself after the actor was terminal and the queue drained. Core policy checks remained unconfigured. The CLI outcome was still unchecked; the semantic pass came from the separate unchanged oracle. No new Source observer or webhook delivery chain was exercised in this phase.

## Preservation audit

All 56 frozen blind evidence files retained their SHA256 hashes. All 32 original private workspaces and checkpoint-tracked files remained intact, and their unpublished checkpoint OIDs remained absent from the public store. The recovery workspace's separate private checkpoint and unsaved WIP were also preserved and not published. All 113 public Git blobs were marker-free, and public ref trees contained no private paths.

The blind result remains **8 failed assertions out of 5,780**, with only 2 of its 32 public snapshots fully passing. This later repair demonstrates that the authorized author can correct a diagnosed contract defect through the ordinary publication flow; it does not erase the original semantic miss or prove automatic semantic checking.
