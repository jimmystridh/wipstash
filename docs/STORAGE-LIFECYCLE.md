# Explicit bounded storage lifecycle

`services/storage` is a standalone Rust library and CLI. It supplements the capture/materialization bounds in `STORAGE.md`; it does not automatically enable collection in the core engine. Linux synthetic fixtures are the executed verification boundary. Do not run collection on valuable state without an independent backup and a quiescent, cooperative writer environment.

## Accounting and pressure admission

`usage(roots, max_entries)` walks existing, absolute, disjoint roots and returns logical bytes, Unix allocated bytes (`st_blocks * 512`), and entry count. Directory metadata is counted, as are SQLite/WAL files, staging, backups, refs and objects inside the supplied roots. Symlinks in roots/ancestors or descendants, special files, hardlinked regular files, root overlap, arithmetic overflow and entry-budget exhaustion fail closed. Counts are not deduplicated physical-device usage; reflinks/compression/filesystem metadata and non-Unix allocation accounting differ. A caller must include every writable state/staging root; source workspaces outside those roots are not counted.

`admit(roots, Budget { max_bytes, max_entries, reserve_bytes }, incoming_bytes, incoming_entries)` rejects when current maximum of allocated/logical usage plus declared growth and reserve exceeds the byte budget, or current plus declared entries exceeds the entry budget. It also checks filesystem available space on every root. This is a read-only preflight, **not a reservation or hard filesystem quota**. A service must serialize preflight plus mutation and account for all expected artifact, journal, SQLite and staging growth. Concurrent unmanaged writers and underestimated growth can exceed the configured limit. Reject and propagate ENOSPC/write failures; do not present preflight as an ENOSPC guarantee. The core snapshot limits (64 MiB total/16 MiB blob) remain separate.

Examples, after building `cargo build --manifest-path services/storage/Cargo.toml`:

```
services/storage/target/debug/wipstash-storage usage /absolute/state /absolute/staging
services/storage/target/debug/wipstash-storage admit /absolute/state 1073741824 100000 16777216 8388608 32
```

## Retention contract

The default is permanent pin retention. The service never expires checkpoint records, proposals, operations (pending or acknowledged), recovery pins, refs, reflogs, exports, transfer roots or backup records. It never removes working files, adoption staging/backups, database rows, packs or indexes, and never runs `git gc`, prune, repack, reflog expiry, hooks, shell commands or remote access. Objects inside packs remain even when unreachable. Consequently retained history and packs can grow without bound; pressure can require admission denial, operator-managed expansion, or a separately designed and explicitly approved retention policy. This implementation does not invent a time-to-expiry guarantee for acknowledged work.

The only deletion candidates are **loose Git object files**, unreachable from every discovered protected root in the selected object store, whose filesystem mtime is at least the explicit minimum age. Minimum permitted age is one day. Mtime is the conservative eligibility mechanism, not a trusted creation timestamp or a guarantee against a writer that changes timestamps. No automatic scheduler is installed.

## Planning and applying

```
services/storage/target/debug/wipstash-storage plan /absolute/state coordinator.git 604800 > /safe/review-plan.json
services/storage/target/debug/wipstash-storage apply /absolute/state /safe/review-plan.json --confirm-unreachable-loose-removal
```

Keep the plan outside the state directory. Inspect its exact candidate OIDs, compressed sizes, mtimes, SHA-256 file digests, protected roots, complete reachable object set and journal and reference-file digests. Valid repositories are `coordinator.git` or `locals/<portable-id>/objects.git` beneath the state root. The existing `state.lock` must exist; both planning and application acquire the same exclusive advisory lock as the engine. Application regenerates and exactly compares the entire plan under that lock before the first removal. A changed journal, root set, object contents/mtime or newly eligible candidate makes the plan stale. No automatic retry of a stale plan occurs.

Planning validates the known schema version and table column layouts, rejects unknown tables/columns or binary journal encoding, checks SQLite integrity, and refuses incomplete adoption/promotion or running/uncertain-command journals. The dedicated sync-replay.sqlite journal is validated separately against its exact version-0 schema and original typed replication decoder: binding, contiguous sequence/cursor, canonical event digests and cached-head consistency must agree. Every admitted event head and its graph is pinned, including the crash window before a Git ref is installed. Its snapshot digest participates in stale-plan rejection. Auxiliary SQLite journals other than these two and the non-root-bearing repair-budget.sqlite are refused. Every 40-hex object token in all known journal text fields and recursively decoded JSON values is retained if present in the selected store, including arbitrary operation request/results and event payloads. All discovered 40-hex journal tokens, including decoded JSON pins, must resolve somewhere in the known coordinator/private stores; missing pins fail closed. This intentionally can reject unrelated user text that happens to contain a 40-hex string. Known structured fields must parse as JSON. All selected-store refs, packed refs and reflog object tokens are retained. Symbolic per-ref files, alternates, shallow repositories, unsupported object formats, missing reference targets and malformed source refs fail closed. Unrecognized schema revisions require a deliberate implementation update before collection.

Reachability and `fsck` run against a fresh temporary bare Git view with only its object directory pointed at the source store. Source Git configs and hooks are never loaded. Ambient Git environment/config overrides and replacement objects are disabled. Commands are fixed Git plumbing arguments; OID roots go over stdin, never shell interpolation. Git stdout/stderr capture and journal/reference scans are bounded, although Git's own CPU/memory and full-store walk time are not hard-limited.

After removal, the service repeats integrity/reachability inspection and checks the exact protected-root set, reachable-object set and journal/reference-file digests against the plan. It reports actual removed object count/bytes and before/after measured usage. On Unix it syncs changed object directories. If a removal fails partway through, some unreachable objects may already be gone; this is not an atomic rollback transaction. Protected roots must remain recoverable, and application should stop and investigate any verification error. The code does not guarantee power-loss atomicity.

## Cooperative limitations and recovery safeguards

The advisory lock serializes cooperating engine/storage clients only. Filesystem path validation is not descriptor-relative confinement; hostile symlink swaps and unmanaged Git writers can race it. Stop unmanaged writers. Existing pending operation records are pinned, not discarded. Unresolved adoption/promotions must be recovered by the engine first; collection never attempts recovery itself. Read-only SQLite can interact with SQLite's existing shared-memory mechanism. This is not a forensic no-write mount tool.

GC cannot release bytes held by live or retained history, packs, staging or acknowledged-operation pins. It is deliberately conservative and can refuse otherwise legitimate state. Native macOS/Windows validation, reparse-point confinement, reserved multi-process quota accounting, automatic retention policies and power-loss testing remain open.

## Executed tests

`cargo test --manifest-path services/storage/Cargo.toml --offline -- --nocapture`

Sixteen library tests (eight storage and eight reused replication-decoder tests) and sixteen independent recovery audit tests currently cover real aged-unreachable reclamation (262,242 compressed bytes in a newly created synthetic fixture), preservation of pending/acknowledged/checkpoint/young roots, pending-tree descendants, stale-plan and recovery-journal rejection, missing typed/JSON pins and unknown schema, valid replay crash-window full-graph preservation and replay-change rejection, source-config isolation, escaped-JSON pins, malformed packed refs, index-only root refusal, alternate refusal, quota overflow/pressure and overlapping/symlink/hardlink path rejection. Only newly created temporary fixtures are collected; no existing user source or campaign state is removed.
