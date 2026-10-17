# Independent storage and recovery review

Status: reviewed for explicit cooperative collection under the boundaries below. No remaining demonstrated fail-open root-scan defect in the final tested implementation; this is not production-wide or hostile-filesystem assurance. Review date: 2026-10-17. Scope is `services/storage`; tests use newly created temporary stores and synthetic objects only. No existing user store was collected.

## Findings and disposition

- **Fixed: index-only roots.** The first implementation offered a blob referenced only by a Git index for deletion. Unsupported index, pseudoref and linked-worktree structures now cause refusal rather than being ignored.
- **Fixed: escaped replay JSON.** A valid Unicode-escaped object identifier in an operation request was not extracted. JSON values are now recursively decoded, with a depth limit.
- **Fixed: malformed reference metadata.** Malformed packed refs were silently accepted. HEAD, loose refs, packed refs and reflogs now have syntax checks; exact reference-file bytes are included in plan freshness.
- **Fixed: separate replay database.** Actual client replay uses `sync-replay.sqlite`, not the `state.sqlite` replication tables. A crash after replay admission but before Git ref installation leaves its only durable intent there. Collection now reads the dedicated version-0 database, validates its exact two-table layout, integrity, binding, contiguous sequence, canonical envelope digest and cached-head consistency using the original replication decoder. All event heads and descendants are retained, and replay contents participate in plan freshness. Unknown auxiliary SQLite journals remain refused.
- **Fixed: uncertain command writers.** Both running and uncertain command records now stop collection. An uncertain command can indicate an escaped/live writer.
- **Fixed: missing JSON recovery roots.** All discovered 40-hex journal tokens must exist in a known object store before collection. This deliberately permits false refusals for text that merely resembles an object identifier.
- **Fixed: malformed retained export JSON.** Schema-known structured fields and JSON-looking text now require successful decoding; invalid retained export manifests cause refusal.

## Root inventory reviewed

The engine's core state database contains workspace base/checkpoint, checkpoints, proposals, promotion/adoption journals, adoption-conflict roots, candidate evidence, operation replay, and events. Sync exports retain manifests, imports retain results, and remote status retains receipts. Backup state retains committed/pending root/metadata pairs and the queue snapshot. These are covered by the table/column allowlist and generic JSON/token extraction, with required-object existence checks. The separate replay journal is separately validated and pinned. The separate repair-budget database contains proposal identifiers and budget counters, not standalone Git-object roots; repair candidate trees/evidence are represented by normal candidate/proposal state and refs.

All recognized refs and reflogs are pins; commit/tree descendants are obtained with Git traversal. Unfinished promotion/adoption journals stop planning. Unknown tables/columns, unsupported object formats, binary journal values, unreadable data, unsupported auxiliary journals, shallow stores, alternates, symlinks and regular-file hardlinks cause refusal. Worktree content is not a deletion target. Only old unreachable loose objects under the selected managed object store can be candidates; packs, refs, databases, backups, staging and working files are never selected for deletion.

## Freshness and filesystem boundaries

Plan and apply take the same cooperative `state.lock` used by the engine. Apply recalculates the complete plan and compares roots, reachability, candidates, candidate content digests, timestamps and journal/reference digests before unlinking. Retention must be at least one day. Future-mtime objects are retained; an object refreshed after planning invalidates application. Age is a retention floor, not a promise to expire all older objects.

This is not race-proof filesystem confinement. Pathname metadata checks followed by ordinary opens/unlinks have TOCTOU exposure to unmanaged writers and ancestor replacement. The lock excludes only participating writers; it does not prevent a separate process from editing Git refs or replacing paths. Stop unmanaged writers and use a private owned state directory. Do not market this as safe concurrent collection against hostile/uncooperative filesystem mutation. Partial unlink or directory-sync failure can leave a partially applied collection; protected objects must remain protected independently of completion reporting.

## Quota review

`usage` rejects overlapping roots, symlinks, hardlinked regular files, special files, traversal failures and entry-limit excess. Byte/entry addition and allocated block arithmetic are checked. `admit` charges the greater of logical and allocated size, incoming estimates and reserve, and checks available space for each supplied root. These are read-only cooperative preflights, not reservations; concurrent writes, filesystem metadata growth and estimation errors can still exhaust space.

Transport reserve integration is not yet present in the reviewed transport source. Server receive/export and workstation upload/download create separate temporary artifacts. A quota API alone does not demonstrate configured reserve enforcement for those copies or engine-side expansion. Integration and boundary tests must be reviewed separately before claiming end-to-end quota enforcement.

## Reproduction

From the repository root:

    CARGO_HOME=/workspace/shared/.cargo RUSTUP_HOME=/workspace/shared/.rustup PATH=/workspace/shared/.cargo/bin:$PATH cargo test --manifest-path services/storage/Cargo.toml --test recovery_audit

The independent suite is `services/storage/tests/recovery_audit.rs`. Final verification: all 16 independent audit tests and all 16 library tests pass. The audit includes a must-succeed crash-window replay test retaining a commit/tree/blob graph, malformed/missing-root refusals, replay/reference freshness, future/renewed timestamps, and a synthetic garbage collection proving dirty live-worktree bytes remain unchanged. No network listeners, blocked sandbox probes, process-kill probes, credentials or external writes are used.
