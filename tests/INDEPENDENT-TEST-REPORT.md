# Wipstash independent adversarial execution report

17 October 2026. **32/32 integration scenarios passed** against the actual Rust CLI binary, in 18.477 seconds. These are executed tests, not a test plan. The implementation lead separately owns unit-test results.

## Tested artifact and environment

- Binary SHA-256: `1db0fddfaaa79ee1dbc05d930ba5c35f7dc946c42a02ecbdfdc3cbb53691ee58`
- OS: Linux-6.18.55-x86_64-with-glibc2.41
- Git: git version 2.52.0
- Python: 3.12.14 (main, Aug 25 2026, 14:00:49) [Clang 22.1.3 ]
- Run evidence: `tests/artifacts/20261017T150932`
- Exact Rust source hashes: run `environment.json`
- Reproduce: `cargo build` then `python3 tests/adversarial.py`
- Target individual cases: `python3 tests/adversarial.py Adversarial.test_NAME`

## What ran

Four deterministic scripted actors used four isolated working directories, independent CLI processes and separate private Git stores under one local OS account. Checkpoint and publication calls ran concurrently; a separate worker subprocess demonstrated background integration. Tests read persisted Git objects, ancestry and candidate evidence, and restarted processes against retained Git/SQLite state after deliberate exit-86 fault hooks. These were **not real Codex or Claude Code sessions, separate authenticated users, separate machines, or a network deployment**. MCP coverage was a scripted stdio protocol smoke test only.

Coverage includes:

- Concurrent disjoint proposals; same-line conflict quarantine while unrelated work progresses
- Broken private WIP; exact immutable publication; public reachable-object audit excluding earlier private ancestor content and synthetic secrets
- No implicit adoption, explicit dirty adoption, ignored-file collision rejection, stale generation and foreign/backward target rejection
- Binary/CRLF/LF/executable-bit preservation, deletions, permitted untracked files, symlink/case-collision rejection
- Duplicate operation identities and changed-request rejection; no-op and republished-tree handling
- Process crashes after checkpoint pin/commit, publication pin, before/after promotion CAS, and after adoption intent/during apply/after apply
- Full old-or-new live-tree recovery plus matching adopted head/generation; divergent authoritative history produces recovery_required without resetting it
- Coordinator-storage unavailability, queued local publication/reconnect, explicit cached-head adoption, and refusal to pretend offline latest is known
- Explicit private conflict resolution and stale live-input rejection
- Textually clean but semantically broken source integrates unchecked; an external post-integration Python probe demonstrates TypeError
- Explicit required-check rejection against exact candidate tree
- Declared scripted conflict repair with exact inputs and Git provenance; unrelated edits cannot falsely resolve conflict; resolution metadata does not enter source tree
- Local bare-repository backup and fresh clone containing a reachable accepted-but-unintegrated proposal; result never claims GitHub protection

- Public restore to an empty state preserves integrated source and reachable pending proposals, creates zero private workspaces, and quarantines unresolved publication eligibility; integrate/retry cannot silently reactivate it
- Restore rejects an existing populated state without changing live workspace files or its shared head

## Defects discovered and closed

1. **Excluded local artifacts:** source review found fixture-local build/private artifacts would be captured. Capture now uses isolated Git ignore matching and conservative exclusions. The four-actor and privacy tests pass.
2. **Every clean adoption failed:** execution found missing staging directories before Git materialization (ENOENT). Created staging directories; normal and crash adoption scenarios now pass.
3. **False no-op transitions:** review found unchanged proposals always created integration commits. Explicit already_included handling now preserves the head; regression passes.
4. **False complete backup:** an executed fresh-clone test showed accepted unintegrated proposal objects absent despite complete status. Reachable proposal roots are now exported and fresh-clone regression passes.
5. **False conflict resolution:** execution showed a worker changing only an unrelated document could integrate unresolved source conflict content. Exact conflict-path declarations and changed-path validation were added; negative and positive scripted-repair regressions pass.

Earlier failing-run command logs remain in the test artifacts directory. Successful reruns do not erase the initial findings.

## Evidence boundaries and remaining release gates

This is a local prototype result, not validation of the complete design. No native macOS/Windows, LAN/WAN, authenticated multiuser authorization, revoked identities, real AI-client confinement, OS sandboxing of repair/check commands, GitHub network/authentication/backup, or full operational disaster restore was exercised. Configured repair scripts and checks are trusted local commands, not securely confined hostile code. Cooperative workspace capture does not prevent arbitrary unmanaged writers. The tests do not establish crash behavior at every instruction or power-loss/storage-loss durability. Faults exit actual processes on retained local storage; they are not physical power cuts. No global subprocess/security audit was performed. Unchecked merges and scripted repair make no semantic correctness or universal no-data-loss claim.

## Executed scenario inventory

- `test_adoption_intent_process_crash`: PASS
- `test_adoption_mid_apply_process_crash`: PASS
- `test_adoption_process_crash_reconciliation`: PASS
- `test_background_worker_integrates_without_adopting`: PASS
- `test_backup_preserves_accepted_unintegrated_proposal`: PASS
- `test_byte_roundtrip_and_private_adoption`: PASS
- `test_checkpoint_after_commit_retry`: PASS
- `test_checkpoint_after_pin_retry`: PASS
- `test_declared_scripted_repair_records_exact_inputs`: PASS
- `test_deletions_and_allowed_untracked_files`: PASS
- `test_dirty_adoption_conflict_preserves_live`: PASS
- `test_divergent_head_fences_crash_recovery`: PASS
- `test_explicit_adoption_resolution_and_stale_live_guard`: PASS
- `test_foreign_or_backward_adoption_is_rejected`: PASS
- `test_four_actor_disjoint_concurrency`: PASS
- `test_ignored_collision_blocks_adoption`: PASS
- `test_mcp_stdio_protocol_smoke`: PASS
- `test_offline_cached_adoption_requires_explicit_oid`: PASS
- `test_offline_save_publish_and_reconnect`: PASS
- `test_operation_id_binding_and_stale_generation`: PASS
- `test_optional_required_check_rejects_exact_candidate`: PASS
- `test_private_broken_and_sanitized_history`: PASS
- `test_promotion_before_cas_recovery`: PASS
- `test_promotion_process_crash_reconciliation`: PASS
- `test_public_restore_preserves_source_and_fences_pending`: PASS
- `test_public_restore_rejects_existing_state`: PASS
- `test_publish_after_pin_retry`: PASS
- `test_repair_unrelated_edit_does_not_resolve_conflict`: PASS
- `test_same_line_conflict_does_not_block_disjoint`: PASS
- `test_semantically_broken_clean_merge_remains_unchecked`: PASS
- `test_unchanged_and_republished_tree_is_noop`: PASS
- `test_unsupported_paths_fail_before_checkpoint`: PASS
