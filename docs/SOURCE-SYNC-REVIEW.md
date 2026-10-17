# Source synchronization trust-boundary review

17 October 2026. Independent review of the filesystem artifact transport, limited to the code and local fixtures below.

## Security model

A source directory and its contents are explicitly trusted by the operator. Pinned project/device/authority labels, epoch comparison, a transfer checksum, and `confirm_trusted_source` are **not authentication**. Anyone who can construct an artifact can claim a configured sender label. The source exchange is a cooperative local fixture, not authenticated LAN/WAN hosting, an authorization boundary against another same-account process, or authority migration.

Public export must contain only the selected public graph. Private checkpoint ancestry, private recovery commits, unrelated objects, workspace metadata, and executable policy must not cross that boundary. Deliberately published file contents are public; filename exclusions do not detect arbitrary secrets.

## Review acceptance criteria

- Configuration is immutable; fresh clients cannot become authorities through init, restore, integration, promotion recovery, or configuration changes.
- Client source cache availability never claims remote coordinator connectivity.
- Every head event is bound to the configured project/device/authority/epoch and ordered before public ref application. Rejected divergence does not consume a replay sequence. An old exact duplicate cannot rewind a newer head.
- Proposal acceptance binds sender, operation, public base, selected commit and declared intent. Retrying an artifact does not create another proposal, change an accepted proposal, or reopen cancellation/integration.
- Object admission validates identities, graph completeness, exact reachable closure and resource limits before objects become visible in destination storage. Root refs are installed deliberately and separately from live workspace adoption.
- Git subprocesses do not execute uploaded hooks, source filters, injected environment configuration, replacement refs, or remote helpers. Quarantine is a newly created repository, not the supplied source directory.
- Export paths cannot overwrite state, private stores or registered live workspaces. Filesystem source mutation is bounded by the explicit cooperative/trusted-directory assumption; checksums alone are not proof of sender identity.
- Sync import/export does not materialize or mutate live files; explicit adoption remains necessary.

## Verification

`cargo build --locked` completed successfully. `python3 tests/review_source_sync/review.py` passed 12/12 independent real CLI/Git/SQLite regressions on Linux. Detailed output is retained in `tests/review_source_sync/results.log`; source and binary SHA-256 values are in `tests/review_source_sync/sha256.txt`. Other agents own broader transfer and workflow suites; their pass counts are not duplicated here.

No successful authenticated transport, multi-device isolation, process-kill campaign, power-loss test, native macOS/Windows test, or network listener is implied by this review.

## Findings and resolution log

1. **Rejected graph installed public pins.** Initial `sync_import` called the installer before head replay/fast-forward and proposal identity validation. An unrelated head rejected as stale still appeared under `refs/wipstash/transfers/`. Reproduced with real CLI/Git. Fixed by `transfer::prepare` plus non-mutating replay `check`; graph and semantic admission now run against quarantine before `Prepared::install`. Independent divergence, sequence-gap and proposal-identity cases pass with unchanged public refs.
2. **Export could write inside a live workspace.** Destination validation originally excluded only daemon state. Fixed by rejecting overlap with registered workspaces. Independent regression checks the file list remains unchanged.
3. **Client configuration could inherit an orphan repository.** A failed/partial initialization without authority metadata could leave an existing coordinator store. Fixed by requiring no preexisting coordinator repository before client configuration. Existing initialized authority-to-client and configured client-to-authority/epoch changes are rejected.
4. **Client cache implied coordinator connectivity.** `coordinator_online` originally tested local repository existence. Client workspace status and updates now report false, label cache semantics, and explicitly leave remote contact unverified. Independent dirty-workspace test verifies repeated import/updates do not adopt files.
5. **Transfer size mismatch.** Object codec supports up to 64 MiB but engine framing uses an 8 MiB transport cap. Export now rejects over-cap payloads before reserving the sequence; engine artifacts deliberately remain limited to 8 MiB. Codec and engine limits must not be described as identical.
6. **Any-parent ancestry permits authority-history switching.** A public-format merge whose first parent starts an unrelated history and whose second parent is the old head passed the original fast-forward test. A dedicated regression demonstrates acceptance of this malformed source history. Fixed by enforcing first-parent continuity for import and replay recovery; the independent regression now passes.

7. **Duplicate proposal receipt could claim renewed acceptance.** A second export operation for an already cancelled/integrated proposal preserved the row but returned `coordinator_accepted` and emitted another acceptance event. Fixed by returning the existing disposition and suppressing repeated acceptance events. Independent cancellation/re-export regression verifies both the terminal row and single event.

## Remaining trust and operational limitations

- Supplied Git configuration/state and parent directories are trusted local storage. The implementation clears ambient Git variables and global/system configuration, disables replacements/hooks/templates, uses raw object plumbing, and does not check out uploaded content. This is not containment against a concurrent same-account actor modifying trusted directories, local repository configuration, source files, or symlinks between validation and use.
- Files are read with byte bounds and final-component symlink rejection. Path checks and source confirmation do not provide directory-descriptor-based race protection or prove origin. The artifact payload digest detects inconsistent bytes; a malicious sender can replace both data and checksum.
- Commit grammar plus private-ref checks block accidental private checkpoint ancestry. They do not establish sender identity or make arbitrary deliberately published content secret-free. Someone constructing a public-format object can choose its contents and author metadata.
- Raw uncompressed transfer avoids Git pack/delta expansion. Object, tree-depth, snapshot-entry, ancestry and framing limits bound the accepted representation. Git subprocess CPU/wall time and aggregate retained-storage/event volume remain unbounded; full-history exchange eventually reaches fixed limits.
- Cross-Git/SQLite application is deliberately ordered rather than one atomic transaction. Validated/admitted objects may remain after interruption before replay/receipt commit. Read-only preflight requires the existing engine lock; no other supported writer may modify the replay database outside it. This review does not establish power-loss durability.
- Exact retry receipts can describe the original result rather than the latest current head; current state should be queried separately. Same source path does not bind mutable file contents: operation/manifest/content checks must still pass on import. Export reconstruction uses retained original manifest/root identity.
- A client cannot cancel a proposal after its export identity is reserved, even if artifact creation failed: delivery may already have occurred. `sync_reexport` repairs delivery without inventing a new publication. Authority receipts report observations separately from retained local queue state. There is no authenticated revocation, authority migration, remote cancellation protocol, identity provisioning, or remote fence in this fixture.


## Authority receipt follow-up review

Receipts carry only the pinned source/proposal binding and an explicit allowlist of observation fields; they carry no Git objects, policy, command output, private detail or implicit adoption request. Receipt import binds project, authority, epoch, allowed sender, recipient, deterministic authority proposal ID, exact local proposal commit/base and prior local export reservation. A locally cancelled or never-exported proposal cannot acquire a remote acceptance observation through the supported path.

Revisions are per authority proposal, not the head replay cursor. Unseen lower revisions, a different envelope at the same revision, and reuse of an operation with altered content fail closed. Terminal observations cannot change disposition/head/evidence/repair fields. An exact historical duplicate can return its original receipt, but it cannot overwrite the newer persisted observation. These are trusted-source assertions, not cryptographic proofs of integration or checks; an integrated receipt does not import its integration head or edit live files.

Three added independent regressions passed: revision/operation identity conflicts; exact-but-unexported and locally cancelled proposal rejection; and conservative cancellation fencing after a failed-but-reserved export with successful reconstruction. The separate end-to-end QA suite owns recipient/commit/unknown-field mutations, stale terminal ordering and file/generation invariance. Legacy authority journals created before origin tracking have no automatic receipt-origin backfill; fresh accepted proposals record origin atomically with acceptance.
