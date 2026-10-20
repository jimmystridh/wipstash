# Standalone CLI acceptance — 20 October 2026

`wip` is installed on PATH. Source-control MCP, special agent launchers and required client services are retired. Codex, Claude Code, OpenCode and Pi have the same CLI skill and four imported device profiles. Start each coding agent normally in its own clone; existing sessions may need a restart to clear cached MCP tools.

## Migration

All 40 existing workspace IDs, paths, source-file hashes/modes and generation values were preserved. All 40 successfully returned CLI Status afterward. Private Git history, retained operation IDs, credentials and transport queues remain in place. Eight acceptance-only workspace registrations were archived successfully afterward; their directories and history were retained. Agent configuration backups are private on this Mac under `~/.local/share/wipstash/cli-migration-20261020/config-backup`; they are excluded from cloud acceptance uploads.

Only Wipstash entries were removed from the four clients' MCP settings. Eight cloud client launch services and the running Wipstash client helpers/collectors were stopped. Existing native authority and GitHub backup operator processes were retained. Historical workspaces retain their original authority; they were not silently rebound to the cloud.

## Functional evidence

| Coverage | Result |
| --- | --- |
| Core library | 178 existing cases passed; 8 audit cases passed afterward, including the new archive guard |
| Transport library | 79 passed |
| Transport authorization | 12-case security suite passed; added exact-validation authorization case passed separately |
| Delivery worker | 9 passed initially; the 2 corrected head/backoff cases passed on retest |
| Agent collaboration | 13 passed |
| Async validation and repair | 23 passed |
| Shared Commit | 13 passed initially; corrected lost-reply case passed on retest |
| Standalone CLI | All 11 subprocess contracts passed; lifecycle case passed again after the archive fix |
| Other root integrations | 9 inspector-diff and 2 SQLite runtime cases passed |
| Cloud gateway | All 14 cases passed in the Linux image build |
| Static checks | Root and transport strict Clippy, formatting, Python compilation, skill validation and diff whitespace checks passed |

The final live campaign used four independent authenticated device identities and four unique clones. All confirmed task claims/comments, shared source-preserving empty commits, exact-ID retries, completed claims, passing exact-head validation, complete Wip-action audit delivery and authenticated central log reads. Pi first queued its commit offline and delivered it with `wip sync`. Native model sessions were not started.

The earlier live campaign exposed redundant full synchronization and slow chunked cloud imports; these were reduced to targeted coordination and the existing bounded whole-artifact import. It also demonstrated lease expiry during an overlong test. The corrected final run used an explicit 900-second acceptance lease. Checks remain asynchronous. Workspace cleanup additionally exposed and fixed the close-start audit record blocking its own archive: prior evidence must still be delivered, and only the matching current start record is exempted.

## Measured cloud calls

Seconds from this Mac, four concurrent callers against the warm single-instance service:

| Identity | Clone | Confirmed claim | Commit / offline Sync | Exact-head query |
| --- | ---: | ---: | ---: | ---: |
| codex | 8.7 | 23.0 | 45.2 | 37.4 |
| opencode | 14.2 | 35.8 | 57.6 | 36.4 |
| claude | 13.3 | 35.0 | 57.6 | 36.5 |
| pi | 11.4 | 33.3 | 39.4 | 29.0 |

Initial online Commit measurements were 155–166 seconds; the final online samples were 45–58 seconds. These still show substantial durable cloud request overhead and serialization. They are not throughput guarantees. The exact-head query reads retained evidence; it does not rerun checks. No source files were changed by the live campaign.

## Deployed authority

- Service: `https://wipstash-demo-134099336412.europe-north2.run.app`
- Revision: `wipstash-demo-00009-fkd`, Stockholm, 2 CPU / 4 GiB, one always-on instance.
- Immutable image: `sha256:0ff94095142f6f891b4088c34fda3725b6791f2bd3b16ea40d9c5dbe26926630`.
- Successful build: `86ec8c9b-3b47-4240-ad8a-bfa1c92b4dcc`.
- Shared head unchanged: `3e01befb2bb1f221227d14d5b6e5be2a63a072e5`.
- Verified tree: `f39f2745d7a2bdbe714ed6a8bb5f9ec4b1490c85`; retained exact-head evidence passes Python tests, JavaScript syntax and JavaScript behavior checks under the current policy.
- Friday stop retained: 23 October 2026, 23:59 Stockholm (`21:59 UTC`).

Private acceptance artifacts are retained under `gs://dev-innov-cm-wipstash-demo-20261019/acceptance/20261020-cli/`. The source archive, client binary hash, migration summary and live timings are separate from global client configuration backups and credentials.

This acceptance covers macOS CLI use and the Linux cloud service. The CI-only SQLite concurrency campaign was not executed here; paid model acceptance, Windows runtime behavior, large repositories and multi-instance writable scaling are not established by this run. Native activity outside `wip` requires explicit optional import; complete Wip-action delivery does not imply coverage of every native edit or shell command.
