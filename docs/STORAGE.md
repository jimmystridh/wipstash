# Storage safety boundaries

These are local, cooperative safeguards, tested on Linux. They are not native Windows/macOS validation, a filesystem security boundary, a power-loss guarantee, or a full storage-management implementation.

## Paths and staging

The engine can canonicalize caller-supplied roots once and retain the resulting canonical path. An initial alias such as macOS `/tmp` may therefore resolve successfully. At the Git capture/materialization boundary, the supplied directory and its existing ancestors must be real directories, with no symlink components or `..` traversal. Tree paths are ASCII only, with no dot components, Windows device names, forbidden punctuation, trailing spaces/dots, `.git`, case-fold collisions, or fixed excluded names. Symlink and special-file entries are unsupported. Paths are limited to 4,096 bytes and 64 components.

Materialization requires an empty directory. It validates paths, modes, collisions, object sizes and blob/tree hashes before creating files. Missing or checksum-mismatched objects fail before file creation. All regular staged files are synced after writing bytes and permissions; Unix staging directories are synced child-first. This fits adoption's separate staging and journal flow. A write/sync failure can leave partial staging, and callers must not promote it. No live-workspace rollback is attempted by this backend.

The directory checks use pathname operations. Another process can swap an ancestor between checking and opening it. Captures can also race same-size edits. Stop unmanaged writers; these checks are not descriptor-relative race-proof confinement. Excluded/ignored files are not captured or backed up.

## Capacity and bounded inputs

Before writing capture objects or staging data, capacity checks compare filesystem available space with:

`payload bytes + 8,192 bytes per file + 1,048,576 bytes reserve`

Arithmetic is checked for overflow. Checks also run incrementally before reading each included file/blob. Capture checks the repository filesystem; materialization checks the staging filesystem. Insufficient capacity returns `insufficient_storage`. This estimate is deliberately conservative for small files but is neither a reservation nor accurate full-store accounting. Concurrent writers, quotas, compression overhead, filesystem metadata, refs, database growth and adoption backup space can still exhaust storage after preflight. Write/sync errors propagate; ENOSPC is not simulated by the capacity arithmetic tests.

A capture/materialization permits at most 10,000 included path prefixes, 16 MiB per blob, 64 MiB aggregate blob bytes and 4 MiB per tree object. Oversized data returns `storage_limit`. Capture checks metadata sizes before reading; materialization queries Git object sizes before allocating their contents. Git stdout is limited to 32 MiB and stderr to 1 MiB per invocation; excess is drained and then rejected. Limits bound application buffers, not Git's own memory/CPU or elapsed time. The complete accepted snapshot remains buffered in memory, and subprocess input adds temporary copies. These conservative prototype limits may reject otherwise valid projects.

## Durability and integrity

Git commands request `core.fsync=all` and `core.fsyncMethod=fsync`. Materialization verifies the root tree, recursively listed subtrees and every blob by recomputing its Git object ID. This detects valid compressed content stored under an incorrect object ID as well as missing/unreadable objects. It is not a repository-wide integrity audit and does not validate unrelated objects or the entire commit ancestry.

Git configuration/hook null-device paths use `/dev/null` on Unix and `NUL` on Windows. Directory sync currently has a Unix implementation only. Windows directory durability, reparse points, executable semantics, native tool availability and filesystem behavior remain unvalidated. File and Git sync success does not establish power-loss durability of the full Git/SQLite/adoption transaction.

The core does not automatically prune objects or expire pins. The separate storage service supports explicit, reviewed collection of aged loose objects unreachable from all protected roots, with locked plan revalidation and integrity checks. It preserves pins, packs, database records, working files and recovery staging; it is not a general retention manager. See [storage lifecycle](STORAGE-LIFECYCLE.md) for eligibility, refusal conditions, cooperative limits and commands. Maintain independent backups of valuable source data.
