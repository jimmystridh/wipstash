# Durable resumable proposal uploads

The authenticated Service routes expose `POST /v1/transfers` with exact manifest
bytes; `GET /v1/transfers/{id}`; `PUT /v1/transfers/{id}/{offset}` with raw chunk
bytes; and `POST /v1/transfers/{id}/finish`. Certificate identity comes from the
mTLS adapter, never request headers. The ACL is reloaded for every operation. Retained manifest authority and epoch
are revalidated against current service configuration before every transfer-ID
status, chunk, or finish operation, including completed-result replay.

Transfer IDs hash a domain/version, certificate fingerprint, device, project and
exact manifest bytes. Changed metadata produces a distinct transfer, not mutable
metadata on an existing transfer. Client-provided filesystem paths are absent.
Payloads remain bounded to 8 MiB, manifests to 16 KiB, individual chunks to 256 KiB,
and the durable receipt journal to 4096 accepted chunks per transfer. The provided
client uses 256 KiB chunks and at most three identical attempts per request.

A chunk acknowledgement reports only `committed_offset`. It never acknowledges
source acceptance. On Unix, the payload is fsynced before a new offset is written through
an atomic, fsynced journal replacement and directory fsync. A process restart
reopens the same transfer. Any payload tail beyond the committed journal offset
was not acknowledged and is truncated before the next append. Gaps, changed-byte
replays, and overlapping new ranges are rejected. Identical lost-ack replays do
not append data twice.

Finish requires the whole payload, verifies its length and SHA-256, applies the
configured project/authority/epoch binding, and invokes the core's quarantine
import. Only successful core import permits `import_result` to be committed.
A crash between core import and completion-journal persistence retries the core's
idempotent import. This does not imply coordinator validation/integration has
finished; the core's proposal state remains authoritative.

## Retention and quota

Incomplete acknowledged chunks never expire and are never automatically removed.
They remain resumable until explicit operator-directed maintenance. All partial
and complete transfer files share configured storage admission with core state;
quota exhaustion rejects new growth rather than evicting acknowledged sources.

On Unix, after successful core import and fsync of the completion journal, the duplicate
transport payload is reclaimed. Source storage now belongs to the core's durable
import/pinning lifecycle. Compact completion metadata and each accepted chunk's
offset, length and digest are retained, so exact completed-transfer retries still
work without keeping a second full payload. A crash during cleanup is recovered
on a subsequent begin/status/completion replay. Completion journals themselves do
not expire: eventually entry/byte quotas require explicit operator maintenance.
This is bounded storage admission, not an infinite-retention capacity promise.

## Platform and threat limits

Directory durability for the file backend is implemented with Unix directory fsync.
Windows uses the transactional backend described below. Other platforms fail closed
with `resumable_directory_durability_unsupported`. The network client adapter is portable.
Configured ancestors and transfer files reject symlinks and traversal. Root
permissions are owner-only on Unix. Checks do not defend against a malicious
same-account process racing filesystem replacements. Filesystem corruption or
failed fsync is reported; it is not presented as successful acknowledgement.

Tests use synthetic files and the real engine through the in-memory request
adapter, including restart, lost acknowledgements, revocation, corruption,
binding isolation and premature finish. They neither bind network listeners nor
claim a physical power-loss or live Windows filesystem campaign.

## Windows transactional backend

On Windows the existing, trusted configured staging directory contains
`resumable-v1.sqlite3` and its persistent rollback journal. No extra configuration
or wire-protocol change is required. Unix retains the file/journal backend and
its existing transfer identifiers. Copied Unix staging state is rejected on
Windows; there is no automatic conversion or silent abandonment of retained
acknowledgements. Unknown application IDs, schema versions and schema definitions
are rejected.

Windows requires an existing absolute local fixed-NTFS directory. UNC/network
shares, mapped network drives, alternate namespaces, reparse ancestors and
reparse database/journal files are rejected. The operator must provision and
protect this directory before service startup; this implementation does not
create it or claim to durably publish a newly created directory. Same-account
path replacement races remain outside the threat model.

The backend uses pinned rusqlite 0.39.0 with bundled SQLite and fallible integer
conversions. Each connection sets and verifies PERSIST journal mode,
synchronous=EXTRA and auto_vacuum=NONE. Initialization commits a fixed schema and
application identifier before any transfer acknowledgement. Metadata, receipt
history and payload bytes change together in BEGIN IMMEDIATE transactions.
Successful SQLite commit is required before acknowledging new data or completion.
SQLite's Windows VFS flushes files with FlushFileBuffers; PERSIST commits by
flushing the invalidated journal header rather than deleting the journal entry.
EXTRA is not presented as a Windows directory-fsync implementation.

Bootstrap and subsequent durability rely on SQLite's Windows file protocol and
local NTFS honoring FlushFileBuffers for newly created files and their metadata.
Storage hardware, drivers, controllers and virtual-machine hosts must faithfully
honor flush requests. Operators must preserve both database and journal together,
never independently delete/rename the journal, and use SQLite-supported backup or
stop the service before moving storage. A device or host that lies about flushes
is outside this guarantee. Physical power-loss survival has not been verified.

Incomplete replay compares retained bytes and accepts exact subranges, including
ranges spanning accepted chunks. Completed replay uses only original receipt
boundaries and digests. Successful completion deletes the duplicate payload in
the same transaction that stores the immutable core-import result. Deleted BLOB
pages become reusable within SQLite; the database and persistent journal retain
physical high-water sizes and remain fully charged by the shared storage scan.
Completion is logical deletion, not secure erasure: payload bytes can remain in
free database pages and the persistent journal. Database, journal and backups
remain sensitive after completion. There is no automatic VACUUM or physical
disk-reclamation claim. Append admission
conservatively includes the full payload capacity and bounded metadata because
updating a BLOB can rewrite and journal earlier pages. Status and exact replay do
not require new-growth admission. Exhaustion never triggers incomplete eviction.

Portable in-process tests compile this private backend on Linux as well as
Windows and cover reopen/lost acknowledgements, subranges, conflicting appends,
bindings/epochs, completion, schema corruption, aborted transactions and actual
SQLite SQLITE_FULL rollback. A private, explicitly selected test VFS injects
SQLITE_IOERR_FSYNC at every observed append/completion sync position. A marker
immediately after the mutation transaction's successful commit distinguishes
commit-critical flushes from connection-close cleanup. Failures before that
boundary must return an error and reopen as atomic old-or-new state; failures in
later close cleanup may return success only with the exact committed new state.
Idempotent retries are checked in both cases. The test VFS leaves the
production/default VFS unchanged.

On Windows SQLite retains the PERSIST journal handle because its VFS reports
SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN. After a successful commit has already flushed
the invalid journal header, sqlite3PagerClose performs an additional journal
flush. SQLite explicitly treats this close path as always successful; failure
of that redundant cleanup flush does not mean the earlier transaction commit
failed. Tests track the actual commit-return boundary rather than assuming a
fixed flush count. The shim also exercises this retained-handle behavior on
portable test hosts. These checks do not weaken the requirement that every
commit-critical flush succeed before an acknowledgement.

These are deterministic process-level checks, not physical power-loss experiments. The public Unix backend cannot opt into this
portable test implementation.

References: [SQLite atomic commit and persistent journals](https://www.sqlite.org/atomiccommit.html#persistent_rollback_journals),
[SQLite PRAGMAs](https://www.sqlite.org/pragma.html),
[Windows FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers),
[Windows CreateFile metadata flushing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

### Separate core filesystem limits on Windows

The SQLite staging contract above is not a blanket durability claim for every
trusted-core filesystem operation. Core Git materialization and directory-based
artifact export currently flush regular files but only perform directory-entry
flushes on Unix. Their Windows namespace durability has not been established by
this transport work. Core adoption also still depends on Unix-style directory
flushing and is not a supported Windows durable-adoption path; its failures must
not be ignored or converted to successful flushes. Passing native resumable
integration establishes functional import/replay, not physical power-loss
survival of all core Git, export, or adoption paths.

Git process arguments on Windows use a separate, conservative compatibility
adapter for Rust's canonical verbatim drive paths. Only unambiguous local drive
paths shorter than 248 UTF-16 code units are converted to conventional drive
syntax for Git arguments and its index-path environment variable. UNC/device
namespaces, dot traversal, trailing dots/spaces, reserved DOS names, alternate
streams and invalid Windows characters are rejected. This does not normalize or
replace paths used by Rust's filesystem validation, nor extend the namespace
durability guarantees above. Unix Git arguments remain unchanged.
