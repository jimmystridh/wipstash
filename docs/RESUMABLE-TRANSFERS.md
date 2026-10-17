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
source acceptance. The payload is fsynced before a new offset is written through
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

After successful core import and fsync of the completion journal, the duplicate
transport payload is reclaimed. Source storage now belongs to the core's durable
import/pinning lifecycle. Compact completion metadata and each accepted chunk's
offset, length and digest are retained, so exact completed-transfer retries still
work without keeping a second full payload. A crash during cleanup is recovered
on a subsequent begin/status/completion replay. Completion journals themselves do
not expire: eventually entry/byte quotas require explicit operator maintenance.
This is bounded storage admission, not an infinite-retention capacity promise.

## Platform and threat limits

Directory durability is implemented with Unix directory fsync. Other platforms
fail closed with `resumable_directory_durability_unsupported`; native Windows
power-loss durability is not claimed. The network client adapter is portable.
Configured ancestors and transfer files reject symlinks and traversal. Root
permissions are owner-only on Unix. Checks do not defend against a malicious
same-account process racing filesystem replacements. Filesystem corruption or
failed fsync is reported; it is not presented as successful acknowledgement.

Tests use synthetic files and the real engine through the in-memory request
adapter, including restart, lost acknowledgements, revocation, corruption,
binding isolation and premature finish. They neither bind network listeners nor
claim a physical power-loss or live Windows filesystem campaign.
