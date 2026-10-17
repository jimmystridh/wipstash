# Transport admission and replay contract

`src/replication.rs` is a transport-independent, tested building block for implementation-plan §9. The explicit source-exchange engine now uses its bounded payload verification, admission preflight and durable head replay. See [SOURCE-SYNC.md](SOURCE-SYNC.md). This caller uses separately trusted directory artifacts and explicit provenance confirmation, not authenticated network identities. The separate authenticated service now uses the engine boundary; see [NETWORK.md](NETWORK.md). Deployed LAN/WAN verification remains open.

## Implemented boundary

- Versioned, typed JSON envelopes reject unknown fields/variants, invalid identifiers, invalid public Git OID syntax and invalid/overflowing counters. The byte slice is capped at 16 KiB before JSON parsing. The separate HTTP service must also enforce its network read bounds before passing data to this decoder; see [network contract](NETWORK.md).
- Admission takes a separate `PeerIdentity` from its caller and checks its project, device, authorized authority and replication permission. The project, authority ID and positive epoch are pinned to trusted local configuration and persisted in a dedicated SQLite database. Both lower and higher unexpected epochs fail closed. An envelope cannot update the binding. Even a duplicate must pass all identity/epoch checks.
- `ReplayStore::receive` accepts contiguous sequences only. Exact typed retries are duplicates; altered events at an existing sequence and reused operation IDs at new sequences are rejected. JSON whitespace and field order do not change identity. This protocol intentionally permits one event per operation ID; an eventual multi-event operation stream will need a distinct event ID.
- The event journal, cached advertised public head and cursor commit together in a SQLite immediate transaction, with WAL/FULL settings. Reopen preserves deduplication and cursor. The cached head is an untrusted availability advertisement, not a verified installed object or permission to adopt. Proposal events do not advance it.
- Raw transfer verification consumes at most declared length plus one byte, rejects declarations above 8 MiB, detects short/long streams and verifies a lowercase SHA-256 transfer digest. `VerifiedPayload` means byte length/checksum verified only. It cannot install a Git ref or call the engine. The transfer digest is distinct from a Git object ID and provides no sender authentication.

## Required caller responsibilities

Supply identity only after authenticated transport validation and project authorization, including revocation checks and permission to attest the pinned authority’s event stream. Never construct it from client-supplied identity headers or envelope claims. This module does not obtain credentials or perform authentication, TLS, pairing, certificates, authorization database lookup, or network I/O. `may_replicate` is trusted caller input, not a role discovery mechanism.

Use a dedicated local replay database, not the engine database. Acknowledge only after `receive` succeeds. Enforce network timeouts, concurrency/rate limits and aggregate transfer/storage quotas before calling the contract; the synchronous reader has no timeout. A per-object size bound does not bound an infinite number of events or transfers. Replay history is retained without pruning. `cursor_expired` fails closed if an old sequence has no retained journal entry; snapshot/resynchronization and pruning are not implemented.

The source-exchange path now validates bounded uncompressed raw Git-object containers, exact root closure and public commit grammar in quarantine before shared installation. It does not accept packs or establish sender authentication. The separate service adds certificate-authenticated project admission, network/storage limits and durable resumable transfer metadata; see [network contract](NETWORK.md) and [resumable transfers](RESUMABLE-TRANSFERS.md). Deployed acceptance of that composed path remains open. A sender can give malicious bytes and their matching checksum; raw checksums do not make those bytes safe. This module deliberately does not import packs or run Git against uploads.

Authority migration still requires fencing the old writer and preserving accepted proposals and operation metadata, then an authenticated, verified handover. Reopening this store with a different project, authority or epoch fails. There is no automatic authority migration, failover election, reset or snapshot install API. The module checks an established fence; it cannot fence a remote process itself.

## Verification

Run `cargo test --locked replication::tests`. Tests cover ordered replay, duplicate canonicalization, sequence/operation conflicts, project/device/permission checks, old/new authority epochs, invalid/oversized envelopes, transaction rollback, on-disk reopen, proposal cache behavior and bounded/checksummed raw transfer failures.

These decoder/replay tests are local Rust/SQLite tests, including a deliberately aborted cursor write. Separate service tests exercise real TLS handshakes and ACL/revocation behavior through in-memory adapters, plus injected transfer failures. Neither suite establishes a power-loss drill, real network outage or two-device deployment. No network listener or alternative to the blocked Unix socket was created.
