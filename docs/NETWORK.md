# Authenticated LAN and hosted networking

The same `services/transport` binary serves a LAN coordinator or a hosted
coordinator. Hosting, certificate provisioning, firewall configuration and DNS are
operator responsibilities. Native GitHub CI has run real loopback listeners and
four independently enrolled scripted device identities on Linux, macOS and Windows.
This supersedes the earlier no-listener evidence boundary, but deployed multi-host
LAN/WAN operation remains unverified. No public endpoint, real credential vault or
production credentials have been provisioned; CI generates disposable synthetic
CAs, certificates and invitations.

## Trust boundary

Every sync connection requires TLS client authentication against the configured CA.
Guided pairing uses a separate server-authenticated TLS enrollment endpoint with
invitation authorization and proof of possession; it does not expose sync routes or
permit unauthenticated sync access.
Clients also pin the authority certificate's SHA-256 DER fingerprint. The server
maps each client certificate fingerprint to a project/device/role ACL entry,
rechecking current ACL authorization for each request. HTTP identity headers are
not trusted. Revoked, unknown or wrong-project devices cannot import proposals or
retrieve another device's proposal receipts. Project, authority and epoch must
match the separately trusted engine configuration; network data cannot change them.

The server executes one configured engine binary against one configured state
path. Requests cannot select executables, state paths, policy, repair commands or
shell operations. Received objects are quarantined and verified before admission.

## Components

Use [guided remote pairing](PAIRING.md) for normal setup, invitation, join, device
revocation and replacement. `wipstash remote setup` generates the protected
authority profile without starting listeners; `wipstash remote serve` explicitly
starts the separate enrollment and sync endpoints. `remote join` verifies a
read-only authenticated connection and does not publish or adopt source.

The following legacy/manual commands remain supported:

- `wipstash-transport serve /absolute/service.json`: authenticated authority service
  plus its serialized autonomous integration worker.
- `wipstash-transport worker /absolute/client.json`: durable client outbox and head /
  receipt polling. Only explicitly published proposals are eligible for upload.
- `wipstash-transport client /absolute/client.json '<operation JSON>'`: one explicit
  upload, download or catch-up operation.

The exact strict configuration fields are defined by `Config` in
`services/transport/src/lib.rs` and `ClientConfig` in `src/main.rs`. All engine,
state, staging and certificate paths must be operator-controlled. State and staging
must be separate, disjoint directories outside source workspaces. Keep private-key
files outside source repositories and never publish real configuration files.
The manual service/client configuration reads existing credentials. Guided setup
and join are the separate credential-generation/enrollment path; they do not
provision credentials into native vaults.

Server fields: engine, state, staging, project, authority, epoch, device, acl, ca,
certificate, key, listen and optional limits. Client fields: engine, state, staging,
ca, certificate, key, server_name, authority_fingerprint, address, project,
authority, epoch, device and authority_device. `address`/`listen` are socket
addresses; `server_name` is the certificate name verified by TLS.

### TLS private-key source

Both server and client use exactly one `key` value. Existing `"key":
"/absolute/device-key.pem"` configuration remains supported. Explicit native
vault opt-in is `"key": {"native_vault": "wipstash/device-tls"}`. The object accepts
only `native_vault`; extra fields, duplicate selectors, invalid credential IDs,
and file/fallback combinations are rejected. Configuration contains an identifier,
never secret material. `Client::from_files` remains available to Rust callers;
`Client::from_key_source` accepts either source.

The selected credential must already contain one unencrypted PEM private key
(PKCS#1, PKCS#8, or SEC1), at most 64 KiB. Multiple keys are rejected. Certificate
and CA PEM files remain operator-controlled files, bounded to 1 MiB each. Secret
buffers are zeroized after parsing; the TLS implementation retains its signing key
in memory for the connection/service lifetime. No key is logged, serialized,
written to a fallback file, or passed in process arguments.

Retrieval uses the platform read-only adapter: Linux libsecret/Secret Service,
macOS Keychain, or Windows Credential Manager. Unavailable, locked, missing,
ambiguous, or malformed credentials fail startup; there is no unlock prompt,
automatic provisioning, file fallback, or plaintext transport fallback. Existing
file mode remains an explicit operator choice. Native lookup conventions and
runtime prerequisites are defined by `crates/platform/src/vault/`; provision and
validate under the intended service account outside this program.

Synthetic key parsing, configuration, and injected-vault failure tests do not
access any real store. Actual service-account retrieval, locked-store behavior,
certificate matching, rotation and TLS operation must still be validated on each
native OS before deployment. No real credential-store runtime acceptance is
claimed here.

### Managed authorization and legacy ACL files

Guided profiles use `acl: {"managed": "/absolute/authority/pairing.sqlite"}`.
The protected SQLite store is authoritative for device state, active certificate
generation, invitations and revocation; it is rechecked on each request, including
requests on existing TLS connections. Rotation commits the replacement generation
and revokes the old certificate atomically. Already admitted work may finish.
Do not edit pairing journals or treat them as authorization records.

Legacy `acl: "/absolute/acl.json"` remains supported. Its `peers` map keys are
lowercase certificate SHA-256 fingerprints, with
`{device, project, role: "client", revoked}` records. Replace these files atomically
for revocation and explicitly update trusted configuration for rotation. Neither
mode permits certificates to self-authorize replacement identities.

Guided secret storage is protected for the current execution account: Unix
0700/0600 modes and Windows protected DACL verification. Unsupported protection
fails closed. It does not create a different service account or establish real
native-vault provisioning. Profile secrets must remain outside source workspaces;
see [PAIRING.md](PAIRING.md) for restart journals and trusted invitation transfer.

## Delivery and failure behavior

Publication and adoption remain deliberate. The service can integrate accepted
proposals automatically, but never checkpoints private edits or adopts into a
client workspace. Clean merges need no checks when policy checks are empty;
conflicts stay quarantined unless a configured repair policy can safely execute.

Client retries retain exact operation identity and artifact bytes. Head history
is paginated and replayed contiguously. Receipt lookup is restricted to the
publishing device. Durable outboxes survive ordinary restart; identity errors
pause instead of retrying with changed identity. See [DAEMONS.md](DAEMONS.md),
[SOURCE-SYNC.md](SOURCE-SYNC.md) and
[RESUMABLE-TRANSFERS.md](RESUMABLE-TRANSFERS.md).

Defaults bound source payloads to 8 MiB, concurrent connections to 32, storage to
1 GiB / 200,000 entries with a 64 MiB free-space reserve, and each certificate to
120 requests/minute with a burst of 30. Storage admission is conservative
preflight, not a transactional disk reservation against unmanaged local writers.
Rate-limited clients receive 429 and a bounded Retry-After; insufficient storage
returns 507. Read-only history remains usable under growth pressure. Large source
histories can exceed current bounded artifact limits; there is no silent history
truncation or cursor skipping.

## Deployment acceptance gate

Before exposing a real host, verify native filesystem durability, certificate
issuance/rotation/revocation, service supervision, bounded resource use and
recovery from a stopped authority. Then run four independent clients over actual
TLS with delay, disconnects, lost acknowledgements, stale epochs and revocation.
Retain the build hash and redacted evidence. Passing native-CI guided pairing
establishes selected actual loopback TLS and managed device-lifecycle contracts.
The separate Linux real-TLS upload-fault campaign also passed at functional commit
`1488774be3582fb0322de74f1071245ced08f114` in [native CI 39095243418](https://github.com/jimmystridh/wipstash/actions/runs/39095243418).
Artifact `12124098556` records four device identities, two server restarts, a
262,144-byte retained offset, eight upload attempts, one pre-send drop, one lost
acknowledgment, one cross-device rejection, six certificate/ACL rejections and two
integrated publications. All stored public blobs, including unreachable objects,
were audited. The earlier fixture sequencing failure is superseded. In-memory
tests, application fault injection and real loopback sockets do not establish
hosted multi-machine network behavior or power-loss safety. See [SCOPE.md](SCOPE.md) for revision-specific
evidence and [tests/README.md](../tests/README.md) for guarded CI commands.

Never disable TLS verification, use a plaintext fallback or run concurrent writable
authorities. Recovery activation currently relies on an explicit operator assertion
that the old authority has stopped; it is not authenticated distributed fencing.
