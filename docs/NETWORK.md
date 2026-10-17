# Authenticated LAN and hosted networking

The same `services/transport` binary serves a LAN coordinator or a hosted
coordinator. Hosting, certificate provisioning, firewall configuration and DNS are
operator responsibilities. The implementation exists; this cloud test environment
has not run a listening service, so deployed LAN/WAN operation is not yet verified.
No public endpoint, certificate authority or credentials have been provisioned.

## Trust boundary

Every connection requires TLS client authentication against the configured CA.
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
Existing credentials are read; configuration does not create or enroll devices.

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

ACL files contain `peers`, a map from lowercase certificate SHA-256 fingerprints
to `{device, project, role: "client", revoked}` records. Replace ACL files
atomically when revoking a device. Rotation requires an explicit trusted
configuration update; certificates cannot self-authorize replacement identities.

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
Retain the build hash and transcripts. Existing in-memory TLS and injected
transport tests do not establish real hosted network behavior or power-loss safety.

Never disable TLS verification, use a plaintext fallback or run concurrent writable
authorities. Recovery activation currently relies on an explicit operator assertion
that the old authority has stopped; it is not authenticated distributed fencing.
