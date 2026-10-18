# Guided remote pairing

The normal setup path uses CLI flags and protected invitation files, not hand-written ACL or certificate JSON. The transport binary must be installed alongside `wipstash`; the root `remote` command executes that fixed sibling. Legacy transport `serve SERVICE_JSON`, `worker CLIENT_JSON`, and `client CLIENT_JSON OPERATION_JSON` remain available.

Install both binaries into the same Cargo bin directory from this checkout:

```sh
cargo install --locked --path .
cargo install --locked --path services/transport
wipstash remote help
```

These commands install the executables only. They do not create credentials or start services. If using a custom install directory, keep both executables together and add that directory to your PATH.

## Coordinator

Profiles and invitation files must live outside every source tree and registered managed workspace. Setup rejects profile/source overlap before importing or generating keys; invitation export and join reject known-workspace overlap without deleting files. The read-only engine probe must supply a complete workspace list; missing metadata fails closed. Secret-creating setup, join, invite and rotation also fail closed if a registered workspace path cannot be resolved. Deleted unrelated workspace folders do not block serving, listing devices, revocation or cancellation of pending invitations; those operations validate stored path metadata without resolving workspace folders.

Use an existing private parent directory. All paths must be absolute. Run as the account that will later run the listener. Example paths and addresses below are placeholders, not deployment instructions already executed:

```sh
wipstash remote setup --directory /private/authority --state /private/authority-state \
  --project demo --authority central --device central-device --source /private/source \
  --server-name coordinator.example --enrollment-address 192.0.2.10:7444 \
  --sync-address 192.0.2.10:7443
wipstash remote serve --directory /private/authority
```

Defaults bind loopback (`127.0.0.1:7444` enrollment, `127.0.0.1:7443` sync), with TLS name `localhost`; remote devices need explicitly reachable addresses and the matching server name. The two endpoints are separate. Sync always requires a client certificate. Enrollment exposes only credential enrollment and recovery. On a fresh authority state, `--source` explicitly selects the initial public source import; it is never inferred from the current directory. Omit it only when the engine state is already initialized. Setup generates a local CA and server credentials, writes protected configuration, validates the engine binding, and initializes an authority with no peers. It does not open listeners or install an operating-system service. Serve is the explicit listener-starting step.

```sh
wipstash remote device invite --directory /private/authority \
  --device laptop --out /private/invites/laptop.invite
```

The output parent must already exist and be private. Invitation files are create-only. An invitation lasts 15 minutes by default; `--expires-in SECONDS` accepts 60–86400. Invite reserves the engine peer before creating a network grant invitation; reservation alone grants no access. Pre-existing engine peers without a matching pairing intent are not silently claimed.

If an invitation output is lost or writing it fails after reservation, inspect the protected output first. To explicitly invalidate only pending invitations and reissue, run `wipstash remote device cancel-invite --directory /private/authority --device laptop`, then repeat `device invite` (or `device rotate` for an existing generation) with a new output path. This does not revoke an active device or reuse a retired identity.

Transfer the entire invitation through a trusted private channel. The invitation contains a bearer secret and the intended project, device, authority, CA, endpoints, TLS names and pins. A pin received in an untrusted invitation does not independently authenticate the coordinator. Never paste the secret into argv, a URL, environment variables, chat logs, or shell history. The CLI prints no invitation secret.

## Joining device

```sh
wipstash remote join --directory /private/laptop --state /private/laptop-state \
  --invite-file /private/invites/laptop.invite
```

For a protected pipe, use `--invite-stdin` instead of `--invite-file`; stdin is bounded. File input must satisfy the same private-storage checks. `--engine /absolute/wipstash` overrides the fixed sibling engine for setup and join.

Join shows the authority, project and client device. It rejects conflicting existing bindings. Before contacting the server, it durably saves the exact local private key, CSR, request ID and profile intent. An uncertain response never causes a fresh identity or grant attempt. Retry the same command, invitation and directory after interruption. Recovery uses proof of possession of that original private key and a fresh challenge. A committed response may be recovered within the server's fixed recovery window after invite expiry; an expired uncommitted invitation cannot be redeemed.

Issuance, local installation, engine configuration, and authenticated connectivity are separate stages. Join validates the issued response, installs certificates, configures a fresh engine or verifies an exact binding, then makes a read-only authenticated history request. It never uploads a proposal or adopts a head. If the final check fails, credentials remain installed and the diagnostic says connectivity is unverified. Retry the same join to finish. Do not delete the pending profile to “fix” an uncertain issuance.

Use the generated client configuration with the existing background worker when desired:

```sh
wipstash-transport worker /private/laptop/client.json
```

Starting that worker is a separate explicit choice and may perform configured synchronization work.

## Status, diagnosis and revocation

```sh
wipstash remote status --directory /private/laptop
wipstash remote doctor --directory /private/laptop
wipstash remote doctor --directory /private/laptop --online
wipstash remote device list --directory /private/authority
wipstash remote device revoke --directory /private/authority --device laptop
```

Status reports local recorded state, including whether a previous connectivity check completed. It is not a live health assertion. Doctor checks local files and their protection without launching an engine, opening a writable store, enrolling, recovering or probing the network. It does not certify current authorization or remote reachability by default. Explicit `doctor --online` for a client adds a bounded read-only authenticated history request without installing or changing credentials; it distinguishes pin mismatch and server rejection where available.

Revocation takes effect for subsequent requests, including requests on existing TLS connections; already admitted work may finish. A retired device identity is never reassigned to an unrelated device.

## Replacement / certificate rotation

```sh
wipstash remote device list --directory /private/authority
wipstash remote device rotate --directory /private/authority --device laptop \
  --generation 1 --out /private/invites/laptop-replacement.invite
wipstash remote join --directory /private/laptop-generation-2 --state /private/laptop-state \
  --invite-file /private/invites/laptop-replacement.invite
```

Use the actual current generation from `device list`. Join the replacement into a new private profile directory while retaining the same client engine state and identity. The old generation is revoked atomically when replacement enrollment commits. Switch the worker to the new profile only after installation. Existing resumable transfers must restart under IDs derived from the new certificate fingerprint; operation IDs, replay history and receipt ownership remain stable. Authority CA and server-pin rotation require a separate trusted rollout and are not handled by device rotation.

## Protection and verification limits

Unix profiles require private directories and files (0700/0600), safe path traversal and durable create-only writes. SQLite and its journals live under the private authority directory. Windows support depends on the private-file backend and managed-store backend supporting and verifying a protected DACL for the current execution account; otherwise setup fails closed. It does not provision another service account. Existing native-vault support is retrieval-only and is not used to pretend new keys were saved into a vault. Do not assume interactive-user storage is available to a service identity. Windows directory-entry power-loss durability is not claimed.

Bootstrap and join journals intentionally retain sensitive material for restart. Treat the entire profile as a secret backup. Do not edit these journals or use them as authorization records; the coordinator's managed SQLite store is authoritative. Existing conflicting files are never overwritten. Private-file publication uses a flushed private staging file and no-replace publication. Interrupted staging files remain private; incomplete final journals fail closed and may require operator inspection.

This implementation's local workflow tests use disposable synthetic fixtures only. Compilation, native platform checks, and end-to-end enrollment validation must pass the feature-branch CI gates before deployment. No real credentials, grants or listeners were provisioned while implementing it.

Secret-bearing restart journals are stored under the profile’s private `credentials/` directory, which is excluded from workspace capture as defense in depth. Root-level legacy `bootstrap.json` or `join-intent.json` is rejected with a manual-review diagnostic; no automatic move, overwrite or deletion is performed. Review possible prior source exposure and rotate affected credentials before migration. Public profile, setup-intent and issued-response metadata remain outside that secret subdirectory.
