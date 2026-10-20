# Cloud Run hosting

Cloud Run is an additional authority backend. The standalone `wip` CLI supports this backend and the existing native mTLS coordinator. Every agent retains an owned local directory and client state; source sharing, coordination and audit delivery use the server. This backend is intended for a trusted, small demo rather than an untrusted multi-tenant service.

## Durable state

The container uses a private, temporary working copy of the authority. The authoritative copy is a private Cloud Storage bucket, accessed through its object API rather than a mounted filesystem.

Every completed transport operation snapshots the SQLite databases through their backup API, captures the stable Git and transfer files, uploads SHA-256 content-addressed chunks and a manifest, then conditionally publishes the manifest reference using the control object's generation. Responses are released only after publication. Interrupted uploads cannot change the last acknowledged root. Temporary check directories and OS locks are excluded; public history, operation records, transfer offsets, coordination, replay protection and the private audit are included.

Each container acquires a generation-fenced ownership record. Automatically numbered Cloud Run revisions advance a durable minimum revision. A newer revision may atomically take ownership of the last acknowledged root; a retired revision cannot reclaim it after a restart. Instances of the same revision respect the live owner’s lease, with recovery after its 90-second expiry. The older instance cannot publish afterward and becomes unavailable. Keep automatic revision names enabled; rolling back requires deploying the older image as a new revision. Instance limits reduce overlap but are not the fencing mechanism. Concurrent authoritative mutations are serialized; checks run against a separate disposable copy of the Git repository outside that transaction. Validation claim and completion are separately durable. This remains one writable authority, not a horizontally scaled merge engine.

The first deployment can use Init's explicit `public_history` option with a verified sanitized backup and an exactly matching source tree. It preserves the selected public commit and its reachable history while starting a separate authority's coordination ledger. The supplied backup also retains its original public recovery metadata. This is not a zero-loss migration of active private workspaces or pending operations. Keep the existing authority and private WIP until a deliberate client transition; do not repoint old bindings.

## Authentication

Cloud Run terminates external HTTPS. In this explicit mode, clients verify Google's normal HTTPS certificate chain and sign each application request using their P-256 device private key. The proof binds the exact configured service origin, method, route, body checksum, timestamp and a fresh nonce. The server verifies the signature against the exact certificate fingerprint in its operator-controlled ACL, checks expiry and revocation, and durably consumes nonces. Transport identity never comes from a caller-supplied device name or forwarding header.

TLS certificate pinning and client-certificate authentication remain mandatory in the existing native transport. They are not silently disabled or reused as a claim about HTTPS mode. Cloud credentials are provisioned through private operator-generated profiles; native guided mTLS enrollment is a separate mode. An operator changes the cloud ACL through a reviewed durable checkpoint and revision handoff. Cloud Run IAM controls deployment and bucket access; application proof is required even if the HTTPS service accepts unauthenticated platform requests.

## Build and provision

The Python service is in `services/cloudrun`, with dependencies pinned by `uv.lock`. Build the Linux engine and transport using its Dockerfile and Cloud Build configuration. Both Rust lockfiles are required. Upload reviewed source only; credentials and private project state do not belong in the build context or image.

Create a dedicated bucket with uniform bucket access, public access prevention and versioning, plus a dedicated runtime service account whose storage role is scoped to that bucket. Do not attach project-wide administrative credentials. The runtime still executes operator-configured checks without an OS security sandbox; use trusted source only.

Run `prepare.py` with a fresh private directory, verified public backup, exact HTTPS endpoint and local engine binary. It creates separate device keys/profiles and the initial seed, without replacing existing credentials. Publish the seed using `durable.Checkpoints`, retaining its receipt, then release preparation ownership before starting Cloud Run.

Deploy with 2 vCPU, 4 GiB RAM, instance-based CPU allocation, manual scaling of one and a per-revision maximum of one, and bounded request concurrency. Set:

- `WIPSTASH_BUCKET`: the private authority bucket.
- `WIPSTASH_AUDIENCE`: the exact HTTPS origin clients sign.
- `WIPSTASH_ROOT`: the same absolute directory used by the prepared service configuration.

Use `/health` for startup and liveness probes. It exposes readiness only. Never make database objects or detailed inspector output public.

Import each provisioned profile with `wip remote add NAME --config ABS_CLIENT_JSON`, then `wip clone NAME DIRECTORY`. Each clone has independent workspace ownership. Direct delivery, coordination, receipts and audit run inside connected CLI commands. A pending Commit is not shared until an authority receipt confirms it. No workstation service or MCP registration is needed.

## Standalone CLI acceptance

The current authority runs revision `wipstash-demo-00009-fkd`. Four authenticated CLI identities passed isolated clone, direct sharing, offline recovery, coordination, exact-head validation and central audit acceptance. See [the dated report and measured latency](CLI-VALIDATION.md). Earlier MCP measurements below are historical.

## Acceptance and operation

Run `uv run --directory services/cloudrun python -m unittest -v test_cloudrun`, the core tests, and the transport tests. Hosted acceptance must also cover four device identities, a shared commit and receipt, background checks, unknown/revoked/forged/replayed requests, deployment during activity and recovery into a fresh container. Record measured timing rather than inferring performance from CPU size.

Cloud Run logs contain operation paths, credential fingerprints, elapsed time and checkpoint hashes, not source bodies or private keys. The private audit and state are in the bucket. Preserve the last published manifest, its chunks and the control object together. Object versioning is recovery assistance, not tested disaster recovery by itself. Do not age-delete content objects still referenced by retained manifests.

Use a stable service account, bucket and signed origin across revisions. Deploying a different origin requires an explicit client configuration change. Stop client workers before retiring a device or changing its binding. Deleting Cloud Run does not delete the bucket; preserve a reviewed final checkpoint before any cleanup.

## Local agents using the hosted demo

The provisioned demo keeps four private device profiles, imported as `cloud-codex`, `cloud-opencode`, `cloud-claude` and `cloud-pi`.

```sh
wip clone cloud-codex ./codex-work
wip clone cloud-opencode ./opencode-work
wip clone cloud-claude ./claude-work
wip clone cloud-pi ./pi-work
```

Start the corresponding coding agent normally inside each directory. Each Clone creates a unique workspace ID, including additional sessions of the same client. Existing registered directories are preserved with `wip attach`, retaining their original authority and pending operations. Source-control MCP, `wipstash-cloud`, and resident workstation workers/collectors are retired. Source editing remains local; the CLI exchanges source, receipts, coordination and audit over signed HTTPS. Native activity outside the CLI can be imported explicitly.

The demo uses a private bucket and a separate authority ledger seeded from the local demo’s public history. The local demo’s GitHub backup remains separate; cloud commits are not automatically mirrored there. A Cloud Task scales the service to zero on Friday, 2026-10-23 at 23:59 Europe/Stockholm, preserving the bucket. Renew the hosting period deliberately before resuming after that deadline.

## Initial hosting acceptance, before the CLI migration

The deployed Stockholm demo uses 2 vCPU, 4 GiB and one continuously allocated instance. Its four device identities were exercised through real native CLI/protocol clients; no model-driven agent sessions were started for acceptance.

- Native core tests passed (188 main cases plus auxiliary suites); the additional corrupt-destination regression passed. Transport library tests (79) and all 11 native mTLS security cases passed. The final receipt regression and strict core/transport Clippy checks passed.
- Four independent local stdio MCP connections discovered 27 tools and returned metadata Status in 14–15 ms. Warm authenticated cloud catch-up took 0.9–2.4 seconds with all four profiles active. A fresh client imported public history in 11.8 seconds. On the final revision, four simultaneous warm catch-ups took 2.3–4.3 seconds; calls immediately after replacement took 12.8–15.3 seconds. Local metadata latency does not describe remote catch-up latency.
- A source-preserving Commit was delivered with its retained operation ID, then confirmed by an authority receipt as `already_included`. Commit Status explicitly reports `shared: true` after receipt import. Its first full-history upload took 40.1 seconds; this is not a claim that remote sharing completes in metadata-call time.
- The server passed 88 Python tests, JavaScript syntax validation and seven JavaScript behavior tests for the exact demo head `3e01befb2bb1f221227d14d5b6e5be2a63a072e5`. A native gateway test completed a foreground RPC in 462 ms while a three-second check ran separately.
- A real revision replacement recovered into a fresh container. An independent read-only restore took 22.7 seconds, preserved the exact demo source tree and nonce records, and verified 1,272 audit-chain records. It neither acquired ownership nor published state.
- Live authenticated requests succeeded; an exact replay returned 409, and altered or missing proofs returned 403. Four supervised workers and four collectors delivered audit records with fresh collection health.
- Private Cloud Storage archives preserve the implementation source and an online backup of the original local demo’s audit. Active local workspaces and their authority bindings remain intact. The scheduled Friday stop was retained, and the expiry identity successfully exercised the Cloud Run update API with a harmless keep-running request.

The MCP and resident-client measurements above are historical evidence from the initial hosting deployment; they do not describe the current CLI interface. These measurements cover this small trusted demo and its history. Large repositories, sustained contention, multi-instance writable scaling and sandboxing hostile check commands remain outside this acceptance.
