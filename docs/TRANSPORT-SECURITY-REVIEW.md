# Transport and platform security review

Review date: 17 October 2026. Scope: `services/transport`, `crates/platform`, and the engine export/import call boundaries used by transport. This is a source review with offline tests, not a deployed-system penetration test or full-specification closure certificate.

## Verified controls and fixes

- Rustls requires a CA-valid client certificate; the service maps the leaf DER SHA-256 fingerprint to a local ACL. Headers cannot choose device, project, or role. Client authentication verifies CA, server name, and pinned authority certificate before sending HTTP requests.
- The ACL is refreshed before HTTP body allocation and again under the operation gate before engine work. Unknown, revoked, wrong-project, and wrong-role identities fail closed. ACL reads now check regular-file type and size before bounded reading; oversize files cannot allocate their full size. Symlink ACLs are rejected.
- Upload framing is length bounded, and payload length/digest plus device/project/authority/epoch/kind are checked before temporary files or imports. The engine remains responsible for strict manifest schema and Git object closure validation.
- Receipt creation now queries local proposal origin and verifies ownership before export. The integration regression asserts that denied receipt creation leaves export history unchanged. Retained export reconstructs existing records without reserving another event; recipient checks prevent returning another device's receipt. History exposes heads only.
- Network operation IDs are namespaced by authenticated device. Replays reconstruct retained bytes; different kind/proposal under the same identifier is rejected. Workstation uploads verify local project/authority/epoch and proposal identity. Downloads verify pinned remote binding and the requested kind/proposal before import.
- Workstation engine/state/staging paths must be absolute, and local binding identifiers and epoch are checked before engine execution. Engine invocation does not use a shell or accept a remote executable/state/path.
- Normal transport staging uses unique temporary directories. Cleanup follows scope exit, including errors. Bounded export reads reject symlinks and nonregular files. Deployment must still protect staging and state from same-account writers and configure Windows ACLs appropriately; random names alone do not establish an OS security boundary.
- Remote failures return a generic rejection, and engine stderr is discarded rather than sent to peers. Head source contents are intentionally shared within the authorized project. No vault lookup occurs in these tests.
- Client connection-driver tasks now have an abort-on-drop guard, so request cancellation cannot deliberately detach the driver. A stalled-response regression uses TLS over an in-memory duplex stream and verifies connection closure after cancellation. This is defensive lifecycle ownership; the test does not establish that every prior Hyper cancellation path leaked.
- Native vault secrets redact Debug output and zeroize owned buffers. No plaintext fallback or provisioning is implemented. Linux rejects ambiguous matches; macOS was changed from first-match selection to all-match cardinality checking and also rejects ambiguity. This macOS FFI change requires native validation.

## Actual bounds

| Resource | Current bound |
|---|---|
| Manifest | 16 KiB |
| Raw object payload | 8 MiB |
| Export control body | 4 KiB, checked after general HTTP body accumulation |
| ACL file | 1 MiB, checked before and during reading |
| Engine stdout / HTTP client response | 16 MiB |
| Server connection slots | 32 in `serve` |
| HTTP parser buffer | 32 KiB |
| TLS handshake | 10 seconds in server stream adapter |
| HTTP operation | 90 seconds in HTTP adapter |
| Server connection / outbound request | 120 seconds in network adapters |
| Engine invocation | 60 seconds |
| Concurrent service engine operations | One per Service instance |

These are per-operation and per-instance limits. The public stream and route test adapters do not independently impose every outer network timeout/concurrency limit. Explicit callers must preserve those wrappers. Neither a maximum individual transfer nor an output cap bounds total durable storage, total operations, engine-internal memory, or all subprocess descendants.

## Open production gates

1. **Aggregate quotas and fairness:** an authorized client can create arbitrarily many distinct export IDs/proposals. There is no persistent per-peer rate/byte/event quota or state reservation. Export history is unpaginated and eventually exceeds bounded stdout, blocking history and replay lookup. Multiple Service processes bypass the in-memory operation gate. Do not describe this as DoS-complete.
2. **Subprocess-tree drain:** transport kills its engine child on cancellation but does not establish descendant-tree emptiness. Git descendants can outlive the root. Durable interrupted-operation fencing must remain in force. Unix platform process groups explicitly offer cooperative cleanup only; detached descendants and controller-crash cleanup are not contained. Windows job source has creation-time association, no breakaway allowance, and empty-job checking, but native failure evidence is outstanding.
3. **Native IPC and vault validation:** Unix credentials and Windows pipe SID adapters describe already-connected endpoints; they do not create owner-restricted endpoints. Native macOS/Windows tests, Windows ACL behavior, locked/ambiguous credential stores, and process failure drills remain release gates.
4. **Local trust/configuration:** operator-owned engine, state, staging, TLS files, and ACL must be protected. File metadata/open checks are not a defense against a malicious same-account writer racing filesystem access. The engine child inherits the service environment; isolate the service account and avoid unrelated secrets there.
5. **Deployment evidence:** no listener, real LAN/WAN deployment, CA provisioning, certificate rotation, production disk-pressure test, or power-loss test was run here. Per-request revocation assumes the local ACL has been updated securely.

## Recommended minimally safe admission design

Implement configurable, fail-closed limits without automatic deletion:

- Authenticate and refresh revocation before buffering bodies (implemented). Apply endpoint-specific declared and streaming byte caps before accepting body bytes; export control should use 4 KiB at the HTTP layer rather than the general wire bound.
- Maintain token buckets keyed by authenticated device, with explicit burst and refill configuration and a bounded map derived from the ACL. Charge before buffering and before spawning the engine, including failed authenticated requests. Unknown identities must not allocate buckets. A restart-reset bucket is only a local burst control, not a durable abuse quota; document that distinction.
- Configure hard retained-event/proposal/byte caps and a minimum free-space reserve. Reserve estimated worst-case bytes/events transactionally in the authoritative engine database before admitting a new operation. Release reservations on proven completion/recovery only. Retries of an already-reserved operation must be recognized without consuming another event or quota. Reject rather than delete when exhausted.
- Enforce the same persistent caps for every process and local mutation entry point. A transport-only directory scan or preflight free-space check races other writers and is not a complete quota. Add bounded indexed operation lookup and paginated history so reaching a cap does not prevent replay/recovery.
- Keep limits operator-configured and test low-cap fixtures for rejected-before-spawn behavior, restart persistence, simultaneous processes, exact retry, and disk-pressure recovery. Numeric production defaults require workload/retention requirements; they are not inferred by this review.

## Test evidence

`services/transport/tests/security.rs` exercises real Rustls/HTTP over in-memory duplex streams plus actual local engine fixtures: wrong CA/name/pin/identity, absent client certificate, plaintext rejection, hostile identity headers, reused-session revocation, bounds, proposal replay, receipt ownership and denied-mutation history stability.

`services/transport/tests/review_boundaries.rs` independently covers binding dimensions, malformed framing, payload boundary edges, exact certificate mapping, pre-spawn configuration rejection, bounded ACL rejection, and canceled TLS-driver lifetime. These tests do not bind sockets or read real credentials. Run:

```
CARGO_HOME=/workspace/shared/.cargo RUSTUP_HOME=/workspace/shared/.rustup PATH=/workspace/shared/.cargo/bin:$PATH cargo test --manifest-path services/transport/Cargo.toml --locked --offline
```

Review fixes should be included in final whole-project testing and native CI before release claims are updated.
