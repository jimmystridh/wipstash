# Wipstash gap-closure work

Updated 18 October 2026. This is implementation work on the cooperative prototype with selected native cross-platform and actual loopback TLS evidence. The full product specification remains the target. Code, deterministic tests, native execution and deployed acceptance are separate milestones.

## Implemented boundaries

- **Command recovery:** durable pre-launch intent and generation invalidation; interrupted commands never replay. An uncertain workspace refuses new mutation until explicit writer-stopped acknowledgement. That acknowledgement does not prove detached processes stopped.
- **Adoption integrity:** captured bytes and executable mode bind installation; recovery verifies installed content and deleted paths. Detectable external changes fail closed.
- **Policy and repair:** validated policy and durable repair attempt/time reservations survive restart. Repair defaults to confined-or-unavailable; the explicit `trusted_unsandboxed` profile is for trusted development fixtures. Live bubblewrap execution was blocked by NETLINK_ROUTE restrictions; no live confinement claim follows from contract tests.
- **Public recovery v2:** published intent, public ownership, original queue eligibility/order, operation identity, replay metadata and policy identity are preserved. Restored execution remains fenced until explicit review, old-authority-stopped assertion, matching policy and exact sync binding. Private checkpoints/workspaces and executable policy are excluded. Legacy v1 recovery still needs review and republishing.
- **Storage:** bounded inputs, available-space preflight, object verification and explicit syncs; a separate conservative loose-object collector and storage admission service have 32 reported tests. This is not automatic checkpoint expiry, a full retention manager or a power-loss guarantee.
- **Client interface:** bounded MCP lifecycle, typed workflow tools, hostile-frame tests and client examples. Claude Code 2.1.302 completed an actual stdio handshake and tool discovery. Codex configuration parsing passed; model smoke was blocked by the read-only app-server environment. Neither result establishes model-driven collaboration or writer interception.
- **Native adapters:** lifecycle, IPC and credential-vault adapters exist. Earlier Windows GNU/macOS Darwin cross-checks were followed by passing native Linux/macOS/Windows CI contracts. Full Windows adoption, broader filesystem behavior, arbitrary process containment and real credential-store acceptance remain open.
- **Authenticated transport:** mTLS service/client code binds certificate identity to project/device ACLs, rechecks revocation and uses quarantined source admission. Durable replay, outbox retries and resumable upload code extend independent client/authority exchange. In-memory security/transfer contracts are now supplemented by actual native-CI loopback listeners and four scripted device identities exercising guided pairing, managed SQLite authorization, revocation, rotation and server restart. The separate real-TLS upload-fault campaign is still awaiting a successful corrected run; deployed multi-host LAN/WAN remains unverified.
- **Asynchronous GitHub backup:** durable public-root replication library and worker/CLI integration exist alongside the local bare-Git backup path. Real remote authentication, namespace policy and fresh-host restore have not been established.

## Residual gates and evidence needed

| Gate | Remaining boundary | Required evidence or access |
|---|---|---|
| Real client workflows | Claude handshake/discovery and Codex parsing are narrower than model sessions | Actual Codex/Claude source workflows, disconnect recovery and verified writer coordination |
| Writer/process containment | External editors and detached descendants remain outside the cooperative contract | Native process-tree/job/lease acceptance and failure drills on each supported platform |
| Native macOS/Windows | Selected native CI contracts passed; not complete platform acceptance | Full Windows adoption and filesystem hazards, arbitrary writer/process containment, real vault retrieval and installer acceptance |
| LAN/WAN hosting | Guided pairing and device lifecycle passed over real loopback TLS; no deployed multi-host drill | Corrected real-TLS upload-fault campaign, authorized multi-host deployment, quotas, supervision and network failure drills |
| GitHub recovery | Local/injected tests do not establish real remote protection | Approved repository/namespace and credential flow, worker acceptance, fresh-host restore and explicit recovery activation |
| Confined model repair | Live sandbox execution unavailable; model workflow unverified | Permitted sandbox runner, actual model adapter and malicious-input tests |
| Capacity/retention | Conservative loose-object collection and preflight only | Complete root/pin coverage, native storage pressure, capacity and intentional loss-window acceptance |
| Power loss / disk loss | Syncs and process-crash fixtures are narrower than hardware failure | Authorized fault-capable environment and storage-failure/restore evidence |
| Performance | Coarse engine lock serializes core operations | Measured latency/backlog on target topology; no speedup over Git is claimed |

Checks on synchronized source remain empty by default. A clean merge is not a semantic correctness claim. Recovery activation depends on operator assertions; it is not authenticated distributed fencing.

## Reproduce and interpret results

Use the [test harness guide](../tests/README.md), [scope](SCOPE.md), [network contract](NETWORK.md) and [resumable transfer contract](RESUMABLE-TRANSFERS.md). Run the root suites and each separate component's tests against the exact revision being evaluated; a root `cargo test` alone does not certify every standalone service. Retain source/binary hashes, tool versions, commands and results locally when reporting a run.

Application-layer [WAN simulation](WAN-SIMULATION.md) injects delayed/faulted delivery. In-memory TLS tests exercise real cryptographic handshakes without binding a listener. Neither is a real two-device deployment. Separate guided-pairing CI does bind actual loopback listeners; four device identities on one runner still do not constitute four physical hosts. Scripted actors are not AI model sessions; cross-checks are not native runtime tests; process termination is not power loss. Intermediate passing results do not certify later edits or close the full product specification.


## Feature checkpoint and unfinished release gate

Checkpoint `42a40025b4d8c3d6b0bfd7bd6b59a597562d5735` passed native Linux/macOS/Windows, the four-device CLI loopback setup/join/revoke/rotate/restart scenario, 53 browser interception tests, 53 real-HTTP browser tests and strict Clippy. Subsequent enrollment response-bound checks also passed. Earlier “no native runtime” and “no listening service” statements are superseded by these selected-contract results.

Guided setup is documented in [PAIRING.md](PAIRING.md). It uses isolated TLS enrollment, a managed SQLite authorization store and protected current-account files. Legacy file ACL configuration remains supported. Publication and adoption remain explicit. Test credentials are synthetic; no real credential vault or external account was provisioned.

Final CI remains pending: feature revision `e9afab` encountered a Unix fixture-permission failure being corrected. The reconstructed real-TLS upload-fault campaign compiled but hit a fixture `sequence_gap`; it must pass after correction before being cited as acceptance evidence. Main remains `112f8e7` until final green. These are revision-specific checkpoints, not a claim that current source or the full original product specification is production-ready.
