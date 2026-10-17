# Wipstash gap-closure work

17 October 2026. This is implementation work on the Linux-tested cooperative prototype. The full product specification remains the target. Code, deterministic tests, native execution and deployed acceptance are separate milestones.

## Implemented boundaries

- **Command recovery:** durable pre-launch intent and generation invalidation; interrupted commands never replay. An uncertain workspace refuses new mutation until explicit writer-stopped acknowledgement. That acknowledgement does not prove detached processes stopped.
- **Adoption integrity:** captured bytes and executable mode bind installation; recovery verifies installed content and deleted paths. Detectable external changes fail closed.
- **Policy and repair:** validated policy and durable repair attempt/time reservations survive restart. Repair defaults to confined-or-unavailable; the explicit `trusted_unsandboxed` profile is for trusted development fixtures. Live bubblewrap execution was blocked by NETLINK_ROUTE restrictions; no live confinement claim follows from contract tests.
- **Public recovery v2:** published intent, public ownership, original queue eligibility/order, operation identity, replay metadata and policy identity are preserved. Restored execution remains fenced until explicit review, old-authority-stopped assertion, matching policy and exact sync binding. Private checkpoints/workspaces and executable policy are excluded. Legacy v1 recovery still needs review and republishing.
- **Storage:** bounded inputs, available-space preflight, object verification and explicit syncs; a separate conservative loose-object collector and storage admission service have 32 reported tests. This is not automatic checkpoint expiry, a full retention manager or a power-loss guarantee.
- **Client interface:** bounded MCP lifecycle, typed workflow tools, hostile-frame tests and client examples. Claude Code 2.1.302 completed an actual stdio handshake and tool discovery. Codex configuration parsing passed; model smoke was blocked by the read-only app-server environment. Neither result establishes model-driven collaboration or writer interception.
- **Native adapters:** lifecycle, IPC and credential-vault adapters exist. Windows GNU and macOS Darwin target cross-checks passed. Native runtime, filesystem, process containment and credential-store acceptance remain open.
- **Authenticated transport:** mTLS service/client code binds certificate identity to project/device ACLs, rechecks revocation and uses quarantined source admission. Durable replay, outbox retries and resumable upload code extend independent client/authority exchange. Security and transfer fixtures use in-memory adapters; no listening service or deployed LAN/WAN drill was run.
- **Asynchronous GitHub backup:** durable public-root replication library and worker/CLI integration exist alongside the local bare-Git backup path. Real remote authentication, namespace policy and fresh-host restore have not been established.

## Residual gates and evidence needed

| Gate | Remaining boundary | Required evidence or access |
|---|---|---|
| Real client workflows | Claude handshake/discovery and Codex parsing are narrower than model sessions | Actual Codex/Claude source workflows, disconnect recovery and verified writer coordination |
| Writer/process containment | External editors and detached descendants remain outside the cooperative contract | Native process-tree/job/lease acceptance and failure drills on each supported platform |
| Native macOS/Windows | Cross-check success is not native execution | Native compile/protocol/filesystem/process/vault suites on permitted runners |
| LAN/WAN hosting | Service and resumable transport code tested without a listener | Authorized deployment, certificate lifecycle/revocation, interrupted uploads and multi-machine failure drills |
| GitHub recovery | Local/injected tests do not establish real remote protection | Approved repository/namespace and credential flow, worker acceptance, fresh-host restore and explicit recovery activation |
| Confined model repair | Live sandbox execution unavailable; model workflow unverified | Permitted sandbox runner, actual model adapter and malicious-input tests |
| Capacity/retention | Conservative loose-object collection and preflight only | Complete root/pin coverage, native storage pressure, capacity and intentional loss-window acceptance |
| Power loss / disk loss | Syncs and process-crash fixtures are narrower than hardware failure | Authorized fault-capable environment and storage-failure/restore evidence |
| Performance | Coarse engine lock serializes core operations | Measured latency/backlog on target topology; no speedup over Git is claimed |

Checks on synchronized source remain empty by default. A clean merge is not a semantic correctness claim. Recovery activation depends on operator assertions; it is not authenticated distributed fencing.

## Reproduce and interpret results

Use the [test harness guide](../tests/README.md), [scope](SCOPE.md), [network contract](NETWORK.md) and [resumable transfer contract](RESUMABLE-TRANSFERS.md). Run the root suites and each separate component's tests against the exact revision being evaluated; a root `cargo test` alone does not certify every standalone service. Retain source/binary hashes, tool versions, commands and results locally when reporting a run.

Application-layer [WAN simulation](WAN-SIMULATION.md) injects delayed/faulted delivery. In-memory TLS tests exercise real cryptographic handshakes without binding a listener. Neither is a real two-device deployment. Scripted actors are not AI model sessions; cross-checks are not native runtime tests; process termination is not power loss. Intermediate passing results do not certify later edits or close the full product specification.
