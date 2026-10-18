# Native-agent MCP contention simulation

Run completed 18 October 2026. Source tree `9897467043aa3f86930a811bd08d3f9addb350ca`, published commit `5bb87a98eb360c86e01f6ae32ec911028bfc849a`; frozen binary SHA256 `17f406790e388a36791228012b1b3cdc1f0fd496e1d816b58ccee264dcaf3088`.

## Result

**Semantic failure followed by recovery. This was not an all-snapshot pass.** Four autonomous native model actors completed eight feature lineages through real stdio MCP. All eight features were correct in the final shared head, and every lineage ended integrated or superseded. One earlier integrated head was semantically wrong because a model submitted an incorrect conflict resolution while engine checks were off. The fixed independent oracle detected it. Coordinator feedback and an observer restart are retained as interventions, even though the coordinator never edited feature source.

This is model-driven MCP transport evidence. It is **not standalone Codex CLI or Claude Code product-client acceptance**.

## Workload and transport

Four isolated actors implemented two new functions each in billing, inventory, text processing and statistics. A deliberately single-line shared feature registry created contention. Actors checkpointed private synthetic history, published one coherent feature at a time, retained unselected live WIP, handled returned resolution tasks in separate public-snapshot checkouts, and continued with their second feature from the original private workspace. All first proposals were queued before integration began.

Every Wipstash operation used the compiled server's real stdin/stdout transport, with initialize, initialized notification, tools/list and tools/call frames, structured/text response agreement and graceful EOF. The workload bridge **pipelined those ordered startup frames without waiting for each startup response**. The server handled the messages sequentially, but the campaign does not prove a strictly sequenced client lifecycle. The bridge started a new MCP session per request. Models chose source edits and subsequent operations; they were not scripted coding personas. Automatic integration was a read/process loop using the generic MCP integration operation, not a model embedded in Wipstash.

There were 460 completed workload/observer/audit bridge sessions: 126 actor calls and 319 integration polls, with the remainder initialization, observer and audit calls. No long-lived product-client session is claimed. A separate post-workload smoke waited for the initialize reply before sending initialized, discovered the exact 12 current tools, performed three successful read-only tool calls in the same session, and exited by EOF. Its first attempt had a harness-only assertion expecting 13 tools and stopped at discovery; that expectation was corrected to the source-derived tool names, with no server change. These two separate smoke attempts are excluded from the 460-session count and do not replace the pipelined campaign evidence. No check/repair policy process, network listener, process-kill test, credentials or grants were created.

## Concrete failure

1. Billing's subtotal_cents integrated at `84066c4f95332b4a5888b58a37bff197b749a8aa` and passed the oracle.
2. The stats actor opened a median resolution against that exact head. The only conflict was registry.py. The current public registry advertised subtotal_cents.
3. The actor authored a registry containing median and slugify, dropping subtotal_cents and advertising slugify before its implementation existed. It ran the oracle, but its shell command continued after the failing check and checkpointed/submitted the bad source.
4. Resolution submission correctly bound the captured head and explicit conflict attestation. `head_advanced` was false. The accepted proposal was stats-median-submit-1, revision 1. It integrated **unchecked**, producing `af2dbd5bf8796099bd304e0a9718db2e591f0c83`.
5. The external oracle immediately failed the retained-feature requirement. This was an actor-authored semantic error, not evidence that the core substituted or silently overwrote different content.
6. The stats actor acknowledged its error independently. The coordinator then explicitly reported the lost feature, requested corrective work, and restarted its observer to retain failures while allowing remaining work to continue. The oracle and requirements stayed unchanged.
7. The text actor independently found the invalid public registry, added the real slugify function, restored subtotal_cents registration, preserved median, and submitted its normal isolated resolution. Subsequent accepted heads were valid; later features completed normally.

The failed public snapshot, exact relevant MCP request/response fields, oracle output and content hashes are retained. The failure record SHA256 is `c4b6e5088a61647adcb4adb6c67c6f68c6b15eb064d317e05214b611e096d0ed`. Recovery does not erase this failed observation. An unchecked clean integration cannot certify semantic correctness. External tests must be fail-closed before submission, or approved required checks must be configured to gate promotion.

## Verified outcomes

- 8 original publications; 8 integrated proposals and 7 superseded predecessors; no pending, quarantined or escalated lineages at completion.
- 12 isolated resolution opens, 7 accepted resolution submissions and 4 safe stale-resolution rejections. One additional unsubmitted checkout was abandoned after detecting the invalid public snapshot.
- All 8 integrated public heads were checked by the unchanged external oracle. Seven passed; one failed. The baseline also passed. Final head: `c0d520cc1c21b4da26ae5c2176b39b1a41f0f9ab`.
- All 8 final function contracts passed, including specified numeric, empty-input, invalid-input and no-input-mutation cases. This oracle is bounded to the synthetic requirements, not proof for arbitrary programs.
- All four original workspaces stayed at their initial adoption; their final live private canaries remained. 59 resolution-associated before/after manifest samples were unchanged.
- Four private historical checkpoint commits were absent from the public object store. All 40 public blobs, including unreachable intermediate objects, were scanned with no private canary found. No public-store alternates were present.
- Git fsck and SQLite integrity checks passed. No duplicate committed promotions occurred.
- Observer updates left live files unchanged. Explicit observer adoption installed the final public source while preserving its private file.
- Two deliberately withheld successful responses were recovered through operation_status: one actor checkpoint and the observer adoption. An exact adoption replay returned the same outcome. These were response-suppression injections with normal EOF, not crashes or network failures.

Elapsed first publication to last integration was 296.53 seconds. That interval includes model scheduling, coordination, the failed-head diagnosis and observer interruption. It is not a throughput benchmark.

## Product-runtime probe

Installed Codex CLI 0.159.2 recognized existing authentication but failed before model startup with `failed to initialize in-process app-server client: Read-only file system (os error 30)`. Supported no-daemon and ephemeral flags did not resolve it. Separately moving sqlite_home, log_dir and TMPDIR into writable scratch created runtime databases but left the same initialization error. A fresh fully writable CODEX_HOME reported no login. No authentication was copied, changed or provisioned; no denied session history was read. Claude Code was not found in PATH or checked existing writable prefixes.

The separate writable runtime settings follow the official [configuration reference](https://developers.openai.com/codex/config-reference) and [state-location documentation](https://developers.openai.com/codex/config-advanced). Actual Codex/Claude model-driven MCP workflows remain unverified.

## Evidence boundary

The campaign used local synthetic source and a frozen binary, fixture, requirements and oracle. It establishes the observed transport, conflict, stale-head, privacy, explicit-adoption and replay behavior, including a genuine negative semantic result. It does not establish production readiness, optimal change size, sustained fairness, saturation, arbitrary native-writer containment, configured check execution, remote transport or multi-platform product support. Raw model conversations and authentication state are not part of the report.
