# Strict sequential MCP follow-on simulation

Completed 18 October 2026. Same frozen production binary and source tree as the earlier native-agent campaign; new synthetic source/state/workspaces. Published source commit `5bb87a98eb360c86e01f6ae32ec911028bfc849a`; binary SHA256 `17f406790e388a36791228012b1b3cdc1f0fd496e1d816b58ccee264dcaf3088`.

## Result and scope

**PASS: all eight integrated heads and final eight-feature state pass the fixed oracle.** Four genuine autonomous native model actors completed all eight feature lineages over the actual compiled Wipstash stdio MCP server, using a bridge that waited for each initialization, discovery and tool-call response before continuing. Final head: `fe4e1e9ddf5d1c1eeb51c733db84bb7dccea2c8e`.

This is a separate, non-independent follow-on campaign. The same actors deliberately reused prior implementations and knew the earlier oracle failure. Their instructions now explicitly required fail-fast tests before selected public checkpoints/submissions. The original campaign and its failed public head remain unchanged: a later pass does not erase that failure, establish causation for the improvement, or permit a speed comparison.

This is **not a standalone Codex CLI or Claude Code model session**. The authenticated Codex runtime remained blocked before startup; separate writable runtime paths did not fix it, and a fresh writable home had no login. No authentication was copied or provisioned. The earlier report retains the exact runtime findings.

## Actual transport sequence

For each of 495 sessions, the bridge:

1. Started the real Wipstash executable with stdio pipes.
2. Sent initialize and awaited the matching response, including protocol revision 2025-11-25.
3. Sent initialized notification, then tools/list, and awaited the matching tool-list response.
4. Sent the model-selected typed tool call, or the generic tool for initialization/integration, and awaited the matching result.
5. Verified text and structured results agreed and the tool error flag matched the engine outcome, then closed stdin and verified successful EOF exit.

All 495 recorded send/receive sequences matched that order; discovery returned the 12 tools present in the frozen source. The bridge source SHA256 is `1c9fc76deb5f2734ad5c506ccaf1631053b81e912ae71ad4276b115db16a89b9` and was unchanged during the run. Models authored/reconciled source and selected operations themselves; they were not deterministic scripted feature authors. There were 129 actor calls and 351 integration polls, plus fixture initialization, observer and audit calls. Each request used a separate server process, so no persistent product-client connection or full MCP specification certification is implied.

## Workload and findings

The four actors implemented billing, inventory, text-processing and statistics functions, two features each, with one coherent feature per initial publication. A single-line feature registry forced conflicts. All actors began from the same new baseline and all first publications were queued before integration. Native edits stopped before checkpointing. Conflicts were returned through actual MCP responses and resolved only in new public-snapshot checkouts. Actors continued their second feature in their original private workspaces without adopting/resetting them.

- 8 original publications; 8 integrated proposals and 7 superseded predecessors. No unresolved lineages remained.
- 14 isolated resolution opens, 7 accepted replacement submissions and 7 safely rejected stale submissions. Submitted-revision bounds were retained. Compatible advanced-head admissions observed: 0; this arm does not supply a positive test of that separate branch.
- The frozen external oracle checked all 8 integrated public heads plus the baseline. Failed integrated heads: 0. Previously accepted feature contracts remained required at every subsequent head. Final source passed all eight bounded function contracts.
- All four original live-WIP canaries remained; 70 resolution-associated before/after manifest samples were unchanged. Four private historical checkpoint commits were absent from public storage; all 40 public blobs, including unreachable objects, were clear of private canaries.
- Git object integrity and SQLite integrity passed. No duplicate committed promotions were found.
- Observer updates did not change live files. Explicit observer adoption installed the final public source and preserved its private file.
- Two intentionally withheld successful responses, one checkpoint and one adoption, were recovered through operation_status. Exact adoption replay returned the same result. Processes ended by normal EOF; this was not a crash or network-fault test.

No coordinator source fixes, mid-campaign semantic feedback, observer restart or engine-policy changes were needed in this follow-on run. Two actors initially applied the public privacy oracle to deliberately private canary setup; its expected canary rejection stopped their shell before publication. They corrected their fixture workflow themselves. Those local setup mistakes were not accepted public semantic failures.

Elapsed first publication to final integration was 275.78 seconds, including actor scheduling. Reuse, learned feedback, ordering and startup differences prevent performance comparisons with the earlier campaign.

## What the results do not prove

Engine required checks remained off. The unchanged external oracle observed accepted heads; it was not an engine promotion gate. A valid textual merge and exact head/conflict attestation do not prove feature semantics, as the preserved earlier failure demonstrated. This follow-on success does not establish production readiness, configured check execution, general code correctness, saturation, sustained fairness, optimal publication size, arbitrary native-writer containment, remote operation, cross-platform acceptance, or actual Codex/Claude product-client support.

Raw model conversations, private workspace contents and authentication state are not published. The sanitized summary and provenance retain binary/source, fixture, oracle, requirements, bridge and report hashes. The earlier failed campaign remains a distinct evidence item.
