# Sustained genuine-native-agent benchmark

This harness instruments four independently reasoning native coding agents, each implementing eight frozen domain features. It never implements features, supplies conflict resolutions, orchestrates publication turns, or decides when a native actor should publish. Every actor authors Python code and tests, invokes the CLI, follows its own proposal, resolves current-head conflicts, and opens its own next wave.

## Fixed boundaries

- Frozen SPEC.md before an independently authored oracle; oracle hash in oracle-frozen.json.
- Core SHA256 ded60ad5c3a533d01cf646228f03f38e7e3aa5b45941da115f5e6429233d9a51.
- Automatic integrate(max_proposals=1) starts every 350 ms, subject to ordinary command completion.
- 45-minute active upper bound plus 5-minute drain. Finish earlier only after all four actors are terminal and accepted queue empty. Unfinished quarantined/escalated work is retained, never disguised by republishing.
- One new original workspace per feature and separate resolution workspace per head attempt.
- Post-publication private checkpoint and additional unsaved WIP are sealed and hash-recorded; never adopted/reset. Marker contents are synthetic.
- Core policy/check runner remains unconfigured. Author tests and independent semantic oracle are different evidence.
- No sockets/listeners, provider credentials, command_run, process termination, fault injection, webhook delivery, or external publication.
- Resolution lineage maximum is three submitted revisions. Stale opens/submits are logged separately and do not silently reset lineage.

## Components

actor_api.py wraps a single explicit CLI request, author test invocation, private seal, or status write. It has no implementation or resolution loop. coordinator.py calls only integrate and reads a locked SQLite snapshot. The standalone observer binary uses the actual product Source implementation, polls at 20 ms, verifies stable unique projected IDs, privacy, current status, and no historical replay after restart. Observer source is adapted from the existing observe_pressure example with a 50-minute upper bound; product source is unchanged. analyze.py is read-only and computes observed metrics, replays durable journal order for exact queue depth, and scans every public Git blob plus public ref tree for private markers/paths. It verifies original report/private-file hashes and absence of unpublished private checkpoint OIDs in the public object store.

## Interpretation

Queue-age lower bound is publication response-return time to integration call start, clamped at zero when calls overlap under the core writer lock. The conservative upper bound spans publication request start through integration call return, including lock and service overhead. Internal admission/service timestamps were not instrumented, so exact queue residence is not claimed. Report accepted-to-outcome latency and operation duration too. End-to-end feature time starts at workspace-open request; root-publication-to-integration includes native-agent reasoning/editing/test time and stale reopens.

Accepted publications include initial features and resolution revisions. Quarantines are conflict outcomes, not final permanent failures. Final completed features, uncompleted features, exhausted lineages, and failed RPCs are separate. A missing-proposal query after a stale submission is an actor protocol error, not a SQLite IOERR.

A measured queue peak of one is not saturation, even with four simultaneous unfinished feature lineages. All 32 completed features would demonstrate no observed starvation in this bounded workload, not a general fairness guarantee. One fixed-order run has no randomized matched batch comparator and cannot establish optimal checkpoint or publication size. These are native model agents, not standalone Codex CLI or Claude Code product sessions. Event evidence is Source projection, not the webhook-to-ChatGPT chain.

## Administrative setup limitation

The first actor launched at13:59:39UTC. The fourth launch initially hit the seven-agent-slot limit because a previous campaign actor remained active; the parent interrupted that old actor, and D launched at14:00:45UTC. This administrative intervention/launch skew is recorded separately from integration/conflict rescues. The automatic coordinator was never paused for it, and the earlier actors proceeded independently.
