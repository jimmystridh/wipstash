# Independent adversarial integration tests

Run from the repository root after building:

    cargo build
    python3 tests/adversarial.py

`--binary PATH` selects a binary; `--artifacts PATH` selects an evidence directory.

These tests launch real `wipstash` subprocesses against Git objects and persisted local state. The four actors are deterministic Python-scripted personas in distinct directories, with concurrent checkpoint and publication processes. They are **not** real Codex or Claude Code agent sessions, separate operating-system users, separate devices, or an authenticated network deployment.

The checked-in fixture matches the proposed adversarial fixture, with exact-byte hashes in `fixtures/manifest.json`. Synthetic excluded canaries are not real credentials. Tests retain every CLI request, response, exit status and timing, plus fixture/store state for diagnosis. No GitHub destination is configured.

Assertions cover disjoint concurrent proposals, same-line conflict quarantine and unrelated progress, immutable broken-source publication, no implicit adoption, sanitized public object reachability, operation identity binding/retries, stale generations, dirty adoption conflict, private/excluded file preservation, binary/CRLF/executable-bit round trips, and actual process termination at promotion/adoption failpoints.

A successful run establishes only the exercised local prototype behavior. It does not establish power-loss durability, storage-loss recovery, native macOS/Windows compatibility, authenticated remote isolation, arbitrary external writer containment, autonomous model conflict repair, or GitHub backup/restore. Fault hooks explicitly exit the process; they are not power failures. Retained-state restart is required before recovery assertions.
