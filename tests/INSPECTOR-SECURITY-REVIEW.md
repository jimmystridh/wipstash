# Inspector independent security review

## Executed locally

- `python3 tests/inspector_security.py --artifacts evidence/inspector/independent-final`: **99 in-memory API/security requests passed**.
- `rustc --edition=2021 --test tests/inspector_diff.rs -o /tmp/wipstash-inspector-independent-diff && /tmp/wipstash-inspector-independent-diff`: **9 parser tests passed** (three independent adversarial cases plus six frontend parser tests).
- Python test scripts pass `py_compile`.

The API fixture is generated exclusively through the real Wipstash core CLI. It contains four isolated scripted workspaces, six private checkpoints, four proposals, three committed integrations, and one quarantined conflicting proposal. It retains an older private-only broken checkpoint, a newer unpublished checkpoint, and unsaved live workspace bytes. Unicode and HTML-like source content/intent, a binary file, and a roughly 2.5 MB text file are included. Core portable-path validation forbids Unicode/HTML-like filenames, so these are not falsely presented as core-generated supported names.

Coverage:

- Private checkpoint history stays distinct from shared proposals/integrations; unpublished content is absent from shared changes.
- Conflicting proposals remain explicitly quarantined and inspectable.
- Pagination, workspace filtering (including empty/all), stale IDs, changed-file selection, binary handling, and bounded/truncated huge text.
- SQL/revision/option injection strings, path traversal and Git pathspec magic; poisoned stored OIDs fail closed.
- Exact Host and Origin checks, cross-site rejection, all non-GET methods rejected, no wildcard CORS.
- Static traversal, encoded traversal, query/fragment ambiguity, and symlink escapes rejected.
- Shared proposals remain inspectable without original local repositories; private entries fail closed when their own store is unavailable.
- Every original state file and live workspace file retains identical bytes and mode after inspection. Missing state is not initialized; empty/incomplete state is not repaired.
- A separate real four-workspace fixture is crashed during adoption. Inspection leaves both the interrupted journal and partially applied live workspace unchanged; no rollback/recovery runs.

Retained evidence is generated under the requested artifact directory: `fixture.json`, `fixture-commands.json`, `commands.json`, and `security-results.json`. It is local, ignored evidence, not required to be committed.

## Issues found and corrected by implementation owners

1. Multi-file unified diff headers inherited hunk state and were misclassified as changes. Reset at file boundaries; independently verified.
2. Extreme hunk indices could overflow. Saturating arithmetic; independently verified.
3. Public proposal inspection selected original local storage unconditionally. Prefer public objects, retain local fallback for offline proposals; independently verified with local stores unavailable.
4. The UI sent an empty workspace filter for All workspaces while the API treated it as an exact empty ID. API now normalizes empty to no filter; independently verified.

## Browser validation boundary

`tests/inspector_browser.py` is prepared for an environment where Chromium launch is permitted. It intercepts every request: assets come from the local WASM bundle and API calls execute the service's in-memory CLI. External requests are aborted; no application listener is started. Planned assertions cover actual WASM workspace/history/file selection, private/shared separation, literal HTML/Unicode rendering, binary/truncation notices, split/unified/wrap, failure/retry, keyboard help, theme, and mobile screenshots.

**This browser script has not been executed in the restricted cloud environment.** The parent's Chromium launch encountered a denied socket operation, and no retry or bypass was attempted. There is no claim of local visual QA or browser interaction success. The real TCP HTTP adapter was not exercised through a listener either; service-owner parser unit tests and source review complement the in-memory route tests. Run browser/transport checks in an authorized CI or desktop environment before claiming end-to-end browser validation.

Example authorized-CI sequence (after building both binaries and the WASM bundle):

```sh
python3 tests/inspector_security.py --artifacts evidence/inspector/ci
python3 tests/inspector_browser.py --assets apps/inspector/dist --fixture evidence/inspector/ci/fixture.json
```
