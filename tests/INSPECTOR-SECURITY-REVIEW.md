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

## Browser validation and transport boundary

The real WASM browser suite **passed in authorized Ubuntu CI** for commit `6e5b651`, run `39081768039`. The retained browser report records 46 API requests, zero page exceptions or dialogs, and unchanged state/workspace manifests. The single HTTP 503 console error is the deliberately injected failure/retry case. Screenshots and the JSON report were retained as CI artifacts and reviewed by the parent task.

`tests/inspector_browser.py` intercepts every request: assets come from the built WASM bundle and API calls execute the service's in-memory CLI. Responses use the same production security headers, including CSP, as the service's HTTP adapter. External requests are aborted; no application listener is started. Passed assertions cover actual WASM workspace/history/file selection, private/shared separation, literal HTML/Unicode rendering, binary/truncation notices, split layout and wrap, failure/retry, keyboard help, theme, and mobile workspace/private/shared navigation.

The first mobile screenshot was captured before its final diff finished loading. Follow-up runner assertions now wait for a selected Unicode source diff, check that the mobile page has no horizontal overflow (internal code scrolling is allowed), and capture explicitly labelled synthetic dark/light previews. These additional visual assertions await a subsequent CI run; the first passing run does not establish their success.

**No browser was run successfully in the restricted cloud environment.** The parent's local Chromium launch encountered a denied socket operation; no retry or bypass was attempted. Browser execution occurred in authorized CI. The real TCP HTTP adapter was not exercised through a listener: this establishes WASM/UI behavior under production CSP with intercepted transport, not live-TCP end-to-end behavior. Service-owner parser unit tests and source review complement the in-memory route tests.

Example authorized-CI sequence (after building both binaries and the WASM bundle):

```sh
python3 tests/inspector_security.py --artifacts evidence/inspector/ci
python3 tests/inspector_browser.py --assets apps/inspector/dist --fixture evidence/inspector/ci/fixture.json
```

## Actual HTTP acceptance

[Run 39082914515](https://github.com/jimmystridh/wipstash/actions/runs/39082914515), commit `8f8d7041e71738d3a88de0e9da6f219a724b6bc6`, passed both transport modes in native GitHub CI:

- Intercepted browser run: 54 API requests, production security headers and unchanged state/workspaces.
- Actual loopback server run: 53 API requests, plus 19 direct HTTP admission/asset checks. Browser response checks found no header/status errors, page exceptions or dialogs. One 503 was deliberately injected to verify retry; all other same-origin browser traffic reached the owned HTTP server.
- The HTTP checks verified hostile Host/Origin/cross-site/POST rejection and exact HTML/WASM/JavaScript bytes and MIME types. Mobile controls, completed diffs, page-width bounds, keyboard behavior and labelled demo isolation passed.
- Startup, inspection and shutdown left persistent state and workspaces unchanged. Only the owned child server was stopped.

[Browser/HTTP evidence artifact](https://github.com/jimmystridh/wipstash/actions/runs/39082914515/artifacts/12119697702). This establishes the local loopback server/browser path on the CI runner, not remote hosting, real-device network deployment or an authenticated multi-user web service. Earlier local restrictions remain respected.
