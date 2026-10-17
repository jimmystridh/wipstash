# Native platform implementation and verification

This document records implementation boundaries, not a release certification.
Verification below was performed on a Linux cloud executor on 2026-10-17.
Cross-compilation checks Rust types and target-specific API bindings; it does not
exercise Windows or macOS kernels, credentials, permissions, linking, or installers.

## Current support

| Component | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Trusted policy/check command execution | Native process group | Native process group | Native Job Object |
| Concurrent bounded stdout/stderr capture | Implemented | Implemented | Implemented; explicit handle-inheritance allowlist |
| Process identity retained until cleanup | `waitid(WNOWAIT)` | `waitid(WNOWAIT)` | Owned process handle |
| Detached-descendant containment | **Not guaranteed** | **Not guaranteed** | Job membership; no breakaway flags |
| Controller crash cleanup | **Not guaranteed** | **Not guaranteed** | Kill-on-job-close |
| Verified whole-session drain evidence | **Unavailable** | **Unavailable** | Job query must observe zero active processes |
| Filesystem/network confinement in platform runner | **Unavailable** | **Unavailable** | **Unavailable** |
| Default confined repair | Separate Linux bubblewrap backend; fail closed if unavailable | **Unavailable, fail closed** | **Unavailable, fail closed** |
| Native credential retrieval | libsecret adapter | Keychain adapter | Credential Manager adapter |
| Local IPC peer identity primitive | Kernel UID | Kernel UID | Named-pipe impersonated SID |

The platform credential adapters are read-only and require separately provisioned
credentials. They do not provision, prompt, or fall back to plaintext. The IPC
identity primitive is not itself an authenticated daemon endpoint. Endpoint DACLs,
remote-client rejection, request framing, and authorization remain caller concerns.

## Core command integration

`src/policy.rs` uses `wipstash-platform` for trusted checks and the explicitly
unsafe development repair profile. Windows commands require an absolute native
executable path. To run a script or shell command, configure the absolute shell
executable explicitly and supply its arguments. Unix resolves bare names only in
`/usr/bin:/bin`; relative paths containing `/` are relative to the candidate.

Environment inheritance is disabled. Provenance bindings and candidate-scoped
home/temp variables are explicitly supplied. Windows also copies `SystemRoot`
when present and derives a System32-only PATH. Arguments are passed without an
implicit shell; Windows applies CRT quoting with an explicit application path.
Shells retain their own command-language parsing rules.

Windows creation atomically assigns the process to its job using the extended
job-list attribute. There is no launch-then-assign window or uncontained fallback.
Only stdin/stdout/stderr handles are inherited; the job handle is not inherited.
The parent closes its output writers after process creation. stdin receives EOF.
Any setup, spawn, or drain error fails the command rather than claiming success.

Output streams are drained concurrently. The policy retains hashes of at most
8 KiB per stream and total observed byte counts, not raw output. Post-drain output
collection is bounded; incomplete collection fails the command. An escaped Unix
process can retain a pipe and reader thread, so cooperative execution must never
be presented as hostile-worker containment. Unix group cleanup does not prove
that all descendants have stopped writing. Windows drain proves only job
emptiness, not filesystem or network isolation.

The default repair profile never falls back to this trusted runner. Its backend
is reported as `unavailable` on non-Linux hosts. No platform capability boolean
can authorize confined model repair.

## Verification performed for this change

| Verification | Result |
| --- | --- |
| Core Linux `cargo check --offline` | Passed |
| Core Linux `cargo test --offline --no-run` | Passed |
| Policy bounded-prefix hashing, expired budget, fixed-path resolution | 3 tests passed |
| Policy invalid-input and explicit-profile validation | 2 tests passed |
| Platform synthetic tests, excluding cooperative lifecycle fixture | 9 passed |
| Platform Linux all-target strict Clippy | Passed |
| Platform `x86_64-pc-windows-gnu` all-target check and strict Clippy | Passed |
| Platform `aarch64-apple-darwin` all-target check and strict Clippy | Passed |
| Windows native execution/output test | Added and cross-checked; not executed here |
| Windows core policy capture test | Added; needs native core build/execution |
| macOS native process/IPC/Keychain behavior | Not executed here |
| Real credential-store lookup | Not performed |
| Live hostile-process/socket/bubblewrap campaign | Not performed; execution restrictions respected |

These are focused results for the platform change, not the aggregate project test
report. Full core and service suites are recorded separately. The native CI matrix
is configured in `.github/workflows/native.yml`; its existence is not evidence of
a passing CI run. Before claiming release readiness, execute the native builds,
policy capture tests, nested-job/handle-inheritance scenarios, timeout and crash
cleanup, IPC ownership checks, and authorized credential-store tests on each OS.
Linux and macOS need a separately verified containment backend before enforced
whole-session or hostile-worker guarantees can be enabled.
