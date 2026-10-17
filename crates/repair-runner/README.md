# Confined repair runner (optional)

This independent Rust crate provides a fail-closed Linux bubblewrap adapter.
The main policy boundary uses it for default confined repair. Explicit
`execution_profile: "trusted_unsandboxed"` is a separately labeled unsafe
development-only escape hatch; it is never selected automatically.
`sandbox_disabled: true` only denies repair execution and cannot forge support. No command is ever run without
`/usr/bin/bwrap`; unsupported platforms return `Unsupported`, and missing tools,
unsupported close_range, resource limits or namespace setup return errors.

## Integration contract

- The coordinator must materialize a separate, disposable candidate, keep its
  exclusive ownership/lock through execution, and pass its canonical absolute
  directory. Never pass the live workspace, coordinator store, a home directory,
  or a directory containing secrets. The runner cannot infer those roles from a
  filesystem path. Do not permit concurrent replacement, writes, or mount changes
  by other actors. Symlinks, hard links and special files present before execution
  are rejected. The source workspace is not a mount input.
- The OS and installed runtime directories must be trusted, administrator-managed,
  free of credentials and nested unexpected mounts. Only `/usr/bin`, `/usr/lib`
  and (when present) `/usr/lib64` are read-only runtime mounts. No broad root,
  `/etc`, home, host `/proc`, host `/dev`, `/run`, or host temporary mount is used.
- The candidate is the only writable **host-backed** mount. Private `/tmp`
  (64 MiB), `/proc`, and minimal `/dev` are created inside the sandbox. Root is
  remounted read-only. PID, user, network, IPC and UTS namespaces are mandatory;
  nested user namespaces and capabilities are disabled. A new session and
  die-with-parent provide normal runner lifecycle containment.
- Environment is cleared twice. Only a fixed PATH, temporary HOME and TMPDIR are
  supplied; stdin is closed and inherited nonstandard descriptors are marked
  close-on-exec. No model/provider credential, user environment or network socket
  is forwarded. An inference broker is **not implemented**: an inference-based
  repair worker remains gated on a separately reviewed credential-free interface.
- Executable path and argv have bounds; candidate trees have entry, depth and
  initial-byte bounds. Runtime is at most 120 seconds and combined captured output
  at most 1 MiB. Exceeding output or wall time kills/reaps the owned bwrap process.
  Kernel limits additionally cap per-process CPU, address space, open descriptors,
  process count, individual file size, and core dumps. These are not aggregate
  cgroup CPU/memory/disk quotas. A dedicated quota-backed candidate filesystem is
  required if total output disk exhaustion is in the threat model.
- Treat worker modifications as untrusted. Revalidate final candidates before
  showing/applying diffs; successful process exit is not patch approval.

`Request` contains `candidate`, an absolute sandbox `executable`, `args`,
`timeout`, `output_limit`, and optional fixed provenance `bindings`. `run` returns captured `Outcome` only on zero exit.
A failed setup/worker exit is `Failed { code, stderr }`; there is no fallback.
`sandbox_arguments` inspects the contract without running a process.

## Evidence, 2026-10-17

`cargo test --manifest-path crates/repair-runner/Cargo.toml --offline`:
4 tests passed; opt-in live test ignored. Tests cover mandatory namespace flags,
one writable host mount, absence of dangerous fallback flags, bounded inputs,
and rejecting candidate symlinks/hardlinks while preserving synthetic source.

Exactly one opt-in `live_confinement_probe` was attempted. It failed before the
fixture command ran, with exit 1 and this exact stderr:

> bwrap: loopback: Failed to create NETLINK_ROUTE socket: Operation not permitted

Live confinement, network isolation, timeout cleanup, and output termination are
**unverified in this environment**. No elevation, host security changes, alternate
sandbox route, Unix socket experiment, or process-kill campaign was attempted.
The ignored probe is retained for an authorized compatible CI host; it checks
outside-candidate invisibility, a private network view, runtime read-only status,
absence of credential variables, successful candidate-only writes, and unchanged
synthetic external source. Do not claim those assertions passed here.
