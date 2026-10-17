# GitHub public backup worker

`services/backup` is a separate Rust executable. The coordinator never waits for
GitHub. The service copies an explicitly selected **sanitized local public backup**
into a durable local outbox, then separately replicates it to one configured
GitHub owner/repository/namespace. It does not create repositories, credentials,
accounts, paid services, or background OS services.

## Verification status and durability contract

The library and CLI have local fixture tests. CLI tests cover configuration
rejection, destination binding, local enqueue/restart/idempotency, exclusion of an
unreachable private object, automatic source advancement/deduplication while the
fake transport is offline, empty-worker behavior, and persisted capped backoff.
The library exercises fake/local remotes, interrupted verification and retries.
**Live GitHub authentication, push, fresh-fetch verification and disaster recovery
have not been verified in this environment.** The full backup Windows cross-build
is currently blocked locally by the missing MinGW C compiler required for bundled
SQLite; a successful platform-only cross-check is not a full-service build. Do not infer live deployment from a
passing fixture test.

A coordinator acknowledgement means local/coordinator durability only. There is
an intentional asynchronous loss window until all of these steps finish:

1. The core writes its sanitized public backup to the configured local bare repo.
2. The worker enqueues the configured public source snapshot (or an operator
   explicitly enqueues it when automatic source polling is not configured).
3. This worker pushes and freshly fetches/verifies the exact public ref set.

`status.status.verified_watermark` advances only after step 3. A `pending` job is
not a remote backup. A watermark of zero alone is not proof of any successful
backup. The source can change after enqueue; subsequent changes require another
snapshot. With `public_source` configured, each worker tick re-verifies and
enqueues that sanitized source before draining one job; unchanged snapshots
deduplicate. Without it, enqueue remains explicit. The worker never reads private
core state. Core public-export refresh and GitHub replication run independently.

Private workspace trees, checkpoints, unpublished proposals, raw policy commands,
credentials and unsent private operations are not backed up. Publicly published
source/history, accepted proposal intent and allowlisted recovery metadata are
public backup content. Scrubbing private refs cannot redact secrets already
committed into that public history. Review public source and intent before
publishing/enqueueing, especially when using a public GitHub repository.

## Build and explicit configuration

Run from the project root:

```sh
cargo build --release --manifest-path services/backup/Cargo.toml
cargo test --manifest-path services/backup/Cargo.toml
```

Create `/absolute/path/github-backup.json` yourself:

```json
{
  "outbox": "/absolute/path/backup-outbox",
  "public_source": "/absolute/path/public-backup.git",
  "github": {
    "owner": "YOUR_GITHUB_OWNER",
    "repository": "YOUR_EXISTING_BACKUP_REPOSITORY",
    "namespace": "wipstash",
    "credential_helper": "libsecret"
  }
}
```

All filesystem arguments must be absolute and must not contain `..` components.
The optional `public_source` must be the core's sanitized public export, outside
the outbox directory. Omit it to require manual enqueue. The configuration rejects
unknown keys. Keep the outbox on durable, trusted local
storage, separate from core state and from the sanitized public repository. Do not
share it between unrelated projects. Existing outboxes pin the full configuration:
changing owner, repository, namespace or credential helper fails with
`backup_destination_changed`. Use a new outbox for a deliberately changed binding;
do not edit its database to repoint it.

Only HTTPS to `https://github.com/OWNER/REPOSITORY.git` is supported. There is no
arbitrary remote URL, SSH, token, password, shell credential helper, or plaintext
credential fallback. Allowed existing OS-vault helpers are `osxkeychain`, `manager`
and `libsecret`. Configure/authenticate your chosen installed helper separately;
this executable does not create credentials or request interactive authentication.
Git global/system configuration, prompts, hooks, URL redirects and implicit tags
are disabled for transport. The exact owner/repository path is used in credential
lookup. The executable still depends on trusted `git` and helper binaries on PATH
and a trusted local OS-vault session. Windows `SystemRoot` and `WINDIR` are
allowlisted OS location variables; no credential environment variables are inherited.

## Produce and enqueue a sanitized public snapshot

The core's local backup output is the only intended source. Never point this
command at the core's private state store or an arbitrary checkout. For example,
after initializing core state, create an empty bare destination and explicitly
flush the core public backup into it:

```sh
git init --bare --template= /absolute/path/public-backup.git
./target/debug/wipstash --state /absolute/path/core-state \
  '{"op":"backup_flush","destination":"/absolute/path/public-backup.git","operation_id":"backup_export_1"}'
./services/backup/target/release/wipstash-backup \
  --config /absolute/path/github-backup.json \
  enqueue --public-source /absolute/path/public-backup.git
```

Use a new core operation ID for each new flush request. Core `backup_tick` can
refresh its already-configured local public backup; it does not push to GitHub.
For continuing asynchronous updates, run the core worker under a supervisor as
well as the GitHub worker below:

```sh
./target/debug/wipstash --state /absolute/path/core-state worker
```

The core worker integrates proposals and runs `backup_tick` against the local
public destination configured by the initial `backup_flush`. The GitHub worker
reads only the configured `public_source` output. Both must remain running for
new coordinator state to propagate automatically; this CLI does not start the
core worker or inspect its private state.
 The service validates the public integration/metadata/proposal pairing
and metadata history, then copies only their required objects into its spool.
Enqueue has no GitHub network access and returns before any remote replication.
Enqueueing an unchanged snapshot does not append a duplicate job. Unknown metadata
fields and invalid/mismatched public refs fail closed.

## Run and supervise the worker

```sh
./services/backup/target/release/wipstash-backup \
  --config /absolute/path/github-backup.json status
./services/backup/target/release/wipstash-backup \
  --config /absolute/path/github-backup.json worker --max-attempts 8
```

The one-shot worker exits once the outbox is empty or its iteration budget is
exhausted. The budget is 8 by default, explicitly configurable from 1 through
1000. Every attempted job counts, including successful jobs; another invocation
continues any remaining durable jobs. Failed iterations leave the job pending and
persist a retry deadline. Backoff starts at 5 seconds, doubles, and caps at 300
seconds; restarts retain it. Clock rollback waits are clamped to 300 seconds per
iteration. Errors are JSON codes rather than raw Git diagnostics or credentials.

For an independently supervised background process:

```sh
./services/backup/target/release/wipstash-backup \
  --config /absolute/path/github-backup.json worker --watch --max-attempts 8
```

`--watch` checks the configured public source and outbox every five seconds when
idle; while draining backlog it checks the source before each job. Each source
snapshot is verified before enqueue. It resets its attempt budget after a
successful tick. Missing or malformed source output fails closed and uses the
same persisted retry backoff; already-enqueued jobs remain durable. It exits nonzero after the configured number
of consecutive unsuccessful iterations. A second worker using the same outbox
fails its process lock. A supervisor may restart the process; the retry deadline
and outbox survive restart. The program remains in the foreground and does not
install or modify a system service. Stop it through your normal supervisor; an
interrupted operation stays pending and is verified again on restart.

Each Git invocation has a 120-second managed-process deadline. Stdout is drained
concurrently with stderr and retained up to 16 MiB; oversized output fails closed.
Stderr is drained without retention or disclosure. A short post-exit pipe deadline
prevents an inherited open pipe from hanging verification. Deadline or incomplete
output failure leaves the backup job unverified and retryable. A full iteration
can involve multiple Git invocations, so 120 seconds is not a whole-job deadline.

The process adapter uses cooperative process groups on Unix and Job Objects on
Windows. Unix detached descendants are not contained, and this is not a filesystem
or network sandbox. Trusted Git/helper binaries remain a prerequisite. Linux
synthetic subprocess deadline/output fixtures are tested locally; native macOS and
Windows runtime validation remains separate. Verification scratch repositories
and completed outbox jobs are retained; automatic disk retention/GC is not
implemented. Monitor disk usage and preserve pending spool objects.

Remote updates use atomic ref pushes and exact leases. Unexpected pre-existing
namespace refs, divergence, missing public refs or a failed verification stop the
watermark from advancing. Never resolve divergence by deleting refs or force
resetting the remote blindly. Investigate which public history is authoritative.
No unrelated repository branches are intentionally updated.

## Restore a fresh public repository

```sh
./services/backup/target/release/wipstash-backup \
  --config /absolute/path/github-backup.json \
  restore --destination /absolute/path/new-restored-public.git
```

The destination must not exist, and its parent must exist. Restore fetches into a
fresh bare store and checks the public schema, connectivity and stable exact ref
set. Failure can leave a partial destination for diagnosis; retry with a new path.
A successful result is a verified public Git snapshot, **not an activated core
coordinator or recovered private workspace**. Use namespace `wipstash` when this
output will feed the core's existing public recovery flow; custom transport
namespaces are not automatically renamed for that flow.

Core v2 public recovery restores a fenced coordinator. Review the recovered state,
restore the matching policy and original sync binding, ensure the old authority
is stopped, and then explicitly use the documented core recovery activation
procedure. Activation assertions are operator trust, not authenticated authority
migration. v1 snapshots lack the newer recovery metadata. See [operations](OPERATIONS.md)
and [storage](STORAGE.md) for core commands and recovery boundaries.
