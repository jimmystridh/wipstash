# Standalone CLI

Agents and humans use the same `wip` executable through normal shell commands. No source-control MCP registration, special agent launcher or resident client service is required. Native file edits stay in an agent-owned clone; source, coordination and audit use direct authenticated server calls.

## Install and start

Build with `cargo build --release --locked --bin wip`, then install `target/release/wip` on PATH. Windows uses `wip.exe`. Git must also be installed; Python is only needed for the optional native-history collector. The `wipstash` binary remains an internal/operator engine used by existing server tooling.

```sh
wip init my-project
wip clone ./my-project ./alice
wip clone ./my-project ./bob
cd alice
# Edit files with ordinary tools.
wip add apa.js
wip diff --staged
wip commit -m 'tjenis tjenis'
wip status
```

For a provisioned remote device, import its private profile once:

```sh
wip remote add demo --config /private/path/client.json --default
wip clone demo ./my-work
# Or: wip clone https://SERVICE.run.app ./my-work --profile demo
```

The profile retains the device's existing key paths, server identity and local state. Credentials are not copied into source. Native mTLS and Cloud Run signed HTTPS remain supported. Cloud Run hosts a single configured repository per service origin. Enrollment and credential provisioning remain operator actions; a URL alone grants no access.

Start `codex`, `opencode`, `claude` or `pi` normally inside the chosen clone. Each concurrent agent session needs its own clone, even two sessions of the same client. Install [the shared skill](../skills/wipstash-source-control/SKILL.md) for workflow guidance.

## Staging and sharing

`wip add PATH...` captures exact contents at Add time, including eligible additions/deletions. Later edits remain unstaged. `wip restore --staged PATH...` removes staged changes without editing working files. `wip add .` and `wip commit --all` stage all eligible changes. Empty staging requires explicit `--allow-empty`.

Commit saves and attempts sharing in one command. It delivers the staged source and obtains an authority receipt without waiting for background checks. `shared: true` establishes sharing; passing exact-head server validation establishes check eligibility. Offline and interrupted operations remain recoverable on disk; `wip sync` retries pending delivery with the original IDs. There is no separate publish or integration step.

`wip get-latest` (`fetch`) reads incoming commits and coordination. `wip merge [TARGET]` deliberately changes local files. A peer's commit never edits another agent's directory. Compatible successive commits do not require merging between them. Source-control commands in one clone are serialized; arbitrary native file writers remain cooperative.

## Commands

| Area | Commands |
| --- | --- |
| Repository | `init`, `clone`, `attach`, `remote add`, `remote list` |
| Source | `add`, `restore --staged`, `commit`, `status`, `diff`, `log`, `get-latest`, `merge`, `sync` |
| Recovery | `commit-status`, `operation list`, `operation show`, `operation retry` |
| Conflicts | `conflict list`, `show`, `open`, `resolve` |
| Coordination | `task list`, `claim`, `renew`, `complete`, `release`; `comment add`, `list` |
| Validation | `check`; `repair list`, `acknowledge`, `claim`, `renew`, `release` |
| Lifecycle | `workspace list`, `close --writers-stopped`, `reopen` |
| Audit | `audit status`, `log`, `verify`, `record`, `import`, `collect` |
| Advanced | `request OP --params JSON`; trusted `admin OP [--state STATE] --params JSON` |

Every command accepts global `--json`, `--offline` and `-C DIRECTORY`. Use `--help` for detailed arguments. Normal Status inspects files and staging; `status --quick` reads metadata only. Audit Log reads the authority when online and connected; offline reads are explicitly local.

Exit statuses are 0 completed, 1 rejected/error, 2 invalid arguments, 3 pending/unconfirmed and 4 conflict. For Commit, inspect `shared` as well as the exit status. The CLI records exact mutation requests before execution. After a lost reply, inspect `operation list`, `operation show ID` and `commit-status ID`; retry the same retained operation with `operation retry ID`. Historical replies are not current sharing evidence.

## Migration

`wip attach --state ABS_STATE --workspace EXISTING_ID [--profile PROFILE]` adds protected `.wip` metadata to an existing registered directory. It retains the source files, workspace ID, generation, private history, pending operations and authority binding. A remote client state needs its matching imported profile. Do not repoint existing workspaces to another authority.

Drain available deliveries, stop Wipstash client workers/collectors, remove only Wipstash's MCP registrations, and retire its agent launchers after validating CLI access. Preserve queues, journals, credentials and workspaces. Operator servers keep their background validation; a server process is distinct from a workstation delivery daemon.

Every CLI action is audited. Activity outside the CLI can be imported explicitly through `audit collect` or `audit import`; full native collection is optional and its coverage stays visible. See [audit](AUDIT.md), [background validation](BACKGROUND-VALIDATION.md), [network transport](NETWORK.md) and [Cloud Run](CLOUD-RUN.md).
