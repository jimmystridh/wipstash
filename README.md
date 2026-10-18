# Wipstash

### Save the mess. Share the change. Keep working.

Wipstash gives coding agents their own workspaces and private checkpoints, then brings their deliberately published changes together. Each agent chooses when to adopt the shared result.

Four bots can work on one project without sharing one working directory, publishing every half-finished thought, or having another bot's changes land under their cursor.

**Private WIP → deliberate publish → autonomous integration → deliberate adopt.**

Wipstash is a Rust prototype with a working local collaboration loop, a JSON CLI, stdio MCP, and explicit source exchange between independent client and authority stores. Start with the disposable demo below. The tested operating profile is cooperative Linux; native platform, TLS service, and remote backup work are experimental. [Exact scope and release gates →](docs/SCOPE.md)

## Inspect the work

**Wipstash Inspector** is a compact Dioxus web UI for understanding what happened without changing it. Browse private checkpoints, published proposals, quarantined conflicts and shared integrations; select a file to inspect a unified or side-by-side diff.

- Real journal order and explicit comparison bases, rather than invented timestamps
- Workspace and loaded-history filters, keyboard navigation, dark/light themes and a responsive layout
- Lazy, bounded diffs with line numbers and clear binary/truncation notices
- A separate read-only service: browsing never checkpoints, publishes, integrates, adopts or recovers your state

Build and launch it against an **existing** Wipstash state directory:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
python3 apps/inspector/scripts/build.py
cargo run --locked --manifest-path services/inspector/Cargo.toml -- \
  --state /absolute/path/to/state \
  --assets apps/inspector/dist
```

Open **http://127.0.0.1:47831**. This is a local operator tool that can show private checkpoint source. Keep it on your own trusted machine; do not port-forward it or expose it through a remote proxy. It has no remote login or mutation routes.

[Interface and shortcuts](apps/inspector/README.md) · [Read-only API and security boundary](services/inspector/README.md) · [Adversarial inspection tests](tests/INSPECTOR-SECURITY-REVIEW.md)

## The four decisions that matter

| Step | What happens | Who decides? |
| --- | --- | --- |
| **Checkpoint** | Save a private snapshot, including broken or unfinished source | The workspace owner |
| **Publish** | Offer exactly one selected checkpoint with an intent | The workspace owner |
| **Integrate** | Merge queued proposals into the shared head; quarantine unresolved conflicts | The worker, under configured policy |
| **Adopt** | Reconcile a chosen shared head with the workspace's current WIP | The workspace owner |

```text
Bot A  private workspace → checkpoints ── publish ──┐
Bot B  private workspace → checkpoints ── publish ──┤
Bot C  private workspace → checkpoints ── publish ──┼→ integration → shared head
Bot D  private workspace → checkpoints ── publish ──┘                    │
                                                                        │
       each workspace ←──────── deliberate adopt ────────────────────────┘
```

Fetching an update leaves live files alone. Publishing a checkpoint does not publish its private checkpoint ancestry. An unresolved proposal can wait while unrelated work moves forward.

Checks are **off by default**. You can save and publish code that does not compile. Opt into checks or repair workers when your project needs them; a clean merge alone says nothing about whether the code works. Configured repair defaults to confined execution and stays quarantined when the confinement backend is unavailable.

## Try it

Requirements: Rust/Cargo, Git with `merge-tree --write-tree`, and Python 3. The repository pins its tested Rust toolchain in [rust-toolchain.toml](rust-toolchain.toml); it does not declare an MSRV. First build may download dependencies.

```sh
# From a checkout of this repository:
cargo build --locked
```

Run this from the repository root. It creates disposable synthetic source, state, and two isolated workspaces. No credentials or remote service are needed.

```sh
python3 - <<'PY'
import json, pathlib, subprocess, tempfile

binary = str(pathlib.Path('target/debug/wipstash').resolve())
root = pathlib.Path(tempfile.mkdtemp(prefix='wipstash-demo-'))
source = root / 'source'
source.mkdir()
(source / 'hello.txt').write_text('initial\n')

def request(**body):
    result = subprocess.run(
        [binary, '--state', str(root / 'state'), json.dumps(body)],
        check=True, capture_output=True, text=True)
    reply = json.loads(result.stdout)
    assert reply['ok'], reply
    print(body['op'], json.dumps(reply))
    return reply

request(op='init', source=str(source))
for name in ('alice', 'bob'):
    request(op='open', workspace=name, path=str(root / name),
            operation_id='open-' + name)

(root / 'alice' / 'hello.txt').write_text('published by alice\n')
request(op='checkpoint', workspace='alice', expected_generation=0,
        operation_id='save-alice')
request(op='publish', workspace='alice', checkpoint='save-alice',
        intent='Update greeting', operation_id='publish-alice')
request(op='integrate')
request(op='proposal_status', proposal='publish-alice')
request(op='updates', workspace='bob')
assert (root / 'bob' / 'hello.txt').read_text() == 'initial\n'

request(op='adopt', workspace='bob', target='latest',
        expected_generation=0, operation_id='adopt-bob')
assert (root / 'bob' / 'hello.txt').read_text() == 'published by alice\n'
print('PASS: Bob changed only after adoption. Demo directory:', root)
PY
```

The important moment is the first assertion: Alice's change is integrated, Bob knows about it, and Bob's files still contain `initial`. Only `adopt` changes them.

For background integration, replace manual `integrate` calls with a worker in another terminal, using the demo's printed directory:

```sh
./target/debug/wipstash --state /absolute/demo/directory/state worker
```

Stop it with Ctrl-C. The local worker processes queued proposals and retries configured local backup; it does not automatically move source-exchange artifacts between machines.

Before using your own source: `init` makes the imported tree the initial public head. Review it first. Keep state, source, and workspace directories separate. Stop external writers before checkpoint/adoption. Filename exclusions are not a secret scanner. [Operational contract →](docs/OPERATIONS.md)

## Four bots, one project

Imagine one bot changing an API, one updating its caller, one writing tests, and one fixing docs:

1. Each gets an ordinary directory and checkpoints its own WIP. Their private histories can be as messy as they need.
2. The API bot publishes one chosen snapshot. Later edits stay private until separately published.
3. The worker integrates it. If the caller bot's proposal conflicts, that proposal is quarantined; the docs change can still land.
4. The test bot checks for updates and adopts when ready. If adoption conflicts with its private work, the live workspace stays unchanged and an explicit resolution path is available.
5. Everyone can inspect proposal status and operation records instead of guessing what a timeout meant.

That is the workflow the test harness exercises with **four deterministic scripted actors**. Claude Code stdio initialization and tool discovery have been verified; actual model-driven Codex/Claude workflows and arbitrary native-writer containment remain release gates.

## Why Git underneath?

Git already provides content-addressed objects, immutable commits, trees, ancestry, and three-way merge. Wipstash uses those building blocks while exposing operations that match how agents work.

- **Private object stores** retain workspace checkpoints.
- **Public-base ancestry** exports the selected snapshot without linking its private checkpoint chain.
- **A shared integration head** records accepted combinations.
- **SQLite journals and generations** track operation identity, state transitions, and recovery.

Git remains the storage and merge foundation. Wipstash adds the boundary between saving work, sharing work, and accepting somebody else's work. It does not require a clean build to save your place.

## CLI, MCP, and independent clients

**CLI:** one JSON request, one JSON response. Reuse an operation ID only for the identical request; query status after uncertain outcomes.

```sh
./target/debug/wipstash --state /absolute/path/to/state '{"op":"status","workspace":"alice"}'
./target/debug/wipstash --state /absolute/path/to/state mcp
```

**MCP:** typed workflow tools plus a generic request tool over stdio. [Client setup](docs/CLIENTS.md) includes [Codex](examples/clients/codex.toml) and [Claude Code](examples/clients/claude.mcp.json) examples. Registration does not intercept native edits or enforce a writer freeze.

**Source exchange:** independent client stores export deliberate public proposals; an authority imports and integrates them; clients import public heads and explicitly adopt. The core currently exchanges bounded filesystem artifacts with separately trusted provenance. [Protocol and commands →](docs/SOURCE-SYNC.md)

**Receipts:** the authority can return a proposal observation with its disposition, evidence category, identity, and revision. Clients distinguish local transport state from the latest received authority observation. A receipt does not install a head, adopt source, or prove the authority is reachable right now. Raw worker output and private checkpoint histories are excluded from receipt payloads.

## Where it stands

| Area | Current boundary |
| --- | --- |
| Private checkpoints, publication, integration, adoption | Implemented and exercised with real CLI/Git/SQLite on Linux; cooperative writers required |
| Independent stores and receipts | Implemented explicit artifact exchange, ordered replay, object verification, and targeted proposal observations |
| CLI and stdio MCP | Implemented; Claude Code 2.1.302 stdio handshake/tool discovery verified, Codex configuration parsing verified; model-driven workflows remain unverified |
| Checks and repair | Empty by default; durable repair budgets and confined-or-unavailable repair dispatch. Linux sandbox execution is not verified in this environment; no bundled model worker |
| Public recovery | Version 2 preserves public intent, ownership, queue order, operation identity and replay metadata; restored execution stays fenced until explicit operator activation. Private WIP is excluded |
| Authenticated transport | mTLS service/client implementation, certificate ACLs and resumable uploads; in-memory security and transfer tests, no listening-service or multi-machine acceptance run |
| Storage | Conservative loose-object collection and storage admission; no automatic expiry of private checkpoints or acknowledged uploads, no power-loss guarantee |
| Native platform and GitHub backup | Native adapters cross-check on Windows GNU/macOS Darwin targets; asynchronous GitHub backup components exist. Native runtime, real remote credentials and fresh-host recovery remain gates |
| Supported deployment | Development/evaluation on Linux; production, native macOS/Windows, and multi-machine release gates remain open |

The full contracts, limits, and missing gates live in [SCOPE.md](docs/SCOPE.md), [STORAGE.md](docs/STORAGE.md), and [GAP-CLOSURE.md](docs/GAP-CLOSURE.md). Keep an independent backup of valuable original work.

## Test the promises

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
python3 tests/adversarial.py
python3 tests/gap_closure.py
python3 tests/mcp_protocol.py
python3 tests/source_sync.py

# Standalone components are separate Cargo packages:
for component in crates/platform crates/repair-runner services/storage services/transport services/backup; do
  cargo test --locked --manifest-path "$component/Cargo.toml"
done
```

The suites probe exact-checkpoint publication, private ancestry isolation, concurrent proposals, stale generations, conflict quarantine, unchanged files before adoption, explicit resolution, replay, and retained-state recovery. See the [test harness guide](tests/README.md) and [source-exchange review](docs/SOURCE-SYNC-REVIEW.md).

Record the tested revision and retain local test artifacts when reporting results; earlier passing runs do not certify later changes. [WAN simulation](docs/WAN-SIMULATION.md) tests delayed/faulted application messages; production networking needs its own evidence. No performance target or production-readiness claim follows from these fixtures.

## Next gates

- Real Codex and Claude workflows with a verified writer-coordination contract
- Native Linux/macOS/Windows process, IPC, and filesystem acceptance tests
- Deployed TLS transport acceptance: certificate lifecycle, revocation, resumable transfer and multi-machine failure drills
- Real remote backup and a fresh-host restore drill with explicit recovery coverage
- Live confined model repair, conservative GC acceptance, storage-pressure and power-loss testing

Contributions that close a gate should include a reproducible test and a precise statement of what it proves. Start with [scope](docs/SCOPE.md), then the [operations reference](docs/OPERATIONS.md) or [source exchange](docs/SOURCE-SYNC.md).

## License

[MIT](LICENSE). Build on it. Keep the notice.
