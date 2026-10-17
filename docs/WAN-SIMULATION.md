# Application-layer WAN delivery simulation

## Scope

`simulations/wan` is a standalone Rust executable that path-includes the actual
`src/replication.rs` replay/admission contract. It has its own Cargo manifest, lock,
and build directory; it does not add dependencies to the main application.

Four scripted **receiving replicas of one authority stream** each own a separate
SQLite database. This exercises metadata-advertisement delivery, admission,
durable cursor/head bookkeeping, and retry behavior. It does **not** establish
four concurrent writers, election, source/object synchronization, a usable remote
service, TCP, TLS, authentication, bandwidth shaping, netem, or kernel/network
fault behavior. `PeerIdentity` is trusted synthetic caller input. No sockets,
credentials, security settings, or process termination are used.

## Reproduce

From the project root (Rust and cached crates required):

```sh
export CARGO_HOME=/workspace/shared/.cargo
export RUSTUP_HOME=/workspace/shared/.rustup
export PATH="$CARGO_HOME/bin:$PATH"
simulations/wan/run_profiles.sh
```

This runs broadband and satellite profiles with seeds 7, 41, and 2026, concurrently
in six separate processes, plus a sustained
satellite run with seed 99173 and 128 operations per receiver (512 applications). A fresh timestamped output directory is used by default.
For a single run:

```sh
cargo run --offline --locked --manifest-path simulations/wan/Cargo.toml -- \
  41 satellite 64 /tmp/wipstash-wan-41-fresh
```

The output directory must not contain receiver databases from an earlier run.
The deterministic PRNG seed determines packet ordering and losses. Measured
wall-clock runtimes and scheduler lateness depend on host load.

## Workload and failures

Each profile sends 64 operations to all four replicas (256 unique applications).
Every fifth event is `ProposalAccepted`, which advances the journal/cursor while
leaving the cached head unchanged. Other events carry distinct hexadecimal heads.

| Property | Broadband | Satellite |
|---|---:|---:|
| Normal one-way base + uniform integer jitter | 30–200 ms | 180–600 ms |
| Fixed retransmission timeout | 650 ms | 1,400 ms |
| Per-replica outstanding window | 8 | 8 |
| Random data loss per send | 12% | 12% |
| Random ACK loss after admission | 18% | 18% |
| Extra duplicate copy probability | 20% | 20% |

A scripted first-window reorder additionally gives replica 1 sequence 1 a 700 ms
delay and later sequences 40–100 ms. A first data loss and an early ACK-loss case
are scripted. Replicas 2 and 3 have a bidirectional partition from nominal 1,000
to 3,500 ms; queued arrivals during that interval also drop. Reconnect is explicit.
The other probabilistic faults **continue after reconnect**; there is no hidden
perfect-delivery final drain. Sender retries unacknowledged operations with a
fixed timeout, not adaptive backoff or production congestion control. Out-of-order
operations are rejected, then retransmitted; there is no receiver reorder buffer.

Receivers close/reopen their SQLite stores after nominal 1.8–2.85 seconds and
at least one committed event. The replayed last operation must return Duplicate.
This is deterministic clean close/reopen, not a crash, SIGKILL, or power-loss test.
An incompatible epoch binding must reject reopen. Periodic stale-epoch and revoked
permission attempts, including already committed sequences, must reject without
changing the cursor or cached head.

## Real latency and limits

A 10 ms tick scheduler uses `std::thread::sleep`, not accelerated virtual time.
Each queued packet records an actual monotonic `Instant`. Before every data/ACK
delivery the simulator sleeps any remaining configured delay and asserts that
actual elapsed time is at least that delay. `delivery_timing` JSONL records include
both configured and measured delay. Slow SQLite work or host load may increase
latency and wall-clock partition duration; catch-up ticks cannot erase a packet's
required delay. Summary fields record configured/measured totals, maximum measured
delay, host-scheduler lateness, and elapsed wall-clock run duration.

Bounds: event count 16–1,000; eight outstanding sequence positions per receiver;
queue below 4,096 entries; fewer than 100,000 sends; max(9,000, 140 × event count) logical ticks (nominal
90 seconds for 64 events; 179.2 seconds for 128 events) before a convergence assertion fails. Because real per-packet delays
are enforced, the nominal tick bound is **not a hard wall-clock watchdog**. There
is no claim that arbitrary sustained loss must eventually converge. These seeded,
bounded tests require convergence and fail loudly if it does not happen.

## Correctness checks and evidence

For every accepted operation, sequence must equal the previous cursor plus one.
For every gap/duplicate, cursor and head remain unchanged; the expected head is
checked after every delivery. Exactly 256 Applied admissions must occur. All 64
operations must be acknowledged by every receiver before success, and every
receiver must have reopened. Final fresh reopen verifies cursor, expected head,
exact row count, and SQLite `integrity_check=ok` independently per file. All fault
counters must be nonzero; passing without exercising failures is forbidden.

Canonical campaign output is `evidence/wan-simulation/final/`:

- `<profile>-<seed>/trace.jsonl`: configuration, drops, timing, admissions, ACKs,
  rejected probes, partition/reconnect, and reopen observations
- `<profile>-<seed>/summary.json`: pass status, seed, actual duration, fault totals
- `<profile>-<seed>/receiver-{0,1,2,3}.sqlite`: final durable state
- `<profile>-<seed>.log`: process result

The earlier top-level profile directories are preliminary development runs,
superseded by `final/`. The intermediate `measured/` campaign also passed but
predates final style fixes and timeout scaling. All seven final runs use the same
frozen executable, source and lockfile; `final/source-binary.sha256` records hashes. `contract.sha256` identifies the production
contract used. Independent contract tests reside in
`simulations/wan/tests/independent_contract.rs`; they additionally inspect every
persisted prefix and inject transactional rollback failures.

For complete latency distributions and retry counts:

```sh
python3 simulations/wan/summarize.py evidence/wan-simulation/final
```

Measured latency distributions include the intentionally faster/slower initial
reordering probes, so satellite minimums can be below 180 ms. Native SQLite stores
remain in local run directories; `evidence/wan-simulation/release/` omits stores
and compiled outputs and includes compressed traces, summaries, source hashes,
QA logs, and an independently reviewed results table.

## Recorded final result

Seven final-source runs passed: 2,048 unique durable applications and 9084 retries. The sustained 128-operation-per-replica satellite run took 125.097 seconds. See `evidence/wan-simulation/release/RESULTS.md` for all seven rows and latency distributions.
