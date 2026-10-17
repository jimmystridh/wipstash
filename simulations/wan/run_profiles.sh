#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export CARGO_HOME="${CARGO_HOME:-/workspace/shared/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/workspace/shared/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"
cargo build --offline --locked --manifest-path simulations/wan/Cargo.toml
root="${1:-evidence/wan-simulation/reproduction-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$root"
pids=()
for profile in broadband satellite; do
  for seed in 7 41 2026; do
    simulations/wan/target/debug/wipstash-wan-sim "$seed" "$profile" 64 "$root/$profile-$seed" > "$root/$profile-$seed.log" 2>&1 &
    pids+=("$!")
  done
done
simulations/wan/target/debug/wipstash-wan-sim 99173 satellite 128 "$root/satellite-99173-128" > "$root/satellite-99173-128.log" 2>&1 &
pids+=("$!")
status=0
for pid in "${pids[@]}"; do wait "$pid" || status=1; done
cat "$root"/*.log
exit "$status"
