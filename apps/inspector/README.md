# Wipstash Inspector UI

A read-only, local-first Dioxus 0.7.10 Rust/WASM inspector. The interface connects to the companion `services/inspector` HTTP API and never runs workspace commands. No trackers, external fonts, CDN dependencies, remote analytics, or source uploads.

## Build

Use the repository's pinned Rust toolchain, then install the official registry tool once:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
python3 apps/inspector/scripts/build.py
```

The script builds release WASM and writes `apps/inspector/dist`. Serve that directory through the companion server's `--assets` flag, on the same origin as its API. See [`services/inspector/README.md`](../../services/inspector/README.md) for server setup and scope. No development proxy or CORS is needed for this build. The bootstrap is an external ES module, compatible with `script-src 'self' 'wasm-unsafe-eval'`; no inline JavaScript is required. `--debug` produces a faster unoptimized build when desired.

The Rust frontend has its own `Cargo.lock` and does not change the core's dependency graph. `Dioxus.toml` is included for developers using the optional Dioxus CLI; the documented build script does not need `dx`.

## Use

- Choose all workspaces or a named workspace; generation and adopted-base information remain explicit.
- Switch between local recovery commits and shared proposals/promotions.
- History is ordered by journal sequence, not fabricated timestamps. Entries without a sequence are labelled “order unknown.”
- Select a history entry, then a file. Diffs are fetched lazily and bounded by the server and renderer. Request identities prevent an old response appearing under a newly selected title or file.
- Filter the **loaded page** of history by title, ID, workspace, status, or commit. File search likewise filters the loaded page. Pagination loads older history and further file pages; counts and change totals apply to the current page.
- Unified and side-by-side diffs retain source line numbers and explicit `+`/`-` markers. Binary, empty, loading, failed, and truncated results are labelled.
- Switch dark/light appearance. Only that UI preference is stored in localStorage; source and API responses are not cached there.
- Keyboard: `/` focuses history search, `j`/`k` select adjacent history entries, `s` toggles split view, `?` opens help, Escape closes it. Shortcuts ignore inputs, selects, textareas, editable content and modified key combinations.
- Mobile retains the workspace selector and private/shared navigation.

Read-only is an application boundary, not proof that the caller's local machine is trustworthy. Do not expose this server publicly: private recovery record source is intentionally visible to the local inspector.

## Explicit demo and design preview

Append `?demo=1` to open a fully labelled synthetic demo. It never substitutes for a failed live API request. Demo data stays in the bundle, is synthetic, and is never fetched from a user's state.

```sh
cargo run --locked --manifest-path apps/inspector/Cargo.toml \
  --example render_preview -- /tmp/wipstash-inspector-preview.html
```

This exports the **same real Dioxus component tree** as self-contained HTML for socket-free layout review. It is a static design preview: browser interactions require the WASM build. No HTTP listener is started by the exporter.

## Verify

```sh
cargo fmt --manifest-path apps/inspector/Cargo.toml --check
cargo test --locked --manifest-path apps/inspector/Cargo.toml
cargo clippy --locked --manifest-path apps/inspector/Cargo.toml --all-targets -- -D warnings
cargo check --locked --manifest-path apps/inspector/Cargo.toml --target wasm32-unknown-unknown
python3 apps/inspector/scripts/build.py
```

Pure parser tests cover numbering, paired changes, empty/binary diffs, multiple file boundaries, adversarial large indices, and render limits. SSR tests exercise the real components, synthetic/live separation, explicit binary/truncation notices, and HTML escaping in both layouts. The repository's independent `tests/inspector_browser.py` can exercise the WASM app using browser route interception in a permitted browser environment; do not treat SSR or compile checks as a substitute for interactive browser validation.

Version references: [Dioxus official guide](https://dioxuslabs.com/learn/0.7/) and [Dioxus 0.7.10 crate](https://docs.rs/crate/dioxus/0.7.10). 0.8 prereleases were deliberately excluded.
