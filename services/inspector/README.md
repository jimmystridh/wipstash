# Local read-only inspector

This operator-only viewer exposes **private local checkpoints**, proposal metadata and shared integration history. It is not a collaborator endpoint. Anyone able to connect on this machine can inspect these records. Do not port-forward it, put it behind a remote proxy, or serve it on shared/untrusted machines. This first version deliberately has no remote binding option, authentication, or mutation routes.

## Run

From the project root:

```
cargo run --manifest-path services/inspector/Cargo.toml -- \
  --state /absolute/path/to/existing/state \
  --bind 127.0.0.1:47831 \
  --assets apps/inspector/dist
```

`--assets` is optional (without it, only the API is served). The UI uses the same origin. For a separately served development UI, `--allow-origin http://127.0.0.1:8080` permits exactly that local HTTP origin, never wildcard CORS. `--bind` must be an IP socket address on loopback. Browser requests must use the exact configured IP and port in Host. No request path or parameter selects a state directory or arbitrary Git revision.

Do not serve an unreviewed asset directory: JavaScript there has access to all private checkpoint data. Symlinks escaping the configured asset root, traversal, percent-encoded asset paths and unapproved file extensions are refused. Serve a production asset build; the CSP deliberately blocks remote scripts and dev-server WebSockets.

## JSON contract (v1)

All endpoints are GET. Query parameters must not repeat. Errors have HTTP 400/403/404/405/413/422/503 and `{"error":{"code":"...","message":"..."}}`. Operational errors are sanitized and never include absolute filesystem paths or Git stderr. Responses are not cached.

- `/api/overview` -> `{read_only:true,workspaces:[{id,generation,base,checkpoint:string|null}],proposals:[{id,workspace,checkpoint,intent,state,head:string|null}],conflicts:[{id,workspace,target,base,generation,state}]}`. Each array has a hard 1,000-record bound; a larger overview returns 413 rather than silently hiding records. Proposals expose factual persisted state; conflicts are adoption conflicts, including resolved entries if retained by the engine.
- `/api/history?kind=private&workspace=A&limit=50&offset=0` -> `{entries:[{id,workspace,kind,title,status,commit,base,generation:number|null,sequence:number|null}],next_offset:number|null}`. `kind` is `private` (default) or `shared`; workspace is optional. Private contains checkpoints. Shared contains proposals and promotion records. Entry IDs are `checkpoint:<operation-id>`, `proposal:<operation-id>`, `promotion:<operation-id>`. Ordering is descending persisted local `events.seq`. Checkpoints correlate checkpoint events, proposals correlate published events, and promotions correlate integrated events by proposal and exact new head (including recovery). `sequence` is null where restored/imported rows have no matching local event; these follow known events with deterministic source/insertion fallback. Sequence is an event order, not a timestamp. No artificial timestamps/branches are supplied. A checkpoint's `local_saved` status describes its recorded snapshot, not the live worktree or remote durability. The model contains no commit timestamps. Limits are 1–200; offset is 0–1,000,000.
- `/api/changes?entry=checkpoint:save-1&limit=100&offset=0` -> `{files:[{path,status,additions:number|null,deletions:number|null,binary:boolean}],next_offset:number|null,comparison}`. Status is `added`, `deleted`, `modified` or `type_changed`. Renames are represented as delete/add. Comparison is `adopted_base` for checkpoints, `proposal_base` for proposals, or `previous_shared_head` for promotions. These are not necessarily changes from the preceding checkpoint. Binary counts are null. Non-UTF-8 paths fail explicitly with 422 rather than aliasing filenames. The byte-preserving engine currently also enforces portable names at capture.
- `/api/diff?entry=checkpoint:save-1&path=src%2Fmain.rs` -> `{path,text,binary,truncated}`. Path must exactly match a changed file in that entry. Git literal pathspecs prevent wildcard or pathspec magic interpretation. Text is unified diff with three context lines, at most 256 KiB; invalid UTF-8 content is displayed with replacement characters, not treated as an exact byte reconstruction. Binary returns empty text. A true `truncated` flag must be visibly labelled in the UI.

No direct commit endpoint exists. Entry IDs must match persisted rows. Proposal objects use the coordinator store when present and otherwise their original local store for offline proposals. Checkpoints use their isolated workspace object store; promotions use the coordinator.

## Read-only and consistency boundary

The service does **not** import or call `engine::execute`: no initialization, schema migration, recovery, checkpointing, or live worktree inspection occurs. It opens an existing `state.lock` read-only, waits at most 500 ms for a shared cooperative lock, and holds it throughout each request's SQLite and Git reads. Source database and WAL are copied under that lock into a private temporary directory, then queried with SQLite read-only/query-only/trusted-schema-off and a two-second VM progress deadline. This avoids SQLite creating a missing SHM next to source state. Source DB/WAL are each capped at 256 MiB, temporary copies are deleted on drop. Each API request has its own snapshot; separate pagination requests can observe subsequent committed state. No consistency with noncooperative external Git or filesystem writers is promised.

Git is launched without a shell and with explicit recorded full object IDs, sanitized GIT_* environment, no replace objects, optional locks, lazy fetch, external diffs or textconv. Output is drained with fixed retained byte caps, and each subprocess has a five-second timeout. Changed-file metadata is capped at 2 MiB per Git stream. Extremely large diffs return a bounded preview or timeout rather than exhaust memory. Git repository configuration is assumed locally trusted; this is not a sandbox for attacker-controlled repository configurations or a hostile local filesystem.

The server is sequential (one active request) with a two-second total header deadline and socket write timeout and a 16 KiB header bound. It rejects duplicate headers, request bodies, non-HTTP/1.1 requests, cross-site browser fetches, foreign Origin and Host headers. It adds no-store, nosniff, frame-denying CSP and a same-origin resource policy. This is defense in depth against browser-origin leakage, not protection from malicious local processes. No request logging, source logging or analytics are enabled.

## Test without sockets

```
cargo test --manifest-path services/inspector/Cargo.toml
cargo run --manifest-path services/inspector/Cargo.toml -- \
  --state /existing/state --request '/api/history?kind=private&workspace=A'
```

The in-memory CLI emits `{status,body,content_type}` and supports `--method`, `--host`, `--origin`, `--fetch-site`, and `--assets` for adversarial tests. It never binds a listener when `--request` is provided. Live-listener validation belongs in an environment where binding is authorized.
