# Local peer authorization primitives

These core operations are local administrator actions. They are not network RPC
methods, TLS certificate issuance, or ACL authorization. No key or certificate is
created. Their purpose is to reserve artifact-source identities before a separate
managed enrollment workflow grants transport access.

## Initialize an authority binding

After `init` has created the authoritative project, submit:

```json
{"op":"sync_initialize_authority","operation_id":"setup-1","project":"project","authority":"authority","epoch":1,"device":"hub"}
```

This explicit bootstrap creates an authority binding with zero peers. Project,
authority and local device must be valid identifiers; epoch is 1 through signed
64-bit maximum. It cannot initialize a client or change an existing binding.
Repeating the same binding with a new operation ID preserves all existing peers.
The response is the same configuration shape as `sync_status`.

Legacy `sync_configure` is unchanged: it still requires nonempty peers and the
entire existing configuration must match exactly. It cannot remove peers.

## Reserve an additional peer

```json
{"op":"sync_add_peer","operation_id":"enroll-laptop-1","peer":"laptop"}
```

Requires an authority binding. Identifiers contain 1–100 ASCII letters, digits,
underscores or hyphens. The local device is rejected. At most 100 peer labels may
be reserved. Adding an already-reserved peer succeeds without appending it again,
even at capacity. No operation removes or resets an existing label, imported
operation, proposal origin, receipt or export.

The response includes `state: "peer_pinned"`, `peer`, `already_present`, the full
`config`, and `transport_access_granted: false`. This is not evidence that a
remote device is authenticated or authorized by a transport service. A managed
New enrollment must reject labels already owned or retired, except a durable
retry of that same enrollment intent. Explicit rotation may continue the same
identity and its existing history. Retired labels remain reserved permanently.

## Journaling and recovery

Both operations require an operation ID and reject unexpected request fields.
IDs bind the entire request: an exact retry returns the saved result; a changed
request using the same ID fails with `idempotency_mismatch`. As with other core
journaled operations, failed requests can also have saved results; use a new
operation ID after correcting the request. Saved responses are historical:
`sync_status` supplies the current configuration after later peer additions.

A successful configuration update, audit event and operation result commit in
one SQLite transaction under the engine's exclusive state lock. Both operations,
including retries, are blocked while public recovery requires explicit activation.
Read-only `sync_status` remains available. These operations never rebind a
recovered authority or establish fencing of an old authority process.

Run the local regression suite after building:

```sh
python3 tests/sync_peer_authorization.py
```

## Non-mutating binding inspection

`{"op":"sync_binding_status"}` runs before normal engine initialization and
recovery. It returns `initialized`, `config` (null or the exact stored binding),
and state `unconfigured` or `configured`. Absent or empty state is reported as
unconfigured without creating files. It never reads project source or Git data,
changes directory permissions, or performs recovery. Existing state is inspected
under its existing read-only lock with immutable read-only SQLite access.
Corrupt/partial state and nonempty WAL/rollback journals fail closed; the latter
returns `binding_inspection_requires_recovery`. Run an explicitly intended normal
engine operation to recover/checkpoint before retrying, rather than treating that
error as fresh state. This local probe is not a network RPC endpoint.

### Client initialization recovery

Legacy client `sync_configure` durably records its exact pending configuration
before creating a template-free bare cache. A failed/interrupted initialization
can resume only that same configuration. Existing repositories without the
pending intent remain rejected. A pending repository must contain only validated
empty initialization artifacts; refs, objects, symlinks, extra files and foreign
Git config are rejected without deletion or reset. Unsafe or ambiguous partial
artifacts require operator review rather than cleanup by the retry.

Final configuration, authority metadata and pending-intent removal commit together.
The read-only binding probe reports `pending_config` (null or that exact intent);
it does not treat the pending intent as active authorization or initialized state.

### Workspace exclusion boundary

The binding probe also returns `workspace_roots`, including every registered
canonical workspace path, or an empty array for fresh state. Pairing clients must
reject private profile and invite-file destinations overlapping any of these
roots, in addition to the explicit source root. The probe reads only registrations
from the state database; it does not touch or resolve live workspace files.

The list is bounded at 1000 roots and 4096 UTF-8 bytes per root. Malformed,
nonabsolute, NUL-containing or parent-relative paths, invalid database rows and
database errors fail closed. No invalid or excess registration is silently
omitted. An over-limit result returns `workspace_root_limit_exceeded`.
