# Accepted MCP Events design

Implementation was accepted on 2026-10-18. This readable reconstruction records
the accepted contract; it is not a claim of byte identity with the earlier file.

The target is OpenAI MCP Events 2026-07-28 for ChatGPT Work/dots. Existing local
stdio stays unchanged. The optional self-hosted HTTPS/supported-private-tunnel
connection exposes sanitized status and subscription management only. It never
publishes, integrates, adopts or mutates workspaces implicitly.

Events cover action-required (merge conflicts and failed checks, with distinct
new failed attempts), proposal-integrated and public-head-advanced. Select a
project, optional workspace or proposal, and desired event types. Payloads carry
minimal IDs/type/time/status only; source/diff/private WIP/path/raw check output
are excluded. Recheck current status before acting on an old alert.

Delivery is best-effort: a bounded five-minute in-memory buffer/retry budget,
stable event IDs and duplicate recognition, no historical replay and no
exactly-once guarantee. Restarts may lose delivery. Metadata for subscriptions
and authorization persists. Queue faults/overflow cannot block integration and
must expose degraded/incomplete delivery. Receipt does not establish agent action.

Identity uses direct GitHub OAuth, not Auth0 and not GitHub Actions OIDC.
Wipstash owns the audience-bound MCP authorization/token layer; GitHub tokens
are not passed through. Numeric-ID per-project grants apply. jimmystridh is the
intended initial account, with numeric identity verified before provisioning.
Invites are required in v1: single-use, valid 24 hours, numeric-ID/project-bound,
matching authenticated login required, administrator-only issuance/revocation.

Local grant removal stops new requests and event sends immediately. GitHub app
revocation alone does not guarantee immediate revocation of existing local
grants; explicit local removal is required. Real app registration, domain, keys,
secrets and access provisioning are separately approved setup steps.

Completion requires automated negative tests for duplicates, restarts, full
queues, revocation and unsafe callbacks AND an actual ChatGPT subscription test.
See services/mcp-events/README.md for engineering choices and acceptance steps.
