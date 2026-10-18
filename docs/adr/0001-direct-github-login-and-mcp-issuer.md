# ADR 0001: Direct GitHub login and Wipstash MCP issuer

Status: accepted, 2026-10-18.

Use direct GitHub OAuth for stable numeric human identity. Wipstash owns its
MCP-facing authorization server and audience-bound token validation. No Auth0
broker and no GitHub-token passthrough. Apply local project grants and v1
single-use 24-hour invitations bound to account ID and project.

This creates explicit security responsibility for independent PKCE/state,
client/redirect/resource binding, browser/CSRF protection and consent, rotating
token families, expiry, replay detection and immediate local grant revocation.
GitHub app revocation is not a substitute for local revocation. Real OAuth setup
and secrets remain separate actions; no credentials are bundled.
