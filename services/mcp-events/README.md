# Optional MCP Events connection

Separate OpenAI MCP Events 2026-07-28 service for ChatGPT Work/dots. Existing
trusted local stdio remains unchanged. The HTTPS connection can only read
sanitized status and manage subscriptions; it cannot call the mutation engine.

## Contract

- `action_required`: merge conflict, failed checks, or policy evaluator error.
  Each newly failed attempt has a new ID; delivery retries retain the event ID.
- `proposal.integrated`: includes already-included proposals, without falsely
  reporting head advancement for an already-included proposal.
- `public_head.advanced`: emitted by the integration authority. Imported client
  observations do not originate alerts. Head advancement affects all workspaces
  in the project; proposal scope matches only the causal proposal.
- Filters require a project and optionally a workspace OR proposal. Subscribe
  separately to each desired event type. Subscription identity includes owner,
  callback URL, event and canonical arguments.
- Payloads contain only event identity/type/time, project/proposal IDs and fixed
  short statuses. No source, diffs, private WIP, paths or raw check output.
- Status reports fixed proposal states and last committed public head ID,
  with an explicit pending-promotion flag. Recheck before any further action.
- Queue and retries are bounded to five minutes in memory. Overflow/faults and
  restart gaps are visible as degraded delivery, never block integration.
  Subscriptions and authentication metadata persist separately. No history replay
  and no exactly-once promise. A webhook receipt is not an agent action.

## Identity and access

Direct GitHub OAuth proves a numeric GitHub identity. GitHub tokens are never MCP
bearer tokens. Wipstash issues audience-bound opaque access tokens and rotating
refresh tokens with hashes stored privately. Separate upstream/downstream PKCE
and state, secure browser binding, CSRF and explicit per-client consent apply.
Only allowlisted ChatGPT CIMD URLs and exact redirects are accepted; no open DCR.
Callbacks are HTTPS-only, with public IP checks, DNS-pinned connections, no
redirects, signed single-use challenge verification and Standard Webhooks HMAC.
The OpenAI callback error code is -32015, not the experimental draft's -32027.

Numeric-ID project grants are explicit. Invites are single-use, valid 24 hours,
bound to the specified numeric ID and project, and require matching GitHub login.
Forwarding a link does not authorize another account. Issuance/revocation requires
local administrator access; no MCP tool exposes it. Local grant removal stops
new requests and sends immediately, though already transmitted bytes cannot be
recalled. Grant epochs prevent old credentials/subscriptions reviving on regrant.
GitHub app revocation alone does not guarantee instant local grant revocation.

The intended initial account is jimmystridh; its numeric ID must be verified
before granting access. No unverified ID, credentials, grants or actual invites
are bundled. OAuth app registration, domain/tunnel and secrets are separate
operator actions. Nothing in the source performs those steps automatically.

## Verification and release gate

    cargo test --locked --manifest-path services/mcp-events/Cargo.toml
    cargo fmt --manifest-path services/mcp-events/Cargo.toml --check
    cargo clippy --locked --manifest-path services/mcp-events/Cargo.toml --all-targets -- -D warnings

Tests use synthetic identities and mock/in-memory transport. Completion also
requires actual GitHub/browser/HTTPS/ChatGPT subscription validation after setup:
connect/rescan, authenticate and consent, list/subscribe/verify callback, trigger
matching and nonmatching events, confirm safe payload/receipt, verify ChatGPT's
response separately, then revoke/unsubscribe and confirm no future delivery.
Record redacted results and exact source revision, never credentials or links
containing invitation/code secrets. Passing local tests is not production-ready.

This source was reconstructed from retained authored patches after a workspace
reset on 2026-10-18. Verification for the prior snapshot does not establish this
snapshot's correctness; see the new evidence report for fresh results.

References:
- https://developers.openai.com/plugins/build/mcp-events
- https://developers.openai.com/plugins/build/auth
- https://developers.openai.com/plugins/deploy/connect-chatgpt
- https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps

## Executable configuration and administration

The executable takes a JSON configuration file followed by an explicit command.
It never starts a listener merely because a configuration was supplied. Example
shape for a same-machine HTTPS proxy or supported private tunnel:

```json
{
  "issuer": "https://wipstash.example.com",
  "bind": "127.0.0.1:8400",
  "https_proxy": true,
  "github": {
    "client_id": "REPLACE_WITH_APPROVED_GITHUB_CLIENT_ID",
    "client_secret_env": "WIPSTASH_GITHUB_CLIENT_SECRET"
  },
  "auth_database": "/srv/wipstash-events/private/auth.sqlite",
  "event_database": "/srv/wipstash-events/private/subscriptions.sqlite",
  "projects": {
    "example-project": "/srv/wipstash-authority/state"
  },
  "clients": [
    {
      "client_id": "https://chatgpt.com/oauth/client.json",
      "name": "ChatGPT",
      "redirect_uris": [
        "https://chatgpt.com/connector_platform_oauth_redirect"
      ]
    }
  ],
  "event_capacity": 1024,
  "max_connections": 128
}
```

This is an example, not a deployed configuration. Replace the issuer, paths and
client identifiers with approved values. The issuer is a canonical HTTPS origin,
without a trailing slash. The MCP resource is exactly `ISSUER/mcp`; GitHub's
registered callback must be exactly `ISSUER/oauth/github/callback`, with wildcard
matching disabled. Use the exact ChatGPT metadata and redirect shown in its
management page. V1 supports allowlisted ChatGPT CIMD URLs with public-client
S256 PKCE and one fixed scope, `mcp:events`, covering permitted status and event
subscriptions. Unsupported client authentication methods are rejected.

Project paths identify existing authority state directories containing
`state.sqlite` and `state.lock`. The service reads them without calling the
engine. No grants are inferred from project configuration or a GitHub username.
The authentication and subscription databases must be separate files in an
already provisioned private directory owned by the service account. On Unix,
that directory must be mode 0700 and private files mode 0600; Windows uses the
existing current-user protected-DACL checks. Use absolute, non-symlink paths.
The service does not create directories or repair permissions.

For direct HTTPS, set `https_proxy` to false, select an appropriate bind address,
and add:

```json
"tls": {
  "certificate": "/srv/wipstash-events/tls/certificate-chain.pem",
  "private_key": "/srv/wipstash-events/private/server-key.pem"
}
```

The private key uses the same audited owner-only file checks as token storage.
In proxy/tunnel mode, the listener is restricted to loopback. The trusted proxy
must preserve the public `Host`, strip `Forwarded` and `X-Forwarded-Host`, and
replace `X-Forwarded-Proto` with exactly `https`. Do not forward arbitrary client
values. The service rejects other hosts, cross-origin browser requests and
plaintext-public listener configurations. Configure proxy access logs to omit
query strings and cookies: OAuth callback codes and invitation links are secret.
The application itself does not log request URLs, tokens, cookies or bodies.

```sh
# Offline configuration validation: no listener, credentials or network calls.
wipstash-mcp-events /absolute/path/config.json check-config

# Run only after deployment, secret provisioning and access are authorized.
wipstash-mcp-events /absolute/path/config.json serve

# Substitute an independently verified numeric GitHub account ID.
wipstash-mcp-events /absolute/path/config.json admin grant GITHUB_NUMERIC_ID example-project
wipstash-mcp-events /absolute/path/config.json admin invite GITHUB_NUMERIC_ID example-project
wipstash-mcp-events /absolute/path/config.json admin revoke GITHUB_NUMERIC_ID example-project
wipstash-mcp-events /absolute/path/config.json admin revoke-user GITHUB_NUMERIC_ID

# Supply only the invitation token, via stdin rather than process arguments.
wipstash-mcp-events /absolute/path/config.json admin revoke-invite < private-invite-token.txt
```

`admin invite` intentionally prints the one-time link and expiry to the invoking
operator. Treat that output as private and send it only to its intended account.
The browser must verify that same GitHub numeric identity before redemption.
Administrative commands use local private-database ownership as their authority;
there are no HTTP administration routes. `revoke` invalidates current token
families as well as the selected project grant and outstanding invitations;
remaining projects require reauthorization. The explicit `check-config` command
validates shape and security policy only; it does not verify credentials, TLS
certificates, GitHub sign-in or real ChatGPT event delivery.
