# ADR 0002: Bounded volatile event delivery

Status: accepted, 2026-10-18.

Use a bounded five-minute in-memory queue/retry budget instead of durable event
delivery history. Subscription/auth metadata persists independently. Stable IDs
allow duplicate recognition, but no exactly-once or historical replay promise.

This intentionally accepts loss on restart/overflow. Queue faults must not block
integration; delivery degradation is visible. Recipients recheck current state
before acting. A webhook receipt acknowledges transport, not an agent action.
