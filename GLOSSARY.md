# Wipstash glossary

- **Checkpoint:** deliberate capture of private workspace state, including broken code.
- **Proposal:** explicitly published checkpoint submitted for integration.
- **Integration:** authority decision to incorporate an accepted proposal into public history.
- **Adoption:** separate deliberate update of live workspace files to a public target.
- **Action-required event:** sanitized observation of a merge conflict, failed check or evaluator failure; a new failed attempt has a distinct event identity.
- **Event subscription:** persistent owner-bound choice of event/filter/callback and lifetime.
- **Volatile delivery buffer:** bounded five-minute in-memory retry queue, lost on restart; not replay history.
- **GitHub principal:** stable numeric GitHub account identity, distinct from a mutable login name.
- **Project grant:** local Wipstash authorization for that principal; checked on requests and delivery.
- **Grant epoch:** persisted version preventing revoked credentials/subscriptions reviving after regrant.
- **Invitation:** administrator-issued single-use 24-hour link bound to a numeric account and project.
