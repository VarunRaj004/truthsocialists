# Community Core

Phase 8 implements privacy-reviewed public derivatives, anonymous assessment,
and auditor comparison:

- publication requires explicit complainant opt-in, a handler-authored derivative,
  automated PII screening, and approval by a different staff member with the
  reviewer role;
- public payloads contain only normalized text and content-addressed sanitized
  derivatives. Their commitment binds the private complaint commitment and
  immutable ciphertext hash as provenance;
- the existing Groth16 vote circuit is verified against a signed current-root
  vote lease, complaint scope, fixed choice, commitment, and person-derived
  nullifier. One nullifier can vote once per complaint, including after device
  replacement because it derives from persistent `P`;
- the window is exactly seven days; results need ten votes and 60% support for
  either `SUPPORT` or `OPPOSE`, otherwise they are `INCONCLUSIVE`;
- an authenticated auditor signs comparison and freeze/escalation events.
  Freezing changes only public visibility and never closes, deletes, or changes
  the private handler case;
- PostgreSQL constraints preserve opt-in, unique vote nullifiers, fixed windows,
  and append-only votes/assessments.

Votes assess the approved redacted information; they do not establish truth.
