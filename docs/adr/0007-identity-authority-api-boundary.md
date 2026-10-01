# ADR 0007: Identity Authority API boundary

- Status: Accepted for prototype
- Date: 2026-10-01

## Context

The membership and recovery libraries need a network boundary without allowing
clients to choose a tenant, submit their own identified subject, or move
signature verification outside the locked recovery transaction. The public
checkpoint API must not expose enrollment records.

## Decision

The Identity Authority service instance is constructed for one trusted tenant
and one tenant-dedicated database. Identified enrollment receives its synthetic
identity reference exclusively from an injected authenticated-session adapter.
It is not present in the deterministic-CBOR request body.

Recovery challenges use a dedicated Ed25519 key distinct from the membership
checkpoint key. Recovery authorization verification runs through the
`completeRecoveryAtomic` callback using the challenge and enrollment values
locked by PostgreSQL. Public routes return only signed checkpoints and ordered
deltas.

The HTTP adapter accepts only `application/cbor`, limits request bodies to 64
KiB, requires UUIDv4 idempotency keys for enrollment and recovery completion,
returns generic CBOR errors, and emits no request logs. The supplied in-memory
idempotency implementation is restricted to local tests; durable transaction-
coupled idempotency remains required for the Phase 2 exit gate.

## Consequences

- A request cannot override tenant routing or its authenticated identity.
- Recovery signature checks cannot race an enrollment rotation.
- Public membership synchronization does not query or serialize identity rows.
- Deployments must provide a real session adapter and persistent idempotency
  implementation rather than silently trusting headers.
