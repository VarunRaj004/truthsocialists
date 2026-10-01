# ADR 0005: Serializable identity and recovery transactions

- Status: Accepted
- Date: 2026-10-01

## Context

Enrollment allocates a never-reused membership-tree index. Recovery changes the
active device and recovery credential while revoking the old membership leaf and
allocating a replacement. Partial completion would either strand the user,
retain a lost device as active, or make the public membership view disagree with
the identity authority.

The SaaS design also requires identity data to stay inside a tenant trust zone.
Selecting a tenant from an untrusted request field would permit cross-tenant
routing attacks.

## Decision

Each prototype identity database is bound on first initialization to one tenant
UUID and slug. Application routing resolves the database from an authenticated,
trusted tenant identity.

Index allocation and recovery use PostgreSQL `SERIALIZABLE` transactions with
bounded retries. A successful recovery transaction locks the challenge and
enrollment, verifies the challenge's recovery generation, invokes cryptographic
authorization over the locked values, then atomically:

1. replaces the old leaf with the fixed empty value;
2. allocates a fresh monotonic index and active leaf;
3. queues the revoke and activate operations;
4. rotates the recovery ID and Ed25519 public key;
5. increments the recovery generation; and
6. consumes the one-time challenge.

Failed authorization increments the durable attempt counter without revealing
whether the recovery identifier maps to an active enrollment at the public API.

## Consequences

- Concurrent enrollments cannot receive the same index.
- Concurrent submissions of one recovery challenge can produce only one rotation.
- An old signed challenge cannot authorize a later recovery generation.
- The identity service must use a PostgreSQL database per tenant for this phase.
- Tree checkpoint publication remains a separate worker that drains the durable
  pending-update queue; it is the next persistence milestone.
