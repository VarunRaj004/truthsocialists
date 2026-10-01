# ADR 0009: Transaction-coupled Identity Authority idempotency

- Status: Accepted for prototype
- Date: 2026-10-01

## Context

Process-memory idempotency cannot protect a multi-instance service and has a
crash window: a mutation can commit before its replay response is retained.
Enrollment and recovery also allocate permanent membership indices, so silently
re-running either operation is unsafe.

## Decision

Store a UUIDv4 key, request hash, and exact canonical-CBOR response in the
tenant Identity Authority database. Claiming the key, performing the mutation,
and saving the response execute in one PostgreSQL `SERIALIZABLE` transaction.
Matching committed retries return the stored response without re-executing the
operation. Reusing a key with a different request hash fails with a conflict.

Enrollment hashes include the authenticated synthetic identity and request body.
Recovery hashes include the complete canonical request body. When recovery
authorization fails, the attempt counter commits but the incomplete idempotency
claim is removed, permitting a corrected request under the same key.

Records expire after 24 hours. Clients must not assume replay availability after
that window. The in-memory coordinator remains a test-only adapter for fake
operations.

## Consequences

- A database commit always retains the response needed for safe retries.
- Multiple service instances share the same replay and conflict decision.
- Recovery replay succeeds even though the underlying challenge is consumed.
- Cleanup must retain completed records for the documented 24-hour window.
