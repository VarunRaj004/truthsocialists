# ADR 0006: Durable membership checkpoint publication

- Status: Accepted
- Date: 2026-10-01

## Context

Enrollment and recovery change the active Poseidon membership tree immediately,
but complaint proofs use only signed public roots. Publishing a root without the
exact ordered delta, or deleting queued updates before the checkpoint commits,
could leave clients unable to reconstruct membership paths. A corrupted
materialized leaf table must also not be silently signed.

## Decision

A tenant checkpoint worker runs immediately and every 30 seconds without
overlapping executions. Publication uses one PostgreSQL `SERIALIZABLE`
transaction that locks membership state and pending updates. It replays the full
published update history from the fixed empty tree, verifies the previous root
and checkpoint hash, applies the pending operations in sequence, and independently
reconstructs the materialized leaf table. The two roots must match.

Only then does the worker create the deterministic-CBOR delta, sign the next
checkpoint with the tenant's dedicated Ed25519 key, persist the checkpoint and
ordered update rows, advance the hash chain, mark leaf epochs, and delete the
published queue entries. The signer output is verified against its advertised
public key before database mutation.

## Consequences

- A returned checkpoint always has its complete reconstructable delta.
- A crash before commit leaves the pending batch available for retry.
- Database drift or checkpoint-chain corruption fails closed before signing.
- More than one update to the same leaf in a batch is allowed and remains ordered.
- Full-history replay is intentionally simple for the prototype; snapshots or
  incremental authenticated state can optimize it after profiling without
  changing the public protocol.
