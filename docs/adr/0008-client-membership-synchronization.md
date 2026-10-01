# ADR 0008: Client membership synchronization from genesis

- Status: Accepted
- Date: 2026-10-01

## Context

Semaphore-style proofs require the client to know the current signed root and a
valid path for its active leaf. Asking the Identity Authority for a private path
would reveal which membership index the client controls. Accepting snapshots
without their history would also make equivocation and malformed deltas harder
to detect.

## Decision

The prototype client starts from the fixed depth-16 empty tree and downloads the
public ordered delta chain. For every epoch it verifies the dedicated Ed25519
checkpoint signature, exact predecessor hash, contiguous epoch, non-decreasing
publication time, tenant ID in the delta, delta hash, contiguous operation
sequence, activation/revocation semantics, and reconstructed Poseidon root.

Updates are applied to a copy of the accepted leaves and tree. State changes only
after every check passes. Membership proofs are generated locally, and proof
path bits must match the claimed leaf index.

## Consequences

- The server does not learn which membership path a client needs.
- Skipped, reordered, cross-tenant, modified, or root-inconsistent updates fail
  without corrupting the last accepted client state.
- New installations must synchronize from epoch zero for the prototype. A later
  trusted snapshot format may reduce startup cost without changing checkpoints.
- Delta distribution can be cached publicly because it contains no identity
  mapping or recovery information.
