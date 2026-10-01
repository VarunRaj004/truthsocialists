# Identity store

`@cyber-cipher/identity-store` is the PostgreSQL persistence boundary for the
prototype identity authority. Each database is permanently bound to one trusted
tenant UUID and slug. Tenant selection must come from the authenticated SaaS
routing layer, never from a request-body field.

The store currently provides:

- synthetic-only enrollment with monotonic, never-reused membership indices;
- durable five-minute recovery challenges and failed-attempt counters;
- serializable recovery transactions that consume the challenge, rotate the
  Ed25519 recovery credential, revoke the old leaf, allocate a new leaf, and
  enqueue both tree updates atomically;
- replay protection through challenge consumption and recovery-generation checks;
- 24-hour PostgreSQL idempotency records whose response bytes commit in the
  same serializable transaction as enrollment or recovery completion;
- a minimal, unique issuance fact per enrollment/matter version, committed
  atomically with the blind-signature response and containing no blind protocol
  value, entitlement serial, commitment, or signature;
- a serializable checkpoint publisher that reconstructs and validates the full
  update history before signing each new Poseidon root;
- a non-overlapping 30-second worker, plus current-checkpoint and paginated-delta
  reads for public API adapters;
- a registry that resolves stores from a trusted tenant identity.

## Migration

Run `applyIdentityMigrations(pool)` and then `store.initializeTenant()` once for
the tenant database. The first initialization binds the database; later calls
must provide exactly the same tenant UUID and slug.

## Integration test

Set `TEST_DATABASE_URL` to an isolated PostgreSQL database whose name ends in
`test`, then run `pnpm --filter @cyber-cipher/identity-store test`. The test
resets only the `ida` schema and verifies concurrent allocation, durable replay,
changed-request conflicts, and double-submit recovery behavior. Without the
variable, the PostgreSQL test is explicitly
skipped while type checking and compilation still run.

## Checkpoint worker

Create a `PostgresCheckpointPublisher` with the tenant's dedicated Ed25519
checkpoint signer, then wrap it in `MembershipCheckpointWorker` and call
`start(onError)`. The worker runs immediately and every 30 seconds without
overlapping ticks. Publication locks membership state, replays persisted history,
checks it against the last signed root and current leaf table, signs the next
checkpoint, persists its ordered delta, advances the hash chain, and removes the
published queue entries in one serializable transaction.
