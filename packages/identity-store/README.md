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
- a registry that resolves stores from a trusted tenant identity.

## Migration

Run `applyIdentityMigrations(pool)` and then `store.initializeTenant()` once for
the tenant database. The first initialization binds the database; later calls
must provide exactly the same tenant UUID and slug.

## Integration test

Set `TEST_DATABASE_URL` to an isolated PostgreSQL database whose name ends in
`test`, then run `pnpm --filter @cyber-cipher/identity-store test`. The test
resets only the `ida` schema and verifies concurrent allocation and double-submit
recovery behavior. Without the variable, the PostgreSQL test is explicitly
skipped while type checking and compilation still run.
