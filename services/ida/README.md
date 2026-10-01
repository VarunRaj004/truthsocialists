# Identity Authority service

`@cyber-cipher/ida-service` is the tenant-bound application and HTTP boundary for
prototype enrollment, recovery, and public membership synchronization. It uses
Node's HTTP server directly and introduces no web-framework dependency.

## Implemented routes

- `POST /ida/v1/enrollments`
- `POST /ida/v1/recovery/challenges`
- `POST /ida/v1/recovery/complete`
- `GET /public/v1/membership/checkpoints/current`
- `GET /public/v1/membership/deltas?afterEpoch=0&limit=100`

All bodies and successful responses are deterministic CBOR. Write bodies are
limited to 64 KiB. Enrollment and recovery completion require a UUIDv4
`Idempotency-Key`. Error bodies contain only a stable generic code.

Enrollment does not accept an identity field. An injected
`EnrollmentSessionAuthorizer` derives the synthetic identity reference from an
already authenticated session. The service instance is bound to one tenant, so
request fields cannot select a database or signing key.

## Recovery verification

The application creates a signed five-minute challenge with the dedicated
recovery-challenge Ed25519 key. Completion verifies the exact stored challenge,
tenant, recovery ID, generation, expiry, person anchor, new device hash, new
recovery ID, and new recovery public key inside the locked PostgreSQL recovery
transaction. The challenge and checkpoint keys are required to be different.

## Composition boundary

`createIdentityHttpServer` requires explicit implementations for:

- `IdentityAuthorityOperations`, normally `IdentityAuthorityApplication`;
- the authenticated enrollment-session adapter.

`IdentityAuthorityApplication` uses the PostgreSQL store's durable idempotent
operations. The request hash, exact response CBOR, and state mutation commit in
one serializable transaction; a committed retry therefore returns the original
bytes without allocating another leaf or consuming a challenge twice. Enrollment
hashes bind the authenticated synthetic identity as well as the request body.

`InMemoryIdempotencyCoordinator` remains available only as a fallback for local
tests and fake operations that do not implement the durable methods. It must not
be used for a multi-instance deployment.
The service intentionally has no default trust-header or development-login
bypass.
