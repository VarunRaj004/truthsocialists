# `@cyber-cipher/membership-core`

Tenant-scoped active-membership prototype for Cyber Cipher.

Implemented:

- Circom-compatible Poseidon hashing over BN254
- the specified person, device, member-leaf, empty-leaf, and Merkle-node formulas
- sparse configurable trees, with depth 16 as the production profile
- monotonic leaf allocation; revoked indices are replaced with the fixed empty leaf and never reused
- membership-path construction and verification
- synthetic-only enrollment guardrails
- device/recovery rotation after external recovery authentication
- deterministic public update batches and Ed25519-signed checkpoint chains
- SaaS registry isolation and a ban on checkpoint-key reuse between tenants

The in-memory service is a security-domain prototype, not a durable transaction store. Its `rotateAfterVerifiedRecovery` entry point assumes the recovery challenge and old recovery signature were already verified. The next slice will implement that five-minute challenge protocol and a serializable persistence adapter.

Each SaaS tenant owns a separate service instance, checkpoint key, membership state, database routing target, and public checkpoint namespace. The public update-batch hash commits the 16-byte tenant ID; checkpoint keys cannot be shared across tenants.

Run from the repository root:

```text
pnpm check
pnpm test
```
