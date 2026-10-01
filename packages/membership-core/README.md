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
- HKDF-SHA256 recovery signing, person-backup, and mailbox-bundle key derivation
- deterministic Ed25519 recovery keys derived from the 128-bit user-held seed
- AES-256-GCM recovery backups bound to tenant, recovery ID, purpose, and generation
- tenant-bound signed five-minute recovery challenges with bounded attempts
- old-recovery-key authorization, one-time challenge consumption, and mandatory credential rotation
- deterministic public update batches and Ed25519-signed checkpoint chains
- client-side ordered-delta parsing, checkpoint-chain verification, atomic local
  tree updates, and current membership-witness construction
- SaaS registry isolation and a ban on checkpoint-key reuse between tenants

The in-memory service remains the security-domain model. `TenantRecoveryService`
verifies the five-minute challenge and old recovery signature before calling
`rotateAfterVerifiedRecovery`; `@cyber-cipher/identity-store` provides the
serializable PostgreSQL implementation used across processes and restarts.

`MembershipCheckpointClient` begins at the fixed empty tree and accepts only a
contiguous chain. Every update verifies the dedicated checkpoint signature,
predecessor hash, tenant-bound delta hash, operation sequence and semantics,
publication-time monotonicity, and the reconstructed Poseidon root. A rejected
update leaves the last accepted tree unchanged.

Each SaaS tenant owns a separate service instance, checkpoint key, membership state, database routing target, and public checkpoint namespace. The public update-batch hash commits the 16-byte tenant ID; checkpoint keys cannot be shared across tenants.

Run from the repository root:

```text
pnpm check
pnpm test
```
