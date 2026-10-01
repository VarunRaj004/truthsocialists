# Truth Socialists - Cyber Cipher

Cyber Cipher is an eligibility-gated anonymous complaint platform designed around unlinkable blind entitlements, private active-membership proofs, encrypted handler routing, recoverable device revocation, anonymous follow-up, community assessment, and publicly verifiable transparency logs.

This repository currently contains the version 1 design baseline and implementation contracts.

## Start here

- [Specification package index](docs/cyber-cipher/README.md)
- [Updated SRS](docs/cyber-cipher/01_UPDATED_SRS.md)
- [Cryptographic protocol](docs/cyber-cipher/03_CRYPTOGRAPHIC_PROTOCOL.md)
- [Implementation roadmap](docs/cyber-cipher/07_IMPLEMENTATION_ROADMAP.md)
- [Security acceptance plan](docs/cyber-cipher/08_SECURITY_AND_ACCEPTANCE_TEST_PLAN.md)
- [Deliverable 4: comparative verifiability report](docs/cyber-cipher/DELIVERABLE_4_VERIFIABILITY_REPORT.md)
- [Consolidated PDF](deliverables/Cyber_Cipher_Design_Baseline_v1.pdf)
- [Downloadable specification ZIP](deliverables/Cyber_Cipher_Specification_Package_v1.zip)

Machine-readable supporting artifacts include:

- deterministic-CBOR CDDL;
- reproducible CBOR/hash/Ed25519 test vectors and generator;
- OpenAPI 3.1 boundary contract;
- reference PostgreSQL schema;
- Mermaid service-architecture source;
- consolidated PDF builder.

## Prototype cryptographic baseline

- RSA-3072 `RSABSSA-SHA384-PSS-Randomized` blind entitlement per matter version
- Groth16 over BN254 with Poseidon and a depth-16 active-membership tree
- AES-256-GCM complaint encryption with X25519/HKDF-SHA256/AES-256-GCM HPKE key wrapping
- Ed25519-signed receipts, leases, checkpoints, and transparency-log tree heads
- RFC 6962-style SHA-256 append-only log with three witnesses and 2-of-3 finality

The prototype uses Semaphore-style Merkle membership. A custom zero-knowledge RSA accumulator remains planned research work behind the membership-provider interface.

## Current status

Design baseline complete. The TypeScript Phase 1 protocol core and the first
tenant-isolated identity persistence slice are implemented; cross-language
conformance and dedicated continuous fuzzing remain before the Phase 1 exit gate.

Implemented so far:

- pnpm/TypeScript monorepo foundation and protocol-conformance CI;
- strict deterministic-CBOR encoder/decoder;
- SHA-256 framing, BN254 scalar validation, hash-to-field and domain constants;
- canonical protocol-object builders;
- Ed25519 signature/key-ID verification;
- strict receipt, membership-checkpoint, and 60-second proof-lease verification;
- AES-256-GCM complaint encryption helpers and deterministic authenticated-data bindings;
- RFC 9180 base-mode X25519/HKDF-SHA256/AES-256-GCM handler-DEK wrapping;
- RFC 6962-style log leaf/node hashing and circuit artifact manifests;
- tenant-scoped depth-16 Poseidon membership tree, monotonic allocation, revocation, recovery rotation, public deltas, and signed checkpoints;
- HKDF-derived recovery keys, encrypted recovery backups, signed five-minute challenges, one-time authorization, and mandatory recovery rotation;
- SaaS tenant registry that forbids checkpoint-key reuse and keeps tenant trust zones separately routed;
- tenant-bound PostgreSQL identity storage with serializable enrollment allocation,
  durable recovery challenges, atomic device/recovery rotation, and old-leaf revocation;
- durable 30-second membership checkpoint publication with history replay,
  signed hash chaining, ordered deltas, and non-overlapping worker execution;
- deterministic-CBOR Identity Authority endpoints for authenticated synthetic
  enrollment, signed recovery, current checkpoints, and paginated deltas, with
  transaction-coupled PostgreSQL idempotency for enrollment and recovery;
- tenant-bound Ed25519 institutional-session tokens with issuer, audience,
  lifetime, session-ID, and synthetic-subject validation;
- tenant-bound matter publication with immutable UUID/version metadata,
  RSA-3072 enforcement, 24-hour lead time, and encrypted PKCS#8 envelopes;
- RFC 9474 randomized blind-entitlement issuance with local final verification,
  one issuance fact per enrolled person/matter version, public matter discovery,
  and evidence-bearing post-close key retirement;
- a client membership synchronizer that validates checkpoint signatures, hash
  chaining, tenant deltas, Poseidon roots, and active membership paths;
- conformance tests against the published reference vectors.

See [`packages/protocol-core`](packages/protocol-core/README.md),
[`packages/membership-core`](packages/membership-core/README.md),
[`packages/identity-store`](packages/identity-store/README.md), and
[`packages/matter-registry`](packages/matter-registry/README.md) for the
executable code and current boundaries. The network boundary is in
[`services/ida`](services/ida/README.md).

This is not production-ready software. Real deployment requires external cryptographic, penetration, privacy, accessibility, legal, and operational reviews.
