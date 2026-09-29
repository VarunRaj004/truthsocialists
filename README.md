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

Design baseline complete. The TypeScript Phase 1 protocol core is implemented; cross-language conformance and dedicated continuous fuzzing remain before the Phase 1 exit gate.

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
- conformance tests against the published reference vectors.

See [`packages/protocol-core`](packages/protocol-core/README.md) for the executable code and boundaries.

This is not production-ready software. Real deployment requires external cryptographic, penetration, privacy, accessibility, legal, and operational reviews.
