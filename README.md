# Truth Socialists - Cyber Cipher

Cyber Cipher is an eligibility-gated anonymous complaint platform designed around unlinkable blind entitlements, private active-membership proofs, encrypted handler routing, recoverable device revocation, anonymous follow-up, community assessment, and publicly verifiable transparency logs.

This repository contains the completed synthetic-data experimental MVP and its version 1 design baseline.

## Start here

- [Specification package index](docs/cyber-cipher/README.md)
- [Updated SRS](docs/cyber-cipher/01_UPDATED_SRS.md)
- [Cryptographic protocol](docs/cyber-cipher/03_CRYPTOGRAPHIC_PROTOCOL.md)
- [Implementation roadmap](docs/cyber-cipher/07_IMPLEMENTATION_ROADMAP.md)
- [Security acceptance plan](docs/cyber-cipher/08_SECURITY_AND_ACCEPTANCE_TEST_PLAN.md)
- [MVP deployment and acceptance runbook](docs/cyber-cipher/11_MVP_DEPLOYMENT_AND_ACCEPTANCE.md)
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

The synthetic-data experimental MVP is complete through Phase 8 and includes a
tenant-fixed local/SaaS demo runtime with separate trust-zone database routes.
Run `pnpm acceptance:mvp` for the automated release suite, or follow the
[deployment runbook](docs/cyber-cipher/11_MVP_DEPLOYMENT_AND_ACCEPTANCE.md).

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
- pinned Circom 2.2.3/circomlib 2.0.5/snarkjs 0.7.6 tooling, complaint and
  community-vote Groth16/BN254 circuits, locked constraint counts, negative
  witness tests, a content-addressed proof-verifier allowlist, canonical artifact
  manifests, real development-proof integration tests, and a backend-neutral
  client prover boundary for later Android/iOS Rapidsnark adapters.
- the first Phase 5 complaint-client slice: evidence type/size/signature policy,
  NFC text normalization, privacy-neutral filenames, deterministic-CBOR manifests,
  salted commitments, AES-256-GCM package encryption, and handler-specific HPKE
  DEK wrapping with authenticated routing context.
- tenant-bound, signed 60-second proof-session leases and a PostgreSQL complaint
  acceptance transaction that atomically spends the entitlement/nullifier,
  records encrypted-object metadata, queues the initial transparency-log event,
  signs the randomized receipt, and consumes the challenge only on success.
- anonymous deterministic-CBOR complaint HTTP endpoints, durable
  content-addressed ciphertext storage, fixed RSA-entitlement/lease/Groth16
  verification order, and transaction-coupled 24-hour request idempotency.
- RFC 6962 transparency-tree construction, inclusion/consistency proofs,
  hash-chained Ed25519 tree heads, three prototype witnesses with 2-of-3
  finality, gossip fork evidence, public CBOR download/proof responses, durable
  tenant-bound storage, and offline receipt/log verification.
- P-256 WebAuthn staff authentication, assignment-only handler access, signed
  allowed/denied audit decisions, policy-versioned case lifecycles and SLA
  controls, DEK-only cross-organization HPKE rewrap, and anonymous bidirectional
  HPKE mailbox messaging with encrypted recovery bundles.
- opt-in public derivatives with PII screening and independent review,
  Groth16-backed anonymous community votes with seven-day/quorum/threshold rules,
  unique complaint-scoped nullifiers, and signed auditor comparison, freeze, and
  escalation events that cannot alter the private case.

See [`packages/protocol-core`](packages/protocol-core/README.md),
[`packages/membership-core`](packages/membership-core/README.md),
[`packages/identity-store`](packages/identity-store/README.md), and
[`packages/matter-registry`](packages/matter-registry/README.md), and
[`packages/zk-circuits`](packages/zk-circuits/README.md), and
[`packages/complaint-core`](packages/complaint-core/README.md), and
[`packages/complaint-store`](packages/complaint-store/README.md) for the
executable code and current boundaries. Phase 6 is in
[`packages/transparency-log`](packages/transparency-log/README.md), and
[`packages/handler-core`](packages/handler-core/README.md) contains the Phase 7
handler and anonymous-mailbox boundary. Phase 8 is in
[`packages/community-core`](packages/community-core/README.md). The current HTTP boundaries are in
[`services/ida`](services/ida/README.md) and
[`services/complaint-intake`](services/complaint-intake/README.md).

This is not production-ready software. Real deployment requires external cryptographic, penetration, privacy, accessibility, legal, and operational reviews.
