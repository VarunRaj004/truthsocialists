# Cyber Cipher Specification Package

Status: Prototype design baseline 1.0

Date: 2026-09-25

Source documents: the August/September 2026 SRS, current-system study, and cryptographic design supplied by Team Cyber Ciphers.

This directory is the implementation baseline for Cyber Cipher, an unlinkable, eligibility-gated complaint platform. It supersedes conflicting technical statements in the source PDFs while preserving their central objectives: one eligible person per matter, anonymous complaint submission, device revocation, confidential handling, anonymous follow-up, community corroboration, and public auditability.

## Deliverables

1. [Updated SRS](01_UPDATED_SRS.md)
2. [Threat model and privacy/data-flow model](02_THREAT_MODEL_AND_DATA_FLOWS.md)
3. [Cryptographic protocol specification](03_CRYPTOGRAPHIC_PROTOCOL.md)
4. [Canonical CBOR schemas and test vectors](04_CBOR_SCHEMAS_AND_TEST_VECTORS.md)
5. [Database and API contracts](05_DATABASE_AND_API_CONTRACTS.md)
6. [Service architecture](06_SERVICE_ARCHITECTURE.md)
7. [Phased implementation roadmap](07_IMPLEMENTATION_ROADMAP.md)
8. [Security and acceptance-test plan](08_SECURITY_AND_ACCEPTANCE_TEST_PLAN.md)
9. [Deliverable 4: comparative verifiability report](DELIVERABLE_4_VERIFIABILITY_REPORT.md)
10. [SaaS tenancy profile](09_SAAS_TENANCY.md)
11. [Phase 4 operator checklist](10_PHASE4_OPERATOR_CHECKLIST.md)

Machine-readable supporting artifacts are under `schemas/`, `api/`, `database/`, and `test-vectors/`.

## Binding design decisions

- Prototype private membership: Groth16 over BN254, Circom 2, Poseidon, depth-16 append-only active-membership tree.
- Entitlement: matter-version-specific RSA-3072 RSABSSA-SHA384-PSS-Randomized blind signature.
- Hybrid binding: the entitlement contains a commitment to the same hidden person secret used by the membership proof and matter nullifier.
- Revocation: revoked leaves become a fixed empty value; indices are never reused; membership checkpoints update in 30-second batches.
- Submission roots: current root only, protected by a signed 60-second proof-session lease.
- Recovery: user-held 128-bit recovery seed; derived Ed25519 recovery key; five-minute challenges; mandatory rotation after every successful recovery.
- Complaint confidentiality: per-complaint AES-256-GCM data key wrapped to the handler organization using HPKE X25519/HKDF-SHA256/AES-256-GCM.
- Complaint integrity: salted SHA-256 over a deterministic-CBOR manifest.
- Receipts: randomized contents, deterministic CBOR, dedicated Ed25519 signature.
- Transparency: RFC 6962-style SHA-256 append-only Merkle log, Ed25519 signed tree heads, three witnesses, 2-of-3 quorum.
- Anonymous follow-up: complaint-specific Ed25519/X25519 mailbox keys derived from a fresh 256-bit seed.
- Future work: a custom zero-knowledge RSA accumulator membership provider behind the same membership interface.

## Normative language

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as requirement levels. Security-relevant encodings use deterministic CBOR as defined by RFC 8949; floats and indefinite-length values are forbidden.

## Remaining deployment inputs

The design is implementable, but a real deployment must name the IdA, handler organizations, auditor, and three independent witnesses; select a jurisdiction; validate retention periods; provision domains and KMS/HSM resources; and approve the initial matter catalogue. These are configuration and governance inputs, not unresolved protocol choices.
