# ADR 0003: Isolate SaaS tenants by trust zone and key namespace

- Status: Accepted
- Date: 2026-09-30

## Context

Cyber Cipher can serve multiple organizations, but conventional row-level multi-tenancy would make one missing tenant predicate capable of linking identity and complaint data across customers. Membership roots and signing keys also need unambiguous tenant ownership.

## Decision

The prototype uses a shared stateless application/control plane with a separate identity database, complaint database, object-store namespace, and KMS key namespace per tenant. High-assurance customers may receive a fully dedicated deployment using the same interfaces.

Every tenant has distinct checkpoint, proof-lease, receipt, RSA entitlement, handler HPKE, log, and witness configuration. Checkpoint signing keys cannot be reused across tenants. Membership services are constructed for exactly one 16-byte tenant ID. Public membership deltas include that tenant ID, and their hash is signed indirectly through the membership checkpoint.

The control plane stores tenant routing and public configuration only. It cannot query identity and complaint stores together. Real NIC values and complaint content are forbidden from control-plane telemetry.

## Consequences

- A database-routing or key-selection error fails at a tenant-specific signature/key-ID boundary.
- Per-tenant databases cost more than shared tables but reduce cross-tenant disclosure risk and simplify deletion, residency, backup, and dedicated-deployment requirements.
- Shared proof-verification workers must be stateless and receive an allowlisted tenant configuration selected before parsing untrusted proof metadata.
- Production routing, authorization, and persistence adapters still require adversarial isolation testing.
