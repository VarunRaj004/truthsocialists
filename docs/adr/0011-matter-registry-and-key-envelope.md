# ADR 0011: Matter registry and RSA key envelope

- Status: Accepted for prototype; RSA DER encoding amended by ADR 0012
- Date: 2026-10-01

## Context

Blind entitlement issuance requires every matter version to publish immutable,
verifiable RSA parameters before submissions open, while keeping private key
material out of application databases and the repository.

## Decision

Create a tenant-bound PostgreSQL matter registry that stores only public
metadata. Matter IDs are UUIDv4 values; versions are positive unsigned 32-bit
integers beginning at one and advancing without gaps. Publication is rejected
unless it occurs at least 24 hours before the opening time.

Generate a dedicated 3072-bit RSA key for each version with exponent 65537.
ADR 0012 records why the canonical standalone SPKI uses the generic RSA
encoding while the only permitted operation fixes the RFC 9474 PSS suite. The
full SHA-256 SPKI hash is `matterKeyId`.

Encrypt transient PKCS#8 DER using AES-256-GCM and an injected secret-manager
KEK. The authenticated context binds tenant ID, matter ID/version,
`matterKeyId`, and KEK key ID. Only the encrypted envelope may be written to the
dedicated secrets volume; the registry has no private-key or KEK column.

## Consequences

- A wrong-size, wrong-exponent, or non-RSA key is rejected before publication;
  suite isolation is enforced by the dedicated-key and signing-service boundary.
- Public metadata cannot be silently edited; corrections require the next version.
- Backdating cannot bypass the lead-time rule because the store supplies its
  trusted clock value.
- FIPS validation is an operational property of the deployed OpenSSL provider;
  the code enforces a compatible key profile but does not itself certify the runtime.
