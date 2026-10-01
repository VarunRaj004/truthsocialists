# Matter registry

`@cyber-cipher/matter-registry` is the tenant-bound public matter and key-metadata
boundary for Phase 3.

It provides:

- dedicated RSA-3072 key generation with exponent 65537 and canonical DER;
- a pinned RFC 9474 `RSABSSA-SHA384-PSS-Randomized` implementation, which fixes
  SHA-384, MGF1-SHA384, a 48-byte salt, and 32-byte message randomization;
- client preparation/blinding/finalization and server blind-signing boundaries;
- the full SHA-256 SPKI fingerprint as `matterKeyId`;
- AES-256-GCM encryption of PKCS#8 private keys using an injected secret-manager
  KEK, with tenant/matter/version/key identifiers authenticated as AAD;
- a tenant-bound PostgreSQL registry containing public keys and metadata only;
- immutable, sequential matter versions and UUIDv4 matter identifiers;
- enforcement of publication at least 24 hours before opening;
- derived `PUBLISHED`, `OPEN`, `CLOSED`, and explicit `RETIRED` lifecycle states.
- post-close retirement automation that publishes a destruction-evidence digest.

The generated private PKCS#8 bytes are transient. Callers must encrypt them
immediately, erase their buffers where the runtime permits, and write only the
encrypted envelope to a dedicated secrets volume. The registry schema contains
no private-key, KEK, entitlement, identity, or complaint-content column.

Node uses its OpenSSL RSA generator. This produces the required FIPS 186-5-
compatible profile, but production claims of FIPS validation additionally
require deploying Node/OpenSSL with an approved FIPS provider and configuration.

## Integration test

Set `TEST_DATABASE_URL` to an isolated PostgreSQL database whose name ends in
`test`, then run `pnpm --filter @cyber-cipher/matter-registry test`. Only the
`matter_registry` schema is reset.
