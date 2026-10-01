# Matter registry

`@cyber-cipher/matter-registry` is the tenant-bound public matter and key-metadata
boundary for Phase 3.

It provides:

- RSA-3072 RSASSA-PSS key generation with exponent 65537, SHA-384,
  MGF1-SHA384, and a 48-byte salt profile;
- strict validation of the PSS parameters embedded in canonical DER
  SubjectPublicKeyInfo;
- the full SHA-256 SPKI fingerprint as `matterKeyId`;
- AES-256-GCM encryption of PKCS#8 private keys using an injected secret-manager
  KEK, with tenant/matter/version/key identifiers authenticated as AAD;
- a tenant-bound PostgreSQL registry containing public keys and metadata only;
- immutable, sequential matter versions and UUIDv4 matter identifiers;
- enforcement of publication at least 24 hours before opening;
- derived `PUBLISHED`, `OPEN`, `CLOSED`, and explicit `RETIRED` lifecycle states.

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
