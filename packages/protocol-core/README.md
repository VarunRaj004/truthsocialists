# `@cyber-cipher/protocol-core`

The first executable Cyber Cipher component. It implements protocol framing and validation that must agree across mobile clients and services.

Implemented:

- RFC 8949 deterministic-CBOR encoding and strict decoding for the Cyber Cipher profile
- rejection of indefinite lengths, non-minimal values, invalid UTF-8/NFC, duplicate or misordered keys, forbidden simple values, and trailing bytes
- byte/hex/base64url and unsigned-big-endian helpers
- SHA-256 length framing and BN254 hash-to-field conversion
- BN254 field-element canonicality checks
- Poseidon domain-constant derivation
- canonical entitlement, complaint-manifest, log-entry, receipt, and membership-checkpoint builders
- DER-SPKI key identifiers and domain-separated Ed25519 verification
- conformance tests against the checked-in Python-generated vectors

Not implemented here:

- AES-GCM, HPKE, RSA blind signatures, Poseidon permutations, Groth16, or key generation
- service-specific authorization and unknown-field policy beyond exported exact-key helpers
- network, database, or user-interface behavior

Run from the repository root:

```text
pnpm install
pnpm check
pnpm test
```

This package intentionally has no runtime dependencies. It uses Node's cryptographic implementation for SHA-256 and Ed25519 verification.
