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
- proof-lease, complaint-encryption AAD, handler-DEK AAD, and artifact-manifest builders
- DER-SPKI key identifiers and domain-separated Ed25519 verification
- strict receipt, membership-checkpoint, and current-root proof-lease verification
- AES-256-GCM sealing/opening with 256-bit keys, 96-bit nonces, and 128-bit tags
- RFC 9180 base-mode HPKE handler-DEK wrapping using X25519/HKDF-SHA256/AES-256-GCM
- RFC 6962-style SHA-256 log leaf and node hashes
- conformance tests against the checked-in Python-generated vectors
- a NIST AES-256-GCM vector, HPKE context-binding tests, and randomized CBOR parser smoke fuzzing

Not implemented here:

- RSA blind signatures, Poseidon permutations, Groth16, or service signing-key generation
- service-specific authorization and unknown-field policy beyond exported exact-key helpers
- network, database, or user-interface behavior

Run from the repository root:

```text
pnpm install
pnpm check
pnpm test
```

The package uses Node's cryptographic implementation for SHA-256, AES-GCM, and Ed25519 verification. HPKE is delegated to pinned `@hpke/core` and `@hpke/dhkem-x25519` packages; protocol code does not implement the RFC 9180 primitives.
