# ADR 0001: Build the protocol core before services and UI

- Status: Accepted
- Date: 2026-09-28

## Context

Cyber Cipher depends on identical byte encodings, hashes, field conversions, key identifiers, and signature inputs across the mobile app and several services. Building application flows before this layer would allow incompatible or ambiguous implementations to spread across the project.

## Decision

The first implementation package is `@cyber-cipher/protocol-core`. It has no runtime dependencies and provides strict deterministic-CBOR encoding/decoding, byte framing, SHA-256, BN254 scalar validation, hash-to-field conversion, SPKI key identifiers, and domain-separated Ed25519 verification. It must reproduce the published Python-generated vectors before identity, complaint, or UI services begin.

## Consequences

- Protocol incompatibilities fail early in CI.
- Services share the same validation rules and signed bytes.
- Schema-specific unknown-key checks remain explicit rather than being hidden in a generic serializer.
- Cryptographic primitives still come from the platform or reviewed libraries; this package does not implement AES, Ed25519, RSA, HPKE, Poseidon, or Groth16 mathematics.
