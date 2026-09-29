# ADR 0002: Fix authenticated-encryption and HPKE wrapper profiles

- Status: Accepted
- Date: 2026-09-29

## Context

The design selected AES-256-GCM and RFC 9180 HPKE but left the byte encoding of authenticated data implicit. Different field concatenation or integer encodings would make clients and handlers incompatible and could omit a security-critical binding.

## Decision

Complaint packages use AES-256-GCM with a 32-byte DEK, 12-byte fresh nonce, 16-byte tag, and deterministic-CBOR AAD binding protocol version, complaint ID, matter ID/version, complaint commitment, and handler key ID.

The DEK is wrapped in RFC 9180 base mode with KEM `0x0020` (DHKEM X25519/HKDF-SHA256), KDF `0x0001` (HKDF-SHA256), and AEAD `0x0002` (AES-256-GCM). HPKE `info` is the fixed label, matter ID, and four-byte big-endian matter version. Deterministic-CBOR AAD binds protocol version, complaint ID, complaint commitment, and handler key ID.

Node's crypto implementation supplies AES-GCM. Pinned `@hpke/core` and `@hpke/dhkem-x25519` packages supply HPKE; project code does not implement either primitive.

## Consequences

- Any routing, matter, commitment, or handler-key substitution causes authentication failure.
- Handler reassignment rewraps the same DEK and does not re-encrypt complaint content.
- Other language implementations must reproduce these exact AAD and `info` bytes.
- Nonce uniqueness remains the caller's responsibility and will be enforced by higher-level complaint-package APIs and tests.
