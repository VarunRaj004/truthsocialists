# ADR 0004: Bind recovery authorization to tenant, generation, and signed challenge

- Status: Accepted
- Date: 2026-09-30

## Context

The initial design required a five-minute challenge and old recovery-key signature but did not define their exact byte statements. An implicit format could permit incompatible clients, field omission, or replay across a SaaS tenant or recovery generation.

## Decision

The recovery service signs a strict deterministic-CBOR challenge containing tenant ID, challenge ID, recovery ID/generation, issue/expiry times, server nonce, and dedicated signing-key ID. The client signs a second deterministic-CBOR object containing tenant ID, the SHA-256 hash of the complete signed challenge, stored person anchor, replacement device hash, replacement recovery ID/public key, and expected generation.

The user-held 16-byte recovery seed is expanded with HKDF-SHA256 using the 16-byte recovery ID as salt and three distinct protocol labels. Derived keys cover Ed25519 recovery signing, AES-256-GCM person backup, and AES-256-GCM mailbox bundle. Backup AAD binds tenant, recovery ID, purpose, and generation.

## Consequences

- A challenge, tenant, generation, person anchor, device, or replacement-key substitution invalidates authorization.
- Successful recovery consumes the challenge and rotates both device and recovery credentials.
- Possession of the recovery seed remains sufficient for takeover until the credential is rotated; users must protect the seed offline.
- The in-memory atomic prototype must be replaced by a serializable database transaction before multi-process deployment.
