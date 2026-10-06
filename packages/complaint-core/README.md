# Complaint core

This package starts the Phase 5 client-side complaint-intake slice. It validates
the prototype evidence allowlist and size limits, normalizes complaint text to
NFC, generates privacy-neutral attachment names, builds the deterministic-CBOR
manifest, computes the 32-byte-salted SHA-256 commitment, encrypts the complete
private package with a fresh AES-256-GCM key and nonce, and HPKE-wraps only that
key to the selected handler's versioned X25519 public key.

The returned ciphertext blob includes the 16-byte GCM authentication tag. Its
AAD binds the complaint ID, matter/version, commitment, and handler key ID.
Client plaintext and the DEK are never returned by the preparation API; the DEK
buffer is overwritten after wrapping.

This first slice performs conservative magic-byte checks and rejects known PDF
active-content markers. It also includes a tenant-bound, Ed25519-signed complaint
proof-session service that issues exactly 60-second current-root leases, rejects
stale roots and cross-tenant use, prevents concurrent replay, and marks a
challenge consumed only after the supplied submission transaction succeeds.

The included proof-session store is deliberately in-memory. The next Phase 5
slice replaces that boundary with the PostgreSQL transaction that atomically
stores ciphertext, spends the entitlement/nullifier, consumes the challenge,
creates the initial log outbox record, and issues the signed receipt. Full
metadata stripping, robust PDF sanitization, and object storage also remain.
