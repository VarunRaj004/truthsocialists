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
active-content markers. Full metadata stripping, robust PDF sanitization, proof
leases, atomic server-side acceptance, signed receipts, and object storage are
the remaining Phase 5 work.
