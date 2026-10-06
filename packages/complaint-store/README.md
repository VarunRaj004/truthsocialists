# Complaint store

This package implements the durable Phase 5 acceptance transaction in a
tenant-bound PostgreSQL complaint database. It mirrors only public matter
metadata and never imports identity/enrollment records.

`acceptComplaint` locks the public matter and proof session, rechecks the
submission window, lease hash, expiry, handler key, and caller-supplied
side-effect-free RSA/ZK authorization. In one serializable transaction it then:

1. spends the blind-entitlement serial;
2. spends the matter-scoped complaint nullifier;
3. writes the encrypted complaint metadata;
4. creates the canonical initial public log event and durable outbox row;
5. creates and verifies the randomized Ed25519 receipt;
6. marks the proof-session challenge consumed.

Any error rolls all six effects back. Serialization failures retry up to three
times, so the authorization callback and receipt signer must remain
side-effect-free. Ciphertext bytes live in the object-store boundary; the
database stores only its bounded `object://` URI, size, hash, nonce, HPKE
envelope, and routing key identifiers.

A UUIDv4 idempotency key and SHA-256 request hash are reserved inside the same
transaction. Identical committed retries return the original receipt without
rerunning authorization; changed bytes conflict. Reservations expire after 24
hours, and failed transactions leave no reservation behind.
