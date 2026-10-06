# Complaint intake service

This service completes the Phase 5 anonymous encrypted-submission boundary. It
exposes `POST /complaints/v1/proof-sessions` and
`POST /complaints/v1/complaints` using deterministic CBOR and never requires or
reads an identified user session.

The fixed authorization order is:

1. lock the tenant-local matter and current proof session;
2. verify the RSA-3072 RFC 9474 blind entitlement and its matter key/serial;
3. verify the signed 60-second current-root lease;
4. reconstruct all eight frozen complaint public signals;
5. verify the allowlisted Groth16/BN254 complaint artifact;
6. atomically spend the serial/nullifier, record encrypted-object metadata,
   enqueue the initial public-log event, sign the randomized receipt, consume
   the challenge, and complete the idempotency record.

`FileCiphertextObjectStore` writes a SHA-256-addressed object through a private
temporary file, flushes it, atomically renames it, and reads it back before the
database may return a receipt. Identical retries deduplicate. A failed database
transaction can leave an unreferenced encrypted object, but it cannot consume a
credential; deployment should periodically remove objects not referenced after
the 24-hour retry window. Each SaaS tenant must use a separate database,
object-store directory/bucket, proof-lease key, receipt key, and service
credential.

The native HTTPS factory is the deployment entry point. Plain HTTP is available
only for local tests. The client transport guard requires HTTPS, with an
explicit opt-in exception for test-only `.onion` endpoints. The HTTP adapter
does not access or log source IPs, TLS fingerprints, headers, bodies, serials,
nullifiers, proofs, or complaint identifiers.

The current evidence policy rejects active/embedded PDF content, MIME/signature
mismatches, archives, empty files, oversized inputs, and supplies neutral local
filenames. Original evidence is encrypted and handler-restricted; Phase 8
creates separately sanitized, reviewed public derivatives.
