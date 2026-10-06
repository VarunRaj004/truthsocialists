# Transparency Log

Phase 6 implements Cyber Cipher's public append-only audit layer.

- RFC 6962-style SHA-256 leaf and node hashing, inclusion proofs, and consistency proofs.
- Dedicated Ed25519 operator-signed tree heads chained to the previous finalized head.
- Exactly three independently keyed prototype witnesses and 2-of-3 finality.
- Retryable non-final heads, same-size fork evidence, and mutation rejection.
- Canonical-CBOR public download/proof responses and an offline receipt/log verifier.
- A tenant-bound PostgreSQL leaf, head, and witness-signature store.

`receiptInclusionStatus` returns `FINAL`, `NOT_FINAL`, or `INVALID`, which is the
plain-language state a client can display during background receipt checks. A
single unavailable witness still permits finality; fewer than two valid,
distinct witness signatures never do.

The included witnesses simulate independent operators for the MVP. Production
deployment requires separately administered hosts, networks, and key custody.
