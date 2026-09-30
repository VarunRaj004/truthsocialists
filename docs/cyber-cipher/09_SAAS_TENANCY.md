# SaaS Tenancy Profile

## 1. Deployment model

Cyber Cipher uses a shared control plane and stateless compute where safe, while retaining the original separation between identity, complaint, handler, and public-audit trust zones inside every tenant.

```text
Shared control plane: tenant routing, public configuration, software releases
Tenant identity zone: enrollment, membership, recovery, blind issuance
Tenant complaint zone: proof sessions, encrypted complaints, receipts, mailbox routing
Tenant handler zone: handler HPKE keys and authorized decryption
Public zone: tenant-namespaced log, witnesses, auditor, redacted community portal
```

The prototype persistence profile is database-per-tenant and object-prefix-per-tenant. A dedicated stack is available for high-assurance tenants. A future shared-database profile is prohibited until composite tenant keys, database row-level security, connection-pool reset tests, and cross-tenant property tests are complete.

## 2. Tenant cryptographic boundary

Each tenant has unique keys for membership checkpoints, proof leases, receipts, RSA blind entitlements, handler HPKE, transparency logs, and witnesses. The membership registry rejects checkpoint-key reuse. Matter IDs remain random UUIDv4 values and matter RSA keys remain version-specific.

Membership checkpoints retain the v1 body. Tenant selection is bound by the dedicated checkpoint key and by `updateBatchHash`, whose deterministic-CBOR delta includes the 16-byte tenant ID. Verifiers resolve the tenant configuration from a trusted route or installation profile before checking the key ID and signature.

## 3. Shared components

The following may be shared because they are stateless or public: API gateway, web/mobile distribution, circuit artifacts, proof-verification workers, monitoring infrastructure with privacy-safe labels, build pipeline, and public software documentation.

The following are never shared across tenants: identity records, HMAC/encryption keys for NIC data, membership allocation state, recovery records, RSA private keys, complaint databases, object-store encryption context, handler keys, staff authorization, and signing keys.

## 4. Operational requirements

- Tenant identity is selected before database or KMS access and cannot be overridden by a request body.
- Connection pools are tenant-dedicated in the prototype.
- Logs and metrics exclude NICs, complaint/receipt/mailbox IDs, serials, nullifiers, recovery IDs, IP addresses, and ciphertext hashes.
- Backups, retention, legal holds, deletion, residency, and key rotation are configured per tenant.
- Support personnel receive time-bounded, attributable access to one trust zone and tenant at a time.
- Cross-tenant replay, routing, cache, object-store, KMS, and authorization tests are release blockers.
