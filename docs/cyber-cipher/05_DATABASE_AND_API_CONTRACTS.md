# Database and API Contracts

## 1. Contract principles

- Identity, complaint, transparency-log, witness, and handler data live in separate databases with separate service credentials and backups.
- There are no cross-zone foreign keys, shared ORM models, database links, analytics joins, or shared administrator credentials.
- Binary protocol objects are stored as validated canonical CBOR plus indexed, non-sensitive columns where required.
- Client-supplied identifiers are random UUIDv4/128-bit values. Internal sequential IDs are never exposed across trust zones.
- All write APIs require idempotency keys. Repeating the same key with different request bytes is rejected.
- Public binary APIs use `application/cbor`; diagnostic JSON endpoints, where enabled, are not signature inputs.
- Date/time database columns are UTC. Cryptographic wire timestamps are Unix milliseconds.
- The reference DDL is `database/reference-schema.sql`; physical deployments split its sections into different database clusters.
- In the SaaS prototype, the complete identity and complaint database split is instantiated per tenant. The shared control plane stores routing and public configuration only; it has no cross-zone query credential. See `09_SAAS_TENANCY.md`.

## 2. Identity database

### `enrollment`

Stores one identified eligibility record. `nic_lookup` is a keyed HMAC of normalized NIC for uniqueness; `nic_ciphertext` is encrypted for operational/legal use. The HMAC key and encryption key are independent KMS keys.

Required fields: internal enrollment ID, NIC lookup/ciphertext, eligibility status, `person_anchor`, active device hash/index, recovery ID/public key/generation, enrollment timestamps, and row version.

Forbidden fields: complaint ID/content/commitment, entitlement serial/signature, receipt/mailbox/vote/nullifier.

### `matter_issuance`

Stores only `(enrollment_id, matter_id, matter_version, completed_at)`, with a unique constraint over the first three values. It MUST NOT store the blinded request, entitlement message, serial, person commitment, blind signature, or final signature.

### Membership tables

`membership_leaf` stores index, current field value, state, and update epoch. `membership_checkpoint` stores signed canonical checkpoint bytes and hashes. `membership_update` stores the append/revoke operations needed to reconstruct each root. Index allocation uses a transactionally locked monotonic sequence and never searches for empty slots.

### Recovery tables

`recovery_challenge` stores challenge ID, recovery record reference, signed challenge bytes, expiry, consumed time, and bounded attempt count. Consumed/expired rows are purged within 24 hours. A successful recovery locks the enrollment and recovery rows and commits credential rotation with membership updates.

## 3. Complaint database

### `matter`

Stores public matter ID/version, title, window, RSA SPKI/fingerprint, circuit artifact IDs, handler organization/key ID, publication time, and lifecycle status. `(matter_id, version)` and `matter_key_id` are unique.

### `proof_session`

Stores random challenge ID, purpose, root/epoch, signed lease, issue/expiry times, and consumption state. It stores no client network metadata. Expired sessions are purged within 24 hours.

### `spent_entitlement` and `used_nullifier`

Uniqueness tables enforce one spend. The entitlement table keys on `(matter_key_id, serial)`. The nullifier table keys on `(scope_type, scope_id, nullifier)`. Insertion occurs in the same serializable transaction as complaint/vote acceptance. Raw proofs and proof witnesses are not retained; an optional verification audit record stores artifact ID, verification result, and hash of the canonical proof envelope.

### `complaint`

Stores random complaint ID, matter reference, public commitment, ciphertext object reference/hash/size, AES-GCM nonce/tag, HPKE encapsulated key/wrapped DEK/suite, handler organization/key ID, status, mailbox public fields, accepted time, and initial log-entry hash.

Forbidden fields: NIC, phone, email, person/device hashes, membership index/path, person secret, device secret, recovery ID, source IP, TLS fingerprint, advertising ID, entitlement person commitment, serial/nullifier in the receipt view.

### Lifecycle and access

`case_event` is append-only and stores a signed private event plus its public commitment/log reference. `case_access_event` records authorized or denied accesses without copying complaint plaintext. Status is derived from the latest valid transition and cached in `complaint`; direct status updates outside the transition procedure are denied.

### Mailbox

`mailbox` stores random mailbox ID and the two public keys. `mailbox_message` stores monotonically numbered ciphertexts, direction, previous-message hash, handler key ID as relevant, and creation time. Private mailbox seeds are forbidden.

## 4. Public log database

`log_leaf` is immutable and append-only by database role. It stores leaf index, exact canonical log-entry bytes, leaf hash, and insertion time. `tree_head` stores operator-signed heads, and `witness_signature` stores one signature per configured witness/head. No update or delete privilege is granted to the application role.

Log replication and witness verification do not depend solely on database replication: each witness independently reconstructs the Merkle tree from public leaves.

## 5. API surface

The machine-oriented outline is `api/openapi.yaml`. Required endpoint groups follow.

### Identity and membership

| Method/path | Authentication | Purpose |
|---|---|---|
| `POST /ida/v1/enrollments` | Identified enrollment session | Validate NIC/contact and create person/device membership |
| `POST /ida/v1/matters/{id}/{version}/blind-issuance` | Enrolled device session | Submit blinded RSA request; one completed issuance per NIC/matter version |
| `GET /public/v1/membership/checkpoints/current` | None | Current signed membership checkpoint |
| `GET /public/v1/membership/deltas?afterEpoch=` | None | Public updates for local tree/path reconstruction |
| `POST /ida/v1/recovery/challenges` | Recovery ID plus abuse controls | Issue signed five-minute challenge |
| `POST /ida/v1/recovery/complete` | Recovery signature | Atomic device/recovery rotation |

### Complaints

| Method/path | Authentication | Purpose |
|---|---|---|
| `GET /public/v1/matters` | None | Published matter metadata and keys |
| `POST /complaints/v1/proof-sessions` | None | Current-root 60-second signed lease |
| `POST /complaints/v1/complaints` | RSA token plus Groth16 proof | Atomic anonymous submission |
| `GET /public/v1/receipts/{receiptId}/inclusion` | None; privacy-preserving bulk alternative required | Inclusion proof and finalized tree head |

The per-receipt endpoint is convenient but can reveal which receipt a client checks. Clients SHOULD use bulk checkpoint/leaf downloads through Tor or privacy relay. The UI must disclose this distinction.

### Mailbox

| Method/path | Authentication | Purpose |
|---|---|---|
| `POST /mailboxes/v1/{mailboxId}/challenges` | None plus abuse controls | Issue short-lived mailbox challenge |
| `GET /mailboxes/v1/{mailboxId}/messages` | Mailbox challenge signature | Retrieve ciphertext messages |
| `POST /mailboxes/v1/{mailboxId}/messages` | Mailbox signature | Send encrypted reply |

### Handler and reviewer

| Method/path | Authentication | Purpose |
|---|---|---|
| `GET /handler/v1/cases` | WebAuthn-authenticated staff | Assigned case list |
| `GET /handler/v1/cases/{id}` | Assigned-handler authorization | Ciphertext/envelope and case metadata |
| `POST /handler/v1/cases/{id}/events` | Handler plus action signature | Lifecycle event |
| `POST /handler/v1/cases/{id}/transfer` | Authorized current handler | Cross-organization DEK rewrap |
| `POST /handler/v1/cases/{id}/redactions` | Handler | Proposed public derivative |
| `POST /review/v1/redactions/{id}/decision` | Independent reviewer | Approve/reject redaction |

### Community and audit

| Method/path | Authentication | Purpose |
|---|---|---|
| `GET /public/v1/complaints/{id}` | None | Approved redacted public record |
| `POST /community/v1/proof-sessions` | None | Current-root vote lease |
| `POST /community/v1/complaints/{id}/votes` | Vote proof | Atomic anonymous vote |
| `GET /public/v1/complaints/{id}/vote-result` | None | Aggregate outcome after policy rules |
| `POST /auditor/v1/complaints/{id}/assessment` | Auditor WebAuthn | Signed comparison/freeze/escalation |
| `GET /log/v1/entries` | None | Paginated/full log download |
| `GET /log/v1/tree-heads/latest` | None | Latest operator and witness signatures |
| `GET /log/v1/proofs/inclusion` | None | RFC 6962 inclusion proof |
| `GET /log/v1/proofs/consistency` | None | RFC 6962 consistency proof |

## 6. Atomic submission contract

The following operations are one serializable transaction or one transaction plus a durable outbox whose receipt binds the committed outbox event:

1. lock challenge and verify not consumed/expired;
2. verify matter/window, entitlement, proof, ciphertext metadata, and mailbox keys;
3. insert unique spent serial;
4. insert unique complaint nullifier;
5. insert complaint and initial private event;
6. reserve/append public log entry through the durable log outbox;
7. insert receipt record and mark challenge consumed;
8. commit;
9. sign and return the canonical receipt using the committed values.

If steps 3-8 fail, the serial, nullifier, and challenge remain unconsumed. Idempotent replay of a committed request returns the same receipt; a different request under the same idempotency key is rejected.

## 7. Uniform errors

Unauthenticated cryptographic failures return a common status and body, for example HTTP 400 with code `SUBMISSION_NOT_ACCEPTED`. Logs may record a privacy-safe internal category but MUST NOT record secrets or raw tokens. Rate-limit responses MUST not reveal whether a serial/nullifier exists.

Authenticated administrative APIs may return precise authorization and validation errors because the actor is already identified and audited.

## 8. State transitions

Allowed case transitions are policy-versioned. The default graph is:

```text
SUBMITTED -> ACKNOWLEDGED -> ASSIGNED -> UNDER_REVIEW
UNDER_REVIEW -> ACTION_REQUIRED -> UNDER_REVIEW
UNDER_REVIEW -> RESOLVED | REJECTED | CLOSED
RESOLVED | REJECTED | CLOSED -> APPEALED -> UNDER_REVIEW
```

`SUPPRESSED` and `PUBLIC_FROZEN` are public-visibility flags, not destructive case states. Every transition requires expected previous state, actor, reason code, timestamp, and signature. Optimistic concurrency prevents two conflicting transitions.

## 9. Retention and erasure jobs

Retention jobs operate inside each zone and append privacy-safe deletion events before removing ciphertext/object data. They never delete log leaves or finalized tree heads. Evidence-object deletion is verified by listing and attempting retrieval; encryption-key destruction is recorded separately. Legal holds override timed deletion and require a signed, attributable hold event.
