# Security and Acceptance-Test Plan

## 1. Purpose and environments

This plan verifies the prototype's functional, cryptographic, privacy, and operational claims. Tests use synthetic identities and content. Production secrets and real complainant data are prohibited.

Environments:

- **Unit/conformance:** isolated libraries and circuits.
- **Integration:** all containers with separate databases and development keys.
- **Adversarial:** instrumented environment where testers receive selected databases, credentials, traffic captures, or device images.
- **Recovery/operations:** backup copies and disposable infrastructure.
- **Device lab:** representative low/mid/high Android and iOS devices.

Evidence retained for every test: build/artifact IDs, configuration hash, start/end time, tester, sanitized logs, result, linked defect, and approval.

## 2. Release gates

| Gate | Requirement |
|---|---|
| G1 Protocol conformance | All CBOR/hash/signature vectors match across languages; negative vectors rejected. |
| G2 Cryptographic correctness | Circuit, RSA blind issuance, recovery, HPKE, receipt, and log tests pass; no unresolved critical/high cryptographic finding. |
| G3 Privacy separation | Forbidden-field scans and database-join exercise pass; telemetry contains no prohibited identifier/content. |
| G4 Transaction integrity | Fault injection shows no consumed credential without accepted durable record/receipt and no receipt without durable record/outbox. |
| G5 Verifiability | Receipt, inclusion, consistency, witness quorum, and fork tests pass. |
| G6 Authorization | Handler/reviewer/auditor access tests pass with WebAuthn and attributable events. |
| G7 Resilience | Backup restore, node loss, queue replay, key rotation, and outage drills pass. |
| G8 Product quality | Accessibility, trilingual UI, usability, performance, and retention tests pass. |
| G9 External approval | Independent cryptographic review, penetration test, privacy review, and legal/governance approval completed. |

G1-G8 are required for a synthetic-data demonstration. G9 is additionally required before any real pilot.

## 3. Encoding and key tests

| ID | Test | Expected result |
|---|---|---|
| ENC-01 | Run vector generator twice in clean environments. | Byte-identical JSON and artifact IDs. |
| ENC-02 | Encode vectors in every supported language. | Exact CBOR hex and hashes match. |
| ENC-03 | Supply non-minimal integers, indefinite lengths, duplicate/unknown keys, floats, and tags. | Strict rejection before signature/proof processing. |
| ENC-04 | Supply field values `q`, `q+1`, wrong width, and forbidden zero secrets. | Rejected as noncanonical/invalid. |
| ENC-05 | Supply decomposed Unicode and reordered attachment indices. | Rejected or normalized before commitment; never ambiguously accepted. |
| KEY-01 | Compute key IDs from DER SPKI in all languages. | Full 32-byte fingerprints match. |
| KEY-02 | Use one service's Ed25519 key to sign another object type. | Verification fails because key allowlist/prefix differs. |
| KEY-03 | Attempt RSA matter-key use for ordinary signature/TLS/another matter. | Policy/API rejects use. |
| KEY-04 | Scan repository, images, DB dumps, and logs for private keys/test-to-production key reuse. | No production private material; test seeds clearly isolated. |

## 4. Enrollment, membership, and recovery

| ID | Test | Expected result |
|---|---|---|
| MEM-01 | Enroll a valid synthetic NIC. | One enrollment, one unique active leaf/index, signed next checkpoint. |
| MEM-02 | Enroll same NIC/device concurrently. | Exactly one active enrollment; race safely rejected/idempotent. |
| MEM-03 | Fill/revoke leaves and enroll again. | Revoked index is never reused; allocation is monotonic. |
| MEM-04 | Recompute every root from public deltas. | Root equals signed checkpoint for every epoch. |
| MEM-05 | Tamper with checkpoint root, epoch, predecessor, or signature. | Client rejects and raises fork/integrity warning. |
| MEM-06 | Generate proof for active leaf/current root. | Verification succeeds. |
| MEM-07 | Revoke leaf, wait for root update/lease expiry, reuse old proof/path. | Verification fails. |
| REC-01 | Recover with correct seed and five-minute challenge. | Old leaf revoked; fresh index/device/recovery credential activated atomically. |
| REC-02 | Replay consumed recovery challenge. | Rejected; no state change. |
| REC-03 | Use expired, altered, or wrong-generation challenge. | Rejected uniformly; no state change. |
| REC-04 | Submit two concurrent valid recovery completions. | Exactly one succeeds. |
| REC-05 | Inject failure after revocation but before activation. | Transaction rolls back; original active state remains. |
| REC-06 | Vote before and after legitimate recovery. | Same persistent `P` yields same complaint vote nullifier; second vote rejected. |
| REC-07 | Restore user mailbox bundle and rotate recovery seed. | Existing mailbox seeds recover and bundle re-encrypts; old seed cannot decrypt new bundle. |

## 5. RSA entitlement tests

| ID | Test | Expected result |
|---|---|---|
| RSA-01 | Generate matter key. | 3072-bit modulus, exponent 65537, fixed PSS/SHA-384 parameters, unique fingerprint. |
| RSA-02 | Complete blind issuance and final verification. | Valid token; IdA never receives final message/signature. |
| RSA-03 | Compare stored issuance data with later tokens across a large synthetic sample. | No deterministic token identifier stored by IdA. |
| RSA-04 | Request second issuance for same NIC/matter version. | Rejected by unique issuance fact. |
| RSA-05 | Change matter key ID, serial, commitment, message randomizer, signature, PSS salt assumptions, or public key. | Verification fails. |
| RSA-06 | Reuse blinding randomness in instrumented client. | Test harness detects forbidden reuse; production CSPRNG path never accepts caller-supplied randomness. |
| RSA-07 | Submit token before open/after close. | Rejected with uniform public error. |
| RSA-08 | Close matter and run retirement. | Private key destroyed within 24 hours; public key/metadata remain verifiable. |

## 6. Circuit and proof tests

| ID | Test | Expected result |
|---|---|---|
| ZK-01 | Valid complaint witness and bound public inputs. | Proof verifies with allowlisted artifact. |
| ZK-02 | Change `P`, `D`, `r`, one sibling/path bit, or root. | Proof generation/verification fails. |
| ZK-03 | Use entitlement person commitment from a different `P`. | Proof fails. |
| ZK-04 | Change matter, serial, complaint commitment, or challenge after proving. | Request-to-public-input comparison fails. |
| ZK-05 | Use unknown artifact ID or verification key fetched from request-controlled URL. | Rejected; no dynamic untrusted key fetch. |
| ZK-06 | Reorder public signals. | Rejected against manifest-defined ordering. |
| ZK-07 | Submit malformed curve/proof points and noncanonical field encodings. | Rejected without crash or excessive resource use. |
| ZK-08 | Valid vote proof for each of four choices. | Accepted once per person/complaint. |
| ZK-09 | Reuse vote nullifier with another choice/proof. | Rejected atomically. |
| ZK-10 | Audit R1CS constraints and setup transcripts. | Source/constraint/artifact hashes match manifest; all three contributions verify. |

## 7. Submission, encryption, and receipt tests

| ID | Test | Expected result |
|---|---|---|
| SUB-01 | Valid token/proof/ciphertext submission. | One complaint, spent serial, nullifier, outbox event, and signed receipt. |
| SUB-02 | Replay identical committed request with same idempotency key. | Same receipt returned; no duplicate records. |
| SUB-03 | Reuse idempotency key with different bytes. | Conflict; no additional state. |
| SUB-04 | Replay token under new challenge/request. | Uniform rejection; no second complaint. |
| SUB-05 | Fail at every transaction boundary using fault injection. | Either complete commit or zero credential consumption/state change. |
| SUB-06 | Inspect receipt fields. | Random receipt ID/nonce present; serial/nullifier/root/epoch/person commitment absent. |
| SUB-07 | Modify any receipt field/signature or encode noncanonically. | Client rejects. |
| SUB-08 | Decrypt handler package with assigned organization key. | Plaintext and AAD verify. |
| SUB-09 | Attempt decryption with CS, wrong handler, wrong key version, changed AAD/ciphertext. | Fails without plaintext release. |
| SUB-10 | Rewrap DEK to another organization through authorized transfer. | Ciphertext unchanged; new organization decrypts; signed transfer logged. |
| SUB-11 | Attempt transfer by unauthorized actor or introduce universal escrow key. | Denied/test fails architecture policy. |
| SUB-12 | Upload disallowed type, active PDF/script/archive, oversized file, decompression bomb, or MIME mismatch. | Rejected/quarantined within resource limits. |
| SUB-13 | Upload JPEG with GPS EXIF. | Public derivative and committed bytes have no GPS metadata; original remains encrypted/restricted if retained. |

## 8. Transparency and verification tests

| ID | Test | Expected result |
|---|---|---|
| LOG-01 | Append leaves and verify inclusion at multiple tree sizes. | RFC-style proofs validate; wrong leaf/index/path fails. |
| LOG-02 | Verify consistency for increasing tree sizes. | Valid append-only histories pass; rewritten prefix fails. |
| LOG-03 | Present two divergent signed heads. | Gossip/auditor reports split view; inconsistent head not silently accepted. |
| LOG-04 | One witness unavailable. | Other two can finalize. |
| LOG-05 | Only one witness signs or witnesses disagree. | Head remains non-final and alert is visible. |
| LOG-06 | Modify/reorder a public log entry. | Leaf/root mismatch; signatures/proofs fail. |
| LOG-07 | Delete private complaint row after final inclusion. | Receipt/log still prove prior acceptance; retrieval failure is reported. Do not incorrectly claim log consistency itself detects private-row deletion. |
| LOG-08 | Block submission before receipt. | No proof of acceptance exists; documentation/UI make this limitation explicit. |
| LOG-09 | Accept complaint while log temporarily down. | Durable outbox survives restart; later inclusion succeeds; pending state visible. |
| LOG-10 | Download and verify full log without account. | Independent verifier reconstructs every finalized root. |

## 9. Privacy and unlinkability tests

| ID | Test | Expected result |
|---|---|---|
| PRIV-01 | Give testers full IdA and CS database dumps and application logs. | No deterministic complaint-to-NIC mapping from stored application data. |
| PRIV-02 | Automated schema/log scan for forbidden fields and representative secret patterns. | Zero findings in prohibited zones. |
| PRIV-03 | Inspect ingress, CDN, APM, crash, analytics, and database statement logs. | No complaint-joinable IP, TLS fingerprint, user agent, body, token, nullifier, or mailbox secret. |
| PRIV-04 | Submit two matters and complaint/vote from same person. | Public values are unlinkable except intentionally public case relationships. |
| PRIV-05 | Compare blind issuance and spend timings under realistic traffic. | Report measured correlation risk; no claim of perfect resistance. |
| PRIV-06 | Submit via Tor and direct TLS. | Both work; UI distinguishes privacy level; application stores neither source address with complaint. |
| PRIV-07 | Query inclusion through direct endpoint and bulk/Tor mode. | Documentation and UI identify that direct lookup reveals lookup interest; bulk mode avoids complaint-specific query. |
| PRIV-08 | Export receipt/recovery bundle. | Explicit coercion/loss warning and encryption required. |

## 10. Mailbox, handler, community, and lifecycle tests

| ID | Test | Expected result |
|---|---|---|
| MBX-01 | Authenticate with correct mailbox key/challenge. | Access only to that mailbox ciphertext. |
| MBX-02 | Replay/alter/expire mailbox challenge. | Rejected; no messages disclosed. |
| MBX-03 | Reorder/delete/replace messages. | Sequence and previous-hash verification detects change. |
| AUTH-01 | Assigned handler opens case using WebAuthn. | Allowed and signed access event recorded. |
| AUTH-02 | Unassigned handler/admin attempts access. | Denied and attributable event recorded; no plaintext. |
| AUTH-03 | Attempt invalid lifecycle transition or stale row version. | Rejected without partial event. |
| LIFE-01 | Exercise acknowledgment/assignment/finding/extension/appeal timers. | SLA state and signed events match policy. |
| RED-01 | Try to publish without complainant opt-in or reviewer approval. | Blocked. |
| RED-02 | Seed names, NIC-like strings, GPS, faces, and document metadata in draft. | Automated checks flag; reviewer workflow prevents accidental release in test cases. |
| VOTE-01 | Cast 9 valid votes. | Counts may display per policy, but official outcome is `INCONCLUSIVE`. |
| VOTE-02 | Cast at least 10 votes with exactly/above/below 60% principal choice. | Boundary outcome matches specification. |
| VOTE-03 | Community result conflicts with handler. | `CONFLICTING` and auditor review; no automatic close/delete. |
| VOTE-04 | Auditor freezes public listing. | Public derivative hidden/frozen, private case/history retained, signed reason logged. |

## 11. Performance, resilience, retention, and accessibility

| ID | Test | Expected result |
|---|---|---|
| PERF-01 | Load proof-session/submission path at declared prototype concurrency. | p95 target met for proof-only 2 MB scenario; queues bounded; no secret logged. |
| PERF-02 | Prove both circuits on supported mid-range phone. | Published time/memory/battery measurements meet product threshold. |
| PERF-03 | Verify receipt/inclusion on mid-range phone. | Local verification under one second excluding retrieval. |
| DOS-01 | Send oversized/malformed CBOR, proofs, and slow requests. | Early bounded rejection; no memory/CPU exhaustion. |
| RES-01 | Kill one DB/storage node after acceptance. | No accepted complaint/log entry lost. |
| RES-02 | Backup and restore each zone independently. | Integrity checks pass; restored zone has no credentials/data from another zone. |
| RES-03 | Rotate receipt/log/checkpoint/handler keys. | Old objects remain verifiable/decryptable as policy requires; new objects use new key ID. |
| RET-01 | Advance clock through challenge/log/evidence retention schedules. | Expired transient rows and eligible evidence deleted; permanent commitments remain. |
| RET-02 | Apply/release legal hold. | Timed deletion pauses/resumes with signed events. |
| A11Y-01 | Keyboard, screen-reader, zoom, contrast, and focus audit. | WCAG 2.2 AA acceptance; cryptographic status is understandable without color alone. |
| I18N-01 | Complete critical flows in Sinhala, Tamil, and English. | No untranslated security decisions, clipping, or ambiguous terminology. |

## 12. Security tooling and review

- Property/fuzz tests for CBOR decoders, state machines, Merkle proofs, and API parsers.
- Static analysis and language linters on every change.
- Dependency, license, secret, container, and infrastructure-as-code scanning.
- Reproducible circuit/build verification in clean CI.
- Dynamic scanning of public and authenticated portals.
- Manual authorization, business-logic, privacy, mobile storage, and cryptographic review.
- External review of circuits, RSABSSA integration, recovery protocol, log/witness design, and anonymity claims.

Automated scanners are evidence, not substitutes for review.

## 13. Defect policy

- **Critical:** identity-to-complaint linkage, forged proof/receipt/checkpoint, plaintext exposure, entitlement/nullifier bypass, or unrecoverable accepted-data loss. Blocks all release.
- **High:** practical cross-case access, recovery takeover, witness-finality bypass, key exposure, or persistent network identifier joined to complaint. Blocks release.
- **Medium:** limited metadata leak, hard-to-exploit denial of service, incomplete audit attribution, or policy bypass requiring privileged access. Requires owner/date and explicit pilot approval.
- **Low:** defense-in-depth or documentation issue with no direct security-property violation. Track to closure.

## 14. Final acceptance report

The release report lists every test ID, result/evidence link, artifact and build IDs, open defects, measured performance, residual risks, external-review findings, operator/witness identities, key-ceremony records, and signatures of engineering, security, privacy, operations, accessibility, legal/governance, and product owners.
