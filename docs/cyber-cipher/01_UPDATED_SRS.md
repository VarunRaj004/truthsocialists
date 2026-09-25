# Updated Systems Requirements Specification

## 1. Purpose and scope

Cyber Cipher allows a person whose eligibility has been verified against a national identity record to submit at most one anonymous complaint for a published matter. It supports encrypted evidence, device loss and replacement, anonymous two-way follow-up, independently verifiable case history, public redacted summaries, and anonymous community assessment.

The system does not determine whether an allegation is true, authenticate the real-world origin of evidence, guarantee anonymity against a global traffic-analysis adversary, or identify the author of an abusive anonymous complaint. Community votes are public accountability signals, not judicial or factual findings.

## 2. Security and privacy position

Eligibility is identified at enrollment, but complaint submission is unlinkable at the application-data layer. No component is permitted to store a mapping from a complaint to a NIC. The IdA learns enrollment and matter-entitlement issuance. The complaint domain learns a valid entitlement, a valid current membership proof, and an anonymous complaint. Separation, blind issuance, zero-knowledge proofs, minimized metadata, and optional Tor access jointly reduce linkability.

The system provides verifiability after acceptance. It cannot prove that an operator did not block a submission before issuing a signed receipt. A receipt proves acceptance; later log inclusion and consistency proofs prove that the accepted record was incorporated into the public append-only history.

## 3. Actors and trust boundaries

| Actor | Permitted knowledge and authority | Prohibited knowledge or authority |
|---|---|---|
| Complainant | Own secrets, complaints, receipts, mailbox history | Other users' records |
| Identity Authority (IdA) | NIC record, active device record, issuance fact, recovery public key | Complaint content, receipt, entitlement value, complaint ID |
| Complaint Service (CS) | Public proof inputs, ciphertext, routing metadata, lifecycle state | NIC, phone number, person secret, plaintext evidence |
| Handler organization | Plaintext for assigned complaints; signed case actions | NIC or IdA enrollment data; unrelated complaints |
| Privacy reviewer | Proposed redacted derivative and minimum required context | Raw identity data; unrelated evidence |
| Transparency-log operator | Public commitments and event metadata | Complaint plaintext, attachment plaintext, NIC |
| Witness | Log tree data and signed tree heads | Complaint plaintext or identity data |
| Public auditor | Public log, checkpoints, redacted summaries, aggregate votes | Private complaint content and identity records |
| Community member | Public redacted summary and anonymous voting proof | Raw evidence and complainant identity |
| Infrastructure administrator | Service health and content-free telemetry | Decryption keys or a complaint-to-NIC mapping |

The IdA, complaint domain, and public-audit/log domain MUST be separately administered. Production decryption and signing keys MUST be protected by KMS/HSM controls. Two-person approval is required for destructive key operations and emergency access.

## 4. Core functional requirements

### 4.1 Enrollment and active membership

- **FR-E1:** The client MUST generate a random non-zero BN254 person secret `P` and device secret `D`. `P` is persistent across legitimate device replacement; `D` is device-specific.
- **FR-E2:** `D` and other device-bound credentials MUST be sealed behind device unlock in hardware-backed storage where supported.
- **FR-E3:** The IdA MUST verify NIC eligibility and control of the registered contact channel. Production deployments MUST define the authoritative register integration and failure policy.
- **FR-E4:** One NIC MUST have at most one active device membership at a time.
- **FR-E5:** The active leaf MUST bind `P` and `D` using the domain-separated Poseidon construction defined in the cryptographic specification.
- **FR-E6:** The IdA MUST maintain a depth-16 append-only membership tree. Revocation replaces the leaf with `EMPTY_LEAF`; a revoked index MUST NOT be reused.
- **FR-E7:** Membership changes MUST be batched at most every 30 seconds. A new checkpoint is published only when the tree changed.
- **FR-E8:** The IdA MUST NOT expose an API that accepts a complaint identifier or complaint content.

### 4.2 Matters and blind entitlements

- **FR-T1:** A matter is identified by a random UUIDv4 plus an unsigned 32-bit version. Security-relevant changes and reopening MUST create a new version.
- **FR-T2:** Each matter version MUST use an independent RSA-3072 key pair and MUST publish the matter and public key at least 24 hours before submissions open.
- **FR-T3:** The IdA MUST issue at most one entitlement per NIC per matter version and store only the issuance fact.
- **FR-T4:** Issuance MUST use `RSABSSA-SHA384-PSS-Randomized` blind signing. The IdA MUST NOT learn the unblinded message or signature.
- **FR-T5:** The entitlement message MUST include the protocol version, full SHA-256 `matterKeyId`, random 128-bit serial, and a Poseidon commitment to `P` with fresh non-zero randomness `r`.
- **FR-T6:** An entitlement is valid only during the matter submission window. Its private key MUST be destroyed within 24 hours after the window closes. A reopened matter uses a new version and key.
- **FR-T7:** The CS MUST reject a repeated `(matterKeyId, serial)` and a repeated complaint nullifier. Serial consumption MUST occur only in the transaction that successfully accepts the submission.

### 4.3 Private membership and complaint authorization

- **FR-Z1:** The prototype MUST use a Groth16/BN254 proof generated by a Circom 2 circuit and verified against a content-addressed circuit artifact.
- **FR-Z2:** A complaint proof MUST show knowledge of `P`, `D`, `r`, and a current Merkle path such that the active leaf, entitlement person commitment, and matter-specific complaint nullifier all use the same `P`.
- **FR-Z3:** The complaint proof MUST bind the matter, entitlement serial, complaint commitment, and one-time submission challenge as public inputs.
- **FR-Z4:** The CS MUST accept only the current membership root carried by a valid Ed25519-signed proof-session lease with a maximum lifetime of 60 seconds.
- **FR-Z5:** The current prototype MUST expose a membership-provider interface so that a future custom zero-knowledge RSA accumulator can replace the Merkle provider without changing entitlement, receipt, or complaint APIs.

### 4.4 Complaint submission and evidence

- **FR-S1:** The client MUST normalize complaint text to UTF-8 NFC and create a deterministic-CBOR manifest.
- **FR-S2:** The public complaint commitment MUST be `SHA-256(random 32-byte salt || deterministic-CBOR manifest)`.
- **FR-S3:** Client preprocessing MUST remove metadata or create a safe derivative before the committed public form is calculated. Encrypted originals MAY be retained for the handler and MUST have separately recorded hashes.
- **FR-S4:** The prototype allowlist is PDF, JPEG, PNG, MP4, M4A, and plain text; the limits are 25 MB per file and 100 MB per complaint. Archives, executables, scripts, and active document content MUST be rejected.
- **FR-S5:** Each complaint package MUST be encrypted with a random AES-256-GCM data-encryption key and 96-bit nonce. The data key MUST be wrapped to the assigned handler organization's versioned key using HPKE X25519/HKDF-SHA256/AES-256-GCM.
- **FR-S6:** The CS MUST verify the RSA entitlement and ZK proof before accepting the submission. Verification and insertion of complaint, serial-spend, nullifier, initial log event, and receipt record MUST be atomic.
- **FR-S7:** The CS MUST return a randomized deterministic-CBOR receipt signed by a dedicated Ed25519 receipt key.
- **FR-S8:** Submission error responses MUST not distinguish unknown, previously spent, expired, or malformed entitlements to an unauthenticated caller.
- **FR-S9:** The service MUST support direct TLS and a Tor-compatible endpoint. It MUST NOT persist source IP, TLS fingerprint, advertising identifier, or third-party analytics identifier with complaint data.

### 4.5 Recovery and device replacement

- **FR-R1:** Enrollment MUST create a random 128-bit recovery seed and random 128-bit recovery ID. The recovery seed MUST remain under user control.
- **FR-R2:** The recovery authentication key MUST be an Ed25519 key deterministically derived using HKDF-SHA256 with a domain-specific label. The IdA stores only its public key and recovery record.
- **FR-R3:** The encrypted person-secret backup MUST use AES-256-GCM with a key derived from the recovery seed, the recovery ID as salt, and a fixed protocol label.
- **FR-R4:** Recovery requires a fresh IdA challenge valid for five minutes and a signature from the recovery key over the challenge and new device public material.
- **FR-R5:** Successful recovery MUST atomically revoke the old leaf, allocate a never-before-used leaf index for the new device, preserve `P`, rotate `D`, rotate the recovery ID/seed/key, and publish the membership change.
- **FR-R6:** Failed recovery MUST NOT change active membership. Recovery secrets MUST never be requested through a service-line operator.

### 4.6 Anonymous follow-up

- **FR-F1:** Every complaint MUST use a fresh random 256-bit `followUpSeed`, random 128-bit `mailboxId`, derived Ed25519 authentication key, and derived X25519 encryption key.
- **FR-F2:** The CS stores only the mailbox ID and public keys. Mailbox authentication uses signed server challenges; replies use HPKE.
- **FR-F3:** Mailbox secrets MUST NOT be derived from the entitlement serial, `P`, `D`, NIC, or recovery ID.
- **FR-F4:** Mailbox seeds MAY be placed in a user-controlled AES-256-GCM recovery bundle encrypted from the recovery seed. The IdA and CS MUST NOT receive plaintext bundle contents.
- **FR-F5:** After successful device recovery, the client MUST re-encrypt the user-controlled bundle under the rotated recovery credential.

### 4.7 Handling and reassignment

- **FR-H1:** Each handler organization MUST have a versioned X25519 HPKE key pair protected by its KMS/HSM.
- **FR-H2:** Staff access MUST use phishing-resistant WebAuthn and least-privilege role assignments.
- **FR-H3:** The handler portal MUST decrypt only assigned cases. Every read, state change, export, and key rewrap MUST create an attributable signed audit event.
- **FR-H4:** Internal reassignment within the same organization uses authorization changes. Cross-organization reassignment requires the current handler to rewrap only the data key to the new organization's public key and create a signed transparency-log event.
- **FR-H5:** The prototype MUST NOT contain a universal complaint-decryption or escrow key.
- **FR-H6:** The lifecycle is `SUBMITTED`, `ACKNOWLEDGED`, `ASSIGNED`, `UNDER_REVIEW`, optionally `ACTION_REQUIRED`, then `RESOLVED`, `REJECTED`, or `CLOSED`. Public visibility states such as `SUPPRESSED` do not erase the private case.
- **FR-H7:** Default service targets are acknowledgment within 24 hours, assignment within 72 hours, and initial finding within 14 days. Signed extensions and reassignment reasons MUST be logged. Appeals remain open for 14 days after a final finding.

### 4.8 Redaction, community voting, and auditor comparison

- **FR-C1:** Public release is opt-in. The handler creates a redacted derivative, automated PII checks run, and an independent privacy reviewer approves it. Raw evidence MUST NOT be public.
- **FR-C2:** Community voting uses a separate Semaphore-style circuit with one nullifier per person per complaint.
- **FR-C3:** Voting uses the current root and a signed 60-second lease. Choices are `CORROBORATE`, `DISPUTE`, `INSUFFICIENT_INFORMATION`, and `UNSAFE_OR_ABUSIVE`.
- **FR-C4:** The default window is seven days. A published outcome requires at least 10 valid voters and at least 60% support for a principal outcome; otherwise it is `INCONCLUSIVE`.
- **FR-C5:** A vote is an assessment of the redacted information, not verification of truth.
- **FR-C6:** Comparison states are `ALIGNED`, `CONFLICTING`, `COMMUNITY_INCONCLUSIVE`, and `HANDLER_PENDING`. Conflict triggers auditor review, not automatic deletion or case closure.
- **FR-C7:** An auditor MAY freeze a public listing, request handler justification, or escalate under policy. Every action and reason MUST be logged. Only an authorized case authority may close the underlying complaint.

### 4.9 Transparency and receipts

- **FR-V1:** The log MUST be an RFC 6962-style append-only SHA-256 Merkle tree with domain-separated leaf and node hashes.
- **FR-V2:** Signed tree heads MUST be issued when the log changes, with a target interval of 30 seconds.
- **FR-V3:** Three administratively independent witnesses MUST verify the tree. Two matching witness signatures are required for a checkpoint to be final.
- **FR-V4:** The log MUST provide inclusion and consistency proofs and an unauthenticated bulk-download/auditor interface.
- **FR-V5:** Public entries MUST contain commitments and minimum event metadata only; never NIC, plaintext, attachment, entitlement serial, person commitment, or ZK witness.
- **FR-V6:** The receipt MUST include protocol version, random 128-bit receipt ID, random 256-bit receipt nonce, complaint ID, matter ID/version, complaint commitment, acceptance time, log-entry hash, and receipt-key ID.
- **FR-V7:** The receipt MUST exclude entitlement serial, membership root, person commitment, and nullifier. It MUST be deterministic-CBOR encoded and signed with Ed25519.
- **FR-V8:** The client MUST verify the receipt signature and later verify log inclusion. A receipt without final inclusion after the published service objective MUST display a clear warning.

## 5. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 | Monthly intake availability target: 99.5% for the prototype. Accepted complaints MUST survive loss of one storage node. |
| NFR-2 | A proof-only submission excluding large-file upload SHOULD be acknowledged within three seconds at p95 under declared prototype load. |
| NFR-3 | Receipt and inclusion verification SHOULD finish within one second on a representative mid-range phone, excluding network retrieval. |
| NFR-4 | The depth-16 tree supports 65,536 issued membership indices. Indices are never reused; capacity monitoring MUST alert at 80%. |
| NFR-5 | The UI MUST support Sinhala, Tamil, and English, screen readers, keyboard navigation, and WCAG 2.2 AA contrast and focus behavior. |
| NFR-6 | Verification MUST be reachable within two user actions from a complaint and explain success/failure in plain language. |
| NFR-7 | Prototype operational logs are retained for 30 days without complaint content or raw IP. Encrypted evidence defaults to 12 months after closure unless legal hold applies. Public commitments remain permanent. |
| NFR-8 | Cryptographic artifacts and application builds MUST be reproducible. Artifact IDs are full SHA-256 hashes of deterministic manifests. |
| NFR-9 | All clocks MUST use authenticated time synchronization and tolerate an explicitly configured maximum skew. |
| NFR-10 | Rate limits and abuse defenses MUST not create a persistent identifier joinable to a complaint. |

## 6. Explicit limitations

- A stolen unlocked phone can act until the next membership update takes effect.
- A compromised device can reveal locally held receipts, entitlement values, and mailbox secrets.
- Optional Tor reduces network linkability; direct TLS does not hide the user's address from the ingress network.
- A global observer may correlate timing despite batching and minimized logs.
- Signed receipts improve integrity but weaken receipt-freeness under coercion.
- Community consensus cannot establish factual truth.
- A malicious client may submit manipulated evidence; the platform proves bytes and history, not real-world authenticity.
- If IdA and CS collude and also possess sufficiently precise external traffic/device telemetry, application-layer unlinkability does not eliminate all correlation risk.

## 7. Retention defaults

- Expired challenges and leases: deletion within 24 hours.
- Content-free operational security logs: 30 days.
- Encrypted complaint evidence: 12 months after closure, unless jurisdiction or legal hold requires otherwise.
- Nullifiers and spent serials: matter lifetime plus audit period.
- Redacted public entries, commitments, signed checkpoints, witness signatures, and consistency history: permanent.
- RSA matter private keys: destruction within 24 hours after submission close.

All production retention periods require legal and data-protection approval in the deployment jurisdiction.

## 8. Acceptance boundary

The prototype is ready for controlled testing when all acceptance tests in `08_SECURITY_AND_ACCEPTANCE_TEST_PLAN.md` pass. It is not ready for real complainants until an external cryptographic review, penetration test, privacy review, accessibility test, operational recovery exercise, and jurisdictional legal review are complete.

## 9. Correction register against the supplied documents

| Source statement/problem | Corrected baseline |
|---|---|
| The RSA accumulator description did not define a complete private-membership proof or bind membership to the blind entitlement. | Prototype uses an explicit Semaphore-style Merkle proof. The same hidden `P` determines active membership, entitlement person commitment, and matter nullifier. A custom RSA accumulator remains a future provider. |
| The fallback proposed a Merkle non-membership proof over revoked devices. | The prototype proves membership in the current active-member tree; revoked leaves are replaced with a fixed empty value. |
| Blind RSA used an informal full-domain hash and “strong-prime” modulus. | Use the RFC 9474 `RSABSSA-SHA384-PSS-Randomized` suite, independent FIPS 186-5-compatible RSA-3072 matter keys, and exponent 65537. |
| Entitlement/device revocation semantics were underspecified. | Entitlement is bound to persistent `P`; the ZK proof also requires current device `D`. Device replacement rotates `D` while preserving `P`, so unspent entitlements remain usable only by the recovered active membership. |
| Phone loss relied on a service-line/hotline report. | Recovery uses a user-held 128-bit seed, derived Ed25519 recovery key, signed five-minute challenge, and mandatory atomic credential rotation. |
| Follow-up key was derived from the public entitlement serial. | Each complaint gets an independent random 256-bit follow-up seed and separate mailbox authentication/encryption keys. |
| Complaint content was visible to the complaint service. | Client encrypts the package with AES-256-GCM and HPKE-wraps the data key to the assigned handler organization. The CS stores ciphertext only. |
| Receipt format and privacy fields were not fixed. | Random receipt ID/nonce, deterministic CBOR, dedicated Ed25519 signature, and an explicit exclusion list for serial/nullifier/root/person commitment. |
| Log wording implied that deleting a private database row necessarily breaks a log consistency proof. | The log proves its own append-only public history. A receipt and included leaf prove prior acceptance; missing private data is exposed as retrieval/durability failure, not as a false consistency-proof claim. |
| Network-observer claim implied Tor and batching prevented timing linkage. | Tor is optional and reduces linkability; direct ingress and global timing correlation remain explicit residual risks. |
| Community visibility relied on account age/weighted accounts, conflicting with unlinkable membership. | Anonymous one-person-per-complaint vote proofs, fixed choices, seven-day window, quorum 10, 60% decision threshold, and an auditor-controlled discrepancy workflow. |
| Community voting could be read as verification of truth or automatic shutdown authority. | Votes assess redacted public information only. Conflict triggers review; only an authorized case authority closes the private complaint. |
| Hardware-backed Ed25519 availability was assumed uniformly. | The protocol separates BN254 device membership secret from platform authentication and requires hardware-backed sealing where supported; staff authentication uses WebAuthn. |
| Matter/key identity, setup artifacts, and root leases were not fully versioned. | UUIDv4 plus uint32 matter version, full SPKI fingerprints, SHA-256 content-addressed circuit artifacts, signed checkpoints, and 60-second current-root leases are mandatory. |
