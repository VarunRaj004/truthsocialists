# Deliverable 4: Comparative Report on Individual and Universal Verifiability

## 1. Introduction

The semester-project discussion uses electronic voting to illustrate how a secure online system should provide anonymity, eligibility, uniqueness, and verifiability. In an electronic election, **individual verifiability** lets a voter confirm that the system registered the vote as cast. **Universal or complete verifiability** lets independent auditors determine that all registered votes were processed according to the election rules without compromising ballot secrecy.

The same ideas apply to Cyber Cipher, although the protected object is an anonymous complaint rather than a vote. Individual verifiability means that a complainant can confirm that the system accepted the intended complaint commitment and subsequently preserved its recorded history. Universal verifiability means that an independent person can verify the append-only public history, detect inconsistent log views, and confirm that published community results were calculated from valid recorded inputs.

Swiss guidance treats verifiability as a way to detect manipulation while preserving secrecy. It also combines cryptography with separation of responsibility, independent examinations, publication of source code and documentation, and public scrutiny. Cyber Cipher adopts these principles but does not claim that verifiability proves that an allegation is factually true.

This report describes the **final system design**. These capabilities are specified and testable, but most remain to be implemented in the MVP.

## 2. Translation from electronic voting to Cyber Cipher

| Electronic-voting concept | Meaning in an election | Cyber Cipher equivalent |
|---|---|---|
| Eligible voter | Only a person listed as eligible may vote | Only a person verified by the Identity Authority may obtain active membership and a matter entitlement |
| One person, one vote | An eligible person cannot vote repeatedly in the same election | One person can submit at most one complaint per matter and cast at most one community vote per public complaint |
| Vote secrecy | A ballot must not reveal the voter | A complaint, receipt, entitlement, and membership proof must not reveal the complainant's NIC |
| Cast as intended | The ballot represents the voter's selection | The local manifest and commitment represent the text and sanitized evidence selected by the complainant |
| Recorded as cast | The intended ballot was accepted without alteration | A signed receipt binds the complaint commitment and the corresponding transparency-log entry |
| Tallied as recorded | Every valid recorded ballot contributes correctly to the result | Every accepted community vote contributes once to the published aggregate, and every complaint lifecycle event follows the recorded state machine |
| Public bulletin board | Encrypted ballots and proofs are published for checking | Commitments, lifecycle metadata, signed tree heads, witness signatures, and public vote records are published in an append-only log |
| Election trustees/control components | No single operator can secretly change the election | Separate IdA, complaint service, log operator, handler organizations, auditor, and three witnesses divide responsibility |

## 3. Comparative implementation of security capabilities

| Security capability | Common e-voting implementation | Cyber Cipher design | Verification evidence | Current status or limitation |
|---|---|---|---|---|
| Independent eligibility checking | Electoral register verifies a voter before credentials are issued | The IdA validates the NIC and registered contact channel before creating active membership | IdA enrollment and signed membership-checkpoint records | Designed; real NIC-register integration remains deployment-specific |
| Eligibility without revealing identity during use | Anonymous voting credential or zero-knowledge eligibility proof | Matter-specific RSA blind-signed entitlement plus Semaphore-style current-membership proof | Valid RSA signature and Groth16 proof with no NIC as a public input | Fully specified; circuits and blind-issuance code remain to be built |
| One person per scope | Used voting credential or election nullifier prevents a second ballot | A unique blind-token serial and `complaintNullifier = Poseidon(P, matter)` prevent repeated complaints; a complaint-scoped vote nullifier prevents repeated votes | Database uniqueness constraints and ZK public signals | Designed; persistent `P` must survive recovery to preserve uniqueness |
| Cast/content as intended | Voter checks return codes or another verification value corresponding to selected candidates | Client normalizes the text and attachments, constructs deterministic CBOR, and displays the salted SHA-256 complaint commitment before submission | Local manifest, salt, attachment hashes, and displayed commitment | A compromised client can still commit different content; an independent verifier/export is recommended |
| Recorded as submitted | Voter receives evidence that the ballot box registered the ballot | Complaint service returns a randomized deterministic-CBOR receipt signed by its dedicated Ed25519 key | Receipt signature, complaint commitment, matter reference, acceptance time, and initial log-entry hash | Receipt proves acceptance of the commitment, not the truth of the complaint |
| Inclusion in the public record | Voter locates the encrypted ballot or verification reference on a bulletin board | Client obtains a Merkle inclusion proof connecting the receipt's log-entry hash to a finalized signed tree head | RFC 6962-style inclusion path, log signature, and at least two witness signatures | Finality may be delayed while the outbox/log/witness process completes; UI must show `PENDING` versus `FINAL` |
| Later personal verification | Voter repeats verification after the election | Client retains the manifest, salt, receipt, and recovery-protected complaint material and can recompute the commitment and verify later case events | Recomputed commitment, receipt signature, inclusion proofs, and signed event chain | MVP must add a ciphertext-download route and retain a user-wrapped DEK or equivalent package so the user can verify the stored encrypted bytes, not only the accepted commitment |
| Append-only universal record | Public bulletin board prevents undetected ballot removal or replacement | Transparency log uses SHA-256 leaf/node hashes, consistency proofs, signed tree heads, and three witnesses with 2-of-3 finality | Full log download, consistency proof, operator signature, witness signatures | Protects the public log's history; it does not by itself detect deletion from a separate private complaint database |
| Independent result verification | Auditors verify that each accepted ballot is included and the tally proof is correct | Public verifier reconstructs log roots and checks community vote proofs/nullifiers and aggregation policy | Published proof envelopes or commitments, accepted nullifiers, choices, and result calculation | Per-vote public audit records must be implemented for outsiders to recompute the community result |
| Detection of split views | Bulletin-board replicas or trustees compare views | Clients, auditors, and witnesses gossip signed tree heads and reject inconsistent histories | Conflicting signed heads or failed consistency proofs | Prototype containers demonstrate the protocol; real independence requires witnesses run by separate organizations |
| Separation of responsibility | Multiple trustees/control components share sensitive authority | IdA, complaint service, handler, log, auditor, and witnesses have separate keys, databases, credentials, and duties | Service-specific signatures, access logs, key IDs, and network boundaries | Separate containers on one laptop are not administrative independence |
| Confidentiality during verification | Encrypted ballots and zero-knowledge tally proofs protect vote secrecy | Complaint plaintext and evidence use AES-256-GCM; the data key is HPKE-wrapped to the assigned handler organization | Ciphertext, handler key ID, HPKE envelope, and content commitment | Public verification covers commitments and metadata, not plaintext; this is intentional |
| Transparent implementation | Published protocol, source code, proofs, and independent reviews | CDDL, OpenAPI, SQL schema, circuits, artifact manifests, test vectors, verifier, and operational documentation are intended to be public | SHA-256 content-addressed artifacts and reproducible test vectors/builds | Specifications and vectors exist; source implementation and reproducible builds are pending |
| Independent examination | Cryptographic, software, operational, and intrusion reviews | Circuit review, protocol review, penetration testing, privacy review, operational recovery exercise, and public scrutiny are release gates | Signed reports, artifact/build IDs, defect register, and remediation evidence | Required before a real pilot; internal testing alone is insufficient |

## 4. Individual verifiability workflow

Individual verifiability is implemented as a sequence rather than a single ticket number:

1. **Prepare locally:** The client removes metadata from the public-safe derivatives, normalizes the complaint text, hashes every attachment, and encodes the deterministic-CBOR manifest.
2. **Commit locally:** It generates a random 32-byte salt and calculates `SHA-256(salt || CBOR(manifest))`. The user is shown the commitment before transmission.
3. **Bind authorization:** The Groth16 proof publicly binds the matter, blind-entitlement serial, complaint commitment, current membership root, and short-lived challenge while keeping `P`, `D`, `r`, and the Merkle path private.
4. **Receive evidence of acceptance:** Only after the ciphertext, spent serial, nullifier, complaint row, and durable log outbox event commit atomically does the service return an Ed25519-signed receipt.
5. **Check public inclusion:** The app verifies the receipt and later downloads a Merkle inclusion proof and a signed tree head carrying at least two valid witness signatures.
6. **Check subsequent history:** Signed, committed lifecycle events allow the complainant to verify assignment, investigation, extension, resolution, rejection, suppression, appeal, or closure without trusting a mutable status field alone.

The receipt deliberately excludes the entitlement serial, person commitment, membership root, epoch, and nullifier so that showing a receipt does not disclose the user's membership proof material. Nevertheless, any strong receipt can be coerced from the user; therefore receipt-freeness is only partial.

### Individual-verification result states

| App result | Meaning |
|---|---|
| `ACCEPTED_PENDING_LOG` | Receipt signature is valid, but a witnessed containing checkpoint is not final yet |
| `VERIFIED_INCLUDED` | Receipt, commitment, inclusion proof, tree-head signature, and witness quorum all verify |
| `CONTENT_MISMATCH` | Locally recomputed commitment differs from the signed receipt |
| `LOG_PROOF_INVALID` | Inclusion/consistency proof or signed tree head is invalid |
| `WITNESS_QUORUM_MISSING` | Fewer than two configured witnesses signed the tree head |
| `DATA_UNAVAILABLE` | Prior acceptance remains provable, but the encrypted private record cannot be retrieved |

## 5. Universal verifiability workflow

The transparency log acts like the public bulletin board used in verifiable voting:

1. Each accepted complaint or lifecycle action produces a canonical public event containing only a random event/case reference, event type, matter reference, commitment, time, actor class, and permitted reason code.
2. The log calculates `leafHash = SHA-256(0x00 || CBOR(logEntry))` and constructs parent nodes using `SHA-256(0x01 || left || right)`.
3. When entries change, the operator publishes a signed tree head. Each independent witness downloads the new leaves, verifies consistency with its previous tree head, reconstructs the root, and signs the exact head.
4. A checkpoint is final only with signatures from at least two of the three configured witnesses.
5. Anyone can download the complete public log and use an open-source verifier to recompute roots, check inclusion/consistency proofs, validate signatures, and detect divergent histories.
6. For community assessment, outsiders should be able to verify each published vote proof, confirm one unique nullifier per complaint, recount the four choices, and apply the seven-day, minimum-10-voter, and 60% rules.
7. The public auditor compares the community outcome with the handler finding. A conflict creates an attributable review or temporary public freeze; it never automatically deletes or closes the underlying complaint.

The universal verifier can detect modification, insertion, removal, or inconsistent presentation **inside the public log**. It cannot prove that a submission blocked before receipt existed, that a private allegation is true, or that a handler's real-world investigation was competent. These remain availability, factual, and governance questions rather than cryptographic-verifiability claims.

## 6. Comparison of assurance and trust assumptions

| Question | Individual verifiability | Universal verifiability |
|---|---|---|
| Primary verifier | The complainant's client or an independent receipt-checking tool | Any public auditor using the full log and verifier |
| Main object checked | One complaint commitment and its lifecycle history | The completeness and consistency of the published system history and aggregate community result |
| Private material required | Receipt, manifest, salt, and preferably user-recoverable encrypted-package key/material | None for public log verification |
| Privacy exposure | Verification material links the holder to that complaint only if the holder reveals it | Public data contain commitments and metadata, not NIC or plaintext |
| Trust that remains | Client correctness, protection of local secrets, at least two honest witness keys for finality | Correct public verifier, at least two non-colluding witnesses, correct circuit/artifact allowlist |
| What failure demonstrates | The user's accepted content/history cannot be validated | The public log or aggregate result is inconsistent with published evidence |

## 7. Implementation priorities identified by the comparison

Before claiming that the MVP implements verifiability, the following must be completed:

1. Implement cross-language deterministic-CBOR and signature/hash test-vector conformance.
2. Build the receipt verifier and make the user verify it immediately after submission.
3. Implement log inclusion and consistency proofs, signed tree heads, three witness services, and tree-head gossip.
4. Add a user-verifiable encrypted-package retrieval mechanism. The client should retain the DEK in its protected recovery bundle or hold a user-wrapped DEK, then retrieve and decrypt the stored ciphertext to recompute the signed commitment.
5. Publish each accepted anonymous community vote or a sufficient audit record so an outsider can verify its proof, uniqueness, choice, and inclusion and independently recompute the result.
6. Publish the verifier, schemas, circuit sources, content-addressed artifacts, setup transcripts, build instructions, and test vectors.
7. Test private-row deletion separately from public-log rewriting: the former must produce `DATA_UNAVAILABLE`, while the latter must fail a consistency or inclusion check.
8. Replace same-host demonstration witnesses with independently administered witnesses before any real pilot.
9. Obtain independent cryptographic, software, infrastructure, privacy, and penetration assessments.

## 8. Conclusion

Cyber Cipher applies the central e-voting lesson that a reference number is not verifiability. Individual verifiability is provided by a locally computed complaint commitment, a signed receipt, public-log inclusion, and verifiable lifecycle events. Universal verifiability is provided by an append-only Merkle log, consistency proofs, independently witnessed tree heads, downloadable records, and an open verifier. Blind entitlements and zero-knowledge membership preserve separation between eligibility and complaint identity while nullifiers enforce one person per scope.

The design is stronger than an ordinary complaint portal because an operator cannot silently rewrite the published history without producing inconsistent cryptographic evidence. However, its claims remain intentionally limited: the system does not verify factual truth, guarantee anonymity against global traffic analysis, prove that a pre-receipt request was not blocked, or make community voting authoritative. Complete verifiability also depends on correct implementation, reproducible artifacts, independent witnesses, and external examination; these are mandatory MVP and pilot gates rather than optional improvements.

## References

1. Swiss Federal Chancellery, [Security in e-voting](https://www.bk.admin.ch/en/security-in-e-voting).
2. Swiss Federal Chancellery, [Examination of systems](https://www.bk.admin.ch/en/examination-of-systems).
3. Swiss Federal Chancellery, [Annex of the Federal Chancellery Ordinance on Electronic Voting](https://www.bk.admin.ch/dam/bk/en/dokumente/pore/Annex_of_the_Federal_Chancellery_Ordinance_on_Electronic_Voting_V2.0_July_2018.pdf.download.pdf/Annex_of_the_Federal_Chancellery_Ordinance_on_Electronic_Voting_V2.0_July_2018.pdf).
4. Swiss Federal Chancellery Steering Committee, [Final report on the redesign and relaunch of e-voting trials](https://www.bk.admin.ch/dam/bk/en/dokumente/pore/Final%20report%20SC%20VE_November%202020.pdf.download.pdf/Final%20report%20SC%20VE_November%202020.pdf).
5. Team Cyber Ciphers, *Cyber Cipher Design Baseline v1.0*, 25 September 2026.
