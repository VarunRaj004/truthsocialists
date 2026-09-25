# Cryptographic Protocol Specification

## 1. Version and notation

This specification defines protocol version `1`.

- `H(x)` is SHA-256 unless explicitly stated otherwise.
- `H384(x)` is SHA-384.
- `HKDF(salt, IKM, info, L)` is HKDF-SHA256.
- `CBOR(x)` is RFC 8949 deterministic CBOR according to `schemas/cyber-cipher-v1.cddl`.
- `||` is byte concatenation.
- `I2OSP(x, L)` is an unsigned big-endian integer encoded in exactly `L` bytes.
- `q = 21888242871839275222246405745257275088548364400416034343698204186575808495617`, the BN254 scalar-field modulus.
- Field elements in external encodings are exactly 32-byte unsigned big-endian values strictly less than `q`.
- Random byte strings are produced by the operating system CSPRNG.

Every signed object uses an explicit ASCII signing prefix ending in NUL:

```text
CYBER-CIPHER/v1/<object-type>\x00 || CBOR(unsigned-object)
```

Ed25519 signs these bytes directly. Implementations MUST NOT silently prehash them or substitute Ed25519ph.

## 2. Domain separation

For Poseidon, each domain constant is:

```text
Domain(label) = OS2IP(SHA-256("CYBER-CIPHER/v1/poseidon/" || label)) mod q
```

The result MUST be non-zero. The protocol labels are:

```text
person
device
member-leaf
empty-leaf
merkle-node
entitlement-person
complaint-nullifier
vote-nullifier
vote-message
matter-field
serial-field
complaint-id-field
commitment-field
challenge-field
```

Circuit source MUST contain the precomputed constants. The artifact manifest MUST bind those source files.

For non-circuit hashes, the input is length-framed:

```text
Frame(label, parts...) =
  "CYBER-CIPHER/v1/" || label || 0x00 ||
  I2OSP(len(part1), 8) || part1 || ...

HashToField(label, parts...) = OS2IP(SHA-256(Frame(label, parts...))) mod q
```

## 3. Key catalogue

| Key | Algorithm | Scope | Custody and rotation |
|---|---|---|---|
| Matter entitlement key | RSA-3072 RSASSA-PSS/SHA-384 | One matter version | Prototype: encrypted PKCS#8 in dedicated secrets volume; production: HSM. Destroy private key within 24 hours after submission close. |
| Membership checkpoint key | Ed25519 | IdA membership service | Dedicated KMS/HSM key; publish versioned public key before use. |
| Proof-session lease key | Ed25519 | Complaint verifier | Dedicated key; separate from every other signer. |
| Recovery challenge key | Ed25519 | IdA recovery service | Dedicated key. |
| Receipt key | Ed25519 | Complaint service | Dedicated key; overlap public keys during rotation. |
| Transparency-log key | Ed25519 | Log operator | Dedicated key. |
| Witness keys | Ed25519 | One per witness | Each independently administered. |
| Handler envelope key | X25519 HPKE | One handler organization and key version | KMS/HSM; retain old private versions until all DEKs are rewrapped or data expires. |
| Handler action key | WebAuthn authenticator plus organization signing service | Named staff action | Phishing-resistant user authentication; action signature issued by controlled service. |
| Recovery key | Ed25519 | One recovery generation | Derived locally; public key stored by IdA; rotate after use. |
| Mailbox auth key | Ed25519 | One complaint | Derived locally from follow-up seed. |
| Mailbox encryption key | X25519 | One complaint | Derived locally from follow-up seed. |

An Ed25519/X25519 key ID is the full SHA-256 hash of the canonical DER SubjectPublicKeyInfo. `matterKeyId` is the full SHA-256 hash of the canonical DER RSA SubjectPublicKeyInfo, including the RSASSA-PSS parameters. Text display uses base64url without padding; protocol encodings use the raw 32 bytes.

## 4. RSA blind-signed entitlement

### 4.1 Key generation and publication

Generate a fresh RSA-3072 key with public exponent 65537 using a FIPS 186-5-compatible generator. Do not impose a custom “strong prime” construction. The key MUST be dedicated to RSABSSA for one matter version and MUST NOT be used for ordinary signatures, TLS, encryption, or another matter.

The public key metadata fixes:

- RSABSSA suite: `RSABSSA-SHA384-PSS-Randomized`;
- MGF: MGF1-SHA384;
- PSS salt length: 48 bytes;
- randomized message-preparation prefix: 32 bytes;
- modulus size: 3072 bits;
- public exponent: 65537.

Publish the matter, public key, fingerprint, opening/closing times, and circuit artifact IDs at least 24 hours before issuance/submission opens.

### 4.2 Entitlement message

The application message is deterministic CBOR containing:

```text
protocolVersion = 1
matterKeyId     = 32 bytes
serial          = 16 random bytes
personCommitment = Field(Poseidon(Domain("entitlement-person"), P, r))
```

where `P` and `r` are random non-zero field elements. The RSABSSA randomized preparation creates a 32-byte `messageRandomizer`; the client MUST retain it with the final signature because verification reconstructs the prepared message.

### 4.3 Issuance

1. The client verifies matter metadata and key fingerprint.
2. It constructs and validates the entitlement message.
3. It performs RFC 9474 randomized preparation and blinding using fresh randomness.
4. Over an authenticated enrollment session, it sends the blinded request and matter version to the IdA.
5. The IdA checks the submission window/issuance policy and atomically inserts the unique issuance fact `(NIC-internal-id, matter-id, matter-version)`.
6. The IdA blind-signs and returns the blind signature.
7. The client finalizes/unblinds and verifies locally before saving the token.

The IdA MUST NOT log blinded representatives at a precision/retention that enables later operational correlation. Failed issuance MUST not create the issuance fact unless the signing operation was completed and the response is recoverable idempotently.

### 4.4 Spend

The CS verifies the signature over the exact CBOR entitlement message using the published matter key and retained message randomizer. It checks `matterKeyId`, matter window, serial length, and scalar canonicality. RSA verification occurs outside the Groth16 circuit. The CS then checks that the proof public signals contain matching `serialField` and `personCommitment`.

## 5. Active-membership tree

### 5.1 Leaves

At enrollment:

```text
personHash = Poseidon(Domain("person"), P)
deviceHash = Poseidon(Domain("device"), D)
leaf = Poseidon(Domain("member-leaf"), personHash, deviceHash)
EMPTY_LEAF = Poseidon(Domain("empty-leaf"), 0)
```

The client sends `personHash` and `deviceHash` to the IdA inside the identified enrollment channel. The IdA may associate these hashes and the allocated index with the NIC, but they MUST never appear in the complaint domain or public log. This stored person anchor permits recovery to preserve `P` without revealing it.

The depth is 16. Unallocated and revoked positions contain `EMPTY_LEAF`. Allocation is monotonic; an index is never reused. Internal nodes are:

```text
node = Poseidon(Domain("merkle-node"), left, right)
```

### 5.2 Checkpoint

Every changed 30-second batch increments the unsigned 64-bit `epoch` by one. The membership service signs a deterministic-CBOR checkpoint containing protocol version, epoch, root, previous checkpoint hash, publication time, update-batch hash, and signing-key ID. The checkpoint hash is SHA-256 of its complete signed CBOR object and is appended to the transparency log.

Clients MUST verify the signature and predecessor hash before accepting a new path/root. A checkpoint without a valid predecessor is a fork warning.

## 6. Complaint proof

### 6.1 Private witness

- `P`: non-zero person scalar.
- `D`: non-zero current device scalar.
- `r`: non-zero entitlement-commitment randomness.
- `merkleSiblings[16]`.
- `merklePathBits[16]`, each constrained boolean.

### 6.2 Public signals, in exact order

1. `membershipRoot`
2. `epoch`
3. `matterField`
4. `serialField`
5. `personCommitment`
6. `complaintNullifier`
7. `complaintCommitmentField`
8. `challengeField`

The derivations are:

```text
matterField = HashToField("matter-field", matterId16, uint32be(matterVersion))
serialField = HashToField("serial-field", serial16)
personCommitment = Poseidon(Domain("entitlement-person"), P, r)
complaintNullifier = Poseidon(Domain("complaint-nullifier"), P, matterField)
complaintCommitmentField = HashToField("commitment-field", complaintCommitment32)
challengeField = HashToField("challenge-field", SHA-256(CBOR(unsignedLease)))
```

The circuit recomputes `personHash`, `deviceHash`, leaf, and the 16-level path; constrains the result to `membershipRoot`; recomputes the person commitment and nullifier; and exposes all public signals above. `matterField`, `serialField`, complaint commitment, and challenge are public binding signals even where no private arithmetic depends on them. The verifier MUST compare them to the request; omitting that comparison is a security failure.

### 6.3 External verification order

1. Parse with strict size/canonicality limits.
2. Resolve and verify `artifactId` and verification key.
3. Verify matter metadata and submission window.
4. Verify signed root lease and challenge; require current root/epoch and unexpired 60-second lease.
5. Verify RSA entitlement and derive expected public signals.
6. Verify Groth16 proof.
7. Check unique serial and complaint nullifier.
8. Validate ciphertext, HPKE envelope, mailbox public data, and commitment sizes.
9. Atomically accept, consume, log, and issue receipt.

The challenge ID is random 16 bytes. A challenge is consumed only by a successfully committed submission. Failed verification is rate limited but does not consume it. A successful transaction marks it consumed.

## 7. Voting proof

The voting circuit is separate from the complaint circuit.

Private witness: `P`, `D`, `merkleSiblings[16]`, and `merklePathBits[16]`.

Public signals, in exact order:

1. `membershipRoot`
2. `epoch`
3. `complaintIdField`
4. `voteNullifier`
5. `voteChoice`
6. `voteMessageCommitment`
7. `challengeField`

Derivations:

```text
complaintIdField = HashToField("complaint-id-field", complaintId16)
voteNullifier = Poseidon(Domain("vote-nullifier"), P, complaintIdField)
voteChoice in {0,1,2,3}
voteMessageCommitment = Poseidon(Domain("vote-message"), complaintIdField, voteChoice)
```

Choice mapping: `0=CORROBORATE`, `1=DISPUTE`, `2=INSUFFICIENT_INFORMATION`, `3=UNSAFE_OR_ABUSIVE`.

The same current-root and 60-second signed-lease rules apply. The vote service atomically inserts the unique `(complaintId, voteNullifier)` and aggregate contribution only after proof verification.

## 8. Groth16 artifact lifecycle

- Proof system: Groth16.
- Curve: BN254.
- Circuit language: Circom 2.
- Prover target: Rapidsnark-compatible WASM/native artifacts.
- Phase 1: an existing, publicly verifiable Powers-of-Tau transcript at adequate constraint capacity.
- Phase 2: one circuit-specific ceremony per final circuit with three independent contributions.
- Toxic intermediate files MUST be destroyed by contributors after contribution.

The deterministic artifact manifest records protocol/circuit name and version, tree depth, proof system, curve, compiler and dependency versions, and SHA-256 hashes of source bundle, R1CS, WASM, proving key, verification key, Powers-of-Tau input, phase-two transcript, and creation timestamp. `artifactId` is the full SHA-256 hash of `CBOR(manifest)`. A proof envelope includes scheme, circuit version, artifact ID, proof, and ordered public signals.

Any circuit-source, dependency, compiler, parameter, constraint, or public-input-order change creates a new artifact ID. Verifiers use an explicit allowlist; they MUST NOT fetch an arbitrary verification key named by an untrusted request.

## 9. Recovery protocol

### 9.1 Derivation

The 16-byte recovery seed has 128 bits of effective security. Derive:

```text
recoverySignSeed = HKDF(recoveryId16, recoverySeed16,
  "CYBER-CIPHER/v1/recovery-sign", 32)
backupKey = HKDF(recoveryId16, recoverySeed16,
  "CYBER-CIPHER/v1/person-backup", 32)
bundleKey = HKDF(recoveryId16, recoverySeed16,
  "CYBER-CIPHER/v1/mailbox-bundle", 32)
```

`recoverySignSeed` is the Ed25519 private seed. The person backup and mailbox bundle use AES-256-GCM with fresh random 12-byte nonces and AAD containing protocol version, recovery ID, purpose, and generation.

### 9.2 Challenge and atomic rotation

The IdA returns a signed challenge with random 16-byte challenge ID, recovery ID, issue/expiry times, and server nonce. Maximum lifetime is five minutes. The replacement device signs the challenge hash, new `deviceHash`, new recovery public key/ID, and the stored `personHash` using the old recovery key.

Within one serializable transaction the IdA:

1. locks the recovery and enrollment rows;
2. verifies challenge freshness, non-consumption, signature, and `personHash` equality;
3. replaces the old leaf with `EMPTY_LEAF`;
4. allocates a new monotonic index and leaf using the same `personHash` and new `deviceHash`;
5. invalidates the old recovery credential and stores the new one;
6. consumes the challenge and records the update batch.

If any step fails, none are committed. The user re-encrypts local recovery bundles under the new seed after success.

## 10. Complaint encryption and handler reassignment

Generate random `DEK` (32 bytes) and nonce (12 bytes). Encrypt the deterministic-CBOR private complaint package using AES-256-GCM. AAD binds protocol version, complaint ID, matter ID/version, complaint commitment, and handler key ID.

Wrap `DEK` with RFC 9180 HPKE using:

- KEM: DHKEM(X25519, HKDF-SHA256);
- KDF: HKDF-SHA256;
- AEAD: AES-256-GCM;
- mode: base mode;
- `info`: `"CYBER-CIPHER/v1/handler-dek" || matterId || version`;
- AAD: complaint ID, complaint commitment, and handler key ID.

The CS stores the ciphertext, nonce, tag, HPKE encapsulated key, wrapped DEK, suite identifiers, and handler key ID. It never stores the plaintext DEK.

For cross-organization reassignment, the authorized current handler unwraps the DEK and HPKE-wraps only the same DEK to the destination organization's published key. The signed transfer binds old/new handler IDs, old/new key IDs, complaint ID, ciphertext hash, actor, reason, and time. There is no universal escrow key.

## 11. Complaint commitment and attachments

The client creates a manifest containing protocol version, matter ID/version, NFC-normalized text, and ordered attachment records. Each public-safe attachment record binds zero-based index, byte length, allowlisted MIME type, sanitized NFC filename, and SHA-256 of the final sanitized bytes.

```text
complaintCommitment = SHA-256(salt32 || CBOR(manifest))
```

The salt is random 32 bytes and remains in the private package/user receipt material. The public log contains only the commitment. Encrypted originals may be included in the private package with distinct hashes and safety labels; they MUST NOT be substituted for the committed derivative without producing a new versioned event.

## 12. Receipt

The unsigned receipt contains protocol version, random 16-byte receipt ID, random 32-byte receipt nonce, complaint ID, matter ID/version, complaint commitment, acceptance time in Unix milliseconds, initial log-entry hash, and receipt signing-key ID. It excludes entitlement serial, person commitment, membership root, epoch, nullifier, challenge, IP, and user-agent data.

```text
signature = Ed25519.Sign(receiptSK,
  "CYBER-CIPHER/v1/receipt\x00" || CBOR(unsignedReceipt))
```

The signed receipt is itself deterministic CBOR. The client verifies strict canonical encoding, key ID, signature, matter and commitment equality, and clock plausibility before accepting it.

## 13. Transparency log and witnesses

Use RFC 6962-style domain separation:

```text
leafHash = SHA-256(0x00 || CBOR(logEntry))
nodeHash = SHA-256(0x01 || left32 || right32)
```

A signed tree head contains protocol version, tree size, root hash, timestamp, previous finalized tree-head hash, and log key ID. The log operator signs the prefixed deterministic encoding. Each witness independently downloads/validates new entries, verifies consistency from its last tree head, and signs the exact tree-head hash. A checkpoint is final with signatures from at least two of three configured witnesses.

The complaint receipt may initially bind the accepted log-entry hash before the containing checkpoint is final. The client MUST later retrieve an inclusion proof and a final witnessed tree head. Failure to finalize within the declared objective is visible and alertable; it does not invalidate the receipt signature.

## 14. Anonymous mailbox

For each complaint, generate `followUpSeed32` and `mailboxId16`.

```text
mailboxAuthSeed = HKDF(mailboxId16, followUpSeed32,
  "CYBER-CIPHER/v1/mailbox-auth", 32)
mailboxX25519Seed = HKDF(mailboxId16, followUpSeed32,
  "CYBER-CIPHER/v1/mailbox-hpke", 32)
```

The first output seeds Ed25519. The second is clamped as required for X25519. The CS stores only `mailboxId`, public keys, state, and ciphertext messages. Authentication challenges are random 16 bytes, valid for at most 60 seconds, and consumed only after successful signature verification.

Handler-to-user messages use the mailbox X25519 key with the same RFC 9180 HPKE suite. User-to-handler messages use the current handler organization key. Each encrypted message binds mailbox ID, monotonically increasing message number, direction, and previous-message hash as AAD. This supplies ordering and deletion detection; it is not a Double Ratchet and does not claim post-compromise security.

## 15. Prototype private-key files

Prototype RSA and service private keys stored outside an HSM MUST be encrypted PKCS#8 files in a dedicated secrets volume outside the source repository and database backups. File encryption uses AES-256-GCM with a random 12-byte nonce and a 256-bit KEK from the configured secret manager. AAD includes file-format version, key ID, matter ID/version where applicable, and algorithm identifier. File permissions MUST restrict access to the owning service identity.

## 16. Algorithm agility and future RSA accumulator

Every proof envelope declares `scheme`, `circuitVersion`, and `artifactId`. The application invokes a membership-provider interface with operations to publish state, obtain/update a witness, issue a root lease, produce a proof, and verify a proof.

The future RSA accumulator provider must define a trusted-modulus ceremony or class-group alternative, prime representative derivation, dynamic deletion/witness-update protocol, zero-knowledge membership statement, device-replacement binding to persistent `P`, proof-of-knowledge soundness, and compatibility test vectors. It MUST complete independent cryptographic review before replacing the Merkle provider.
