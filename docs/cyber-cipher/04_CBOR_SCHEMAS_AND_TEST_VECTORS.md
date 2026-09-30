# Canonical CBOR Schemas and Test Vectors

## 1. Encoding profile

All security-relevant CBOR follows RFC 8949 deterministic encoding with these additional rules:

- definite lengths only;
- shortest integer and length encoding;
- map keys are unsigned integers and appear in deterministic encoded-key order;
- duplicate or unknown keys are rejected unless a schema explicitly marks an extension map;
- floats, tags, `null`, and text representations of binary data are forbidden;
- byte lengths are exact;
- UTF-8 text is NFC normalized before encoding;
- UUIDs are raw 16-byte RFC 4122 network-order values;
- timestamps are unsigned Unix milliseconds;
- field elements are canonical 32-byte big-endian values less than the BN254 scalar modulus;
- hashes and key IDs are raw 32-byte strings;
- signatures are raw fixed-width bytes.

The machine-readable CDDL is in `schemas/cyber-cipher-v1.cddl`. JSON in this project is diagnostic only and is never the signed wire representation.

## 2. Schema registry

| Type | Purpose | Signed/encrypted form |
|---|---|---|
| `entitlement-message` | Blind RSA application message | Input to RFC 9474 preparation |
| `entitlement-token` | Spendable message/randomizer/signature tuple | Stored on client; sent once to CS |
| `membership-checkpoint` | Current active root | Ed25519 signed by IdA checkpoint key |
| `proof-lease` | Current-root challenge | Ed25519 signed by proof-session key |
| `proof-envelope` | Groth16 proof and ordered public inputs | Verified against allowlisted artifact |
| `complaint-manifest` | Text and sanitized attachment commitment | Salted SHA-256 commitment |
| `private-complaint-package` | Handler-readable content | AES-256-GCM encrypted |
| `receipt` | User-verifiable acceptance record | Ed25519 signed by CS receipt key |
| `log-entry` | Public tamper-evident event | RFC 6962 leaf hash |
| `signed-tree-head` | Log checkpoint | Ed25519 plus witness signatures |
| `artifact-manifest` | Reproducible circuit identity | SHA-256 content address |

## 3. Integer key assignments

Keys are local to each map. They are never inferred from field names.

### Entitlement message

| Key | Field | Type |
|---:|---|---|
| 1 | protocolVersion | uint, value 1 |
| 2 | matterKeyId | bstr32 |
| 3 | serial | bstr16 |
| 4 | personCommitment | field32 |

### Membership checkpoint unsigned body

| Key | Field | Type |
|---:|---|---|
| 1 | protocolVersion | uint |
| 2 | epoch | uint64 |
| 3 | root | field32 |
| 4 | previousCheckpointHash | bstr32; all-zero only at genesis |
| 5 | publishedAt | uint64 milliseconds |
| 6 | updateBatchHash | bstr32 |
| 7 | signingKeyId | bstr32 |

The signed wrapper uses key `1` for the unsigned body and key `2` for the 64-byte Ed25519 signature.

### Proof lease unsigned body

| Key | Field | Type |
|---:|---|---|
| 1 | protocolVersion | uint |
| 2 | challengeId | bstr16 |
| 3 | purpose | uint: 1 complaint, 2 vote |
| 4 | epoch | uint64 |
| 5 | membershipRoot | field32 |
| 6 | issuedAt | uint64 milliseconds |
| 7 | expiresAt | uint64 milliseconds |
| 8 | serverNonce | bstr32 |
| 9 | signingKeyId | bstr32 |

### Complaint manifest

| Key | Field | Type |
|---:|---|---|
| 1 | protocolVersion | uint |
| 2 | matterId | bstr16 |
| 3 | matterVersion | uint32 |
| 4 | text | NFC UTF-8 text |
| 5 | attachments | ordered array of attachment records |

Attachment record keys are `1=index`, `2=size`, `3=MIME`, `4=sanitized filename`, and `5=SHA-256(final sanitized bytes)`.

### Encryption authenticated data

The AES-256-GCM complaint-package AAD is a deterministic-CBOR map with keys `1=protocolVersion`, `2=complaintId`, `3=matterId`, `4=matterVersion`, `5=complaintCommitment`, and `6=handlerKeyId`.

The HPKE handler-DEK AAD is a deterministic-CBOR map with keys `1=protocolVersion`, `2=complaintId`, `3=complaintCommitment`, and `4=handlerKeyId`. HPKE `info` is the literal UTF-8 protocol label followed by the 16-byte matter ID and four-byte big-endian matter version.

### Recovery objects

The signed recovery-challenge body uses keys `1=protocolVersion`, `2=tenantId`, `3=challengeId`, `4=recoveryId`, `5=recoveryGeneration`, `6=issuedAt`, `7=expiresAt`, `8=serverNonce`, and `9=signingKeyId`. Its signed wrapper is `{1: body, 2: signature64}` and its lifetime cannot exceed five minutes.

The recovery authorization uses keys `1=protocolVersion`, `2=tenantId`, `3=SHA-256(complete signed challenge)`, `4=personAnchor`, `5=newDeviceHash`, `6=newRecoveryId`, `7=newRecoveryPublicKey`, and `8=expectedRecoveryGeneration`.

Recovery-backup AAD uses keys `1=protocolVersion`, `2=tenantId`, `3=recoveryId`, `4=purpose` (`1` person secret, `2` mailbox bundle), and `5=generation`.

### Receipt unsigned body

| Key | Field | Type |
|---:|---|---|
| 1 | protocolVersion | uint |
| 2 | receiptId | bstr16 |
| 3 | receiptNonce | bstr32 |
| 4 | complaintId | bstr16 |
| 5 | matterId | bstr16 |
| 6 | matterVersion | uint32 |
| 7 | complaintCommitment | bstr32 |
| 8 | acceptedAt | uint64 milliseconds |
| 9 | logEntryHash | bstr32 |
| 10 | receiptKeyId | bstr32 |

The signed wrapper is `{1: unsigned-body, 2: signature64}`.

### Log entry

| Key | Field | Type |
|---:|---|---|
| 1 | protocolVersion | uint |
| 2 | eventId | bstr16 |
| 3 | eventType | uint registry value |
| 4 | complaintId | bstr16 or omitted for non-complaint events |
| 5 | matterId | bstr16 or omitted |
| 6 | matterVersion | uint32 or omitted |
| 7 | eventCommitment | bstr32 |
| 8 | occurredAt | uint64 milliseconds |
| 9 | actorClass | uint registry value |
| 10 | reasonCode | uint or omitted |

Public event commitments MUST be purpose-specific hashes of private event objects. They MUST NOT be raw hashes of predictable NICs, entitlement serials, or membership leaves.

## 4. Test-vector generation

`test-vectors/generate_vectors.py` is the normative generator for the included examples. It contains a small deterministic-CBOR encoder rather than relying on a library's default mode. Run:

```powershell
python test-vectors/generate_vectors.py
```

It writes `test-vectors/cyber-cipher-v1-vectors.json` containing:

- encoded entitlement message and SHA-256 hash;
- encoded complaint manifest, fixed salt, and complaint commitment;
- encoded log entry and RFC 6962 leaf hash;
- unsigned receipt bytes, signing input, deterministic Ed25519 public key/signature, and complete receipt bytes;
- unsigned membership checkpoint bytes, signing input, public key/signature, and checkpoint hash;
- hash-to-field framing examples and all Poseidon domain constants;
- negative cases that strict decoders/verifiers must reject.

Fixed private seeds exist only to make the vectors reproducible and MUST NEVER be used outside tests.

## 5. Required conformance assertions

A conforming implementation MUST reproduce every hexadecimal byte string and decimal field value in the vector file. It MUST also reject:

1. non-minimal integer encodings;
2. indefinite-length arrays/maps/byte strings;
3. duplicate or unknown map keys;
4. a field element equal to or greater than `q`;
5. an all-zero scalar where a secret must be non-zero;
6. a receipt whose signature is valid over a differently ordered/noncanonical encoding;
7. a proof envelope whose public-input order differs from the artifact manifest;
8. an entitlement with a 15- or 17-byte serial;
9. a lease longer than 60 seconds or accepted after expiration;
10. a receipt containing a serial, nullifier, root, epoch, or person commitment;
11. Unicode text that was not normalized to NFC before encoding;
12. attachment arrays with duplicate or non-contiguous indices.

## 6. Compatibility policy

Adding a required field, changing a key number, changing a cryptographic derivation, or changing the meaning/order of proof signals requires a new protocol or circuit version. Optional extensions must live inside an explicitly defined extension map in a future schema; version 1 has no generic extension maps. Version-1 decoders fail closed on unknown keys.
