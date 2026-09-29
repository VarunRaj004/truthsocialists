import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  BN254_SCALAR_MODULUS,
  POSEIDON_DOMAIN_LABELS,
  assertExactIntegerKeys,
  artifactManifest,
  attachmentRecord,
  bytesToHex,
  complaintManifest,
  decodeCanonical,
  decodeFieldElement,
  ed25519SpkiFromRaw,
  encodeCanonical,
  entitlementMessage,
  frame,
  hashToField,
  hexToBytes,
  keyIdFromSpkiDer,
  logLeafHash,
  logEntry,
  membershipCheckpointBody,
  poseidonDomain,
  receiptBody,
  sha256,
  signedObject,
  signingInput,
  verifyEd25519Raw,
  verifyMembershipCheckpoint,
  verifyReceipt,
  type CborValue,
} from "../src/index.js";

interface VectorFile {
  bn254ScalarModulus: string;
  entitlementMessage: Record<string, string>;
  complaintManifest: Record<string, string>;
  logEntry: Record<string, string>;
  receipt: Record<string, string>;
  membershipCheckpoint: Record<string, string>;
  hashToField: Record<string, { frameHex: string; decimal: string }>;
  poseidonDomainConstants: Record<string, string>;
  artifactManifest: Record<string, string>;
  negativeCases: Record<string, string>;
}

const vectorPath = new URL(
  "../../../../docs/cyber-cipher/test-vectors/cyber-cipher-v1-vectors.json",
  import.meta.url,
);
const vectors = JSON.parse(readFileSync(vectorPath, "utf8")) as VectorFile;

function expectHex(actual: Uint8Array, expected: string): void {
  assert.equal(bytesToHex(actual), expected);
}

test("BN254 modulus matches the normative vector", () => {
  assert.equal(BN254_SCALAR_MODULUS.toString(), vectors.bn254ScalarModulus);
});

test("entitlement message reproduces canonical CBOR and hash", () => {
  const message = entitlementMessage({
    matterKeyId: hexToBytes(vectors.entitlementMessage.matterKeyIdHex!),
    serial: hexToBytes(vectors.entitlementMessage.serialHex!),
    personCommitment: hexToBytes(vectors.entitlementMessage.personCommitmentHex!),
  });
  const encoded = encodeCanonical(message);
  expectHex(encoded, vectors.entitlementMessage.cborHex!);
  expectHex(sha256(encoded), vectors.entitlementMessage.sha256Hex!);

  const decoded = decodeCanonical(encoded);
  assertExactIntegerKeys(decoded, [1n, 2n, 3n, 4n]);
});

test("complaint manifest and salted commitment reproduce the vector", () => {
  const attachmentBytes = hexToBytes(vectors.complaintManifest.attachmentBytesHex!);
  const attachment = attachmentRecord({
    index: 0n,
    size: BigInt(attachmentBytes.length),
    mimeType: "text/plain",
    sanitizedFilename: "evidence.txt",
    sha256: sha256(attachmentBytes),
  });
  const manifest = complaintManifest({
    matterId: hexToBytes("00112233445546778899aabbccddeeff"),
    matterVersion: 1n,
    text: "Broken streetlight near Lake Road.",
    attachments: [attachment],
  });
  const encoded = encodeCanonical(manifest);
  expectHex(encoded, vectors.complaintManifest.cborHex!);
  expectHex(
    sha256(hexToBytes(vectors.complaintManifest.saltHex!), encoded),
    vectors.complaintManifest.complaintCommitmentHex!,
  );
});

test("log leaf uses RFC 6962-style leaf domain separation", () => {
  const entry = logEntry({
    eventId: hexToBytes("ffeeddccbbaa49888776655443322110"),
    eventType: 1n,
    complaintId: hexToBytes("123e4567e89b42d3a456426614174000"),
    matterId: hexToBytes("00112233445546778899aabbccddeeff"),
    matterVersion: 1n,
    eventCommitment: hexToBytes(vectors.complaintManifest.complaintCommitmentHex!),
    occurredAt: 1790294400123n,
    actorClass: 2n,
  });
  const encoded = encodeCanonical(entry);
  expectHex(encoded, vectors.logEntry.cborHex!);
  expectHex(logLeafHash(encoded), vectors.logEntry.leafHashHex!);
});

test("receipt bytes, signing input, key identifier, and Ed25519 signature verify", () => {
  const body = receiptBody({
    receiptId: hexToBytes("0123456789ab4def8123456789abcdef"),
    receiptNonce: hexToBytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
    complaintId: hexToBytes("123e4567e89b42d3a456426614174000"),
    matterId: hexToBytes("00112233445546778899aabbccddeeff"),
    matterVersion: 1n,
    complaintCommitment: hexToBytes(vectors.complaintManifest.complaintCommitmentHex!),
    acceptedAt: 1790294400123n,
    logEntryHash: hexToBytes(vectors.logEntry.leafHashHex!),
    receiptKeyId: hexToBytes(vectors.receipt.receiptKeyIdHex!),
  });
  const bodyBytes = encodeCanonical(body);
  expectHex(bodyBytes, vectors.receipt.unsignedBodyCborHex!);
  const input = signingInput("receipt", bodyBytes);
  expectHex(input, vectors.receipt.signingInputHex!);
  assert.equal(
    verifyEd25519Raw(
      hexToBytes(vectors.receipt.publicKeyRawHex!),
      input,
      hexToBytes(vectors.receipt.signatureHex!),
    ),
    true,
  );
  expectHex(
    keyIdFromSpkiDer(ed25519SpkiFromRaw(hexToBytes(vectors.receipt.publicKeyRawHex!))),
    vectors.receipt.receiptKeyIdHex!,
  );
  const signed = encodeCanonical(signedObject(body, hexToBytes(vectors.receipt.signatureHex!)));
  expectHex(signed, vectors.receipt.signedReceiptCborHex!);
  const verified = verifyReceipt(signed, hexToBytes(vectors.receipt.publicKeyRawHex!), {
    complaintId: hexToBytes("123e4567e89b42d3a456426614174000"),
    matterId: hexToBytes("00112233445546778899aabbccddeeff"),
    matterVersion: 1n,
    complaintCommitment: hexToBytes(vectors.complaintManifest.complaintCommitmentHex!),
  });
  assert.equal(verified.acceptedAt, 1790294400123n);
});

test("membership checkpoint bytes and signature reproduce the vector", () => {
  const body = membershipCheckpointBody({
    epoch: 42n,
    root: hexToBytes((987654321n).toString(16).padStart(64, "0")),
    previousCheckpointHash: new Uint8Array(32),
    publishedAt: 1790294400000n,
    updateBatchHash: sha256(new TextEncoder().encode("test update batch 42")),
    signingKeyId: hexToBytes(vectors.membershipCheckpoint.signingKeyIdHex!),
  });
  const bodyBytes = encodeCanonical(body);
  expectHex(bodyBytes, vectors.membershipCheckpoint.unsignedBodyCborHex!);
  const input = signingInput("membership-checkpoint", bodyBytes);
  expectHex(input, vectors.membershipCheckpoint.signingInputHex!);
  assert.equal(
    verifyEd25519Raw(
      hexToBytes(vectors.membershipCheckpoint.publicKeyRawHex!),
      input,
      hexToBytes(vectors.membershipCheckpoint.signatureHex!),
    ),
    true,
  );
  const signed = encodeCanonical(
    signedObject(body, hexToBytes(vectors.membershipCheckpoint.signatureHex!)),
  );
  expectHex(signed, vectors.membershipCheckpoint.signedCheckpointCborHex!);
  expectHex(sha256(signed), vectors.membershipCheckpoint.checkpointHashHex!);
  const verified = verifyMembershipCheckpoint(
    signed,
    hexToBytes(vectors.membershipCheckpoint.publicKeyRawHex!),
    { previousCheckpointHash: new Uint8Array(32), minimumEpoch: 42n },
  );
  assert.equal(verified.epoch, 42n);
});

test("length-framed hash-to-field inputs and Poseidon domains match", () => {
  const cases = [
    {
      name: "matter",
      label: "matter-field",
      parts: [
        hexToBytes("00112233445546778899aabbccddeeff"),
        hexToBytes("00000001"),
      ],
    },
    {
      name: "serial",
      label: "serial-field",
      parts: [hexToBytes(vectors.entitlementMessage.serialHex!)],
    },
    {
      name: "complaintCommitment",
      label: "commitment-field",
      parts: [hexToBytes(vectors.complaintManifest.complaintCommitmentHex!)],
    },
  ] as const;

  for (const item of cases) {
    const expected = vectors.hashToField[item.name]!;
    expectHex(frame(item.label, ...item.parts), expected.frameHex);
    assert.equal(hashToField(item.label, ...item.parts).toString(), expected.decimal);
  }

  for (const label of POSEIDON_DOMAIN_LABELS) {
    assert.equal(poseidonDomain(label).toString(), vectors.poseidonDomainConstants[label]);
  }
});

test("artifact manifest is deterministically content addressed", () => {
  const dependencies = new Map<string, CborValue>([["circomlib", "pinned-test-version"]]);
  const manifest = artifactManifest({
    circuitName: "complaint-membership",
    circuitVersion: 1n,
    treeDepth: 16n,
    proofSystem: "groth16",
    curve: "bn254",
    compiler: "circom-2.x-pinned-by-build",
    dependencies,
    sourceHash: sha256(new TextEncoder().encode("source bundle")),
    r1csHash: sha256(new TextEncoder().encode("r1cs")),
    wasmHash: sha256(new TextEncoder().encode("wasm")),
    provingKeyHash: sha256(new TextEncoder().encode("proving key")),
    verificationKeyHash: sha256(new TextEncoder().encode("verification key")),
    powersOfTauHash: sha256(new TextEncoder().encode("powers of tau")),
    phaseTwoTranscriptHash: sha256(new TextEncoder().encode("phase two transcript")),
    builtAt: 1790294400000n,
  });
  const encoded = encodeCanonical(manifest);
  expectHex(encoded, vectors.artifactManifest.cborHex!);
  expectHex(sha256(encoded), vectors.artifactManifest.artifactIdHex!);
});

test("strict decoder rejects every published negative CBOR/scalar case", () => {
  assert.throws(() => decodeCanonical(hexToBytes(vectors.negativeCases.nonMinimalUint23Hex!)));
  assert.throws(() => decodeCanonical(hexToBytes(vectors.negativeCases.indefiniteEmptyArrayHex!)));
  assert.throws(() => decodeCanonical(hexToBytes(vectors.negativeCases.duplicateMapKeyHex!)));
  assert.throws(() => decodeFieldElement(hexToBytes(vectors.negativeCases.fieldEqualToModulusHex!)));
  assert.throws(() =>
    entitlementMessage({
      matterKeyId: new Uint8Array(32),
      serial: hexToBytes(vectors.negativeCases.invalidSerial15BytesHex!),
      personCommitment: new Uint8Array(32),
    }),
  );
  assert.throws(() => decodeCanonical(hexToBytes("6365cc81")), /NFC/);
});

test("decoder rejects noncanonical ordering, forbidden simple values, and trailing data", () => {
  assert.throws(() => decodeCanonical(hexToBytes("a202000100")), /deterministic order/);
  assert.throws(() => decodeCanonical(hexToBytes("f4")), /forbidden/);
  assert.throws(() => decodeCanonical(hexToBytes("0000")), /trailing bytes/);
  assert.throws(() => decodeCanonical(hexToBytes("a12000")), /unsigned/);
});

test("encoder normalizes text and rejects duplicate key encodings", () => {
  expectHex(encodeCanonical("Cafe\u0301"), bytesToHex(encodeCanonical("Café")));
  const duplicate = new Map<number | bigint, CborValue>([
    [1, 1],
    [1n, 2],
  ]);
  assert.throws(() => encodeCanonical(duplicate), /duplicate encodings/);
  assert.throws(() => encodeCanonical(new Map([[-1, 0]])), /unsigned/);
});
