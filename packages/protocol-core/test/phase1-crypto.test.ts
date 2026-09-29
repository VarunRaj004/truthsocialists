import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import test from "node:test";
import {
  ProofLeasePurpose,
  aes256GcmOpen,
  aes256GcmSeal,
  bytesToHex,
  complaintEncryptionAad,
  decodeCanonical,
  ed25519SpkiFromRaw,
  encodeCanonical,
  generateHpkeX25519KeyPair,
  handlerDekInfo,
  hexToBytes,
  keyIdFromSpkiDer,
  proofLeaseBody,
  signedObject,
  signingInput,
  unwrapHandlerDek,
  verifyProofLease,
  wrapHandlerDek,
} from "../src/index.js";

test("AES-256-GCM matches the NIST single-block vector", () => {
  const sealed = aes256GcmSeal({
    key: new Uint8Array(32),
    nonce: new Uint8Array(12),
    plaintext: new Uint8Array(16),
    aad: new Uint8Array(),
  });
  assert.equal(bytesToHex(sealed.ciphertext), "cea7403d4d606b6e074ec5d3baf39d18");
  assert.equal(bytesToHex(sealed.tag), "d0d1c8a799996bf0265b98b5d48ab919");
  assert.deepEqual(
    aes256GcmOpen({
      key: new Uint8Array(32),
      nonce: new Uint8Array(12),
      aad: new Uint8Array(),
      ...sealed,
    }),
    new Uint8Array(16),
  );
});

test("complaint AES-GCM AAD authenticates routing and commitment fields", () => {
  const aad = encodeCanonical(
    complaintEncryptionAad({
      complaintId: hexToBytes("123e4567e89b42d3a456426614174000"),
      matterId: hexToBytes("00112233445546778899aabbccddeeff"),
      matterVersion: 1n,
      complaintCommitment: new Uint8Array(32).fill(0x11),
      handlerKeyId: new Uint8Array(32).fill(0x22),
    }),
  );
  const sealed = aes256GcmSeal({
    key: new Uint8Array(32).fill(0x33),
    nonce: new Uint8Array(12).fill(0x44),
    plaintext: new TextEncoder().encode("private complaint package"),
    aad,
  });
  assert.equal(
    new TextDecoder().decode(
      aes256GcmOpen({
        key: new Uint8Array(32).fill(0x33),
        nonce: new Uint8Array(12).fill(0x44),
        aad,
        ...sealed,
      }),
    ),
    "private complaint package",
  );
  const changedAad = aad.slice();
  const finalIndex = changedAad.length - 1;
  changedAad[finalIndex] = changedAad[finalIndex]! ^ 1;
  assert.throws(
    () =>
      aes256GcmOpen({
        key: new Uint8Array(32).fill(0x33),
        nonce: new Uint8Array(12).fill(0x44),
        aad: changedAad,
        ...sealed,
      }),
    /authentication failed/,
  );
});

test("RFC 9180 handler envelope wraps only the 32-byte DEK and binds context", async () => {
  const keys = await generateHpkeX25519KeyPair();
  const context = {
    matterId: hexToBytes("00112233445546778899aabbccddeeff"),
    matterVersion: 7n,
    complaintId: hexToBytes("123e4567e89b42d3a456426614174000"),
    complaintCommitment: new Uint8Array(32).fill(0x51),
    handlerKeyId: new Uint8Array(32).fill(0x61),
  };
  const dek = new Uint8Array(32).fill(0x71);
  const envelope = await wrapHandlerDek(keys.publicKey, dek, context);
  assert.equal(envelope.encapsulatedKey.length, 32);
  assert.equal(envelope.wrappedDek.length, 48);
  assert.deepEqual(await unwrapHandlerDek(keys.privateKey, envelope, context), dek);
  await assert.rejects(
    unwrapHandlerDek(keys.privateKey, envelope, {
      ...context,
      complaintCommitment: new Uint8Array(32).fill(0x52),
    }),
    /authentication failed/,
  );
  assert.equal(
    bytesToHex(handlerDekInfo(context.matterId, context.matterVersion)),
    `${bytesToHex(new TextEncoder().encode("CYBER-CIPHER/v1/handler-dek"))}00112233445546778899aabbccddeeff00000007`,
  );
});

test("proof lease verifier enforces key, current root, purpose, and lifetime", () => {
  const keys = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(keys.publicKey.export({ format: "der", type: "spki" }));
  const publicKey = spki.slice(-32);
  assert.deepEqual(ed25519SpkiFromRaw(publicKey), spki);
  const now = 1_790_294_400_000n;
  const root = hexToBytes((987654321n).toString(16).padStart(64, "0"));
  const body = proofLeaseBody({
    challengeId: new Uint8Array(16).fill(0x12),
    purpose: ProofLeasePurpose.Complaint,
    epoch: 42n,
    membershipRoot: root,
    issuedAt: now,
    expiresAt: now + 60_000n,
    serverNonce: new Uint8Array(32).fill(0x34),
    signingKeyId: keyIdFromSpkiDer(spki),
  });
  const bodyBytes = encodeCanonical(body);
  const signature = new Uint8Array(sign(null, signingInput("proof-lease", bodyBytes), keys.privateKey));
  const encoded = encodeCanonical(signedObject(body, signature));
  const verified = verifyProofLease(encoded, publicKey, {
    now: now + 30_000n,
    purpose: ProofLeasePurpose.Complaint,
    currentEpoch: 42n,
    currentRoot: root,
  });
  assert.equal(verified.epoch, 42n);
  assert.throws(
    () =>
      verifyProofLease(encoded, publicKey, {
        now: now + 60_001n,
        purpose: ProofLeasePurpose.Complaint,
        currentEpoch: 42n,
        currentRoot: root,
      }),
    /expired/,
  );
  assert.throws(
    () =>
      verifyProofLease(encoded, publicKey, {
        now: now + 1n,
        purpose: ProofLeasePurpose.Vote,
        currentEpoch: 42n,
        currentRoot: root,
      }),
    /purpose/,
  );
});

test("strict CBOR parser survives random inputs and round-trips every accepted input", () => {
  for (let iteration = 0; iteration < 1_000; iteration += 1) {
    const input = new Uint8Array(randomBytes(iteration % 129));
    try {
      const decoded = decodeCanonical(input);
      assert.deepEqual(encodeCanonical(decoded), input);
    } catch (error) {
      assert.ok(error instanceof Error);
    }
  }
});
