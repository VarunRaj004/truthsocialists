import assert from "node:assert/strict";
import test from "node:test";
import {
  bytesToHex,
  decodeCanonical,
  encodeCanonical,
  generateHpkeX25519KeyPair,
  sha256,
} from "@cyber-cipher/protocol-core";
import {
  openPreparedComplaint,
  prepareEncryptedComplaint,
  validateEvidence,
  type ComplaintRandomSource,
} from "../src/index.js";

class DeterministicRandom implements ComplaintRandomSource {
  #next = 1;
  bytes(length: number): Uint8Array {
    const value = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) value[index] = this.#next++ & 0xff;
    return value;
  }
}

test("prepares a deterministic encrypted complaint and handler can open it", async () => {
  const handler = await generateHpkeX25519KeyPair();
  const matterId = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
  const handlerKeyId = new Uint8Array(32).fill(0x44);
  const prepared = await prepareEncryptedComplaint({
    matterId,
    matterVersion: 3n,
    text: "Cafe\u0301 safety report",
    evidence: [{ mimeType: "text/plain", bytes: new TextEncoder().encode("supporting evidence") }],
    handlerKeyId,
    handlerPublicKey: handler.publicKey,
  }, new DeterministicRandom());
  assert.equal(prepared.normalizedText, "Café safety report");
  assert.equal(prepared.complaintId[6]! >> 4, 4);
  assert.equal(prepared.complaintId[8]! >> 6, 2);
  assert.deepEqual(prepared.complaintCommitment, sha256(prepared.complaintSalt, prepared.manifestCbor));
  assert.deepEqual(prepared.ciphertextSha256, sha256(prepared.ciphertextBlob));
  const plaintext = await openPreparedComplaint(prepared, { matterId, matterVersion: 3n, handlerKeyId }, handler.privateKey);
  assert.deepEqual(decodeCanonical(encodeCanonical(plaintext)), plaintext);
});

test("changed complaint routing context fails authenticated decryption", async () => {
  const handler = await generateHpkeX25519KeyPair();
  const matterId = new Uint8Array(16).fill(1);
  const handlerKeyId = new Uint8Array(32).fill(2);
  const prepared = await prepareEncryptedComplaint({
    matterId,
    matterVersion: 1n,
    text: "report",
    evidence: [],
    handlerKeyId,
    handlerPublicKey: handler.publicKey,
  });
  await assert.rejects(
    openPreparedComplaint(prepared, { matterId, matterVersion: 2n, handlerKeyId }, handler.privateKey),
    /authentication failed/,
  );
});

test("evidence policy rejects forbidden, disguised, active, and empty files", () => {
  assert.throws(() => validateEvidence([{ mimeType: "application/zip", bytes: Uint8Array.of(1) }]));
  assert.throws(() => validateEvidence([{ mimeType: "image/png", bytes: new TextEncoder().encode("not png") }]));
  assert.throws(() => validateEvidence([{ mimeType: "application/pdf", bytes: new TextEncoder().encode("%PDF-1.7 /JavaScript") }]));
  assert.throws(() => validateEvidence([{ mimeType: "text/plain", bytes: new Uint8Array() }]));
});

test("evidence filenames are generated locally and do not expose source names", () => {
  const [evidence] = validateEvidence([{ mimeType: "image/jpeg", bytes: Uint8Array.of(0xff, 0xd8, 0xff, 0xd9) }]);
  assert.equal(evidence!.sanitizedFilename, "evidence-1.jpg");
  assert.equal(bytesToHex(evidence!.sha256).length, 64);
});
