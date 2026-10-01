import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import test from "node:test";
import {
  decryptMatterPrivateKey,
  encryptMatterPrivateKey,
  generateMatterRsaKeyMaterial,
  MatterRegistryError,
  validateMatterPublicKey,
  validatePublishMatterInput,
} from "../src/index.js";

function uuidBytes(uuid: string): Uint8Array {
  return new Uint8Array(Buffer.from(uuid.replaceAll("-", ""), "hex"));
}

test("matter RSA key fixes the RSA-3072 public-key profile used by the RFC 9474 suite", () => {
  const key = generateMatterRsaKeyMaterial();
  assert.equal(key.matterKeyId.length, 32);
  assert.deepEqual(validateMatterPublicKey(key.publicKeySpkiDer), key.matterKeyId);

  const undersizedRsa = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65_537 });
  const undersizedSpki = new Uint8Array(undersizedRsa.publicKey.export({ format: "der", type: "spki" }));
  assert.throws(() => validateMatterPublicKey(undersizedSpki), /RSA-3072/);
});

test("matter PKCS#8 envelope authenticates tenant, version, key IDs, and ciphertext", () => {
  const key = generateMatterRsaKeyMaterial();
  const context = {
    tenantId: uuidBytes("11111111-1111-4111-8111-111111111111"),
    matterId: uuidBytes("22222222-2222-4222-8222-222222222222"),
    matterVersion: 1n,
    matterKeyId: key.matterKeyId,
    kekKeyId: new Uint8Array(32).fill(0x31),
  };
  const kek = new Uint8Array(32).fill(0x41);
  const encryptedKeyFile = encryptMatterPrivateKey({
    ...context,
    kek,
    privateKeyPkcs8Der: key.privateKeyPkcs8Der,
    nonce: new Uint8Array(12).fill(0x51),
  });
  assert.deepEqual(
    decryptMatterPrivateKey({ ...context, kek, encryptedKeyFile }),
    key.privateKeyPkcs8Der,
  );
  assert.throws(
    () =>
      decryptMatterPrivateKey({
        ...context,
        matterId: new Uint8Array(16).fill(0x61),
        kek,
        encryptedKeyFile,
      }),
    /authentication failed/,
  );
});

test("matter publication enforces key fingerprint and 24-hour lead time", () => {
  const key = generateMatterRsaKeyMaterial();
  const publishedAt = new Date("2026-10-01T00:00:00.000Z");
  const input = {
    matterId: randomUUID(),
    version: 1,
    title: "Synthetic campus safety matter",
    opensAt: new Date("2026-10-02T00:00:00.000Z"),
    closesAt: new Date("2026-10-03T00:00:00.000Z"),
    rsaSpkiDer: key.publicKeySpkiDer,
    matterKeyId: key.matterKeyId,
    complaintArtifactId: new Uint8Array(32).fill(0x71),
    voteArtifactId: new Uint8Array(32).fill(0x72),
    handlerOrgId: randomUUID(),
    handlerKeyId: new Uint8Array(32).fill(0x73),
  };
  assert.equal(validatePublishMatterInput(input, publishedAt).version, 1);
  assert.throws(
    () =>
      validatePublishMatterInput(
        { ...input, opensAt: new Date("2026-10-01T23:59:59.999Z") },
        publishedAt,
      ),
    (error: unknown) =>
      error instanceof MatterRegistryError && error.code === "PUBLICATION_LEAD_TIME",
  );
  assert.throws(
    () => validatePublishMatterInput({ ...input, matterKeyId: new Uint8Array(32) }, publishedAt),
    /does not match/,
  );
});
