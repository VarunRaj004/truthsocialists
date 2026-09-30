import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  RecoveryBackupPurpose,
  bytesToHex,
  sha256,
  type RecoveryAuthorizationInput,
} from "@cyber-cipher/protocol-core";
import {
  TenantMembershipService,
  TenantRecoveryService,
  deriveRecoveryKeys,
  deviceHash,
  openRecoveryBackup,
  personHash,
  recoveryPublicKey,
  scalarToBytes,
  sealRecoveryBackup,
  signRecoveryAuthorization,
  type CheckpointSigner,
} from "../src/index.js";

function testSigner(): CheckpointSigner {
  const keys = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(keys.publicKey.export({ format: "der", type: "spki" }));
  return {
    publicKey: spki.slice(-32),
    async sign(message: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(sign(null, message, keys.privateKey));
    },
  };
}

function deterministicRandom(): (length: number) => Uint8Array {
  let counter = 0x80;
  return (length) => new Uint8Array(length).fill(counter++);
}

test("recovery HKDF separates signing, person-backup, and mailbox keys", () => {
  const keys = deriveRecoveryKeys(new Uint8Array(16).fill(0x01), new Uint8Array(16).fill(0x02));
  assert.equal(keys.recoverySignSeed.length, 32);
  assert.equal(keys.backupKey.length, 32);
  assert.equal(keys.bundleKey.length, 32);
  assert.notDeepEqual(keys.recoverySignSeed, keys.backupKey);
  assert.notDeepEqual(keys.backupKey, keys.bundleKey);
  assert.equal(
    bytesToHex(keys.recoverySignSeed),
    "4b724350cc597f0e84fcd6ee6fbaf446a1962f63d8d447cafe4df30ea40074b8",
  );
  assert.equal(
    bytesToHex(keys.backupKey),
    "4baf6f1b24ea0cc8a62c97d43cc3c72a40e36e4f64fb732fd94f56d264cfa42a",
  );
  assert.equal(
    bytesToHex(keys.bundleKey),
    "cd0a207c98fc68538fa44fd1f297140d8c675ee0c8ed0971f6d61ed7ad8ee8a0",
  );
  assert.equal(
    bytesToHex(recoveryPublicKey(new Uint8Array(16).fill(0x01), new Uint8Array(16).fill(0x02))),
    "18087c46f1b96e88dbd5e314e5aa8805c1d35ff08cc7e92ea287150b83cf1aeb",
  );
});

test("recovery backup authenticates tenant, purpose, ID, and generation", () => {
  const seed = new Uint8Array(16).fill(0x11);
  const aad = {
    tenantId: new Uint8Array(16).fill(0x21),
    recoveryId: new Uint8Array(16).fill(0x31),
    purpose: RecoveryBackupPurpose.PersonSecret,
    generation: 1n,
  } as const;
  const personSecret = scalarToBytes(123456n);
  const sealed = sealRecoveryBackup(
    seed,
    aad,
    personSecret,
    new Uint8Array(12).fill(0x41),
  );
  assert.deepEqual(openRecoveryBackup(seed, aad, sealed), personSecret);
  assert.throws(
    () => openRecoveryBackup(seed, { ...aad, generation: 2n }, sealed),
    /authentication failed/,
  );
  assert.throws(
    () => openRecoveryBackup(new Uint8Array(16).fill(0x12), aad, sealed),
    /authentication failed/,
  );
});

test("five-minute challenge authorizes one atomic rotation and mandatory key change", async () => {
  const checkpointSigner = testSigner();
  const challengeSigner = testSigner();
  const tenantId = new Uint8Array(16).fill(0x51);
  const membership = new TenantMembershipService(
    { tenantId, tenantSlug: "recovery-tenant" },
    checkpointSigner,
  );
  const oldSeed = new Uint8Array(16).fill(0x61);
  const oldRecoveryId = new Uint8Array(16).fill(0x62);
  const anchor = personHash(777n);
  membership.enroll({
    enrollmentId: "enrollment-recovery",
    syntheticIdentityRef: "synthetic:recovery-user",
    personAnchor: scalarToBytes(anchor),
    deviceHash: scalarToBytes(deviceHash(888n)),
    recoveryId: oldRecoveryId,
    recoveryPublicKey: recoveryPublicKey(oldSeed, oldRecoveryId),
  });
  await membership.publishCheckpoint(1_790_294_400_000n);
  const recovery = new TenantRecoveryService(
    membership,
    challengeSigner,
    deterministicRandom(),
  );
  const issuedAt = 1_790_294_500_000n;
  const challenge = await recovery.issueChallenge(oldRecoveryId, issuedAt);
  assert.equal(challenge.expiresAt, issuedAt + 300_000n);

  const newSeed = new Uint8Array(16).fill(0x71);
  const newRecoveryId = new Uint8Array(16).fill(0x72);
  const newRecoveryPublicKey = recoveryPublicKey(newSeed, newRecoveryId);
  const newDeviceHash = scalarToBytes(deviceHash(999n));
  const authorization: RecoveryAuthorizationInput = {
    tenantId,
    signedChallengeHash: sha256(challenge.signedChallengeCbor),
    personAnchor: scalarToBytes(anchor),
    newDeviceHash,
    newRecoveryId,
    newRecoveryPublicKey,
    expectedRecoveryGeneration: 1n,
  };
  const authorizationSignature = signRecoveryAuthorization(
    oldSeed,
    oldRecoveryId,
    authorization,
  );
  const rotated = recovery.completeRecovery({
    signedChallengeCbor: challenge.signedChallengeCbor,
    authorizationSignature,
    newDeviceHash,
    newRecoveryId,
    newRecoveryPublicKey,
    now: issuedAt + 1_000n,
  });
  assert.equal(rotated.personAnchor, anchor);
  assert.equal(rotated.leafIndex, 1);
  assert.equal(rotated.recoveryGeneration, 2);
  assert.deepEqual(rotated.recoveryPublicKey, newRecoveryPublicKey);
  assert.throws(
    () =>
      recovery.completeRecovery({
        signedChallengeCbor: challenge.signedChallengeCbor,
        authorizationSignature,
        newDeviceHash,
        newRecoveryId,
        newRecoveryPublicKey,
        now: issuedAt + 2_000n,
      }),
    /consumed/,
  );
  await membership.publishCheckpoint(issuedAt + 30_000n);

  const secondChallenge = await recovery.issueChallenge(newRecoveryId, issuedAt + 40_000n);
  const thirdSeed = new Uint8Array(16).fill(0x73);
  const thirdRecoveryId = new Uint8Array(16).fill(0x74);
  const thirdPublicKey = recoveryPublicKey(thirdSeed, thirdRecoveryId);
  const thirdDeviceHash = scalarToBytes(deviceHash(1001n));
  const secondAuthorization: RecoveryAuthorizationInput = {
    tenantId,
    signedChallengeHash: sha256(secondChallenge.signedChallengeCbor),
    personAnchor: scalarToBytes(anchor),
    newDeviceHash: thirdDeviceHash,
    newRecoveryId: thirdRecoveryId,
    newRecoveryPublicKey: thirdPublicKey,
    expectedRecoveryGeneration: 2n,
  };
  const obsoleteKeySignature = signRecoveryAuthorization(
    oldSeed,
    oldRecoveryId,
    secondAuthorization,
  );
  assert.throws(
    () =>
      recovery.completeRecovery({
        signedChallengeCbor: secondChallenge.signedChallengeCbor,
        authorizationSignature: obsoleteKeySignature,
        newDeviceHash: thirdDeviceHash,
        newRecoveryId: thirdRecoveryId,
        newRecoveryPublicKey: thirdPublicKey,
        now: issuedAt + 41_000n,
      }),
    /signature is invalid/,
  );
  const currentKeySignature = signRecoveryAuthorization(
    newSeed,
    newRecoveryId,
    secondAuthorization,
  );
  const rotatedAgain = recovery.completeRecovery({
    signedChallengeCbor: secondChallenge.signedChallengeCbor,
    authorizationSignature: currentKeySignature,
    newDeviceHash: thirdDeviceHash,
    newRecoveryId: thirdRecoveryId,
    newRecoveryPublicKey: thirdPublicKey,
    now: issuedAt + 42_000n,
  });
  assert.equal(rotatedAgain.leafIndex, 2);
  assert.equal(rotatedAgain.recoveryGeneration, 3);
});

test("expired recovery challenge cannot rotate state", async () => {
  const checkpointSigner = testSigner();
  const membership = new TenantMembershipService(
    { tenantId: new Uint8Array(16).fill(0x91), tenantSlug: "expiry-tenant" },
    checkpointSigner,
  );
  const seed = new Uint8Array(16).fill(0x92);
  const recoveryId = new Uint8Array(16).fill(0x93);
  membership.enroll({
    enrollmentId: "expiry-enrollment",
    syntheticIdentityRef: "synthetic:expiry-user",
    personAnchor: scalarToBytes(personHash(5n)),
    deviceHash: scalarToBytes(deviceHash(6n)),
    recoveryId,
    recoveryPublicKey: recoveryPublicKey(seed, recoveryId),
  });
  const service = new TenantRecoveryService(membership, testSigner(), deterministicRandom());
  const challenge = await service.issueChallenge(recoveryId, 1_000_000n);
  assert.throws(
    () =>
      service.completeRecovery({
        signedChallengeCbor: challenge.signedChallengeCbor,
        authorizationSignature: new Uint8Array(64),
        newDeviceHash: scalarToBytes(deviceHash(7n)),
        newRecoveryId: new Uint8Array(16).fill(0x94),
        newRecoveryPublicKey: new Uint8Array(32).fill(0x95),
        now: challenge.expiresAt + 1n,
      }),
    /expired/,
  );
  assert.equal(membership.enrollment("expiry-enrollment")!.leafIndex, 0);
});

test("recovery challenge key must be distinct from checkpoint key", () => {
  const signer = testSigner();
  const membership = new TenantMembershipService(
    { tenantId: new Uint8Array(16).fill(0xa1), tenantSlug: "separate-keys" },
    signer,
  );
  assert.throws(() => new TenantRecoveryService(membership, signer), /must be distinct/);
});

test("recovery challenge stops verification after ten failed signatures", async () => {
  const membership = new TenantMembershipService(
    { tenantId: new Uint8Array(16).fill(0xb1), tenantSlug: "attempt-limit" },
    testSigner(),
  );
  const recoveryId = new Uint8Array(16).fill(0xb2);
  membership.enroll({
    enrollmentId: "attempt-enrollment",
    syntheticIdentityRef: "synthetic:attempt-user",
    personAnchor: scalarToBytes(personHash(8n)),
    deviceHash: scalarToBytes(deviceHash(9n)),
    recoveryId,
    recoveryPublicKey: recoveryPublicKey(new Uint8Array(16).fill(0xb3), recoveryId),
  });
  const service = new TenantRecoveryService(membership, testSigner(), deterministicRandom());
  const challenge = await service.issueChallenge(recoveryId, 2_000_000n);
  const invalidCompletion = {
    signedChallengeCbor: challenge.signedChallengeCbor,
    authorizationSignature: new Uint8Array(64),
    newDeviceHash: scalarToBytes(deviceHash(10n)),
    newRecoveryId: new Uint8Array(16).fill(0xb4),
    newRecoveryPublicKey: new Uint8Array(32).fill(0xb5),
    now: 2_000_001n,
  };
  for (let attempt = 0; attempt < 10; attempt += 1) {
    assert.throws(() => service.completeRecovery(invalidCompletion), /signature is invalid/);
  }
  assert.throws(() => service.completeRecovery(invalidCompletion), /attempt limit/);
  assert.equal(membership.enrollment("attempt-enrollment")!.leafIndex, 0);
});
