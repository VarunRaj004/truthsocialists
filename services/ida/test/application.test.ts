import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { sha256 } from "@cyber-cipher/protocol-core";
import {
  deviceHash,
  personHash,
  recoveryPublicKey,
  scalarToBytes,
  signRecoveryAuthorization,
  type CheckpointSigner,
} from "@cyber-cipher/membership-core";
import type {
  CompleteRecoveryTransactionInput,
  EnrollSyntheticInput,
  PersistentEnrollment,
  RecoveryChallengeDraft,
} from "@cyber-cipher/identity-store";
import {
  IdentityAuthorityApplication,
  type CheckpointRepository,
  type IdentityRepository,
} from "../src/index.js";

function signer(): CheckpointSigner {
  const keys = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(keys.publicKey.export({ type: "spki", format: "der" }));
  return {
    publicKey: spki.slice(-32),
    async sign(message: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(sign(null, message, keys.privateKey));
    },
  };
}

class FakeIdentityRepository implements IdentityRepository {
  challenge?: RecoveryChallengeDraft;
  enrollment: PersistentEnrollment;

  constructor(enrollment: PersistentEnrollment) {
    this.enrollment = enrollment;
  }

  async enrollSynthetic(input: EnrollSyntheticInput): Promise<PersistentEnrollment> {
    this.enrollment = {
      enrollmentId: input.enrollmentId,
      syntheticIdentityRef: input.syntheticIdentityRef,
      personAnchor: input.personAnchor,
      activeDeviceHash: input.deviceHash,
      activeLeafIndex: 0,
      recoveryId: input.recoveryId.slice(),
      recoveryPublicKey: input.recoveryPublicKey.slice(),
      recoveryGeneration: 1,
      active: true,
      rowVersion: 1n,
    };
    return this.clone();
  }

  async issueRecoveryChallenge(
    recoveryId: Uint8Array,
    create: (locked: {
      enrollmentId: string;
      recoveryId: Uint8Array;
      recoveryGeneration: number;
    }) => Promise<RecoveryChallengeDraft>,
  ): Promise<RecoveryChallengeDraft> {
    assert.deepEqual(recoveryId, this.enrollment.recoveryId);
    this.challenge = await create({
      enrollmentId: this.enrollment.enrollmentId,
      recoveryId: this.enrollment.recoveryId.slice(),
      recoveryGeneration: this.enrollment.recoveryGeneration,
    });
    return this.challenge;
  }

  async completeRecoveryAtomic(input: CompleteRecoveryTransactionInput): Promise<PersistentEnrollment> {
    assert.ok(this.challenge);
    assert.deepEqual(input.challengeId, this.challenge.challengeId);
    await input.authorize({
      signedChallengeCbor: this.challenge.signedChallengeCbor.slice(),
      recoveryId: this.enrollment.recoveryId.slice(),
      recoveryGeneration: this.enrollment.recoveryGeneration,
      recoveryPublicKey: this.enrollment.recoveryPublicKey.slice(),
      personAnchor: this.enrollment.personAnchor,
      activeDeviceHash: this.enrollment.activeDeviceHash,
      activeLeafIndex: this.enrollment.activeLeafIndex,
    });
    this.enrollment = {
      ...this.enrollment,
      activeDeviceHash: input.newDeviceHash,
      activeLeafIndex: this.enrollment.activeLeafIndex + 1,
      recoveryId: input.newRecoveryId.slice(),
      recoveryPublicKey: input.newRecoveryPublicKey.slice(),
      recoveryGeneration: this.enrollment.recoveryGeneration + 1,
      rowVersion: this.enrollment.rowVersion + 1n,
    };
    return this.clone();
  }

  private clone(): PersistentEnrollment {
    return {
      ...this.enrollment,
      recoveryId: this.enrollment.recoveryId.slice(),
      recoveryPublicKey: this.enrollment.recoveryPublicKey.slice(),
    };
  }
}

const noCheckpoints: CheckpointRepository = {
  async latestCheckpoint() {
    return undefined;
  },
  async checkpointsAfter() {
    return [];
  },
};

test("application issues a signed challenge and verifies recovery authorization inside the lock", async () => {
  const tenantId = new Uint8Array(16).fill(0x11);
  const recoverySeed = new Uint8Array(16).fill(0x22);
  const recoveryId = new Uint8Array(16).fill(0x33);
  const anchor = personHash(100n);
  const repository = new FakeIdentityRepository({
    enrollmentId: "11111111-1111-4111-8111-111111111111",
    syntheticIdentityRef: "synthetic:student-0001",
    personAnchor: anchor,
    activeDeviceHash: deviceHash(200n),
    activeLeafIndex: 0,
    recoveryId,
    recoveryPublicKey: recoveryPublicKey(recoverySeed, recoveryId),
    recoveryGeneration: 1,
    active: true,
    rowVersion: 1n,
  });
  const challengeSigner = signer();
  const app = new IdentityAuthorityApplication(repository, noCheckpoints, {
    tenantId,
    challengeSigner,
    checkpointPublicKey: signer().publicKey,
    now: () => 1_790_294_400_000n,
    randomBytes: (length) => new Uint8Array(length).fill(length),
  });
  const challenge = await app.issueRecoveryChallenge(recoveryId);
  const newDevice = scalarToBytes(deviceHash(300n));
  const newRecoveryId = new Uint8Array(16).fill(0x44);
  const newRecoveryPublicKey = new Uint8Array(32).fill(0x55);
  const authorizationSignature = signRecoveryAuthorization(recoverySeed, recoveryId, {
    tenantId,
    signedChallengeHash: sha256(challenge.signedChallengeCbor),
    personAnchor: scalarToBytes(anchor),
    newDeviceHash: newDevice,
    newRecoveryId,
    newRecoveryPublicKey,
    expectedRecoveryGeneration: 1n,
  });
  const recovered = await app.completeRecovery({
    signedChallengeCbor: challenge.signedChallengeCbor,
    authorizationSignature,
    newDeviceHash: newDevice,
    newRecoveryId,
    newRecoveryPublicKey,
  });
  assert.equal(recovered.recoveryGeneration, 2);
  assert.deepEqual(recovered.recoveryId, newRecoveryId);
  assert.equal(recovered.personAnchor, anchor);
});

test("application rejects a recovery authorization signed by another seed", async () => {
  const tenantId = new Uint8Array(16).fill(0x61);
  const recoverySeed = new Uint8Array(16).fill(0x62);
  const recoveryId = new Uint8Array(16).fill(0x63);
  const anchor = personHash(400n);
  const repository = new FakeIdentityRepository({
    enrollmentId: "22222222-2222-4222-8222-222222222222",
    syntheticIdentityRef: "synthetic:student-0002",
    personAnchor: anchor,
    activeDeviceHash: deviceHash(500n),
    activeLeafIndex: 0,
    recoveryId,
    recoveryPublicKey: recoveryPublicKey(recoverySeed, recoveryId),
    recoveryGeneration: 1,
    active: true,
    rowVersion: 1n,
  });
  const app = new IdentityAuthorityApplication(repository, noCheckpoints, {
    tenantId,
    challengeSigner: signer(),
    checkpointPublicKey: signer().publicKey,
    now: () => 1_790_294_400_000n,
    randomBytes: (length) => new Uint8Array(length).fill(length + 1),
  });
  const challenge = await app.issueRecoveryChallenge(recoveryId);
  const newDeviceHash = scalarToBytes(deviceHash(600n));
  const newRecoveryId = new Uint8Array(16).fill(0x64);
  const newRecoveryPublicKey = new Uint8Array(32).fill(0x65);
  const wrongSeed = new Uint8Array(16).fill(0x66);
  const signature = signRecoveryAuthorization(wrongSeed, recoveryId, {
    tenantId,
    signedChallengeHash: sha256(challenge.signedChallengeCbor),
    personAnchor: scalarToBytes(anchor),
    newDeviceHash,
    newRecoveryId,
    newRecoveryPublicKey,
    expectedRecoveryGeneration: 1n,
  });
  await assert.rejects(
    app.completeRecovery({
      signedChallengeCbor: challenge.signedChallengeCbor,
      authorizationSignature: signature,
      newDeviceHash,
      newRecoveryId,
      newRecoveryPublicKey,
    }),
    /authorization signature is invalid/,
  );
  assert.equal(repository.enrollment.recoveryGeneration, 1);
});
