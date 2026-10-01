import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  MembershipCheckpointClient,
  TenantMembershipService,
  deviceHash,
  personHash,
  scalarToBytes,
  type CheckpointSigner,
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

test("client applies a signed chain and updates witnesses after recovery", async () => {
  const tenantId = new Uint8Array(16).fill(0x11);
  const checkpointSigner = signer();
  const service = new TenantMembershipService(
    { tenantId, tenantSlug: "university-a" },
    checkpointSigner,
  );
  const enrolled = service.enroll({
    enrollmentId: "enrollment-1",
    syntheticIdentityRef: "synthetic:student-0001",
    personAnchor: scalarToBytes(personHash(101n)),
    deviceHash: scalarToBytes(deviceHash(201n)),
    recoveryId: new Uint8Array(16).fill(0x21),
    recoveryPublicKey: new Uint8Array(32).fill(0x31),
  });
  const first = await service.publishCheckpoint(1_790_294_400_000n);
  assert.ok(first);
  const client = new MembershipCheckpointClient(tenantId, checkpointSigner.publicKey);
  const appliedFirst = client.apply(first);
  assert.equal(appliedFirst.epoch, 1n);
  const firstWitness = client.witness(enrolled.leafIndex);
  assert.equal(client.verifyWitness(firstWitness), true);
  assert.equal(firstWitness.root, service.currentRoot());
  assert.equal(
    client.verifyWitness({
      ...firstWitness,
      proof: { ...firstWitness.proof, index: firstWitness.proof.index + 1 },
    }),
    false,
  );

  const rotated = service.rotateAfterVerifiedRecovery({
    enrollmentId: enrolled.enrollmentId,
    expectedRecoveryGeneration: 1,
    newDeviceHash: scalarToBytes(deviceHash(301n)),
    newRecoveryId: new Uint8Array(16).fill(0x41),
    newRecoveryPublicKey: new Uint8Array(32).fill(0x51),
  });
  const second = await service.publishCheckpoint(1_790_294_430_000n);
  assert.ok(second);
  client.apply(second);
  assert.throws(() => client.witness(enrolled.leafIndex), /not active/);
  const recoveredWitness = client.witness(rotated.leafIndex);
  assert.equal(client.verifyWitness(recoveredWitness), true);
  assert.equal(recoveredWitness.root, service.currentRoot());
});

test("client rejects a modified delta without changing accepted state", async () => {
  const tenantId = new Uint8Array(16).fill(0x61);
  const checkpointSigner = signer();
  const service = new TenantMembershipService(
    { tenantId, tenantSlug: "university-b" },
    checkpointSigner,
  );
  service.enroll({
    enrollmentId: "enrollment-2",
    syntheticIdentityRef: "synthetic:student-0002",
    personAnchor: scalarToBytes(personHash(401n)),
    deviceHash: scalarToBytes(deviceHash(501n)),
    recoveryId: new Uint8Array(16).fill(0x62),
    recoveryPublicKey: new Uint8Array(32).fill(0x63),
  });
  const checkpoint = await service.publishCheckpoint(1_790_294_400_000n);
  assert.ok(checkpoint);
  const client = new MembershipCheckpointClient(tenantId, checkpointSigner.publicKey);
  const modifiedDelta = checkpoint.deltaCbor.slice();
  modifiedDelta[modifiedDelta.length - 1] = modifiedDelta[modifiedDelta.length - 1]! ^ 1;
  assert.throws(
    () => client.apply({ ...checkpoint, deltaCbor: modifiedDelta }),
    /does not bind the supplied delta/,
  );
  assert.equal(client.current().epoch, 0n);
});

test("client rejects cross-tenant and skipped checkpoints", async () => {
  const tenantId = new Uint8Array(16).fill(0x71);
  const checkpointSigner = signer();
  const service = new TenantMembershipService(
    { tenantId, tenantSlug: "university-c" },
    checkpointSigner,
  );
  service.enroll({
    enrollmentId: "enrollment-3",
    syntheticIdentityRef: "synthetic:student-0003",
    personAnchor: scalarToBytes(personHash(601n)),
    deviceHash: scalarToBytes(deviceHash(701n)),
    recoveryId: new Uint8Array(16).fill(0x72),
    recoveryPublicKey: new Uint8Array(32).fill(0x73),
  });
  const first = await service.publishCheckpoint(1_790_294_400_000n);
  assert.ok(first);
  service.enroll({
    enrollmentId: "enrollment-4",
    syntheticIdentityRef: "synthetic:student-0004",
    personAnchor: scalarToBytes(personHash(602n)),
    deviceHash: scalarToBytes(deviceHash(702n)),
    recoveryId: new Uint8Array(16).fill(0x74),
    recoveryPublicKey: new Uint8Array(32).fill(0x75),
  });
  const second = await service.publishCheckpoint(1_790_294_430_000n);
  assert.ok(second);

  const otherTenant = new MembershipCheckpointClient(
    new Uint8Array(16).fill(0x7f),
    checkpointSigner.publicKey,
  );
  assert.throws(() => otherTenant.apply(first), /another tenant/);
  const freshClient = new MembershipCheckpointClient(tenantId, checkpointSigner.publicKey);
  assert.throws(() => freshClient.apply(second), /predecessor|contiguous/);
  assert.equal(freshClient.current().epoch, 0n);
});
