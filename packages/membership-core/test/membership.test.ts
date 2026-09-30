import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  decodeCanonical,
  hexToBytes,
  verifyMembershipCheckpoint,
} from "@cyber-cipher/protocol-core";
import { poseidon2 } from "poseidon-lite";
import {
  MembershipSaasRegistry,
  SparseMembershipTree,
  TenantMembershipService,
  deviceHash,
  emptyLeaf,
  memberLeaf,
  personHash,
  scalarToBytes,
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

function tenant(byte: number, slug: string): { tenantId: Uint8Array; tenantSlug: string } {
  return { tenantId: new Uint8Array(16).fill(byte), tenantSlug: slug };
}

test("Poseidon implementation matches the Circom-compatible two-input vector", () => {
  assert.equal(
    poseidon2([1n, 2n]),
    7853200120776062878684798364095072458815029376092732009249414926327459813530n,
  );
});

test("sparse tree produces and rejects membership paths correctly", () => {
  const tree = new SparseMembershipTree(4);
  const leaf = memberLeaf(personHash(11n), deviceHash(22n));
  tree.setLeaf(3, leaf);
  const proof = tree.proof(3);
  assert.equal(tree.verify(leaf, proof, tree.root), true);
  assert.equal(tree.verify(emptyLeaf(), proof, tree.root), false);
  const originalRoot = tree.root;
  tree.setLeaf(3, emptyLeaf());
  assert.notEqual(tree.root, originalRoot);
  assert.equal(tree.root, tree.emptyValues[tree.depth]);
});

test("tenant membership publishes signed checkpoints and rotates without index reuse", async () => {
  const signer = testSigner();
  const service = new TenantMembershipService(tenant(0x11, "university-a"), signer);
  const anchor = personHash(123n);
  const firstDevice = deviceHash(456n);
  const enrollment = service.enroll({
    enrollmentId: "enrollment-1",
    syntheticIdentityRef: "synthetic:student-0001",
    personAnchor: scalarToBytes(anchor),
    deviceHash: scalarToBytes(firstDevice),
    recoveryId: new Uint8Array(16).fill(0x21),
    recoveryPublicKey: new Uint8Array(32).fill(0x31),
  });
  assert.equal(enrollment.leafIndex, 0);
  enrollment.recoveryId[0] = 0xff;
  assert.equal(service.enrollment("enrollment-1")!.recoveryId[0], 0x21);
  assert.throws(() => service.witness("enrollment-1"), /checkpointed/);

  const first = await service.publishCheckpoint(1_790_294_400_000n);
  assert.ok(first);
  const firstBody = verifyMembershipCheckpoint(first.signedCheckpointCbor, signer.publicKey, {
    previousCheckpointHash: new Uint8Array(32),
    minimumEpoch: 1n,
  });
  assert.equal(firstBody.epoch, 1n);
  const delta = decodeCanonical(first.deltaCbor);
  assert.ok(delta instanceof Map);
  assert.deepEqual(delta.get(2n), new Uint8Array(16).fill(0x11));
  const firstWitness = service.witness("enrollment-1");
  assert.equal(service.verifyWitness(firstWitness), true);

  const rotated = service.rotateAfterVerifiedRecovery({
    enrollmentId: "enrollment-1",
    expectedRecoveryGeneration: 1,
    newDeviceHash: scalarToBytes(deviceHash(789n)),
    newRecoveryId: new Uint8Array(16).fill(0x22),
    newRecoveryPublicKey: new Uint8Array(32).fill(0x32),
  });
  assert.equal(rotated.personAnchor, anchor);
  assert.equal(rotated.leafIndex, 1);
  assert.equal(rotated.recoveryGeneration, 2);
  assert.notEqual(service.currentRoot(), firstWitness.root);
  assert.equal(service.verifyWitness(firstWitness), false);

  const second = await service.publishCheckpoint(1_790_294_430_000n);
  assert.ok(second);
  const secondBody = verifyMembershipCheckpoint(second.signedCheckpointCbor, signer.publicKey, {
    previousCheckpointHash: first.checkpointHash,
    minimumEpoch: 2n,
  });
  assert.equal(secondBody.epoch, 2n);
  const secondWitness = service.witness("enrollment-1");
  assert.equal(secondWitness.proof.index, 1);
  assert.equal(service.verifyWitness(secondWitness), true);
});

test("SaaS registry isolates tenants and forbids checkpoint-key reuse", () => {
  const registry = new MembershipSaasRegistry();
  const sharedSigner = testSigner();
  const first = new TenantMembershipService(tenant(0x41, "tenant-one"), sharedSigner);
  registry.register(first);
  assert.equal(registry.forTenant(new Uint8Array(16).fill(0x41)), first);
  assert.throws(
    () => registry.register(new TenantMembershipService(tenant(0x42, "tenant-two"), sharedSigner)),
    /must not be reused/,
  );
  const second = new TenantMembershipService(tenant(0x42, "tenant-two"), testSigner());
  registry.register(second);
  assert.notEqual(registry.forTenant(new Uint8Array(16).fill(0x42)), first);
  assert.throws(() => registry.forTenant(hexToBytes("ffffffffffffffffffffffffffffffff")), /unknown/);
});

test("prototype enrollment refuses real identity values", () => {
  const service = new TenantMembershipService(tenant(0x51, "safe-prototype"), testSigner());
  assert.throws(
    () =>
      service.enroll({
        enrollmentId: "bad",
        syntheticIdentityRef: "200012345678",
        personAnchor: scalarToBytes(personHash(1n)),
        deviceHash: scalarToBytes(deviceHash(2n)),
        recoveryId: new Uint8Array(16),
        recoveryPublicKey: new Uint8Array(32),
      }),
    /synthetic identities only/,
  );
});

test("checkpoint publication rejects a signer wired to the wrong tenant key", async () => {
  const declared = testSigner();
  const wrong = testSigner();
  const mismatched: CheckpointSigner = {
    publicKey: declared.publicKey,
    sign: wrong.sign,
  };
  const service = new TenantMembershipService(tenant(0x61, "bad-key-wiring"), mismatched);
  service.enroll({
    enrollmentId: "enrollment-wrong-key",
    syntheticIdentityRef: "synthetic:wrong-key",
    personAnchor: scalarToBytes(personHash(3n)),
    deviceHash: scalarToBytes(deviceHash(4n)),
    recoveryId: new Uint8Array(16).fill(0x71),
    recoveryPublicKey: new Uint8Array(32).fill(0x72),
  });
  await assert.rejects(service.publishCheckpoint(1_790_294_400_000n), /wrong key/);
  assert.equal(service.latestCheckpoint(), undefined);
});
