import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { sha256, verifyMembershipCheckpoint } from "@cyber-cipher/protocol-core";
import {
  SparseMembershipTree,
  deviceHash,
  emptyLeaf,
  memberLeaf,
  personHash,
  type CheckpointSigner,
} from "@cyber-cipher/membership-core";
import {
  MembershipCheckpointWorker,
  createSignedMembershipCheckpoint,
  type CheckpointBundle,
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

test("checkpoint builder binds an ordered delta to a signed Poseidon root", async () => {
  const checkpointSigner = signer();
  const leaf = memberLeaf(personHash(101n), deviceHash(201n));
  const tree = new SparseMembershipTree(16);
  tree.setLeaf(0, leaf);
  tree.setLeaf(0, emptyLeaf());
  tree.setLeaf(1, leaf);
  const published = await createSignedMembershipCheckpoint(
    {
      tenantId: new Uint8Array(16).fill(0x11),
      epoch: 3n,
      root: tree.root,
      previousCheckpointHash: new Uint8Array(32).fill(0x22),
      publishedAt: 1_790_294_400_000n,
      updates: [
        { operation: "ACTIVATE", leafIndex: 0, newLeafValue: leaf },
        { operation: "REVOKE", leafIndex: 0, newLeafValue: emptyLeaf() },
        { operation: "ACTIVATE", leafIndex: 1, newLeafValue: leaf },
      ],
    },
    checkpointSigner,
  );
  const body = verifyMembershipCheckpoint(published.signedCheckpointCbor, checkpointSigner.publicKey, {
    previousCheckpointHash: new Uint8Array(32).fill(0x22),
    minimumEpoch: 3n,
  });
  assert.equal(body.epoch, 3n);
  assert.equal(BigInt(`0x${Buffer.from(body.root).toString("hex")}`), tree.root);
  assert.deepEqual(body.updateBatchHash, sha256(published.deltaCbor));
  assert.deepEqual(published.checkpointHash, sha256(published.signedCheckpointCbor));
});

test("checkpoint builder rejects a signer wired to a different public key", async () => {
  const advertised = signer();
  const actual = signer();
  await assert.rejects(
    createSignedMembershipCheckpoint(
      {
        tenantId: new Uint8Array(16).fill(0x11),
        epoch: 1n,
        root: emptyLeaf(),
        previousCheckpointHash: new Uint8Array(32),
        publishedAt: 1n,
        updates: [{ operation: "REVOKE", leafIndex: 0, newLeafValue: emptyLeaf() }],
      },
      { publicKey: advertised.publicKey, sign: actual.sign },
    ),
    /wrong key/,
  );
});

test("checkpoint worker uses the configured clock and prevents duplicate starts", async () => {
  const calls: bigint[] = [];
  let firstTick!: () => void;
  const ticked = new Promise<void>((resolve) => {
    firstTick = resolve;
  });
  const worker = new MembershipCheckpointWorker(
    {
      async publishPending(publishedAt: bigint): Promise<CheckpointBundle | undefined> {
        calls.push(publishedAt);
        firstTick();
        return undefined;
      },
    },
    () => 123_456n,
    30_000,
  );
  worker.start((error) => assert.fail(String(error)));
  await ticked;
  assert.deepEqual(calls, [123_456n]);
  assert.throws(() => worker.start(() => undefined), /already running/);
  worker.stop();
});
