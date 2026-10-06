import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import {
  ed25519SpkiFromRaw, encodeCanonical, keyIdFromSpkiDer, logLeafHash, receiptBody,
  signedObject, signingInput, type CborKey, type CborValue,
} from "@cyber-cipher/protocol-core";
import {
  TransparencyLogOperator,
  TransparencyTree,
  TransparencyWitness,
  TreeHeadGossip,
  consistencyProof,
  merkleRoot,
  signTreeHead,
  verifyConsistency,
  verifyDownloadedLog,
  verifyInclusion,
  receiptInclusionStatus,
  type Ed25519Signer,
} from "../src/index.js";

function signer(): { adapter: Ed25519Signer; privateKey: KeyObject } {
  const pair = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" }));
  return {
    privateKey: pair.privateKey,
    adapter: {
      publicKey: spki.slice(-32),
      sign: (message) => new Uint8Array(sign(null, message, pair.privateKey)),
    },
  };
}

function entries(count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, index) => encodeCanonical(new Map([[1n, BigInt(index + 1)]])));
}

test("RFC 6962 inclusion and consistency proofs cover irregular tree sizes", () => {
  const values = entries(17);
  const leaves = values.map(logLeafHash);
  for (let size = 1; size <= values.length; size += 1) {
    const tree = new TransparencyTree();
    values.slice(0, size).forEach((entry) => tree.append(entry));
    for (let index = 0; index < size; index += 1) {
      assert.equal(verifyInclusion(tree.leafHash(index), index, size, tree.inclusion(index), tree.root()), true);
    }
    for (let oldSize = 1; oldSize <= size; oldSize += 1) {
      const proof = consistencyProof(leaves, oldSize, size);
      assert.equal(verifyConsistency(oldSize, size, merkleRoot(leaves.slice(0, oldSize)), merkleRoot(leaves.slice(0, size)), proof), true);
    }
  }
});

test("two of three witnesses finalize while one unavailable witness is tolerated", async () => {
  const log = signer().adapter;
  const witnesses = [0, 1, 2].map(() => new TransparencyWitness(signer().adapter));
  const operator = new TransparencyLogOperator(log, witnesses);
  entries(4).forEach((entry) => operator.append(entry));
  const head = await operator.publish(1_800_000_000n, [0, 2]);
  assert.equal(head.final, true);
  assert.equal(head.witnessSignatures.length, 2);
  assert.equal(verifyDownloadedLog(entries(4), head, log.publicKey, witnesses.map((item) => item.publicKey)), true);
  const mutated = entries(4); mutated[1] = encodeCanonical(new Map([[1n, 999n]]));
  assert.equal(verifyDownloadedLog(mutated, head, log.publicKey, witnesses.map((item) => item.publicKey)), false);
  operator.append(entries(1)[0]!);
  const next = await operator.publish(1_800_000_100n);
  assert.equal(next.final, true, "the two caught-up witnesses still form quorum");
  assert.equal(next.witnessSignatures.length, 2, "the stale witness cannot attest without catching up");
});

test("only one witness cannot finalize and gossip exposes a same-size fork", async () => {
  const log = signer().adapter;
  const witnesses = [0, 1, 2].map(() => new TransparencyWitness(signer().adapter));
  const operator = new TransparencyLogOperator(log, witnesses);
  operator.append(entries(1)[0]!);
  const head = await operator.publish(1_800_000_000n, [1]);
  assert.equal(head.final, false);
  const retried = await operator.publish(1_800_000_010n, [2]);
  assert.equal(retried.final, true);
  assert.deepEqual(retried.treeHeadHash, head.treeHeadHash);

  const conflicting = await signTreeHead(log, {
    treeSize: 1n,
    rootHash: new Uint8Array(32).fill(7),
    timestamp: 1_800_000_001n,
    previousFinalizedTreeHeadHash: new Uint8Array(32),
  });
  const gossip = new TreeHeadGossip();
  assert.equal(gossip.observe(retried), undefined);
  const evidence = gossip.observe(conflicting);
  assert.equal(evidence?.treeSize, 1n);
});

test("a witness rejects a mutated or incomplete log suffix", async () => {
  const log = signer().adapter;
  const witness = new TransparencyWitness(signer().adapter);
  const values = entries(2);
  const tree = new TransparencyTree(); values.forEach((entry) => tree.append(entry));
  const head = await signTreeHead(log, {
    treeSize: 2n,
    rootHash: tree.root(),
    timestamp: 1_800_000_000n,
    previousFinalizedTreeHeadHash: new Uint8Array(32),
  });
  await assert.rejects(() => witness.observe(head, log.publicKey, [values[0]!], []), /incomplete log suffix/);
});

test("offline receipt verification reports final inclusion without identifying the submitter", async () => {
  const log = signer().adapter;
  const receiptSigner = signer();
  const witnesses = [0, 1, 2].map(() => new TransparencyWitness(signer().adapter));
  const operator = new TransparencyLogOperator(log, witnesses);
  const entry = encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, new Uint8Array(16).fill(3)]]));
  operator.append(entry);
  const head = await operator.publish(1_800_000_000n);
  const body = receiptBody({
    receiptId: new Uint8Array(16).fill(1), receiptNonce: new Uint8Array(32).fill(2),
    complaintId: new Uint8Array(16).fill(3), matterId: new Uint8Array(16).fill(4), matterVersion: 1n,
    complaintCommitment: new Uint8Array(32).fill(5), acceptedAt: 1_800_000_000n,
    logEntryHash: logLeafHash(entry),
    receiptKeyId: keyIdFromSpkiDer(ed25519SpkiFromRaw(receiptSigner.adapter.publicKey)),
  });
  const unsigned = encodeCanonical(body);
  const signedReceiptCbor = encodeCanonical(signedObject(
    body,
    new Uint8Array(sign(null, signingInput("receipt", unsigned), receiptSigner.privateKey)),
  ));
  assert.equal(receiptInclusionStatus(
    { signedReceiptCbor, leafIndex: 0, inclusionProof: operator.inclusion(0), treeHead: head },
    receiptSigner.adapter.publicKey, log.publicKey, witnesses.map((item) => item.publicKey),
  ), "FINAL");
});
