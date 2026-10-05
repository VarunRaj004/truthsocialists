import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { setMaxListeners } from "node:events";
import { readdirSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";
import {
  SparseMembershipTree,
  deviceHash,
  memberLeaf,
  personHash,
} from "@cyber-cipher/membership-core";
import {
  COMPLAINT_PUBLIC_SIGNAL_NAMES,
  Groth16Verifier,
  VOTE_PUBLIC_SIGNAL_NAMES,
  complaintPublicSignals,
  snarkjsGroth16Backend,
  votePublicSignals,
} from "../dist/src/index.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "../..");
setMaxListeners(32, process.stdout, process.stderr);

function membershipFixture() {
  const P = 1001n;
  const D = 2002n;
  const tree = new SparseMembershipTree(16);
  const index = 83;
  tree.setLeaf(index, memberLeaf(personHash(P), deviceHash(D)));
  return { P, D, tree, proof: tree.proof(index) };
}

function paths(circuit) {
  if (process.env.CYBER_CIPHER_ZK_PROFILE === "mvp-simulation") {
    const artifactParent = path.join(repositoryRoot, "tmp", "simulated-zk-artifacts", circuit);
    const artifactIds = readdirSync(artifactParent, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
    assert.equal(artifactIds.length, 1, `expected one simulated ${circuit} artifact`);
    const artifactRoot = path.join(artifactParent, artifactIds[0]);
    return {
      wasm: path.join(artifactRoot, `${circuit}.wasm`),
      zkey: path.join(artifactRoot, `${circuit}_final.zkey`),
      vkey: path.join(artifactRoot, `${circuit}_verification_key.json`),
      metadata: path.join(artifactRoot, "SIMULATION_ONLY.json"),
      manifest: path.join(artifactRoot, `${circuit}_artifact_manifest.cbor`),
    };
  }
  const artifactRoot = path.join(repositoryRoot, "tmp", "zk-development-keys", circuit);
  return {
    wasm: path.join(packageRoot, "build", "circuits", circuit, `${circuit}_js`, `${circuit}.wasm`),
    zkey: path.join(artifactRoot, `${circuit}_development.zkey`),
    vkey: path.join(artifactRoot, `${circuit}_verification_key.json`),
    metadata: path.join(artifactRoot, "DEVELOPMENT_ONLY.json"),
    manifest: path.join(artifactRoot, `${circuit}_artifact_manifest.cbor`),
  };
}

async function verifier(circuit, names, files) {
  const bytes = await readFile(files.vkey);
  const metadata = JSON.parse(await readFile(files.metadata, "utf8"));
  const manifest = await readFile(files.manifest);
  assert.equal(metadata.productionEligible, false);
  assert.equal(createHash("sha256").update(manifest).digest("hex"), metadata.artifactId);
  const artifactId = new Uint8Array(Buffer.from(metadata.artifactId, "hex"));
  const instance = new Groth16Verifier(snarkjsGroth16Backend);
  instance.register({
    artifactId,
    circuitName: circuit,
    circuitVersion: 1,
    publicSignalNames: names,
    verificationKey: JSON.parse(bytes.toString("utf8")),
  });
  return { instance, artifactId };
}

test("real complaint Groth16 proof verifies and cannot be relabelled", async () => {
  const member = membershipFixture();
  const r = 3003n;
  const signals = complaintPublicSignals({
    membershipRoot: member.tree.root,
    epoch: 19n,
    matterId: Uint8Array.from({ length: 16 }, (_, index) => index + 1),
    matterVersion: 1n,
    serial: Uint8Array.from({ length: 16 }, (_, index) => 0x30 + index),
    complaintCommitment: Uint8Array.from({ length: 32 }, (_, index) => 0x50 + index),
    unsignedLeaseCbor: Uint8Array.of(0xa1, 0x01, 0x01),
    personSecret: member.P,
    entitlementRandomness: r,
  });
  const input = {
    ...Object.fromEntries(COMPLAINT_PUBLIC_SIGNAL_NAMES.map((name, index) => [name, signals[index].toString()])),
    P: member.P.toString(),
    D: member.D.toString(),
    r: r.toString(),
    merkleSiblings: member.proof.siblings.map(String),
    merklePathBits: member.proof.pathBits,
  };
  const files = paths("complaint");
  const generated = await groth16.fullProve(input, files.wasm, files.zkey);
  assert.deepEqual(generated.publicSignals, signals.map(String));
  const registered = await verifier("complaint", COMPLAINT_PUBLIC_SIGNAL_NAMES, files);
  const envelope = {
    artifactId: registered.artifactId,
    circuitName: "complaint",
    circuitVersion: 1,
    publicSignals: generated.publicSignals,
    proof: generated.proof,
  };
  assert.equal(await registered.instance.verify(envelope, signals), true);
  const changed = [...generated.publicSignals];
  changed[3] = (BigInt(changed[3]) + 1n).toString();
  assert.equal(await registered.instance.verify({ ...envelope, publicSignals: changed }, signals), false);
  const verificationKey = JSON.parse(await readFile(files.vkey, "utf8"));
  assert.equal(await groth16.verify(verificationKey, changed, generated.proof), false);
});

test("real vote Groth16 proofs verify for all four choices", async () => {
  const member = membershipFixture();
  const files = paths("vote");
  const registered = await verifier("vote", VOTE_PUBLIC_SIGNAL_NAMES, files);
  for (let choice = 0n; choice <= 3n; choice += 1n) {
    const signals = votePublicSignals({
      membershipRoot: member.tree.root,
      epoch: 20n,
      complaintId: Uint8Array.from({ length: 16 }, (_, index) => 0x60 + index),
      voteChoice: choice,
      unsignedLeaseCbor: Uint8Array.of(0xa1, 0x01, Number(choice)),
      personSecret: member.P,
    });
    const input = {
      ...Object.fromEntries(VOTE_PUBLIC_SIGNAL_NAMES.map((name, index) => [name, signals[index].toString()])),
      P: member.P.toString(),
      D: member.D.toString(),
      merkleSiblings: member.proof.siblings.map(String),
      merklePathBits: member.proof.pathBits,
    };
    const generated = await groth16.fullProve(input, files.wasm, files.zkey);
    assert.deepEqual(generated.publicSignals, signals.map(String));
    assert.equal(await registered.instance.verify({
      artifactId: registered.artifactId,
      circuitName: "vote",
      circuitVersion: 1,
      publicSignals: generated.publicSignals,
      proof: generated.proof,
    }, signals), true);
  }
});
