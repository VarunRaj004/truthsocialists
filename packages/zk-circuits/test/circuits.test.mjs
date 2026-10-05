import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  SparseMembershipTree,
  deviceHash,
  emptyLeaf,
  memberLeaf,
  personHash,
} from "@cyber-cipher/membership-core";
import {
  COMPLAINT_PUBLIC_SIGNAL_NAMES,
  VOTE_PUBLIC_SIGNAL_NAMES,
  complaintPublicSignals,
  votePublicSignals,
} from "../dist/src/index.js";

const require = createRequire(import.meta.url);
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function calculator(name) {
  const directory = path.join(packageRoot, "build", "circuits", name, `${name}_js`);
  const build = require(path.join(directory, "witness_calculator.cjs"));
  return build(await readFile(path.join(directory, `${name}.wasm`)));
}

function membershipFixture() {
  const personSecret = 101n;
  const deviceSecret = 202n;
  const tree = new SparseMembershipTree(16);
  const index = 41;
  tree.setLeaf(index, memberLeaf(personHash(personSecret), deviceHash(deviceSecret)));
  return { personSecret, deviceSecret, tree, proof: tree.proof(index) };
}

function complaintFixture() {
  const membership = membershipFixture();
  const entitlementRandomness = 303n;
  const signals = complaintPublicSignals({
    membershipRoot: membership.tree.root,
    epoch: 7n,
    matterId: Uint8Array.from({ length: 16 }, (_, index) => index + 1),
    matterVersion: 2n,
    serial: Uint8Array.from({ length: 16 }, (_, index) => 0xa0 + index),
    complaintCommitment: Uint8Array.from({ length: 32 }, (_, index) => 0x20 + index),
    unsignedLeaseCbor: Uint8Array.of(0xa1, 0x01, 0x01),
    personSecret: membership.personSecret,
    entitlementRandomness,
  });
  const input = Object.fromEntries(COMPLAINT_PUBLIC_SIGNAL_NAMES.map((name, index) => [name, signals[index]]));
  return {
    membership,
    signals,
    input: {
      ...input,
      P: membership.personSecret,
      D: membership.deviceSecret,
      r: entitlementRandomness,
      merkleSiblings: membership.proof.siblings,
      merklePathBits: membership.proof.pathBits,
    },
  };
}

function voteFixture() {
  const membership = membershipFixture();
  const signals = votePublicSignals({
    membershipRoot: membership.tree.root,
    epoch: 7n,
    complaintId: Uint8Array.from({ length: 16 }, (_, index) => 0x70 + index),
    voteChoice: 2n,
    unsignedLeaseCbor: Uint8Array.of(0xa1, 0x01, 0x02),
    personSecret: membership.personSecret,
  });
  const input = Object.fromEntries(VOTE_PUBLIC_SIGNAL_NAMES.map((name, index) => [name, signals[index]]));
  return {
    membership,
    signals,
    input: {
      ...input,
      P: membership.personSecret,
      D: membership.deviceSecret,
      merkleSiblings: membership.proof.siblings,
      merklePathBits: membership.proof.pathBits,
    },
  };
}

function cloneInput(input) {
  return { ...input, merkleSiblings: [...input.merkleSiblings], merklePathBits: [...input.merklePathBits] };
}

async function rejectsWitness(circuit, input) {
  await assert.rejects(circuit.calculateWitness(input, true));
}

test("complaint circuit emits the frozen public-signal order", async () => {
  const circuit = await calculator("complaint");
  const fixture = complaintFixture();
  const witness = await circuit.calculateWitness(fixture.input, true);
  assert.deepEqual(witness.slice(1, 1 + fixture.signals.length), [...fixture.signals]);
});

test("complaint circuit rejects invalid membership and derived claims", async () => {
  const circuit = await calculator("complaint");
  const fixture = complaintFixture();
  for (const mutate of [
    (input) => { input.P += 1n; },
    (input) => { input.D += 1n; },
    (input) => { input.r += 1n; },
    (input) => { input.matterField += 1n; },
    (input) => { input.personCommitment += 1n; },
    (input) => { input.complaintNullifier += 1n; },
    (input) => { input.merkleSiblings[0] += 1n; },
    (input) => { input.merklePathBits[0] = 2; },
  ]) {
    const invalid = cloneInput(fixture.input);
    mutate(invalid);
    await rejectsWitness(circuit, invalid);
  }

  const revoked = cloneInput(fixture.input);
  fixture.membership.tree.setLeaf(fixture.membership.proof.index, emptyLeaf());
  revoked.membershipRoot = fixture.membership.tree.root;
  await rejectsWitness(circuit, revoked);
});

test("vote circuit emits the frozen public-signal order", async () => {
  const circuit = await calculator("vote");
  const fixture = voteFixture();
  const witness = await circuit.calculateWitness(fixture.input, true);
  assert.deepEqual(witness.slice(1, 1 + fixture.signals.length), [...fixture.signals]);
});

test("vote circuit rejects invalid membership, derived claims, and vote choices", async () => {
  const circuit = await calculator("vote");
  const fixture = voteFixture();
  for (const mutate of [
    (input) => { input.P += 1n; },
    (input) => { input.D += 1n; },
    (input) => { input.complaintIdField += 1n; },
    (input) => { input.voteNullifier += 1n; },
    (input) => { input.voteChoice = 4n; },
    (input) => { input.voteMessageCommitment += 1n; },
    (input) => { input.merkleSiblings[4] += 1n; },
    (input) => { input.merklePathBits[4] = 2; },
  ]) {
    const invalid = cloneInput(fixture.input);
    mutate(invalid);
    await rejectsWitness(circuit, invalid);
  }
});
