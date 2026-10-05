import assert from "node:assert/strict";
import test from "node:test";
import {
  assertMvpSimulationPhaseTwoTranscript,
  assertProductionPhaseTwoTranscript,
  parsePhaseTwoContributions,
} from "../src/index.js";

const valid = `
[INFO] snarkJS: contribution #1 Alice:
  aa bb
[INFO] snarkJS: contribution #2 Bob:
  cc dd
[INFO] snarkJS: contribution #3 Carol:
  ee ff
[INFO] snarkJS: contribution #4 Cyber Cipher public final beacon:
  00 11
[INFO] snarkJS: ZKey Ok!
`;

test("production transcript requires three named contributors and the final beacon", () => {
  assert.deepEqual(assertProductionPhaseTwoTranscript(valid), [
    { index: 1, name: "Alice" },
    { index: 2, name: "Bob" },
    { index: 3, name: "Carol" },
    { index: 4, name: "Cyber Cipher public final beacon" },
  ]);
});

test("production transcript accepts the reverse contribution order emitted by snarkjs", () => {
  const reversed = valid.replace(
    /\[INFO\] snarkJS: contribution #1[\s\S]*?\[INFO\] snarkJS: contribution #4 Cyber Cipher public final beacon:\n  00 11/,
    `[INFO] snarkJS: contribution #4 Cyber Cipher public final beacon:
  00 11
[INFO] snarkJS: contribution #3 Carol:
  ee ff
[INFO] snarkJS: contribution #2 Bob:
  cc dd
[INFO] snarkJS: contribution #1 Alice:
  aa bb`,
  );
  assert.deepEqual(assertProductionPhaseTwoTranscript(reversed), [
    { index: 4, name: "Cyber Cipher public final beacon" },
    { index: 3, name: "Carol" },
    { index: 2, name: "Bob" },
    { index: 1, name: "Alice" },
  ]);
});

test("transcript parser removes snarkjs ANSI formatting", () => {
  assert.deepEqual(parsePhaseTwoContributions("\u001b[32mcontribution #1 Alice:\u001b[0m"), [
    { index: 1, name: "Alice" },
  ]);
});

test("production transcript rejects duplicate, development, missing, or invalid contributions", () => {
  for (const invalid of [
    valid.replace("Bob", "Alice"),
    valid.replace("Bob", "test contributor"),
    valid.replace(/contribution #3 Carol:[\s\S]*?ee ff\n/, ""),
    valid.replace("Cyber Cipher public final beacon", "unannounced beacon"),
    valid.replace("ZKey Ok!", "ZKey Invalid"),
  ]) {
    assert.throws(() => assertProductionPhaseTwoTranscript(invalid));
  }
});

test("MVP simulation transcript requires the reserved non-production identities", () => {
  const simulated = valid
    .replace("Alice", "Development-Simulated-A")
    .replace("Bob", "Development-Simulated-B")
    .replace("Carol", "Development-Simulated-C");
  assert.equal(assertMvpSimulationPhaseTwoTranscript(simulated).length, 4);
  assert.throws(() => assertProductionPhaseTwoTranscript(simulated));
  assert.throws(() => assertMvpSimulationPhaseTwoTranscript(valid));
});
