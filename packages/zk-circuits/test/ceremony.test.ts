import assert from "node:assert/strict";
import test from "node:test";
import { assertProductionPhaseTwoTranscript, parsePhaseTwoContributions } from "../src/index.js";

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
