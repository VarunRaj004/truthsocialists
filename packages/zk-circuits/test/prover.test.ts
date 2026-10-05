import assert from "node:assert/strict";
import test from "node:test";
import {
  Groth16ProofGenerator,
  summarizeProverBenchmark,
  type Groth16ProverBackend,
  type ProvingArtifact,
} from "../src/index.js";

const artifact: ProvingArtifact = {
  artifactId: new Uint8Array(32).fill(7),
  circuitName: "vote",
  circuitVersion: 1,
  witnessCalculator: "vote.wasm",
  provingKey: "vote.zkey",
};

test("proof generator binds a backend result to the expected public signals", async () => {
  const backend: Groth16ProverBackend = {
    name: "test-rapidsnark-adapter",
    async prove() {
      return { proof: { valid: true }, publicSignals: ["1", "2", "3", "4", "0", "6", "7"] };
    },
  };
  const generated = await new Groth16ProofGenerator(backend).generate(
    artifact,
    { privateWitness: "not logged" },
    [1n, 2n, 3n, 4n, 0n, 6n, 7n],
  );
  assert.equal(generated.envelope.circuitName, "vote");
  assert.equal(generated.proverBackend, "test-rapidsnark-adapter");
  assert.ok(generated.durationMilliseconds >= 0);
});

test("proof generator rejects a backend that returns mismatched public signals", async () => {
  const backend: Groth16ProverBackend = {
    name: "bad-adapter",
    async prove() {
      return { proof: {}, publicSignals: ["1", "2", "3", "4", "1", "6", "7"] };
    },
  };
  await assert.rejects(
    new Groth16ProofGenerator(backend).generate(artifact, {}, [1n, 2n, 3n, 4n, 0n, 6n, 7n]),
    /do not match/,
  );
});

test("mobile benchmark summary reports median, p95, and peak memory", () => {
  assert.deepEqual(summarizeProverBenchmark({
    artifactId: artifact.artifactId,
    circuitName: "vote",
    backend: "android-rapidsnark-0.0.7",
    deviceModel: "representative-device",
    operatingSystem: "android",
    operatingSystemVersion: "test-version",
    architecture: "arm64",
    durationsMilliseconds: [90, 110, 100, 130, 120],
    peakResidentBytes: 64 * 1024 * 1024,
  }), {
    artifactIdHex: "07".repeat(32),
    samples: 5,
    medianMilliseconds: 110,
    p95Milliseconds: 130,
    peakResidentBytes: 64 * 1024 * 1024,
  });
});
