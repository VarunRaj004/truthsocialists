import assert from "node:assert/strict";
import test from "node:test";
import {
  COMPLAINT_PUBLIC_SIGNAL_NAMES,
  Groth16Verifier,
  type Groth16Backend,
  type Groth16ProofEnvelope,
} from "../src/index.js";

function fixture() {
  let calls = 0;
  const backend: Groth16Backend = {
    async verify(): Promise<boolean> {
      calls += 1;
      return true;
    },
  };
  const verifier = new Groth16Verifier(backend);
  const artifactId = new Uint8Array(32).fill(0x42);
  verifier.register({
    artifactId,
    circuitName: "complaint",
    circuitVersion: 1,
    publicSignalNames: COMPLAINT_PUBLIC_SIGNAL_NAMES,
    verificationKey: { protocol: "groth16", curve: "bn128" },
  });
  const signals = [11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n] as const;
  const envelope: Groth16ProofEnvelope = {
    artifactId,
    circuitName: "complaint",
    circuitVersion: 1,
    publicSignals: signals.map(String),
    proof: { pi_a: [] },
  };
  return { verifier, signals, envelope, calls: () => calls };
}

test("verifier accepts an allowlisted artifact with exactly matching public inputs", async () => {
  const value = fixture();
  assert.equal(await value.verifier.verify(value.envelope, value.signals), true);
  assert.equal(value.calls(), 1);
});

test("verifier rejects changed, reordered, non-canonical, and truncated public inputs", async () => {
  for (const publicSignals of [
    ["99", ...fixture().envelope.publicSignals.slice(1)],
    [fixture().envelope.publicSignals[1]!, fixture().envelope.publicSignals[0]!, ...fixture().envelope.publicSignals.slice(2)],
    ["00", ...fixture().envelope.publicSignals.slice(1)],
    fixture().envelope.publicSignals.slice(0, -1),
  ]) {
    const value = fixture();
    assert.equal(await value.verifier.verify({ ...value.envelope, publicSignals }, value.signals), false);
    assert.equal(value.calls(), 0);
  }
});

test("verifier rejects unknown artifacts and mismatched circuit metadata", async () => {
  const unknown = fixture();
  assert.equal(
    await unknown.verifier.verify(
      { ...unknown.envelope, artifactId: new Uint8Array(32).fill(0x24) },
      unknown.signals,
    ),
    false,
  );
  assert.equal(unknown.calls(), 0);

  const wrongVersion = fixture();
  assert.equal(
    await wrongVersion.verifier.verify({ ...wrongVersion.envelope, circuitVersion: 2 }, wrongVersion.signals),
    false,
  );
  assert.equal(wrongVersion.calls(), 0);
});

test("artifact registration rejects public-signal order drift", () => {
  const verifier = new Groth16Verifier({ async verify() { return true; } });
  assert.throws(
    () => verifier.register({
      artifactId: new Uint8Array(32),
      circuitName: "complaint",
      circuitVersion: 1,
      publicSignalNames: [...COMPLAINT_PUBLIC_SIGNAL_NAMES].reverse(),
      verificationKey: {},
    }),
    /frozen protocol order/,
  );
});

test("verifier converts malformed-proof backend errors into a safe rejection", async () => {
  const artifactId = new Uint8Array(32).fill(0x42);
  const verifier = new Groth16Verifier({ async verify() { throw new TypeError("bad curve point"); } });
  verifier.register({
    artifactId,
    circuitName: "complaint",
    circuitVersion: 1,
    publicSignalNames: COMPLAINT_PUBLIC_SIGNAL_NAMES,
    verificationKey: {},
  });
  const signals = [11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n] as const;
  assert.equal(await verifier.verify({
    artifactId,
    circuitName: "complaint",
    circuitVersion: 1,
    publicSignals: signals.map(String),
    proof: { malformed: true },
  }, signals), false);
});
