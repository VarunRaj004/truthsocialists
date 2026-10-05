import { bytesToHex } from "@cyber-cipher/protocol-core";
import { decimalPublicSignals } from "./signals.js";
import type { CircuitName, Groth16ProofEnvelope } from "./verifier.js";

export interface ProvingArtifact {
  readonly artifactId: Uint8Array;
  readonly circuitName: CircuitName;
  readonly circuitVersion: number;
  readonly witnessCalculator: string;
  readonly provingKey: string;
}

export interface Groth16ProverResult {
  readonly proof: unknown;
  readonly publicSignals: readonly string[];
}

export interface Groth16ProverBackend {
  readonly name: string;
  prove(
    witness: Readonly<Record<string, unknown>>,
    artifact: ProvingArtifact,
  ): Promise<Groth16ProverResult>;
}

export interface GeneratedProof {
  readonly envelope: Groth16ProofEnvelope;
  readonly proverBackend: string;
  readonly durationMilliseconds: number;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export class Groth16ProofGenerator {
  readonly #backend: Groth16ProverBackend;

  constructor(backend: Groth16ProverBackend) {
    if (!backend.name.trim()) throw new TypeError("prover backend name is required");
    this.#backend = backend;
  }

  async generate(
    artifact: ProvingArtifact,
    witness: Readonly<Record<string, unknown>>,
    expectedSignals: readonly bigint[],
  ): Promise<GeneratedProof> {
    if (artifact.artifactId.length !== 32) throw new TypeError("artifact ID must be 32 bytes");
    if (!Number.isSafeInteger(artifact.circuitVersion) || artifact.circuitVersion < 1) {
      throw new RangeError("circuit version must be a positive safe integer");
    }
    if (!artifact.witnessCalculator || !artifact.provingKey) {
      throw new TypeError("both proving assets are required");
    }
    const expected = decimalPublicSignals(expectedSignals);
    const started = performance.now();
    const generated = await this.#backend.prove(witness, artifact);
    const durationMilliseconds = performance.now() - started;
    if (!sameStrings(generated.publicSignals, expected)) {
      throw new Error(
        `prover ${this.#backend.name} returned public signals that do not match ${artifact.circuitName} request bindings`,
      );
    }
    return {
      envelope: {
        artifactId: new Uint8Array(artifact.artifactId),
        circuitName: artifact.circuitName,
        circuitVersion: artifact.circuitVersion,
        publicSignals: [...generated.publicSignals],
        proof: generated.proof,
      },
      proverBackend: this.#backend.name,
      durationMilliseconds,
    };
  }
}

export const snarkjsGroth16Prover: Groth16ProverBackend = {
  name: "snarkjs-wasm",
  async prove(witness, artifact) {
    const { groth16 } = await import("snarkjs");
    return groth16.fullProve({ ...witness }, artifact.witnessCalculator, artifact.provingKey);
  },
};

export interface ProverBenchmarkRecord {
  readonly artifactId: Uint8Array;
  readonly circuitName: CircuitName;
  readonly backend: string;
  readonly deviceModel: string;
  readonly operatingSystem: "android" | "ios";
  readonly operatingSystemVersion: string;
  readonly architecture: "arm64";
  readonly durationsMilliseconds: readonly number[];
  readonly peakResidentBytes: number;
}

export interface ProverBenchmarkSummary {
  readonly artifactIdHex: string;
  readonly samples: number;
  readonly medianMilliseconds: number;
  readonly p95Milliseconds: number;
  readonly peakResidentBytes: number;
}

export function summarizeProverBenchmark(record: ProverBenchmarkRecord): ProverBenchmarkSummary {
  if (record.artifactId.length !== 32) throw new TypeError("artifact ID must be 32 bytes");
  if (!record.backend.trim() || !record.deviceModel.trim() || !record.operatingSystemVersion.trim()) {
    throw new TypeError("benchmark environment metadata is required");
  }
  if (record.durationsMilliseconds.length < 5) throw new RangeError("at least five benchmark samples are required");
  if (!Number.isSafeInteger(record.peakResidentBytes) || record.peakResidentBytes <= 0) {
    throw new RangeError("peak resident memory must be a positive safe integer");
  }
  const sorted = [...record.durationsMilliseconds].sort((left, right) => left - right);
  if (sorted.some((value) => !Number.isFinite(value) || value <= 0)) {
    throw new RangeError("benchmark durations must be positive finite numbers");
  }
  const median = sorted[Math.floor(sorted.length / 2)]!;
  const p95 = sorted[Math.ceil(sorted.length * 0.95) - 1]!;
  return {
    artifactIdHex: bytesToHex(record.artifactId),
    samples: sorted.length,
    medianMilliseconds: median,
    p95Milliseconds: p95,
    peakResidentBytes: record.peakResidentBytes,
  };
}
