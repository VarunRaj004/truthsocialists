import { BN254_SCALAR_MODULUS, bytesToHex } from "@cyber-cipher/protocol-core";
import {
  COMPLAINT_PUBLIC_SIGNAL_NAMES,
  VOTE_PUBLIC_SIGNAL_NAMES,
  decimalPublicSignals,
} from "./signals.js";

export type CircuitName = "complaint" | "vote";

export interface Groth16Backend {
  verify(
    verificationKey: unknown,
    publicSignals: readonly string[],
    proof: unknown,
  ): Promise<boolean>;
}

export interface CircuitArtifact {
  readonly artifactId: Uint8Array;
  readonly circuitName: CircuitName;
  readonly circuitVersion: number;
  readonly publicSignalNames: readonly string[];
  readonly verificationKey: unknown;
}

export interface Groth16ProofEnvelope {
  readonly artifactId: Uint8Array;
  readonly circuitName: CircuitName;
  readonly circuitVersion: number;
  readonly publicSignals: readonly string[];
  readonly proof: unknown;
}

function frozenSignalNames(circuitName: CircuitName): readonly string[] {
  return circuitName === "complaint" ? COMPLAINT_PUBLIC_SIGNAL_NAMES : VOTE_PUBLIC_SIGNAL_NAMES;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function canonicalPublicSignal(value: string): boolean {
  if (value.length > 77) return false;
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) return false;
  const scalar = BigInt(value);
  return scalar < BN254_SCALAR_MODULUS;
}

export class Groth16Verifier {
  readonly #artifacts = new Map<string, CircuitArtifact>();
  readonly #backend: Groth16Backend;

  constructor(backend: Groth16Backend) {
    this.#backend = backend;
  }

  register(artifact: CircuitArtifact): void {
    if (artifact.artifactId.length !== 32) throw new TypeError("artifact ID must be 32 bytes");
    if (!Number.isSafeInteger(artifact.circuitVersion) || artifact.circuitVersion < 1) {
      throw new RangeError("circuit version must be a positive safe integer");
    }
    const expectedNames = frozenSignalNames(artifact.circuitName);
    if (!sameStrings(artifact.publicSignalNames, expectedNames)) {
      throw new TypeError(`${artifact.circuitName} public-signal order is not the frozen protocol order`);
    }
    const key = bytesToHex(artifact.artifactId);
    if (this.#artifacts.has(key)) throw new TypeError("artifact ID is already registered");
    this.#artifacts.set(key, artifact);
  }

  async verify(envelope: Groth16ProofEnvelope, expectedSignals: readonly bigint[]): Promise<boolean> {
    if (envelope.artifactId.length !== 32) return false;
    const artifact = this.#artifacts.get(bytesToHex(envelope.artifactId));
    if (
      artifact === undefined ||
      artifact.circuitName !== envelope.circuitName ||
      artifact.circuitVersion !== envelope.circuitVersion
    ) {
      return false;
    }
    const expectedNames = frozenSignalNames(envelope.circuitName);
    if (!sameStrings(artifact.publicSignalNames, expectedNames)) return false;
    if (envelope.publicSignals.length !== expectedNames.length) return false;
    if (!envelope.publicSignals.every(canonicalPublicSignal)) return false;

    let expected: string[];
    try {
      expected = decimalPublicSignals(expectedSignals);
    } catch {
      return false;
    }
    if (!sameStrings(envelope.publicSignals, expected)) return false;
    try {
      return await this.#backend.verify(
        artifact.verificationKey,
        envelope.publicSignals,
        envelope.proof,
      );
    } catch {
      return false;
    }
  }
}

export const snarkjsGroth16Backend: Groth16Backend = {
  async verify(verificationKey, publicSignals, proof) {
    const { groth16 } = await import("snarkjs");
    return groth16.verify(verificationKey, [...publicSignals], proof);
  },
};
