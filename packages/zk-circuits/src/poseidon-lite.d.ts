declare module "poseidon-lite" {
  export function poseidon3(inputs: readonly [bigint, bigint, bigint]): bigint;
}

declare module "snarkjs" {
  export const groth16: {
    verify(verificationKey: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
    fullProve(
      input: Record<string, unknown>,
      wasmFile: string,
      provingKeyFile: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
  };
}
