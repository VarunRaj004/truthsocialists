import {
  assertExactIntegerKeys,
  decodeCanonical,
  encodeCanonical,
  integerMap,
  type CborKey,
  type CborValue,
} from "@cyber-cipher/protocol-core";
import type { CheckpointBundle, PersistentEnrollment } from "@cyber-cipher/identity-store";
import type { CompleteRecoveryCommand, EnrollmentCommand, RecoveryChallengeResult } from "./application.js";

function mapValue(encoded: Uint8Array, keys: readonly bigint[]): Map<CborKey, CborValue> {
  const decoded = decodeCanonical(encoded);
  assertExactIntegerKeys(decoded, keys);
  return decoded;
}

function bytes(map: Map<CborKey, CborValue>, key: bigint, length: number, name: string): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new TypeError(`${name} must be ${length} bytes`);
  }
  return value;
}

function text(map: Map<CborKey, CborValue>, key: bigint, name: string): string {
  const value = map.get(key);
  if (typeof value !== "string") throw new TypeError(`${name} must be text`);
  return value;
}

export interface EnrollmentWireInput extends Omit<EnrollmentCommand, "syntheticIdentityRef"> {}

export function decodeEnrollmentRequest(encoded: Uint8Array): EnrollmentWireInput {
  const map = mapValue(encoded, [1n, 2n, 3n, 4n, 5n]);
  return {
    enrollmentId: text(map, 1n, "enrollmentId"),
    personAnchor: bytes(map, 2n, 32, "personAnchor"),
    deviceHash: bytes(map, 3n, 32, "deviceHash"),
    recoveryId: bytes(map, 4n, 16, "recoveryId"),
    recoveryPublicKey: bytes(map, 5n, 32, "recoveryPublicKey"),
  };
}

export function decodeRecoveryChallengeRequest(encoded: Uint8Array): Uint8Array {
  return bytes(mapValue(encoded, [1n]), 1n, 16, "recoveryId");
}

export function decodeCompleteRecoveryRequest(encoded: Uint8Array): CompleteRecoveryCommand {
  const map = mapValue(encoded, [1n, 2n, 3n, 4n, 5n]);
  return {
    signedChallengeCbor: bytesVariable(map, 1n, "signedChallengeCbor"),
    authorizationSignature: bytes(map, 2n, 64, "authorizationSignature"),
    newDeviceHash: bytes(map, 3n, 32, "newDeviceHash"),
    newRecoveryId: bytes(map, 4n, 16, "newRecoveryId"),
    newRecoveryPublicKey: bytes(map, 5n, 32, "newRecoveryPublicKey"),
  };
}

function bytesVariable(map: Map<CborKey, CborValue>, key: bigint, name: string): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.length === 0) throw new TypeError(`${name} must be bytes`);
  return value;
}

export function encodeEnrollmentResponse(enrollment: PersistentEnrollment): Uint8Array {
  return encodeCanonical(
    integerMap([
      [1, 1n],
      [2, enrollment.enrollmentId],
      [3, BigInt(enrollment.activeLeafIndex)],
      [4, BigInt(enrollment.recoveryGeneration)],
    ]),
  );
}

export function encodeRecoveryChallengeResponse(challenge: RecoveryChallengeResult): Uint8Array {
  return encodeCanonical(
    integerMap([
      [1, 1n],
      [2, challenge.challengeId],
      [3, challenge.signedChallengeCbor],
      [4, challenge.expiresAt],
    ]),
  );
}

export function encodeCheckpointDeltasResponse(
  tenantId: Uint8Array,
  checkpoints: readonly CheckpointBundle[],
): Uint8Array {
  const entries = checkpoints.map((checkpoint) =>
    integerMap([
      [1, checkpoint.epoch],
      [2, checkpoint.deltaCbor],
      [3, checkpoint.signedCheckpointCbor],
      [4, checkpoint.checkpointHash],
    ]),
  );
  return encodeCanonical(
    integerMap([
      [1, 1n],
      [2, tenantId],
      [3, entries as readonly CborValue[]],
    ]),
  );
}

export function encodeErrorResponse(code: string): Uint8Array {
  return encodeCanonical(integerMap([[1, 1n], [2, code]]));
}
