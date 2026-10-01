import {
  assertExactIntegerKeys,
  decodeCanonical,
  encodeCanonical,
  integerMap,
  sha256,
  type CborKey,
  type CborValue,
} from "@cyber-cipher/protocol-core";
import type { CheckpointBundle, PersistentEnrollment } from "@cyber-cipher/identity-store";
import type { PublishedMatter } from "@cyber-cipher/matter-registry";
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

function uint(map: Map<CborKey, CborValue>, key: bigint, name: string): bigint {
  const value = map.get(key);
  if (typeof value !== "bigint" || value < 0n) throw new TypeError(`${name} must be unsigned`);
  return value;
}

function uuidBytes(uuid: string): Uint8Array {
  return new Uint8Array(Buffer.from(uuid.replaceAll("-", ""), "hex"));
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

export interface BlindIssuanceWireInput {
  matterKeyId: Uint8Array;
  blindedMessage: Uint8Array;
}

export function decodeBlindIssuanceRequest(encoded: Uint8Array): BlindIssuanceWireInput {
  const map = mapValue(encoded, [1n, 2n]);
  return {
    matterKeyId: bytes(map, 1n, 32, "matterKeyId"),
    blindedMessage: bytes(map, 2n, 384, "blindedMessage"),
  };
}

export interface BlindIssuanceWireResponse {
  matterId: string;
  matterVersion: number;
  matterKeyId: Uint8Array;
  blindSignature: Uint8Array;
}

export function encodeBlindIssuanceResponse(value: BlindIssuanceWireResponse): Uint8Array {
  return encodeCanonical(
    integerMap([
      [1, 1n],
      [2, uuidBytes(value.matterId)],
      [3, BigInt(value.matterVersion)],
      [4, value.matterKeyId],
      [5, value.blindSignature],
    ]),
  );
}

export function decodeBlindIssuanceResponse(encoded: Uint8Array): BlindIssuanceWireResponse {
  const map = mapValue(encoded, [1n, 2n, 3n, 4n, 5n]);
  if (map.get(1n) !== 1n) throw new Error("unsupported blind-issuance response version");
  const matterId = Buffer.from(bytes(map, 2n, 16, "matterId")).toString("hex");
  const matterVersion = uint(map, 3n, "matterVersion");
  if (matterVersion > 0xffff_ffffn) throw new RangeError("matterVersion is too large");
  return {
    matterId: `${matterId.slice(0, 8)}-${matterId.slice(8, 12)}-${matterId.slice(12, 16)}-${matterId.slice(16, 20)}-${matterId.slice(20)}`,
    matterVersion: Number(matterVersion),
    matterKeyId: bytes(map, 4n, 32, "matterKeyId"),
    blindSignature: bytes(map, 5n, 384, "blindSignature"),
  };
}

const MATTER_STATE: Record<PublishedMatter["state"], bigint> = {
  PUBLISHED: 1n,
  OPEN: 2n,
  CLOSED: 3n,
  RETIRED: 4n,
};

export function encodePublicMattersResponse(matters: readonly PublishedMatter[]): Uint8Array {
  const entries = matters.map((matter) => {
    const fields: [number, CborValue][] = [
      [1, uuidBytes(matter.matterId)],
      [2, BigInt(matter.version)],
      [3, matter.title],
      [4, BigInt(matter.opensAt.getTime())],
      [5, BigInt(matter.closesAt.getTime())],
      [6, BigInt(matter.publishedAt.getTime())],
      [7, matter.matterKeyId],
      [8, matter.rsaSpkiDer],
      [9, matter.complaintArtifactId],
      [10, matter.voteArtifactId],
      [11, uuidBytes(matter.handlerOrgId)],
      [12, matter.handlerKeyId],
      [13, MATTER_STATE[matter.state]],
    ];
    if (matter.retiredAt !== undefined) fields.push([14, BigInt(matter.retiredAt.getTime())]);
    if (matter.retirementEvidence !== undefined) fields.push([15, matter.retirementEvidence]);
    return integerMap(fields);
  });
  return encodeCanonical(integerMap([[1, 1n], [2, entries as readonly CborValue[]]]));
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

export interface DecodedCheckpointDelta {
  epoch: bigint;
  deltaCbor: Uint8Array;
  signedCheckpointCbor: Uint8Array;
  checkpointHash: Uint8Array;
}

export interface DecodedCheckpointDeltasResponse {
  tenantId: Uint8Array;
  checkpoints: DecodedCheckpointDelta[];
}

export function decodeCheckpointDeltasResponse(
  encoded: Uint8Array,
): DecodedCheckpointDeltasResponse {
  const decoded = mapValue(encoded, [1n, 2n, 3n]);
  const version = decoded.get(1n);
  if (version !== 1n) throw new Error("unsupported checkpoint-deltas response version");
  const tenantId = bytes(decoded, 2n, 16, "tenantId");
  const entries = decoded.get(3n);
  if (!Array.isArray(entries)) throw new TypeError("checkpoint deltas must be an array");
  const checkpoints = entries.map((entry): DecodedCheckpointDelta => {
    assertExactIntegerKeys(entry, [1n, 2n, 3n, 4n]);
    const epoch = entry.get(1n);
    if (typeof epoch !== "bigint" || epoch < 1n) {
      throw new TypeError("checkpoint epoch must be a positive integer");
    }
    const deltaCbor = bytesVariable(entry, 2n, "deltaCbor");
    const signedCheckpointCbor = bytesVariable(entry, 3n, "signedCheckpointCbor");
    const checkpointHash = bytes(entry, 4n, 32, "checkpointHash");
    const expectedHash = sha256(signedCheckpointCbor);
    if (!checkpointHash.every((value, index) => value === expectedHash[index])) {
      throw new Error("checkpoint hash does not match the signed checkpoint");
    }
    return {
      epoch,
      deltaCbor: deltaCbor.slice(),
      signedCheckpointCbor: signedCheckpointCbor.slice(),
      checkpointHash: checkpointHash.slice(),
    };
  });
  return { tenantId: tenantId.slice(), checkpoints };
}

export function encodeErrorResponse(code: string): Uint8Array {
  return encodeCanonical(integerMap([[1, 1n], [2, code]]));
}
