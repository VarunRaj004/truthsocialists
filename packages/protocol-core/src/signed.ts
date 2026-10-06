import { timingSafeEqual } from "node:crypto";
import {
  assertExactIntegerKeys,
  decodeCanonical,
  encodeCanonical,
  type CborKey,
  type CborValue,
} from "./cbor.js";
import {
  ed25519SpkiFromRaw,
  keyIdFromSpkiDer,
  signingInput,
  verifyEd25519Raw,
} from "./crypto.js";
import {
  membershipCheckpointBody,
  proofLeaseBody,
  recoveryChallengeBody,
  receiptBody,
  treeHeadBody,
  type MembershipCheckpointBodyInput,
  type ProofLeaseBodyInput,
  type ProofLeasePurposeValue,
  type RecoveryChallengeBodyInput,
  type ReceiptBodyInput,
  type TreeHeadBodyInput,
} from "./objects.js";
import { assertBytesLength } from "./validation.js";

interface DecodedSignedBody {
  body: Map<CborKey, CborValue>;
  bodyBytes: Uint8Array;
  signature: Uint8Array;
}

function mapValue(map: Map<CborKey, CborValue>, key: bigint): CborValue {
  const value = map.get(key);
  if (value === undefined) throw new TypeError(`missing CBOR field ${key}`);
  return value;
}

function bytesValue(map: Map<CborKey, CborValue>, key: bigint, length: number): Uint8Array {
  const value = mapValue(map, key);
  if (!(value instanceof Uint8Array)) throw new TypeError(`CBOR field ${key} must be bytes`);
  return assertBytesLength(`CBOR field ${key}`, value, length);
}

function uintValue(map: Map<CborKey, CborValue>, key: bigint): bigint {
  const value = mapValue(map, key);
  if (typeof value !== "bigint") throw new TypeError(`CBOR field ${key} must be an integer`);
  return value;
}

function decodeSignedBody(input: Uint8Array, bodyKeys: readonly bigint[]): DecodedSignedBody {
  const wrapper = decodeCanonical(input);
  assertExactIntegerKeys(wrapper, [1n, 2n]);
  const body = mapValue(wrapper, 1n);
  assertExactIntegerKeys(body, bodyKeys);
  const signature = bytesValue(wrapper, 2n, 64);
  return { body, bodyBytes: encodeCanonical(body), signature };
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function verifyDedicatedKey(
  objectType: string,
  decoded: DecodedSignedBody,
  publicKey: Uint8Array,
  encodedKeyId: Uint8Array,
): void {
  const expectedKeyId = keyIdFromSpkiDer(ed25519SpkiFromRaw(publicKey));
  if (!bytesEqual(encodedKeyId, expectedKeyId)) {
    throw new Error(`${objectType} signing-key identifier does not match the supplied public key`);
  }
  if (!verifyEd25519Raw(publicKey, signingInput(objectType, decoded.bodyBytes), decoded.signature)) {
    throw new Error(`${objectType} signature is invalid`);
  }
}

export interface ReceiptVerificationExpectation {
  complaintId?: Uint8Array;
  matterId?: Uint8Array;
  matterVersion?: bigint;
  complaintCommitment?: Uint8Array;
}

export function verifyReceipt(
  encoded: Uint8Array,
  publicKey: Uint8Array,
  expected: ReceiptVerificationExpectation = {},
): ReceiptBodyInput {
  const decoded = decodeSignedBody(encoded, [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n]);
  const value: ReceiptBodyInput = {
    receiptId: bytesValue(decoded.body, 2n, 16),
    receiptNonce: bytesValue(decoded.body, 3n, 32),
    complaintId: bytesValue(decoded.body, 4n, 16),
    matterId: bytesValue(decoded.body, 5n, 16),
    matterVersion: uintValue(decoded.body, 6n),
    complaintCommitment: bytesValue(decoded.body, 7n, 32),
    acceptedAt: uintValue(decoded.body, 8n),
    logEntryHash: bytesValue(decoded.body, 9n, 32),
    receiptKeyId: bytesValue(decoded.body, 10n, 32),
  };
  receiptBody(value);
  if (uintValue(decoded.body, 1n) !== 1n) throw new Error("unsupported receipt protocol version");
  verifyDedicatedKey("receipt", decoded, publicKey, value.receiptKeyId);
  if (expected.complaintId !== undefined && !bytesEqual(value.complaintId, expected.complaintId)) {
    throw new Error("receipt complaint ID does not match");
  }
  if (expected.matterId !== undefined && !bytesEqual(value.matterId, expected.matterId)) {
    throw new Error("receipt matter ID does not match");
  }
  if (expected.matterVersion !== undefined && value.matterVersion !== expected.matterVersion) {
    throw new Error("receipt matter version does not match");
  }
  if (
    expected.complaintCommitment !== undefined &&
    !bytesEqual(value.complaintCommitment, expected.complaintCommitment)
  ) {
    throw new Error("receipt complaint commitment does not match");
  }
  return value;
}

export interface TreeHeadVerificationExpectation {
  previousFinalizedTreeHeadHash?: Uint8Array;
  minimumTreeSize?: bigint;
}

export function verifyTreeHead(
  encoded: Uint8Array,
  publicKey: Uint8Array,
  expected: TreeHeadVerificationExpectation = {},
): TreeHeadBodyInput {
  const decoded = decodeSignedBody(encoded, [1n, 2n, 3n, 4n, 5n, 6n]);
  const value: TreeHeadBodyInput = {
    treeSize: uintValue(decoded.body, 2n),
    rootHash: bytesValue(decoded.body, 3n, 32),
    timestamp: uintValue(decoded.body, 4n),
    previousFinalizedTreeHeadHash: bytesValue(decoded.body, 5n, 32),
    logKeyId: bytesValue(decoded.body, 6n, 32),
  };
  treeHeadBody(value);
  if (uintValue(decoded.body, 1n) !== 1n) throw new Error("unsupported tree-head protocol version");
  verifyDedicatedKey("tree-head", decoded, publicKey, value.logKeyId);
  if (
    expected.previousFinalizedTreeHeadHash !== undefined &&
    !bytesEqual(value.previousFinalizedTreeHeadHash, expected.previousFinalizedTreeHeadHash)
  ) {
    throw new Error("tree-head predecessor does not match");
  }
  if (expected.minimumTreeSize !== undefined && value.treeSize < expected.minimumTreeSize) {
    throw new Error("tree head is stale");
  }
  return value;
}

export interface CheckpointVerificationExpectation {
  previousCheckpointHash?: Uint8Array;
  minimumEpoch?: bigint;
}

export function verifyMembershipCheckpoint(
  encoded: Uint8Array,
  publicKey: Uint8Array,
  expected: CheckpointVerificationExpectation = {},
): MembershipCheckpointBodyInput {
  const decoded = decodeSignedBody(encoded, [1n, 2n, 3n, 4n, 5n, 6n, 7n]);
  const value: MembershipCheckpointBodyInput = {
    epoch: uintValue(decoded.body, 2n),
    root: bytesValue(decoded.body, 3n, 32),
    previousCheckpointHash: bytesValue(decoded.body, 4n, 32),
    publishedAt: uintValue(decoded.body, 5n),
    updateBatchHash: bytesValue(decoded.body, 6n, 32),
    signingKeyId: bytesValue(decoded.body, 7n, 32),
  };
  membershipCheckpointBody(value);
  if (uintValue(decoded.body, 1n) !== 1n) throw new Error("unsupported checkpoint protocol version");
  verifyDedicatedKey("membership-checkpoint", decoded, publicKey, value.signingKeyId);
  if (
    expected.previousCheckpointHash !== undefined &&
    !bytesEqual(value.previousCheckpointHash, expected.previousCheckpointHash)
  ) {
    throw new Error("membership checkpoint predecessor does not match");
  }
  if (expected.minimumEpoch !== undefined && value.epoch < expected.minimumEpoch) {
    throw new Error("membership checkpoint epoch is stale");
  }
  return value;
}

export interface ProofLeaseVerificationExpectation {
  now: bigint;
  purpose: ProofLeasePurposeValue;
  currentEpoch: bigint;
  currentRoot: Uint8Array;
}

export function verifyProofLease(
  encoded: Uint8Array,
  publicKey: Uint8Array,
  expected: ProofLeaseVerificationExpectation,
): ProofLeaseBodyInput {
  const decoded = decodeSignedBody(encoded, [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n]);
  const value: ProofLeaseBodyInput = {
    challengeId: bytesValue(decoded.body, 2n, 16),
    purpose: uintValue(decoded.body, 3n) as ProofLeasePurposeValue,
    epoch: uintValue(decoded.body, 4n),
    membershipRoot: bytesValue(decoded.body, 5n, 32),
    issuedAt: uintValue(decoded.body, 6n),
    expiresAt: uintValue(decoded.body, 7n),
    serverNonce: bytesValue(decoded.body, 8n, 32),
    signingKeyId: bytesValue(decoded.body, 9n, 32),
  };
  proofLeaseBody(value);
  if (uintValue(decoded.body, 1n) !== 1n) throw new Error("unsupported proof-lease protocol version");
  verifyDedicatedKey("proof-lease", decoded, publicKey, value.signingKeyId);
  if (value.purpose !== expected.purpose) throw new Error("proof lease purpose does not match");
  if (value.epoch !== expected.currentEpoch) throw new Error("proof lease epoch is not current");
  if (!bytesEqual(value.membershipRoot, expected.currentRoot)) {
    throw new Error("proof lease membership root is not current");
  }
  if (expected.now < value.issuedAt) throw new Error("proof lease is not active yet");
  if (expected.now > value.expiresAt) throw new Error("proof lease has expired");
  return value;
}

export interface RecoveryChallengeVerificationExpectation {
  now: bigint;
  tenantId: Uint8Array;
  recoveryId?: Uint8Array;
  recoveryGeneration?: bigint;
}

export function verifyRecoveryChallenge(
  encoded: Uint8Array,
  publicKey: Uint8Array,
  expected: RecoveryChallengeVerificationExpectation,
): RecoveryChallengeBodyInput {
  const decoded = decodeSignedBody(encoded, [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n]);
  const value: RecoveryChallengeBodyInput = {
    tenantId: bytesValue(decoded.body, 2n, 16),
    challengeId: bytesValue(decoded.body, 3n, 16),
    recoveryId: bytesValue(decoded.body, 4n, 16),
    recoveryGeneration: uintValue(decoded.body, 5n),
    issuedAt: uintValue(decoded.body, 6n),
    expiresAt: uintValue(decoded.body, 7n),
    serverNonce: bytesValue(decoded.body, 8n, 32),
    signingKeyId: bytesValue(decoded.body, 9n, 32),
  };
  recoveryChallengeBody(value);
  if (uintValue(decoded.body, 1n) !== 1n) {
    throw new Error("unsupported recovery-challenge protocol version");
  }
  verifyDedicatedKey("recovery-challenge", decoded, publicKey, value.signingKeyId);
  if (!bytesEqual(value.tenantId, expected.tenantId)) {
    throw new Error("recovery challenge tenant does not match");
  }
  if (expected.recoveryId !== undefined && !bytesEqual(value.recoveryId, expected.recoveryId)) {
    throw new Error("recovery challenge recovery ID does not match");
  }
  if (
    expected.recoveryGeneration !== undefined &&
    value.recoveryGeneration !== expected.recoveryGeneration
  ) {
    throw new Error("recovery challenge generation does not match");
  }
  if (expected.now < value.issuedAt) throw new Error("recovery challenge is not active yet");
  if (expected.now > value.expiresAt) throw new Error("recovery challenge has expired");
  return value;
}
