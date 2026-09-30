import { integerMap, type CborKey, type CborValue } from "./cbor.js";
import { PROTOCOL_VERSION } from "./constants.js";
import { assertBytesLength, assertNfc, assertUint, decodeFieldElement } from "./validation.js";

const UINT32_MAX = 0xffff_ffffn;
const UINT64_MAX = 0xffff_ffff_ffff_ffffn;

export interface EntitlementMessageInput {
  matterKeyId: Uint8Array;
  serial: Uint8Array;
  personCommitment: Uint8Array;
}

export function entitlementMessage(input: EntitlementMessageInput): Map<CborKey, CborValue> {
  assertBytesLength("matterKeyId", input.matterKeyId, 32);
  assertBytesLength("serial", input.serial, 16);
  decodeFieldElement(input.personCommitment);
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, input.matterKeyId],
    [3, input.serial],
    [4, input.personCommitment],
  ]);
}

export interface AttachmentRecordInput {
  index: bigint;
  size: bigint;
  mimeType: string;
  sanitizedFilename: string;
  sha256: Uint8Array;
}

export function attachmentRecord(input: AttachmentRecordInput): Map<CborKey, CborValue> {
  assertUint("attachment index", input.index, UINT32_MAX);
  assertUint("attachment size", input.size, UINT64_MAX);
  assertNfc("MIME type", input.mimeType);
  assertNfc("sanitized filename", input.sanitizedFilename);
  assertBytesLength("attachment SHA-256", input.sha256, 32);
  return integerMap([
    [1, input.index],
    [2, input.size],
    [3, input.mimeType],
    [4, input.sanitizedFilename],
    [5, input.sha256],
  ]);
}

export interface ComplaintManifestInput {
  matterId: Uint8Array;
  matterVersion: bigint;
  text: string;
  attachments: readonly Map<CborKey, CborValue>[];
}

export function complaintManifest(input: ComplaintManifestInput): Map<CborKey, CborValue> {
  assertBytesLength("matterId", input.matterId, 16);
  assertUint("matterVersion", input.matterVersion, UINT32_MAX);
  assertNfc("complaint text", input.text);
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, input.matterId],
    [3, input.matterVersion],
    [4, input.text],
    [5, input.attachments],
  ]);
}

export interface LogEntryInput {
  eventId: Uint8Array;
  eventType: bigint;
  complaintId?: Uint8Array;
  matterId?: Uint8Array;
  matterVersion?: bigint;
  eventCommitment: Uint8Array;
  occurredAt: bigint;
  actorClass: bigint;
  reasonCode?: bigint;
}

export function logEntry(input: LogEntryInput): Map<CborKey, CborValue> {
  assertBytesLength("eventId", input.eventId, 16);
  assertUint("eventType", input.eventType, UINT32_MAX);
  assertBytesLength("eventCommitment", input.eventCommitment, 32);
  assertUint("occurredAt", input.occurredAt, UINT64_MAX);
  assertUint("actorClass", input.actorClass, UINT32_MAX);
  const entries: [number, CborValue][] = [
    [1, PROTOCOL_VERSION],
    [2, input.eventId],
    [3, input.eventType],
  ];
  if (input.complaintId !== undefined) {
    entries.push([4, assertBytesLength("complaintId", input.complaintId, 16)]);
  }
  if (input.matterId !== undefined) {
    entries.push([5, assertBytesLength("matterId", input.matterId, 16)]);
  }
  if (input.matterVersion !== undefined) {
    entries.push([6, assertUint("matterVersion", input.matterVersion, UINT32_MAX)]);
  }
  entries.push(
    [7, input.eventCommitment],
    [8, input.occurredAt],
    [9, input.actorClass],
  );
  if (input.reasonCode !== undefined) {
    entries.push([10, assertUint("reasonCode", input.reasonCode, UINT32_MAX)]);
  }
  return integerMap(entries);
}

export interface ReceiptBodyInput {
  receiptId: Uint8Array;
  receiptNonce: Uint8Array;
  complaintId: Uint8Array;
  matterId: Uint8Array;
  matterVersion: bigint;
  complaintCommitment: Uint8Array;
  acceptedAt: bigint;
  logEntryHash: Uint8Array;
  receiptKeyId: Uint8Array;
}

export function receiptBody(input: ReceiptBodyInput): Map<CborKey, CborValue> {
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, assertBytesLength("receiptId", input.receiptId, 16)],
    [3, assertBytesLength("receiptNonce", input.receiptNonce, 32)],
    [4, assertBytesLength("complaintId", input.complaintId, 16)],
    [5, assertBytesLength("matterId", input.matterId, 16)],
    [6, assertUint("matterVersion", input.matterVersion, UINT32_MAX)],
    [7, assertBytesLength("complaintCommitment", input.complaintCommitment, 32)],
    [8, assertUint("acceptedAt", input.acceptedAt, UINT64_MAX)],
    [9, assertBytesLength("logEntryHash", input.logEntryHash, 32)],
    [10, assertBytesLength("receiptKeyId", input.receiptKeyId, 32)],
  ]);
}

export interface MembershipCheckpointBodyInput {
  epoch: bigint;
  root: Uint8Array;
  previousCheckpointHash: Uint8Array;
  publishedAt: bigint;
  updateBatchHash: Uint8Array;
  signingKeyId: Uint8Array;
}

export const ProofLeasePurpose = {
  Complaint: 1n,
  Vote: 2n,
} as const;

export type ProofLeasePurposeValue =
  (typeof ProofLeasePurpose)[keyof typeof ProofLeasePurpose];

export interface ProofLeaseBodyInput {
  challengeId: Uint8Array;
  purpose: ProofLeasePurposeValue;
  epoch: bigint;
  membershipRoot: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
  serverNonce: Uint8Array;
  signingKeyId: Uint8Array;
}

export function proofLeaseBody(input: ProofLeaseBodyInput): Map<CborKey, CborValue> {
  if (input.purpose !== ProofLeasePurpose.Complaint && input.purpose !== ProofLeasePurpose.Vote) {
    throw new RangeError("proof lease purpose must be complaint or vote");
  }
  decodeFieldElement(input.membershipRoot);
  assertUint("issuedAt", input.issuedAt, UINT64_MAX);
  assertUint("expiresAt", input.expiresAt, UINT64_MAX);
  if (input.expiresAt < input.issuedAt) {
    throw new RangeError("proof lease expiry must not precede its issue time");
  }
  if (input.expiresAt - input.issuedAt > 60_000n) {
    throw new RangeError("proof lease lifetime must not exceed 60 seconds");
  }
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, assertBytesLength("challengeId", input.challengeId, 16)],
    [3, input.purpose],
    [4, assertUint("epoch", input.epoch, UINT64_MAX)],
    [5, input.membershipRoot],
    [6, input.issuedAt],
    [7, input.expiresAt],
    [8, assertBytesLength("serverNonce", input.serverNonce, 32)],
    [9, assertBytesLength("signingKeyId", input.signingKeyId, 32)],
  ]);
}

export interface ComplaintEncryptionAadInput {
  complaintId: Uint8Array;
  matterId: Uint8Array;
  matterVersion: bigint;
  complaintCommitment: Uint8Array;
  handlerKeyId: Uint8Array;
}

export function complaintEncryptionAad(
  input: ComplaintEncryptionAadInput,
): Map<CborKey, CborValue> {
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, assertBytesLength("complaintId", input.complaintId, 16)],
    [3, assertBytesLength("matterId", input.matterId, 16)],
    [4, assertUint("matterVersion", input.matterVersion, UINT32_MAX)],
    [5, assertBytesLength("complaintCommitment", input.complaintCommitment, 32)],
    [6, assertBytesLength("handlerKeyId", input.handlerKeyId, 32)],
  ]);
}

export interface HandlerDekAadInput {
  complaintId: Uint8Array;
  complaintCommitment: Uint8Array;
  handlerKeyId: Uint8Array;
}

export function handlerDekAad(input: HandlerDekAadInput): Map<CborKey, CborValue> {
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, assertBytesLength("complaintId", input.complaintId, 16)],
    [3, assertBytesLength("complaintCommitment", input.complaintCommitment, 32)],
    [4, assertBytesLength("handlerKeyId", input.handlerKeyId, 32)],
  ]);
}

export interface RecoveryChallengeBodyInput {
  tenantId: Uint8Array;
  challengeId: Uint8Array;
  recoveryId: Uint8Array;
  recoveryGeneration: bigint;
  issuedAt: bigint;
  expiresAt: bigint;
  serverNonce: Uint8Array;
  signingKeyId: Uint8Array;
}

export function recoveryChallengeBody(
  input: RecoveryChallengeBodyInput,
): Map<CborKey, CborValue> {
  assertUint("issuedAt", input.issuedAt, UINT64_MAX);
  assertUint("expiresAt", input.expiresAt, UINT64_MAX);
  if (input.expiresAt < input.issuedAt) {
    throw new RangeError("recovery challenge expiry must not precede its issue time");
  }
  if (input.expiresAt - input.issuedAt > 300_000n) {
    throw new RangeError("recovery challenge lifetime must not exceed five minutes");
  }
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, assertBytesLength("tenantId", input.tenantId, 16)],
    [3, assertBytesLength("challengeId", input.challengeId, 16)],
    [4, assertBytesLength("recoveryId", input.recoveryId, 16)],
    [5, assertUint("recoveryGeneration", input.recoveryGeneration, UINT32_MAX)],
    [6, input.issuedAt],
    [7, input.expiresAt],
    [8, assertBytesLength("serverNonce", input.serverNonce, 32)],
    [9, assertBytesLength("signingKeyId", input.signingKeyId, 32)],
  ]);
}

export interface RecoveryAuthorizationInput {
  tenantId: Uint8Array;
  signedChallengeHash: Uint8Array;
  personAnchor: Uint8Array;
  newDeviceHash: Uint8Array;
  newRecoveryId: Uint8Array;
  newRecoveryPublicKey: Uint8Array;
  expectedRecoveryGeneration: bigint;
}

export function recoveryAuthorization(
  input: RecoveryAuthorizationInput,
): Map<CborKey, CborValue> {
  decodeFieldElement(input.personAnchor);
  decodeFieldElement(input.newDeviceHash);
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, assertBytesLength("tenantId", input.tenantId, 16)],
    [3, assertBytesLength("signedChallengeHash", input.signedChallengeHash, 32)],
    [4, input.personAnchor],
    [5, input.newDeviceHash],
    [6, assertBytesLength("newRecoveryId", input.newRecoveryId, 16)],
    [7, assertBytesLength("newRecoveryPublicKey", input.newRecoveryPublicKey, 32)],
    [8, assertUint("expectedRecoveryGeneration", input.expectedRecoveryGeneration, UINT32_MAX)],
  ]);
}

export const RecoveryBackupPurpose = {
  PersonSecret: 1n,
  MailboxBundle: 2n,
} as const;

export type RecoveryBackupPurposeValue =
  (typeof RecoveryBackupPurpose)[keyof typeof RecoveryBackupPurpose];

export interface RecoveryBackupAadInput {
  tenantId: Uint8Array;
  recoveryId: Uint8Array;
  purpose: RecoveryBackupPurposeValue;
  generation: bigint;
}

export function recoveryBackupAad(input: RecoveryBackupAadInput): Map<CborKey, CborValue> {
  if (
    input.purpose !== RecoveryBackupPurpose.PersonSecret &&
    input.purpose !== RecoveryBackupPurpose.MailboxBundle
  ) {
    throw new RangeError("unsupported recovery backup purpose");
  }
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, assertBytesLength("tenantId", input.tenantId, 16)],
    [3, assertBytesLength("recoveryId", input.recoveryId, 16)],
    [4, input.purpose],
    [5, assertUint("generation", input.generation, UINT32_MAX)],
  ]);
}

export interface ArtifactManifestInput {
  circuitName: string;
  circuitVersion: bigint;
  treeDepth: bigint;
  proofSystem: string;
  curve: string;
  compiler: string;
  dependencies: ReadonlyMap<string, CborValue>;
  sourceHash: Uint8Array;
  r1csHash: Uint8Array;
  wasmHash: Uint8Array;
  provingKeyHash: Uint8Array;
  verificationKeyHash: Uint8Array;
  powersOfTauHash: Uint8Array;
  phaseTwoTranscriptHash: Uint8Array;
  builtAt: bigint;
}

export function artifactManifest(input: ArtifactManifestInput): Map<CborKey, CborValue> {
  assertNfc("circuitName", input.circuitName);
  assertNfc("proofSystem", input.proofSystem);
  assertNfc("curve", input.curve);
  assertNfc("compiler", input.compiler);
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, input.circuitName],
    [3, assertUint("circuitVersion", input.circuitVersion, UINT32_MAX)],
    [4, assertUint("treeDepth", input.treeDepth, UINT32_MAX)],
    [5, input.proofSystem],
    [6, input.curve],
    [7, input.compiler],
    [8, input.dependencies],
    [9, assertBytesLength("sourceHash", input.sourceHash, 32)],
    [10, assertBytesLength("r1csHash", input.r1csHash, 32)],
    [11, assertBytesLength("wasmHash", input.wasmHash, 32)],
    [12, assertBytesLength("provingKeyHash", input.provingKeyHash, 32)],
    [13, assertBytesLength("verificationKeyHash", input.verificationKeyHash, 32)],
    [14, assertBytesLength("powersOfTauHash", input.powersOfTauHash, 32)],
    [15, assertBytesLength("phaseTwoTranscriptHash", input.phaseTwoTranscriptHash, 32)],
    [16, assertUint("builtAt", input.builtAt, UINT64_MAX)],
  ]);
}

export function membershipCheckpointBody(
  input: MembershipCheckpointBodyInput,
): Map<CborKey, CborValue> {
  decodeFieldElement(input.root);
  return integerMap([
    [1, PROTOCOL_VERSION],
    [2, assertUint("epoch", input.epoch, UINT64_MAX)],
    [3, input.root],
    [4, assertBytesLength("previousCheckpointHash", input.previousCheckpointHash, 32)],
    [5, assertUint("publishedAt", input.publishedAt, UINT64_MAX)],
    [6, assertBytesLength("updateBatchHash", input.updateBatchHash, 32)],
    [7, assertBytesLength("signingKeyId", input.signingKeyId, 32)],
  ]);
}

export function signedObject(
  body: Map<CborKey, CborValue>,
  signature: Uint8Array,
): Map<CborKey, CborValue> {
  return integerMap([
    [1, body],
    [2, assertBytesLength("Ed25519 signature", signature, 64)],
  ]);
}
