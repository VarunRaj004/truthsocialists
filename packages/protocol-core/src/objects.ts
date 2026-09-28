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
