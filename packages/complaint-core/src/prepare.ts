import { randomBytes } from "node:crypto";
import {
  aes256GcmOpen,
  aes256GcmSeal,
  attachmentRecord,
  complaintEncryptionAad,
  complaintManifest,
  concatBytes,
  decodeCanonical,
  encodeCanonical,
  integerMap,
  sha256,
  unwrapHandlerDek,
  wrapHandlerDek,
  type CborValue,
  type CborKey,
  type WrappedHandlerDek,
} from "@cyber-cipher/protocol-core";
import { validateEvidence, type EvidenceInput, type ValidatedEvidence } from "./evidence.js";

export interface ComplaintRandomSource {
  bytes(length: number): Uint8Array;
}

const secureRandom: ComplaintRandomSource = {
  bytes: (length) => new Uint8Array(randomBytes(length)),
};

export interface PrepareEncryptedComplaintInput {
  readonly matterId: Uint8Array;
  readonly matterVersion: bigint;
  readonly text: string;
  readonly evidence: readonly EvidenceInput[];
  readonly handlerKeyId: Uint8Array;
  readonly handlerPublicKey: Uint8Array;
}

export interface PreparedEncryptedComplaint {
  readonly complaintId: Uint8Array;
  readonly normalizedText: string;
  readonly manifestCbor: Uint8Array;
  readonly complaintSalt: Uint8Array;
  readonly complaintCommitment: Uint8Array;
  readonly encryptionNonce: Uint8Array;
  readonly ciphertextBlob: Uint8Array;
  readonly ciphertextSha256: Uint8Array;
  readonly handlerEnvelope: WrappedHandlerDek;
}

function randomUuidV4(random: ComplaintRandomSource): Uint8Array {
  const bytes = random.bytes(16);
  if (bytes.length !== 16) throw new TypeError("random source returned the wrong UUID length");
  const result = bytes.slice();
  result[6] = (result[6]! & 0x0f) | 0x40;
  result[8] = (result[8]! & 0x3f) | 0x80;
  return result;
}

function exactRandom(random: ComplaintRandomSource, length: number, label: string): Uint8Array {
  const value = random.bytes(length);
  if (value.length !== length) throw new TypeError(`random source returned the wrong ${label} length`);
  return value.slice();
}

function encryptedPlaintext(
  salt: Uint8Array,
  manifest: ReadonlyMap<CborKey, CborValue>,
  evidence: readonly ValidatedEvidence[],
): Uint8Array {
  return encodeCanonical(integerMap([
    [1, 1n],
    [2, salt],
    [3, manifest],
    [4, evidence.map((item) => integerMap([[1, BigInt(item.index)], [2, item.bytes]]))],
  ]));
}

export async function prepareEncryptedComplaint(
  input: PrepareEncryptedComplaintInput,
  random: ComplaintRandomSource = secureRandom,
): Promise<PreparedEncryptedComplaint> {
  const normalizedText = input.text.normalize("NFC");
  const evidence = validateEvidence(input.evidence);
  const manifest = complaintManifest({
    matterId: input.matterId,
    matterVersion: input.matterVersion,
    text: normalizedText,
    attachments: evidence.map((item) => attachmentRecord({
      index: BigInt(item.index),
      size: BigInt(item.bytes.length),
      mimeType: item.mimeType,
      sanitizedFilename: item.sanitizedFilename,
      sha256: item.sha256,
    })),
  });
  const manifestCbor = encodeCanonical(manifest);
  const complaintSalt = exactRandom(random, 32, "complaint salt");
  const complaintCommitment = sha256(complaintSalt, manifestCbor);
  const complaintId = randomUuidV4(random);
  const dek = exactRandom(random, 32, "DEK");
  const encryptionNonce = exactRandom(random, 12, "AES-GCM nonce");
  const aad = encodeCanonical(complaintEncryptionAad({
    complaintId,
    matterId: input.matterId,
    matterVersion: input.matterVersion,
    complaintCommitment,
    handlerKeyId: input.handlerKeyId,
  }));
  const sealed = aes256GcmSeal({
    key: dek,
    nonce: encryptionNonce,
    plaintext: encryptedPlaintext(complaintSalt, manifest, evidence),
    aad,
  });
  const ciphertextBlob = concatBytes(sealed.ciphertext, sealed.tag);
  const handlerEnvelope = await wrapHandlerDek(input.handlerPublicKey, dek, {
    matterId: input.matterId,
    matterVersion: input.matterVersion,
    complaintId,
    complaintCommitment,
    handlerKeyId: input.handlerKeyId,
  });
  dek.fill(0);
  return {
    complaintId,
    normalizedText,
    manifestCbor,
    complaintSalt,
    complaintCommitment,
    encryptionNonce,
    ciphertextBlob,
    ciphertextSha256: sha256(ciphertextBlob),
    handlerEnvelope,
  };
}

export async function openPreparedComplaint(
  prepared: PreparedEncryptedComplaint,
  context: Omit<PrepareEncryptedComplaintInput, "text" | "evidence" | "handlerPublicKey">,
  handlerPrivateKey: Uint8Array,
): Promise<CborValue> {
  if (prepared.ciphertextBlob.length < 16) throw new TypeError("ciphertext is shorter than its GCM tag");
  const dek = await unwrapHandlerDek(handlerPrivateKey, prepared.handlerEnvelope, {
    matterId: context.matterId,
    matterVersion: context.matterVersion,
    complaintId: prepared.complaintId,
    complaintCommitment: prepared.complaintCommitment,
    handlerKeyId: context.handlerKeyId,
  });
  const aad = encodeCanonical(complaintEncryptionAad({
    complaintId: prepared.complaintId,
    matterId: context.matterId,
    matterVersion: context.matterVersion,
    complaintCommitment: prepared.complaintCommitment,
    handlerKeyId: context.handlerKeyId,
  }));
  const tagOffset = prepared.ciphertextBlob.length - 16;
  try {
    return decodeCanonical(aes256GcmOpen({
      key: dek,
      nonce: prepared.encryptionNonce,
      ciphertext: prepared.ciphertextBlob.slice(0, tagOffset),
      tag: prepared.ciphertextBlob.slice(tagOffset),
      aad,
    }));
  } finally {
    dek.fill(0);
  }
}
