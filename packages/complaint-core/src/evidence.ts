import { sha256 } from "@cyber-cipher/protocol-core";

export const MAX_EVIDENCE_FILE_BYTES = 25 * 1024 * 1024;
export const MAX_COMPLAINT_EVIDENCE_BYTES = 100 * 1024 * 1024;

export const EVIDENCE_MIME_TYPES = [
  "application/pdf",
  "image/jpeg",
  "image/png",
  "video/mp4",
  "audio/mp4",
  "text/plain",
] as const;

export type EvidenceMimeType = (typeof EVIDENCE_MIME_TYPES)[number];

export interface EvidenceInput {
  readonly mimeType: string;
  readonly bytes: Uint8Array;
}

export interface ValidatedEvidence {
  readonly index: number;
  readonly mimeType: EvidenceMimeType;
  readonly sanitizedFilename: string;
  readonly bytes: Uint8Array;
  readonly sha256: Uint8Array;
}

const extensions: Readonly<Record<EvidenceMimeType, string>> = {
  "application/pdf": "pdf",
  "image/jpeg": "jpg",
  "image/png": "png",
  "video/mp4": "mp4",
  "audio/mp4": "m4a",
  "text/plain": "txt",
};

function startsWith(value: Uint8Array, prefix: readonly number[]): boolean {
  return prefix.every((byte, index) => value[index] === byte);
}

function validateFormat(mimeType: EvidenceMimeType, bytes: Uint8Array): void {
  if (mimeType === "application/pdf") {
    if (!startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) throw new TypeError("PDF signature mismatch");
    const source = new TextDecoder("latin1").decode(bytes);
    if (/\/(?:JavaScript|JS|Launch|EmbeddedFile)\b/i.test(source)) {
      throw new TypeError("PDF active or embedded content is not allowed");
    }
    return;
  }
  if (mimeType === "image/jpeg" && !startsWith(bytes, [0xff, 0xd8, 0xff])) {
    throw new TypeError("JPEG signature mismatch");
  }
  if (mimeType === "image/png" && !startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    throw new TypeError("PNG signature mismatch");
  }
  if ((mimeType === "video/mp4" || mimeType === "audio/mp4") &&
      (bytes.length < 12 || new TextDecoder("ascii").decode(bytes.slice(4, 8)) !== "ftyp")) {
    throw new TypeError("ISO BMFF signature mismatch");
  }
  if (mimeType === "text/plain") {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (text.includes("\0")) throw new TypeError("plain text evidence must not contain NUL bytes");
  }
}

export function validateEvidence(inputs: readonly EvidenceInput[]): readonly ValidatedEvidence[] {
  let total = 0;
  return inputs.map((input, index) => {
    if (!EVIDENCE_MIME_TYPES.includes(input.mimeType as EvidenceMimeType)) {
      throw new TypeError(`evidence ${index} has a forbidden MIME type`);
    }
    if (!(input.bytes instanceof Uint8Array) || input.bytes.length === 0) {
      throw new TypeError(`evidence ${index} must not be empty`);
    }
    if (input.bytes.length > MAX_EVIDENCE_FILE_BYTES) {
      throw new RangeError(`evidence ${index} exceeds the 25 MiB limit`);
    }
    total += input.bytes.length;
    if (total > MAX_COMPLAINT_EVIDENCE_BYTES) {
      throw new RangeError("complaint evidence exceeds the 100 MiB limit");
    }
    const mimeType = input.mimeType as EvidenceMimeType;
    validateFormat(mimeType, input.bytes);
    const bytes = input.bytes.slice();
    return {
      index,
      mimeType,
      sanitizedFilename: `evidence-${index + 1}.${extensions[mimeType]}`,
      bytes,
      sha256: sha256(bytes),
    };
  });
}
