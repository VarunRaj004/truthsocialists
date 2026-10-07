import { encodeCanonical, sha256, type CborKey, type CborValue } from "@cyber-cipher/protocol-core";
import type { StaffCredential } from "@cyber-cipher/handler-core";

export interface PublicAttachmentDerivative { mediaType: "image/png" | "image/jpeg" | "application/pdf"; uri: string; sha256: Uint8Array; size: number }
export interface PublicRedactionPayload { summary: string; category: string; attachments: readonly PublicAttachmentDerivative[] }
export type RedactionStatus = "DRAFT" | "PII_FLAGGED" | "PENDING_REVIEW" | "APPROVED" | "REJECTED" | "FROZEN";
export interface RedactionRecord {
  redactionId: string; complaintId: string; version: number; submittedBy: string; reviewedBy?: string;
  complainantOptIn: boolean; payload: PublicRedactionPayload; payloadCbor: Uint8Array; publicCommitment: Uint8Array;
  sourceComplaintCommitment: Uint8Array; sourceCiphertextHash: Uint8Array; status: RedactionStatus;
  piiFindings: string[]; submittedAt: number; reviewedAt?: number; voteOpensAt?: number; voteClosesAt?: number;
}

const patterns: ReadonlyArray<readonly [string, RegExp]> = [
  ["EMAIL", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i],
  ["PHONE", /(?:\+?94|0)[1-9][0-9]{8}\b/],
  ["NIC", /\b(?:[0-9]{9}[VX]|[0-9]{12})\b/i],
  ["IP_ADDRESS", /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/],
];

export function scanPublicPayload(value: PublicRedactionPayload): string[] {
  const text = `${value.summary}\n${value.category}`;
  return patterns.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}

export function encodePublicRedaction(value: PublicRedactionPayload): Uint8Array {
  if (value.summary !== value.summary.normalize("NFC") || value.category !== value.category.normalize("NFC")) throw new TypeError("public redaction text must be NFC");
  if (value.summary.length < 1 || value.summary.length > 10_000 || value.category.length > 100) throw new RangeError("public redaction text is outside policy limits");
  const attachments: CborValue[] = value.attachments.map((item) => {
    if (!item.uri.startsWith("sha256://") || item.sha256.length !== 32 || !Number.isSafeInteger(item.size) || item.size < 1 || item.size > 10_000_000) throw new TypeError("invalid public attachment derivative");
    return new Map<CborKey, CborValue>([[1n, item.mediaType], [2n, item.uri], [3n, item.sha256], [4n, BigInt(item.size)]]);
  });
  return encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, value.summary], [3n, value.category], [4n, attachments]]));
}

function copy(value: RedactionRecord): RedactionRecord { return { ...value, payload: { ...value.payload, attachments: value.payload.attachments.map((item) => ({ ...item, sha256: item.sha256.slice() })) }, payloadCbor: value.payloadCbor.slice(), publicCommitment: value.publicCommitment.slice(), sourceComplaintCommitment: value.sourceComplaintCommitment.slice(), sourceCiphertextHash: value.sourceCiphertextHash.slice(), piiFindings: [...value.piiFindings] }; }

export class RedactionService {
  readonly #records = new Map<string, RedactionRecord>();
  draft(actor: StaffCredential, input: Omit<RedactionRecord, "submittedBy" | "payloadCbor" | "publicCommitment" | "status" | "piiFindings" | "reviewedBy" | "reviewedAt" | "voteOpensAt" | "voteClosesAt">): RedactionRecord {
    if (!actor.roles.has("HANDLER")) throw new Error("handler role required to draft a redaction");
    if (!input.complainantOptIn) throw new Error("public release requires complainant opt-in");
    if (input.sourceComplaintCommitment.length !== 32 || input.sourceCiphertextHash.length !== 32) throw new TypeError("redaction provenance is incomplete");
    if ([...this.#records.values()].some((item) => item.complaintId === input.complaintId && item.version === input.version)) throw new Error("redaction version already exists");
    const payloadCbor = encodePublicRedaction(input.payload); const piiFindings = scanPublicPayload(input.payload);
    const value: RedactionRecord = { ...input, submittedBy: actor.staffId, payloadCbor, publicCommitment: sha256(input.sourceComplaintCommitment, input.sourceCiphertextHash, payloadCbor), piiFindings, status: piiFindings.length ? "PII_FLAGGED" : "PENDING_REVIEW" };
    this.#records.set(value.redactionId, value); return copy(value);
  }
  review(reviewer: StaffCredential, redactionId: string, approve: boolean, now = Date.now()): RedactionRecord {
    const value = this.#records.get(redactionId); if (!value) throw new Error("redaction not found");
    if (!reviewer.roles.has("REVIEWER") || reviewer.staffId === value.submittedBy) throw new Error("independent reviewer required");
    if (value.status !== "PENDING_REVIEW") throw new Error("redaction is not reviewable");
    value.reviewedBy = reviewer.staffId; value.reviewedAt = now; value.status = approve ? "APPROVED" : "REJECTED";
    if (approve) { value.voteOpensAt = now; value.voteClosesAt = now + 604_800_000; }
    return copy(value);
  }
  publicRecord(redactionId: string): RedactionRecord | undefined { const value = this.#records.get(redactionId); return value?.status === "APPROVED" || value?.status === "FROZEN" ? copy(value) : undefined; }
  visibleByComplaint(complaintId: string): RedactionRecord | undefined { const values = [...this.#records.values()].filter((item) => item.complaintId === complaintId && item.status === "APPROVED").sort((a, b) => b.version - a.version); return values[0] ? copy(values[0]) : undefined; }
  setFrozen(redactionId: string, frozen: boolean): void { const value = this.#records.get(redactionId); if (!value || !["APPROVED", "FROZEN"].includes(value.status)) throw new Error("public redaction unavailable"); value.status = frozen ? "FROZEN" : "APPROVED"; }
}
