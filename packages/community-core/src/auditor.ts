import { assertBytesLength, encodeCanonical, sha256, signingInput, verifyEd25519Raw, type CborKey, type CborValue } from "@cyber-cipher/protocol-core";
import type { ActionSigner, StaffCredential } from "@cyber-cipher/handler-core";
import type { RedactionService } from "./redaction.js";
import type { VoteResult } from "./voting.js";

export type HandlerFinding = "SUBSTANTIATED" | "UNSUBSTANTIATED" | "PENDING";
export type ComparisonStatus = "ALIGNED" | "CONFLICTING" | "COMMUNITY_INCONCLUSIVE" | "HANDLER_PENDING";
export type AuditorAction = "NONE" | "REQUEST_JUSTIFICATION" | "FREEZE_PUBLIC" | "ESCALATE" | "UNFREEZE_PUBLIC";
export interface AuditorAssessment { assessmentId: string; complaintId: string; redactionId: string; handlerFinding: HandlerFinding; communityOutcome: string; communityResultHash: Uint8Array; comparisonStatus: ComparisonStatus; action: AuditorAction; reasonCode: string; auditorId: string; occurredAt: bigint; signedEventCbor: Uint8Array; signature: Uint8Array }

export function compareOutcome(handler: HandlerFinding, community: VoteResult): ComparisonStatus {
  if (handler === "PENDING") return "HANDLER_PENDING";
  if (community.outcome === "INCONCLUSIVE") return "COMMUNITY_INCONCLUSIVE";
  if ((handler === "SUBSTANTIATED" && community.outcome === "SUPPORT") || (handler === "UNSUBSTANTIATED" && community.outcome === "OPPOSE")) return "ALIGNED";
  return "CONFLICTING";
}

function assessmentBytes(input: Omit<AuditorAssessment, "signedEventCbor" | "signature">): Uint8Array {
  const statuses: Record<ComparisonStatus, bigint> = { ALIGNED: 1n, CONFLICTING: 2n, COMMUNITY_INCONCLUSIVE: 3n, HANDLER_PENDING: 4n };
  const actions: Record<AuditorAction, bigint> = { NONE: 0n, REQUEST_JUSTIFICATION: 1n, FREEZE_PUBLIC: 2n, ESCALATE: 3n, UNFREEZE_PUBLIC: 4n };
  const findings: Record<HandlerFinding, bigint> = { SUBSTANTIATED: 1n, UNSUBSTANTIATED: 2n, PENDING: 3n };
  return encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, input.assessmentId], [3n, input.complaintId], [4n, input.redactionId], [5n, statuses[input.comparisonStatus]], [6n, actions[input.action]], [7n, input.reasonCode], [8n, input.auditorId], [9n, input.occurredAt], [10n, findings[input.handlerFinding]], [11n, input.communityOutcome], [12n, assertBytesLength("community result hash", input.communityResultHash, 32)]]));
}

export class AuditorService {
  readonly #assessments: AuditorAssessment[] = [];
  constructor(readonly signer: ActionSigner, readonly redactions: RedactionService) {}
  async assess(actor: StaffCredential, input: { assessmentId: string; complaintId: string; redactionId: string; handlerFinding: HandlerFinding; communityResult: VoteResult; action: AuditorAction; reasonCode: string; occurredAt: bigint }): Promise<AuditorAssessment> {
    if (!actor.roles.has("AUDITOR")) throw new Error("auditor role required");
    if (input.communityResult.complaintId !== input.complaintId) throw new Error("community result complaint mismatch");
    const comparisonStatus = compareOutcome(input.handlerFinding, input.communityResult);
    const resultBytes = encodeCanonical(new Map<CborKey, CborValue>([[1n, BigInt(input.communityResult.total)], [2n, input.communityResult.counts.map(BigInt)], [3n, input.communityResult.outcome], [4n, input.communityResult.finalizedAt]]));
    const unsigned = { assessmentId: input.assessmentId, complaintId: input.complaintId, redactionId: input.redactionId, handlerFinding: input.handlerFinding, communityOutcome: input.communityResult.outcome, communityResultHash: sha256(resultBytes), comparisonStatus, action: input.action, reasonCode: input.reasonCode, auditorId: actor.staffId, occurredAt: input.occurredAt };
    const signedEventCbor = assessmentBytes(unsigned);
    const signature = assertBytesLength("auditor assessment signature", await this.signer.sign(signingInput("auditor-assessment", signedEventCbor)), 64);
    if (input.action === "UNFREEZE_PUBLIC") this.redactions.setFrozen(input.redactionId, false);
    else if (input.action === "FREEZE_PUBLIC") this.redactions.setFrozen(input.redactionId, true);
    const value = { ...unsigned, signedEventCbor, signature }; this.#assessments.push(value); return { ...value, signedEventCbor: signedEventCbor.slice(), signature: signature.slice() };
  }
}

export function verifyAuditorAssessment(value: AuditorAssessment, publicKey: Uint8Array): boolean {
  const expected = assessmentBytes(value); return Buffer.from(expected).equals(Buffer.from(value.signedEventCbor)) && verifyEd25519Raw(publicKey, signingInput("auditor-assessment", value.signedEventCbor), value.signature);
}
