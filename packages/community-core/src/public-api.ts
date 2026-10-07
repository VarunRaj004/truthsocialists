import { encodeCanonical, type CborKey, type CborValue } from "@cyber-cipher/protocol-core";
import type { RedactionService } from "./redaction.js";
import type { CommunityVotingService } from "./voting.js";

export interface CommunityPublicResponse { status: number; headers: Readonly<Record<string, string>>; body: Uint8Array }
const HEADERS = { "content-type": "application/cbor", "cache-control": "public, max-age=30", "x-content-type-options": "nosniff" };

export function handleCommunityPublicRequest(redactions: RedactionService, voting: CommunityVotingService, requestUrl: string, now: bigint): CommunityPublicResponse {
  try {
    const url = new URL(requestUrl, "https://public.invalid"); const match = /^\/public\/v1\/complaints\/([^/]+)(\/vote-result)?$/.exec(url.pathname);
    if (!match) return { status: 404, headers: HEADERS, body: encodeCanonical(new Map([[1n, "not-found"]])) };
    const complaintId = decodeURIComponent(match[1]!); const redaction = redactions.visibleByComplaint(complaintId);
    if (!redaction) return { status: 404, headers: HEADERS, body: encodeCanonical(new Map([[1n, "not-public"]])) };
    if (match[2]) {
      const result = voting.result(complaintId, now);
      return { status: 200, headers: HEADERS, body: encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, complaintId], [3n, BigInt(result.total)], [4n, result.counts.map(BigInt)], [5n, result.outcome], [6n, result.quorumMet ? 1n : 0n], [7n, result.thresholdMet ? 1n : 0n]])) };
    }
    return { status: 200, headers: HEADERS, body: encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, complaintId], [3n, BigInt(redaction.version)], [4n, redaction.payloadCbor], [5n, redaction.publicCommitment], [6n, redaction.sourceComplaintCommitment], [7n, redaction.sourceCiphertextHash], [8n, BigInt(redaction.voteOpensAt!)], [9n, BigInt(redaction.voteClosesAt!)]])) };
  } catch { return { status: 409, headers: HEADERS, body: encodeCanonical(new Map([[1n, "result-not-final"]])) }; }
}
