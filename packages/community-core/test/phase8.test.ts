import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import test from "node:test";
import { decodeCanonical, encodeCanonical, encodeFieldElement } from "@cyber-cipher/protocol-core";
import { type ActionSigner, type StaffCredential } from "@cyber-cipher/handler-core";
import { Groth16Verifier, VOTE_PUBLIC_SIGNAL_NAMES, decimalPublicSignals, votePublicSignals } from "@cyber-cipher/zk-circuits";
import {
  AuditorService, CommunityVotingService, RedactionService, VoteProofSessionService,
  evaluateVoteCounts, verifyAuditorAssessment,
} from "../src/index.js";

function signer(): ActionSigner {
  const pair = generateKeyPairSync("ed25519"); const spki = new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" }));
  return { publicKey: spki.slice(-32), sign: (message) => new Uint8Array(sign(null, message, pair.privateKey)) };
}
function staff(role: "HANDLER" | "REVIEWER" | "AUDITOR"): StaffCredential { return { staffId: randomUUID(), organizationId: randomUUID(), roles: new Set([role]), credentialId: new Uint8Array(16), publicKeySpkiDer: new Uint8Array([1]), signCount: 0 }; }

test("publication requires opt-in, PII screening, and an independent reviewer", () => {
  const service = new RedactionService(); const handler = staff("HANDLER"); const reviewer = staff("REVIEWER");
  const common = { redactionId: randomUUID(), complaintId: randomUUID(), version: 1, complainantOptIn: true,
    sourceComplaintCommitment: new Uint8Array(32).fill(1), sourceCiphertextHash: new Uint8Array(32).fill(2), submittedAt: 1_000 };
  const flagged = service.draft(handler, { ...common, payload: { summary: "Contact test@example.com", category: "safety", attachments: [] } });
  assert.equal(flagged.status, "PII_FLAGGED"); assert.throws(() => service.review(reviewer, flagged.redactionId, true, 2_000), /not reviewable/);
  const safe = service.draft(handler, { ...common, redactionId: randomUUID(), version: 2, payload: { summary: "A safety control was unavailable.", category: "safety", attachments: [{ mediaType: "image/png", uri: "sha256://safe", sha256: new Uint8Array(32).fill(3), size: 100 }] } });
  assert.throws(() => service.review(handler, safe.redactionId, true, 2_000), /independent/);
  const approved = service.review(reviewer, safe.redactionId, true, 2_000);
  assert.equal(approved.status, "APPROVED"); assert.equal(approved.voteClosesAt! - approved.voteOpensAt!, 604_800_000);
  assert.equal(service.publicRecord(safe.redactionId)?.payload.summary, safe.payload.summary);
  assert.throws(() => service.draft(handler, { ...common, redactionId: randomUUID(), version: 3, complainantOptIn: false, payload: safe.payload }), /opt-in/);
});

test("vote proof, current lease, unique nullifier, seven-day window, quorum, and 60 percent are enforced", async () => {
  const leaseKeys = generateKeyPairSync("ed25519"); const leases = new VoteProofSessionService(leaseKeys.privateKey);
  const verifier = new Groth16Verifier({ verify: async () => true }); const artifactId = new Uint8Array(32).fill(8);
  verifier.register({ artifactId, circuitName: "vote", circuitVersion: 1, publicSignalNames: VOTE_PUBLIC_SIGNAL_NAMES, verificationKey: {} });
  const voting = new CommunityVotingService(leases, verifier); const complaintId = randomUUID(); const complaintBytes = new Uint8Array(Buffer.from(complaintId.replaceAll("-", ""), "hex"));
  const checkpoint = { epoch: 7n, root: encodeFieldElement(123n) }; const opensAt = 10_000n; const closesAt = opensAt + 604_800_000n;
  voting.open(complaintId, complaintBytes, opensAt, closesAt);
  let firstNullifier = 0n;
  for (let index = 0; index < 10; index += 1) {
    const lease = leases.issue(checkpoint, opensAt + BigInt(index));
    const wrapper = decodeCanonical(lease.signedLeaseCbor); assert.ok(wrapper instanceof Map); const unsignedLeaseCbor = encodeCanonical(wrapper.get(1n)!);
    const choice = index < 6 ? 0n : 1n; const signals = votePublicSignals({ membershipRoot: 123n, epoch: 7n, complaintId: complaintBytes, voteChoice: choice, unsignedLeaseCbor, personSecret: BigInt(index + 1) });
    if (index === 0) firstNullifier = signals[3];
    await voting.submit({ complaintId, choice, voteNullifier: signals[3], signedLeaseCbor: lease.signedLeaseCbor,
      proofEnvelope: { artifactId, circuitName: "vote", circuitVersion: 1, publicSignals: decimalPublicSignals(signals), proof: { valid: true } }, checkpoint, now: opensAt + BigInt(index) });
  }
  const result = voting.result(complaintId, closesAt + 1n); assert.equal(result.outcome, "SUPPORT"); assert.equal(result.total, 10); assert.equal(result.thresholdMet, true);
  assert.equal(evaluateVoteCounts([6, 4, 0, 0]).outcome, "SUPPORT");
  assert.equal(evaluateVoteCounts([5, 4, 0, 0]).outcome, "INCONCLUSIVE");
  assert.equal(evaluateVoteCounts([5, 4, 1, 0]).outcome, "INCONCLUSIVE");
  const replayLease = leases.issue(checkpoint, opensAt + 20n); const replayBody = decodeCanonical(replayLease.signedLeaseCbor) as Map<bigint, unknown>; const replayUnsigned = encodeCanonical(replayBody.get(1n) as never);
  const replaySignals = votePublicSignals({ membershipRoot: 123n, epoch: 7n, complaintId: complaintBytes, voteChoice: 0n, unsignedLeaseCbor: replayUnsigned, personSecret: 1n });
  assert.equal(replaySignals[3], firstNullifier, "device replacement preserves the person-scoped nullifier");
  await assert.rejects(() => voting.submit({ complaintId, choice: 0n, voteNullifier: firstNullifier, signedLeaseCbor: replayLease.signedLeaseCbor,
    proofEnvelope: { artifactId, circuitName: "vote", circuitVersion: 1, publicSignals: decimalPublicSignals(replaySignals), proof: {} }, checkpoint, now: opensAt + 20n }), /already used/);
  const retrySignals = votePublicSignals({ membershipRoot: 123n, epoch: 7n, complaintId: complaintBytes, voteChoice: 0n, unsignedLeaseCbor: replayUnsigned, personSecret: 11n });
  await voting.submit({ complaintId, choice: 0n, voteNullifier: retrySignals[3], signedLeaseCbor: replayLease.signedLeaseCbor,
    proofEnvelope: { artifactId, circuitName: "vote", circuitVersion: 1, publicSignals: decimalPublicSignals(retrySignals), proof: {} }, checkpoint, now: opensAt + 21n });
});

test("auditor detects conflict and freezes only the public derivative", async () => {
  const redactions = new RedactionService(); const handler = staff("HANDLER"); const reviewer = staff("REVIEWER"); const auditor = staff("AUDITOR");
  const draft = redactions.draft(handler, { redactionId: randomUUID(), complaintId: randomUUID(), version: 1, complainantOptIn: true,
    payload: { summary: "Approved public summary", category: "service", attachments: [] }, sourceComplaintCommitment: new Uint8Array(32), sourceCiphertextHash: new Uint8Array(32), submittedAt: 1_000 });
  redactions.review(reviewer, draft.redactionId, true, 2_000); const actionSigner = signer(); const service = new AuditorService(actionSigner, redactions);
  const privateCaseState = "RESOLVED";
  const assessment = await service.assess(auditor, { assessmentId: randomUUID(), complaintId: draft.complaintId, redactionId: draft.redactionId,
    handlerFinding: "SUBSTANTIATED", communityResult: { complaintId: draft.complaintId, total: 10, counts: [2, 8, 0, 0], outcome: "OPPOSE", quorumMet: true, thresholdMet: true, finalizedAt: 3_000n },
    action: "FREEZE_PUBLIC", reasonCode: "OUTCOME_CONFLICT", occurredAt: 4_000n });
  assert.equal(assessment.comparisonStatus, "CONFLICTING"); assert.equal(redactions.publicRecord(draft.redactionId)?.status, "FROZEN");
  assert.equal(redactions.visibleByComplaint(draft.complaintId), undefined, "a freeze removes the payload from the public listing");
  assert.equal(privateCaseState, "RESOLVED", "public freeze does not alter the private case"); assert.equal(verifyAuditorAssessment(assessment, actionSigner.publicKey), true);
  assert.equal(verifyAuditorAssessment({ ...assessment, action: "NONE" }, actionSigner.publicKey), false);
});
