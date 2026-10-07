import { createPublicKey, randomBytes, sign, type KeyObject } from "node:crypto";
import {
  ProofLeasePurpose, assertBytesLength, ed25519SpkiFromRaw, encodeCanonical, hashToField,
  keyIdFromSpkiDer, parseUnsignedBigEndian, proofLeaseBody, sha256, signedObject, signingInput,
  verifyProofLease, type ProofLeaseBodyInput,
} from "@cyber-cipher/protocol-core";
import { Groth16Verifier, voteMessageCommitment, type Groth16ProofEnvelope } from "@cyber-cipher/zk-circuits";

export const VoteChoice = { Support: 0n, Oppose: 1n, Unsure: 2n, Abstain: 3n } as const;
export type VoteOutcome = "SUPPORT" | "OPPOSE" | "INCONCLUSIVE";
export interface MembershipCheckpoint { epoch: bigint; root: Uint8Array }
export interface VoteLease { challengeId: Uint8Array; signedLeaseCbor: Uint8Array; issuedAt: bigint; expiresAt: bigint }
interface StoredLease { hash: Uint8Array; expiresAt: bigint; inFlight: boolean; consumed: boolean }
export interface PublishedVote { complaintId: string; voteNullifier: bigint; choice: bigint; artifactId: Uint8Array; proofEnvelope: Groth16ProofEnvelope; acceptedAt: bigint }
export interface VoteResult { complaintId: string; total: number; counts: readonly [number, number, number, number]; outcome: VoteOutcome; quorumMet: boolean; thresholdMet: boolean; finalizedAt: bigint }

export function evaluateVoteCounts(counts: readonly [number, number, number, number]): Pick<VoteResult, "total" | "outcome" | "quorumMet" | "thresholdMet"> {
  if (counts.some((value) => !Number.isSafeInteger(value) || value < 0)) throw new RangeError("vote counts must be non-negative integers");
  const total = counts.reduce((sum, value) => sum + value, 0); const quorumMet = total >= 10;
  if (quorumMet && counts[0] * 100 >= total * 60) return { total, outcome: "SUPPORT", quorumMet, thresholdMet: true };
  if (quorumMet && counts[1] * 100 >= total * 60) return { total, outcome: "OPPOSE", quorumMet, thresholdMet: true };
  return { total, outcome: "INCONCLUSIVE", quorumMet, thresholdMet: false };
}

export class VoteProofSessionService {
  readonly #privateKey: KeyObject; readonly #publicKey: Uint8Array; readonly #keyId: Uint8Array; readonly #leases = new Map<string, StoredLease>();
  constructor(privateKey: KeyObject) {
    if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") throw new TypeError("vote lease key must be Ed25519");
    this.#privateKey = privateKey; const spki = new Uint8Array(createPublicKey(privateKey).export({ format: "der", type: "spki" })); this.#publicKey = spki.slice(-32);
    if (!Buffer.from(ed25519SpkiFromRaw(this.#publicKey)).equals(Buffer.from(spki))) throw new TypeError("unexpected Ed25519 key encoding"); this.#keyId = keyIdFromSpkiDer(spki);
  }
  publicKey(): Uint8Array { return this.#publicKey.slice(); }
  issue(checkpoint: MembershipCheckpoint, now: bigint): VoteLease {
    const challengeId = new Uint8Array(randomBytes(16)); const expiresAt = now + 60_000n;
    const body = proofLeaseBody({ challengeId, purpose: ProofLeasePurpose.Vote, epoch: checkpoint.epoch, membershipRoot: checkpoint.root, issuedAt: now, expiresAt, serverNonce: new Uint8Array(randomBytes(32)), signingKeyId: this.#keyId });
    const bodyCbor = encodeCanonical(body); const signedLeaseCbor = encodeCanonical(signedObject(body, new Uint8Array(sign(null, signingInput("proof-lease", bodyCbor), this.#privateKey))));
    const key = Buffer.from(challengeId).toString("hex"); if (this.#leases.has(key)) throw new Error("vote challenge collision");
    this.#leases.set(key, { hash: sha256(signedLeaseCbor), expiresAt, inFlight: false, consumed: false });
    return { challengeId, signedLeaseCbor, issuedAt: now, expiresAt };
  }
  async consume<T>(signedLeaseCbor: Uint8Array, checkpoint: MembershipCheckpoint, now: bigint, operation: (lease: ProofLeaseBodyInput) => Promise<T>): Promise<T> {
    const lease = verifyProofLease(signedLeaseCbor, this.#publicKey, { now, purpose: ProofLeasePurpose.Vote, currentEpoch: checkpoint.epoch, currentRoot: checkpoint.root });
    const stored = this.#leases.get(Buffer.from(lease.challengeId).toString("hex"));
    if (!stored || stored.consumed || stored.inFlight || now > stored.expiresAt || !Buffer.from(stored.hash).equals(Buffer.from(sha256(signedLeaseCbor)))) throw new Error("vote proof session rejected");
    stored.inFlight = true;
    try { const result = await operation(lease); stored.consumed = true; return result; }
    finally { stored.inFlight = false; }
  }
}

interface Window { complaintIdBytes: Uint8Array; opensAt: bigint; closesAt: bigint }

export class CommunityVotingService {
  readonly #windows = new Map<string, Window>(); readonly #votes = new Map<string, PublishedVote[]>();
  constructor(readonly leases: VoteProofSessionService, readonly verifier: Groth16Verifier) {}
  open(complaintId: string, complaintIdBytes: Uint8Array, opensAt: bigint, closesAt: bigint): void {
    assertBytesLength("complaint ID", complaintIdBytes, 16); if (closesAt - opensAt !== 604_800_000n) throw new Error("community vote window must be exactly seven days");
    if (this.#windows.has(complaintId)) throw new Error("community vote window already exists"); this.#windows.set(complaintId, { complaintIdBytes: complaintIdBytes.slice(), opensAt, closesAt }); this.#votes.set(complaintId, []);
  }
  async submit(input: { complaintId: string; choice: bigint; voteNullifier: bigint; signedLeaseCbor: Uint8Array; proofEnvelope: Groth16ProofEnvelope; checkpoint: MembershipCheckpoint; now: bigint }): Promise<PublishedVote> {
    const window = this.#windows.get(input.complaintId); if (!window || input.now < window.opensAt || input.now > window.closesAt) throw new Error("community vote window is closed");
    if (input.choice < 0n || input.choice > 3n) throw new Error("invalid vote choice");
    return this.leases.consume(input.signedLeaseCbor, input.checkpoint, input.now, async (lease) => {
      const existing = this.#votes.get(input.complaintId)!; if (existing.some((item) => item.voteNullifier === input.voteNullifier)) throw new Error("vote nullifier already used");
      const complaintField = hashToField("complaint-id-field", window.complaintIdBytes);
      const leaseHash = sha256(encodeCanonical(proofLeaseBody(lease)));
      const expected = [parseUnsignedBigEndian(input.checkpoint.root), input.checkpoint.epoch, complaintField, input.voteNullifier, input.choice, voteMessageCommitment(complaintField, input.choice), hashToField("challenge-field", leaseHash)];
      if (input.proofEnvelope.circuitName !== "vote" || !await this.verifier.verify(input.proofEnvelope, expected)) throw new Error("vote proof rejected");
      const vote: PublishedVote = { complaintId: input.complaintId, voteNullifier: input.voteNullifier, choice: input.choice, artifactId: input.proofEnvelope.artifactId.slice(), proofEnvelope: input.proofEnvelope, acceptedAt: input.now };
      existing.push(vote); return vote;
    });
  }
  publishedVotes(complaintId: string): PublishedVote[] { return (this.#votes.get(complaintId) ?? []).map((item) => ({ ...item, artifactId: item.artifactId.slice() })); }
  result(complaintId: string, now: bigint): VoteResult {
    const window = this.#windows.get(complaintId); if (!window) throw new Error("community vote unavailable"); if (now <= window.closesAt) throw new Error("community result is not final");
    const counts: [number, number, number, number] = [0, 0, 0, 0]; for (const vote of this.#votes.get(complaintId) ?? []) counts[Number(vote.choice)]! += 1;
    return { complaintId, counts, ...evaluateVoteCounts(counts), finalizedAt: now };
  }
}
