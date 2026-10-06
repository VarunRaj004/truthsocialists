import {
  ProofLeasePurpose,
  decodeFieldElement,
  encodeCanonical,
  encodeFieldElement,
  equalBytes,
  hashToField,
  proofLeaseBody,
  sha256,
  unsignedBigEndian,
  verifyProofLease,
} from "@cyber-cipher/protocol-core";
import { verifyBlindEntitlement, type BlindEntitlementToken } from "@cyber-cipher/matter-registry";
import { Groth16Verifier, type Groth16ProofEnvelope } from "@cyber-cipher/zk-circuits";
import type { LockedComplaintAuthorization } from "@cyber-cipher/complaint-store";

export interface ComplaintAuthorizationRequest {
  readonly complaintId: Uint8Array;
  readonly matterId: Uint8Array;
  readonly matterVersion: number;
  readonly complaintCommitment: Uint8Array;
  readonly challengeId: Uint8Array;
  readonly entitlement: BlindEntitlementToken;
  readonly proof: Groth16ProofEnvelope;
}

export class ComplaintAuthorizer {
  constructor(
    private readonly proofLeasePublicKey: Uint8Array,
    private readonly groth16: Groth16Verifier,
  ) {}

  async authorize(
    locked: LockedComplaintAuthorization,
    request: ComplaintAuthorizationRequest,
    acceptedAt: Date,
  ): Promise<void> {
    if (!equalBytes(request.matterId, uuidBytes(locked.matter.matterId))) throw new Error("matter ID mismatch");
    if (request.matterVersion !== locked.matter.version) throw new Error("matter version mismatch");
    if (!equalBytes(request.entitlement.entitlement.matterKeyId, locked.matter.matterKeyId)) {
      throw new Error("entitlement matter key mismatch");
    }
    if (!(await verifyBlindEntitlement(locked.matter.rsaSpkiDer, request.entitlement))) {
      throw new Error("invalid RSA blind entitlement");
    }
    const lease = verifyProofLease(locked.signedLeaseCbor, this.proofLeasePublicKey, {
      now: BigInt(acceptedAt.getTime()),
      purpose: ProofLeasePurpose.Complaint,
      currentEpoch: locked.epoch,
      currentRoot: encodeFieldElement(locked.membershipRoot),
    });
    if (!equalBytes(lease.challengeId, request.challengeId)) throw new Error("proof challenge mismatch");
    if (!equalBytes(request.proof.artifactId, locked.matter.complaintArtifactId)) {
      throw new Error("complaint circuit artifact mismatch");
    }
    if (request.proof.circuitName !== "complaint") throw new Error("wrong proof circuit");
    const matterField = hashToField(
      "matter-field",
      request.matterId,
      unsignedBigEndian(BigInt(request.matterVersion), 4),
    );
    const nullifier = canonicalSignal(request.proof.publicSignals[5], "complaint nullifier");
    const expectedSignals = [
      locked.membershipRoot,
      locked.epoch,
      matterField,
      hashToField("serial-field", request.entitlement.entitlement.serial),
      decodeFieldElement(request.entitlement.entitlement.personCommitment),
      nullifier,
      hashToField("commitment-field", request.complaintCommitment),
      hashToField("challenge-field", sha256(encodeCanonical(proofLeaseBody(lease)))),
    ];
    if (!(await this.groth16.verify(request.proof, expectedSignals))) {
      throw new Error("invalid Groth16 complaint proof");
    }
  }
}

export function complaintNullifierFromProof(proof: Groth16ProofEnvelope): bigint {
  return canonicalSignal(proof.publicSignals[5], "complaint nullifier");
}

function canonicalSignal(value: string | undefined, name: string): bigint {
  if (value === undefined || !/^(?:0|[1-9][0-9]*)$/.test(value)) throw new TypeError(`${name} is invalid`);
  return BigInt(value);
}

function uuidBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value.replaceAll("-", ""), "hex"));
}
