import { createPublicKey, randomBytes, randomUUID, sign, type KeyObject } from "node:crypto";
import {
  ProofLeasePurpose,
  assertBytesLength,
  assertExactIntegerKeys,
  decodeCanonical,
  ed25519SpkiFromRaw,
  encodeCanonical,
  encodeFieldElement,
  keyIdFromSpkiDer,
  proofLeaseBody,
  sha256,
  signedObject,
  signingInput,
  type CborKey,
  type CborValue,
} from "@cyber-cipher/protocol-core";
import type {
  AcceptComplaintInput,
  AcceptedComplaint,
  PersistProofSessionInput,
  PostgresComplaintStore,
  ReceiptSigner,
} from "@cyber-cipher/complaint-store";
import { ComplaintAuthorizer, complaintNullifierFromProof } from "./authorization.js";
import type { CiphertextObjectStore } from "./object-store.js";
import { decodeComplaintSubmission, uuidString, type ComplaintSubmissionWire } from "./wire.js";

export interface CurrentCheckpointProvider {
  current(): Promise<{ epoch: bigint; root: bigint }>;
}

export interface ComplaintPersistence {
  persistProofSession(input: PersistProofSessionInput): Promise<void>;
  acceptComplaint(input: AcceptComplaintInput): Promise<AcceptedComplaint>;
}

export interface IssuedProofSession {
  challengeId: Uint8Array;
  signedLeaseCbor: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
}

export interface ComplaintRandomSource {
  bytes(length: number): Uint8Array;
}

const systemRandom: ComplaintRandomSource = {
  bytes: (length) => new Uint8Array(randomBytes(length)),
};

export class DurableProofSessionIssuer {
  readonly #publicKeyRaw: Uint8Array;
  readonly #signingKeyId: Uint8Array;

  constructor(
    private readonly privateKey: KeyObject,
    private readonly store: Pick<PostgresComplaintStore, "persistProofSession">,
    private readonly checkpoints: CurrentCheckpointProvider,
    private readonly random: ComplaintRandomSource = systemRandom,
    private readonly clock: () => Date = () => new Date(),
  ) {
    if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("proof-session signing key must be Ed25519");
    }
    const spki = new Uint8Array(createPublicKey(privateKey).export({ format: "der", type: "spki" }));
    this.#publicKeyRaw = spki.slice(-32);
    if (Buffer.compare(Buffer.from(ed25519SpkiFromRaw(this.#publicKeyRaw)), Buffer.from(spki)) !== 0) {
      throw new TypeError("unexpected proof-session public key encoding");
    }
    this.#signingKeyId = keyIdFromSpkiDer(spki);
  }

  publicKeyRaw(): Uint8Array {
    return this.#publicKeyRaw.slice();
  }

  async issue(): Promise<IssuedProofSession> {
    const checkpoint = await this.checkpoints.current();
    const challengeId = assertBytesLength("challengeId", this.random.bytes(16), 16).slice();
    const serverNonce = assertBytesLength("serverNonce", this.random.bytes(32), 32).slice();
    const issuedAt = BigInt(this.clock().getTime());
    const expiresAt = issuedAt + 60_000n;
    const body = proofLeaseBody({
      challengeId,
      purpose: ProofLeasePurpose.Complaint,
      epoch: checkpoint.epoch,
      membershipRoot: encodeFieldElement(checkpoint.root),
      issuedAt,
      expiresAt,
      serverNonce,
      signingKeyId: this.#signingKeyId,
    });
    const bodyCbor = encodeCanonical(body);
    const signature = new Uint8Array(sign(null, signingInput("proof-lease", bodyCbor), this.privateKey));
    const signedLeaseCbor = encodeCanonical(signedObject(body, signature));
    await this.store.persistProofSession({
      challengeId,
      epoch: checkpoint.epoch,
      membershipRoot: checkpoint.root,
      signedLeaseCbor,
      issuedAt: new Date(Number(issuedAt)),
      expiresAt: new Date(Number(expiresAt)),
    });
    return { challengeId, signedLeaseCbor, issuedAt, expiresAt };
  }
}

export class ComplaintIntakeApplication {
  constructor(
    private readonly store: ComplaintPersistence,
    private readonly objects: CiphertextObjectStore,
    private readonly authorizer: ComplaintAuthorizer,
    private readonly receiptSigner: ReceiptSigner,
    private readonly random: ComplaintRandomSource = systemRandom,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async submit(idempotencyKey: string, requestBytes: Uint8Array): Promise<AcceptedComplaint> {
    const request = decodeComplaintSubmission(requestBytes);
    const acceptedAt = this.clock();
    const stored = await this.objects.put(request.ciphertext);
    const challengeId = proofLeaseChallenge(request.signedLeaseCbor);
    const input: AcceptComplaintInput = {
      idempotencyKey,
      requestHash: sha256(requestBytes),
      complaintId: uuidString(request.complaintId),
      eventId: randomUUID(),
      matterId: uuidString(request.matterId),
      matterVersion: request.matterVersion,
      challengeId,
      signedLeaseHash: sha256(request.signedLeaseCbor),
      serial: request.entitlement.entitlement.serial,
      nullifier: complaintNullifierFromProof(request.proof),
      complaintCommitment: request.complaintCommitment,
      ciphertextUri: stored.uri,
      ciphertextHash: stored.hash,
      ciphertextSize: stored.size,
      aeadNonce: request.aeadNonce,
      hpkeEnc: request.hpkeEnc,
      wrappedDek: request.wrappedDek,
      handlerKeyId: request.handlerKeyId,
      receiptId: assertBytesLength("receiptId", this.random.bytes(16), 16).slice(),
      receiptNonce: assertBytesLength("receiptNonce", this.random.bytes(32), 32).slice(),
      acceptedAt,
      receiptSigner: this.receiptSigner,
      authorize: (locked) => this.authorizer.authorize(locked, authorizationRequest(request, challengeId), acceptedAt),
    };
    return this.store.acceptComplaint(input);
  }
}

function authorizationRequest(request: ComplaintSubmissionWire, challengeId: Uint8Array) {
  return {
    complaintId: request.complaintId,
    matterId: request.matterId,
    matterVersion: request.matterVersion,
    complaintCommitment: request.complaintCommitment,
    challengeId,
    entitlement: request.entitlement,
    proof: request.proof,
  };
}

function proofLeaseChallenge(encoded: Uint8Array): Uint8Array {
  const wrapper = decodeCanonical(encoded);
  assertExactIntegerKeys(wrapper, [1n, 2n]);
  const body = field(wrapper, 1n);
  assertExactIntegerKeys(body, [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n]);
  const challenge = field(body, 2n);
  if (!(challenge instanceof Uint8Array) || challenge.length !== 16) {
    throw new TypeError("proof lease challenge must be 16 bytes");
  }
  return challenge;
}

function field(map: Map<CborKey, CborValue>, key: bigint): CborValue {
  const value = map.get(key);
  if (value === undefined) throw new TypeError(`missing proof lease field ${key}`);
  return value;
}
