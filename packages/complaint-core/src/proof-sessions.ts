import {
  createPublicKey,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import {
  ProofLeasePurpose,
  assertBytesLength,
  bytesToHex,
  ed25519SpkiFromRaw,
  encodeCanonical,
  equalBytes,
  keyIdFromSpkiDer,
  proofLeaseBody,
  sha256,
  signedObject,
  signingInput,
  verifyProofLease,
  type ProofLeaseBodyInput,
} from "@cyber-cipher/protocol-core";
import type { ComplaintRandomSource } from "./prepare.js";

export interface CurrentMembershipCheckpoint {
  readonly epoch: bigint;
  readonly root: Uint8Array;
}

export interface IssuedProofSession {
  readonly challengeId: Uint8Array;
  readonly signedLeaseCbor: Uint8Array;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
}

interface StoredProofSession {
  readonly tenantId: Uint8Array;
  readonly challengeId: Uint8Array;
  readonly signedLeaseHash: Uint8Array;
  readonly expiresAt: bigint;
  inFlight: boolean;
  consumedAt?: bigint;
}

const systemRandom: ComplaintRandomSource = {
  bytes: (length) => new Uint8Array(randomBytes(length)),
};

function clone(value: Uint8Array): Uint8Array {
  return value.slice();
}

export class InMemoryProofSessionStore {
  readonly #records = new Map<string, StoredProofSession>();

  insert(record: StoredProofSession): void {
    const key = bytesToHex(record.challengeId);
    if (this.#records.has(key)) throw new Error("proof-session challenge collision");
    this.#records.set(key, {
      ...record,
      tenantId: clone(record.tenantId),
      challengeId: clone(record.challengeId),
      signedLeaseHash: clone(record.signedLeaseHash),
    });
  }

  record(challengeId: Uint8Array): Readonly<StoredProofSession> | undefined {
    const value = this.#records.get(bytesToHex(challengeId));
    if (value === undefined) return undefined;
    return {
      ...value,
      tenantId: clone(value.tenantId),
      challengeId: clone(value.challengeId),
      signedLeaseHash: clone(value.signedLeaseHash),
    };
  }

  async runAndConsume<T>(
    tenantId: Uint8Array,
    challengeId: Uint8Array,
    signedLeaseHash: Uint8Array,
    now: bigint,
    operation: () => Promise<T>,
  ): Promise<T> {
    const record = this.#records.get(bytesToHex(challengeId));
    if (record === undefined) throw new Error("proof session is unknown");
    if (!equalBytes(record.tenantId, tenantId)) throw new Error("proof session belongs to another tenant");
    if (!equalBytes(record.signedLeaseHash, signedLeaseHash)) throw new Error("proof-session lease bytes do not match");
    if (record.consumedAt !== undefined) throw new Error("proof session has already been consumed");
    if (record.inFlight) throw new Error("proof session is already in use");
    if (now > record.expiresAt) throw new Error("proof session has expired");
    record.inFlight = true;
    try {
      const result = await operation();
      record.consumedAt = now;
      return result;
    } finally {
      record.inFlight = false;
    }
  }
}

export class ComplaintProofSessionService {
  readonly #privateKey: KeyObject;
  readonly #publicKeyRaw: Uint8Array;
  readonly #signingKeyId: Uint8Array;

  constructor(
    privateKey: KeyObject,
    readonly store: InMemoryProofSessionStore,
    private readonly random: ComplaintRandomSource = systemRandom,
  ) {
    if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("proof-session signing key must be an Ed25519 private key");
    }
    this.#privateKey = privateKey;
    const spki = new Uint8Array(createPublicKey(privateKey).export({ format: "der", type: "spki" }));
    this.#publicKeyRaw = spki.slice(-32);
    if (!equalBytes(ed25519SpkiFromRaw(this.#publicKeyRaw), spki)) {
      throw new TypeError("unexpected Ed25519 SubjectPublicKeyInfo encoding");
    }
    this.#signingKeyId = keyIdFromSpkiDer(spki);
  }

  publicKeyRaw(): Uint8Array {
    return clone(this.#publicKeyRaw);
  }

  issue(
    tenantId: Uint8Array,
    checkpoint: CurrentMembershipCheckpoint,
    now: bigint,
  ): IssuedProofSession {
    assertBytesLength("tenantId", tenantId, 16);
    assertBytesLength("membership root", checkpoint.root, 32);
    const challengeId = this.random.bytes(16);
    const serverNonce = this.random.bytes(32);
    assertBytesLength("challengeId", challengeId, 16);
    assertBytesLength("server nonce", serverNonce, 32);
    const expiresAt = now + 60_000n;
    const body = proofLeaseBody({
      challengeId,
      purpose: ProofLeasePurpose.Complaint,
      epoch: checkpoint.epoch,
      membershipRoot: checkpoint.root,
      issuedAt: now,
      expiresAt,
      serverNonce,
      signingKeyId: this.#signingKeyId,
    });
    const bodyCbor = encodeCanonical(body);
    const signature = new Uint8Array(sign(null, signingInput("proof-lease", bodyCbor), this.#privateKey));
    const signedLeaseCbor = encodeCanonical(signedObject(body, signature));
    this.store.insert({
      tenantId,
      challengeId,
      signedLeaseHash: sha256(signedLeaseCbor),
      expiresAt,
      inFlight: false,
    });
    return {
      challengeId: clone(challengeId),
      signedLeaseCbor,
      issuedAt: now,
      expiresAt,
    };
  }

  verifyUsable(
    tenantId: Uint8Array,
    signedLeaseCbor: Uint8Array,
    checkpoint: CurrentMembershipCheckpoint,
    now: bigint,
  ): ProofLeaseBodyInput {
    assertBytesLength("tenantId", tenantId, 16);
    const lease = verifyProofLease(signedLeaseCbor, this.#publicKeyRaw, {
      now,
      purpose: ProofLeasePurpose.Complaint,
      currentEpoch: checkpoint.epoch,
      currentRoot: checkpoint.root,
    });
    const record = this.store.record(lease.challengeId);
    if (record === undefined) throw new Error("proof session is unknown");
    if (!equalBytes(record.tenantId, tenantId)) throw new Error("proof session belongs to another tenant");
    if (!equalBytes(record.signedLeaseHash, sha256(signedLeaseCbor))) {
      throw new Error("proof-session lease bytes do not match");
    }
    if (record.consumedAt !== undefined) throw new Error("proof session has already been consumed");
    if (record.inFlight) throw new Error("proof session is already in use");
    return lease;
  }

  async submitWithLease<T>(
    tenantId: Uint8Array,
    signedLeaseCbor: Uint8Array,
    checkpoint: CurrentMembershipCheckpoint,
    now: bigint,
    operation: (lease: ProofLeaseBodyInput) => Promise<T>,
  ): Promise<T> {
    const lease = this.verifyUsable(tenantId, signedLeaseCbor, checkpoint, now);
    return this.store.runAndConsume(
      tenantId,
      lease.challengeId,
      sha256(signedLeaseCbor),
      now,
      () => operation(lease),
    );
  }
}
