import { randomBytes as nodeRandomBytes, timingSafeEqual } from "node:crypto";
import {
  assertBytesLength,
  bytesToHex,
  ed25519SpkiFromRaw,
  encodeCanonical,
  keyIdFromSpkiDer,
  recoveryAuthorization,
  recoveryChallengeBody,
  sha256,
  signedObject,
  signingInput,
  verifyEd25519Raw,
  verifyRecoveryChallenge,
} from "@cyber-cipher/protocol-core";
import {
  scalarFromBytes,
  scalarToBytes,
  type CheckpointSigner,
} from "@cyber-cipher/membership-core";
import type {
  CheckpointBundle,
  CompleteRecoveryTransactionInput,
  EnrollSyntheticInput,
  LockedRecoveryAuthorization,
  PersistentEnrollment,
  RecoveryChallengeDraft,
} from "@cyber-cipher/identity-store";

export interface IdentityRepository {
  enrollSynthetic(input: EnrollSyntheticInput): Promise<PersistentEnrollment>;
  issueRecoveryChallenge(
    recoveryId: Uint8Array,
    create: (locked: {
      enrollmentId: string;
      recoveryId: Uint8Array;
      recoveryGeneration: number;
    }) => Promise<RecoveryChallengeDraft>,
  ): Promise<RecoveryChallengeDraft>;
  completeRecoveryAtomic(input: CompleteRecoveryTransactionInput): Promise<PersistentEnrollment>;
}

export interface CheckpointRepository {
  latestCheckpoint(): Promise<CheckpointBundle | undefined>;
  checkpointsAfter(epoch: bigint, limit?: number): Promise<CheckpointBundle[]>;
}

export interface EnrollmentCommand {
  enrollmentId: string;
  syntheticIdentityRef: string;
  personAnchor: Uint8Array;
  deviceHash: Uint8Array;
  recoveryId: Uint8Array;
  recoveryPublicKey: Uint8Array;
}

export interface RecoveryChallengeResult {
  challengeId: Uint8Array;
  signedChallengeCbor: Uint8Array;
  expiresAt: bigint;
}

export interface CompleteRecoveryCommand {
  signedChallengeCbor: Uint8Array;
  authorizationSignature: Uint8Array;
  newDeviceHash: Uint8Array;
  newRecoveryId: Uint8Array;
  newRecoveryPublicKey: Uint8Array;
}

export interface IdentityAuthorityConfig {
  tenantId: Uint8Array;
  challengeSigner: CheckpointSigner;
  checkpointPublicKey: Uint8Array;
  now?: () => bigint;
  randomBytes?: (length: number) => Uint8Array;
}

export interface IdentityAuthorityOperations {
  enroll(command: EnrollmentCommand): Promise<PersistentEnrollment>;
  issueRecoveryChallenge(recoveryId: Uint8Array): Promise<RecoveryChallengeResult>;
  completeRecovery(command: CompleteRecoveryCommand): Promise<PersistentEnrollment>;
  currentCheckpoint(): Promise<CheckpointBundle | undefined>;
  checkpointDeltas(afterEpoch: bigint, limit?: number): Promise<CheckpointBundle[]>;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

export class IdentityAuthorityApplication implements IdentityAuthorityOperations {
  private readonly tenantId: Uint8Array;
  private readonly challengePublicKey: Uint8Array;
  private readonly challengeKeyId: Uint8Array;
  private readonly now: () => bigint;
  private readonly randomBytes: (length: number) => Uint8Array;

  constructor(
    private readonly identities: IdentityRepository,
    private readonly checkpoints: CheckpointRepository,
    private readonly config: IdentityAuthorityConfig,
  ) {
    this.tenantId = assertBytesLength("tenantId", config.tenantId, 16).slice();
    this.challengePublicKey = assertBytesLength(
      "challenge public key",
      config.challengeSigner.publicKey,
      32,
    ).slice();
    const checkpointPublicKey = assertBytesLength(
      "checkpoint public key",
      config.checkpointPublicKey,
      32,
    );
    this.challengeKeyId = keyIdFromSpkiDer(ed25519SpkiFromRaw(this.challengePublicKey));
    const checkpointKeyId = keyIdFromSpkiDer(ed25519SpkiFromRaw(checkpointPublicKey));
    if (bytesToHex(this.challengeKeyId) === bytesToHex(checkpointKeyId)) {
      throw new Error("recovery challenge and membership checkpoint keys must be distinct");
    }
    this.now = config.now ?? (() => BigInt(Date.now()));
    this.randomBytes = config.randomBytes ?? ((length) => new Uint8Array(nodeRandomBytes(length)));
  }

  async enroll(command: EnrollmentCommand): Promise<PersistentEnrollment> {
    if (!command.syntheticIdentityRef.startsWith("synthetic:")) {
      throw new TypeError("prototype enrollment accepts synthetic identities only");
    }
    return this.identities.enrollSynthetic({
      enrollmentId: command.enrollmentId,
      syntheticIdentityRef: command.syntheticIdentityRef,
      personAnchor: scalarFromBytes("personAnchor", command.personAnchor),
      deviceHash: scalarFromBytes("deviceHash", command.deviceHash),
      recoveryId: assertBytesLength("recoveryId", command.recoveryId, 16),
      recoveryPublicKey: assertBytesLength("recoveryPublicKey", command.recoveryPublicKey, 32),
    });
  }

  async issueRecoveryChallenge(recoveryId: Uint8Array): Promise<RecoveryChallengeResult> {
    assertBytesLength("recoveryId", recoveryId, 16);
    const draft = await this.identities.issueRecoveryChallenge(recoveryId, async (locked) => {
      const issuedAt = this.now();
      const expiresAt = issuedAt + 300_000n;
      if (
        issuedAt < 0n ||
        expiresAt > BigInt(Number.MAX_SAFE_INTEGER) ||
        Number.isNaN(new Date(Number(expiresAt)).getTime())
      ) {
        throw new RangeError("recovery challenge time is outside the database timestamp range");
      }
      const challengeId = assertBytesLength("challengeId", this.randomBytes(16), 16).slice();
      const serverNonce = assertBytesLength("serverNonce", this.randomBytes(32), 32).slice();
      const body = recoveryChallengeBody({
        tenantId: this.tenantId,
        challengeId,
        recoveryId: locked.recoveryId,
        recoveryGeneration: BigInt(locked.recoveryGeneration),
        issuedAt,
        expiresAt,
        serverNonce,
        signingKeyId: this.challengeKeyId,
      });
      const message = signingInput("recovery-challenge", encodeCanonical(body));
      const signature = assertBytesLength(
        "recovery challenge signature",
        await this.config.challengeSigner.sign(message),
        64,
      );
      if (!verifyEd25519Raw(this.challengePublicKey, message, signature)) {
        throw new Error("recovery challenge signer returned a signature from the wrong key");
      }
      return {
        challengeId,
        signedChallengeCbor: encodeCanonical(signedObject(body, signature)),
        issuedAt: new Date(Number(issuedAt)),
        expiresAt: new Date(Number(expiresAt)),
      };
    });
    return {
      challengeId: draft.challengeId.slice(),
      signedChallengeCbor: draft.signedChallengeCbor.slice(),
      expiresAt: BigInt(draft.expiresAt.getTime()),
    };
  }

  async completeRecovery(command: CompleteRecoveryCommand): Promise<PersistentEnrollment> {
    assertBytesLength("authorizationSignature", command.authorizationSignature, 64);
    const newDeviceHash = scalarFromBytes("newDeviceHash", command.newDeviceHash);
    assertBytesLength("newRecoveryId", command.newRecoveryId, 16);
    assertBytesLength("newRecoveryPublicKey", command.newRecoveryPublicKey, 32);
    const challenge = verifyRecoveryChallenge(
      command.signedChallengeCbor,
      this.challengePublicKey,
      { now: this.now(), tenantId: this.tenantId },
    );
    return this.identities.completeRecoveryAtomic({
      challengeId: challenge.challengeId,
      newDeviceHash,
      newRecoveryId: command.newRecoveryId,
      newRecoveryPublicKey: command.newRecoveryPublicKey,
      authorize: async (locked) => this.authorizeRecovery(command, locked),
    });
  }

  currentCheckpoint(): Promise<CheckpointBundle | undefined> {
    return this.checkpoints.latestCheckpoint();
  }

  checkpointDeltas(afterEpoch: bigint, limit = 100): Promise<CheckpointBundle[]> {
    return this.checkpoints.checkpointsAfter(afterEpoch, limit);
  }

  private authorizeRecovery(
    command: CompleteRecoveryCommand,
    locked: LockedRecoveryAuthorization,
  ): void {
    if (!equalBytes(command.signedChallengeCbor, locked.signedChallengeCbor)) {
      throw new Error("recovery challenge bytes do not match the issued challenge");
    }
    const challenge = verifyRecoveryChallenge(
      locked.signedChallengeCbor,
      this.challengePublicKey,
      {
        now: this.now(),
        tenantId: this.tenantId,
        recoveryId: locked.recoveryId,
        recoveryGeneration: BigInt(locked.recoveryGeneration),
      },
    );
    const authorization = recoveryAuthorization({
      tenantId: this.tenantId,
      signedChallengeHash: sha256(locked.signedChallengeCbor),
      personAnchor: scalarToBytes(locked.personAnchor),
      newDeviceHash: command.newDeviceHash,
      newRecoveryId: command.newRecoveryId,
      newRecoveryPublicKey: command.newRecoveryPublicKey,
      expectedRecoveryGeneration: challenge.recoveryGeneration,
    });
    if (
      !verifyEd25519Raw(
        locked.recoveryPublicKey,
        signingInput("recovery-authorization", encodeCanonical(authorization)),
        command.authorizationSignature,
      )
    ) {
      throw new Error("recovery authorization signature is invalid");
    }
  }
}
