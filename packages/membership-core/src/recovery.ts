import {
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes as nodeRandomBytes,
  sign,
  timingSafeEqual,
} from "node:crypto";
import {
  RecoveryBackupPurpose,
  aes256GcmOpen,
  aes256GcmSeal,
  assertBytesLength,
  bytesToHex,
  concatBytes,
  ed25519SpkiFromRaw,
  encodeCanonical,
  keyIdFromSpkiDer,
  recoveryAuthorization,
  recoveryBackupAad,
  recoveryChallengeBody,
  sha256,
  signedObject,
  signingInput,
  utf8,
  verifyEd25519Raw,
  verifyRecoveryChallenge,
  type RecoveryAuthorizationInput,
  type RecoveryBackupAadInput,
  type RecoveryBackupPurposeValue,
} from "@cyber-cipher/protocol-core";
import { scalarToBytes } from "./poseidon.js";
import {
  type CheckpointSigner,
  type EnrollmentRecord,
  TenantMembershipService,
} from "./service.js";

const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from(
  Buffer.from("302e020100300506032b657004220420", "hex"),
);
const MAX_RECOVERY_ATTEMPTS = 10;

export interface RecoveryDerivedKeys {
  recoverySignSeed: Uint8Array;
  backupKey: Uint8Array;
  bundleKey: Uint8Array;
}

function derive(
  recoverySeed: Uint8Array,
  recoveryId: Uint8Array,
  label: string,
): Uint8Array {
  assertBytesLength("recoverySeed", recoverySeed, 16);
  assertBytesLength("recoveryId", recoveryId, 16);
  return new Uint8Array(hkdfSync("sha256", recoverySeed, recoveryId, utf8(label), 32));
}

export function deriveRecoveryKeys(
  recoverySeed: Uint8Array,
  recoveryId: Uint8Array,
): RecoveryDerivedKeys {
  return {
    recoverySignSeed: derive(recoverySeed, recoveryId, "CYBER-CIPHER/v1/recovery-sign"),
    backupKey: derive(recoverySeed, recoveryId, "CYBER-CIPHER/v1/person-backup"),
    bundleKey: derive(recoverySeed, recoveryId, "CYBER-CIPHER/v1/mailbox-bundle"),
  };
}

function privateKeyFromSeed(seed: Uint8Array) {
  assertBytesLength("Ed25519 private seed", seed, 32);
  return createPrivateKey({
    key: Buffer.from(concatBytes(ED25519_PKCS8_SEED_PREFIX, seed)),
    format: "der",
    type: "pkcs8",
  });
}

export function recoveryPublicKey(recoverySeed: Uint8Array, recoveryId: Uint8Array): Uint8Array {
  const keys = deriveRecoveryKeys(recoverySeed, recoveryId);
  try {
    const spki = new Uint8Array(
      createPublicKey(privateKeyFromSeed(keys.recoverySignSeed)).export({ format: "der", type: "spki" }),
    );
    return spki.slice(-32);
  } finally {
    keys.recoverySignSeed.fill(0);
    keys.backupKey.fill(0);
    keys.bundleKey.fill(0);
  }
}

export interface RecoveryBackupCiphertext {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

function keyForPurpose(keys: RecoveryDerivedKeys, purpose: RecoveryBackupPurposeValue): Uint8Array {
  if (purpose === RecoveryBackupPurpose.PersonSecret) return keys.backupKey;
  if (purpose === RecoveryBackupPurpose.MailboxBundle) return keys.bundleKey;
  throw new RangeError("unsupported recovery backup purpose");
}

export function sealRecoveryBackup(
  recoverySeed: Uint8Array,
  aadInput: RecoveryBackupAadInput,
  plaintext: Uint8Array,
  nonce: Uint8Array = new Uint8Array(nodeRandomBytes(12)),
): RecoveryBackupCiphertext {
  const keys = deriveRecoveryKeys(recoverySeed, aadInput.recoveryId);
  try {
    const sealed = aes256GcmSeal({
      key: keyForPurpose(keys, aadInput.purpose),
      nonce,
      plaintext,
      aad: encodeCanonical(recoveryBackupAad(aadInput)),
    });
    return { nonce: nonce.slice(), ...sealed };
  } finally {
    keys.recoverySignSeed.fill(0);
    keys.backupKey.fill(0);
    keys.bundleKey.fill(0);
  }
}

export function openRecoveryBackup(
  recoverySeed: Uint8Array,
  aadInput: RecoveryBackupAadInput,
  sealed: RecoveryBackupCiphertext,
): Uint8Array {
  const keys = deriveRecoveryKeys(recoverySeed, aadInput.recoveryId);
  try {
    return aes256GcmOpen({
      key: keyForPurpose(keys, aadInput.purpose),
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
      tag: sealed.tag,
      aad: encodeCanonical(recoveryBackupAad(aadInput)),
    });
  } finally {
    keys.recoverySignSeed.fill(0);
    keys.backupKey.fill(0);
    keys.bundleKey.fill(0);
  }
}

export function recoveryAuthorizationBytes(input: RecoveryAuthorizationInput): Uint8Array {
  return encodeCanonical(recoveryAuthorization(input));
}

export function signRecoveryAuthorization(
  recoverySeed: Uint8Array,
  recoveryId: Uint8Array,
  input: RecoveryAuthorizationInput,
): Uint8Array {
  const keys = deriveRecoveryKeys(recoverySeed, recoveryId);
  try {
    return new Uint8Array(
      sign(
        null,
        signingInput("recovery-authorization", recoveryAuthorizationBytes(input)),
        privateKeyFromSeed(keys.recoverySignSeed),
      ),
    );
  } finally {
    keys.recoverySignSeed.fill(0);
    keys.backupKey.fill(0);
    keys.bundleKey.fill(0);
  }
}

interface RecoveryChallengeRecord {
  enrollmentId: string;
  signedChallengeCbor: Uint8Array;
  consumed: boolean;
  attempts: number;
}

export interface RecoveryChallengeResult {
  signedChallengeCbor: Uint8Array;
  challengeId: Uint8Array;
  expiresAt: bigint;
}

export interface CompleteRecoveryInput {
  signedChallengeCbor: Uint8Array;
  authorizationSignature: Uint8Array;
  newDeviceHash: Uint8Array;
  newRecoveryId: Uint8Array;
  newRecoveryPublicKey: Uint8Array;
  now: bigint;
}

export class TenantRecoveryService {
  private readonly tenantId: Uint8Array;
  private readonly challengePublicKey: Uint8Array;
  private readonly challengeKeyId: Uint8Array;
  private readonly challenges = new Map<string, RecoveryChallengeRecord>();

  constructor(
    private readonly membership: TenantMembershipService,
    private readonly challengeSigner: CheckpointSigner,
    private readonly randomBytes: (length: number) => Uint8Array = (length) =>
      new Uint8Array(nodeRandomBytes(length)),
  ) {
    this.tenantId = membership.tenant().tenantId;
    this.challengePublicKey = assertBytesLength(
      "recovery challenge public key",
      challengeSigner.publicKey,
      32,
    ).slice();
    this.challengeKeyId = keyIdFromSpkiDer(ed25519SpkiFromRaw(this.challengePublicKey));
    if (bytesToHex(this.challengeKeyId) === bytesToHex(membership.checkpointKeyId())) {
      throw new Error("recovery challenge and membership checkpoint keys must be distinct");
    }
  }

  async issueChallenge(recoveryId: Uint8Array, issuedAt: bigint): Promise<RecoveryChallengeResult> {
    const record = this.membership.enrollmentByRecoveryId(recoveryId);
    if (record === undefined || !record.active) throw new Error("recovery challenge is not available");
    let challengeId: Uint8Array;
    do {
      challengeId = assertBytesLength("generated challengeId", this.randomBytes(16), 16).slice();
    } while (this.challenges.has(bytesToHex(challengeId)));
    const serverNonce = assertBytesLength("generated serverNonce", this.randomBytes(32), 32).slice();
    const expiresAt = issuedAt + 300_000n;
    const body = recoveryChallengeBody({
      tenantId: this.tenantId,
      challengeId,
      recoveryId,
      recoveryGeneration: BigInt(record.recoveryGeneration),
      issuedAt,
      expiresAt,
      serverNonce,
      signingKeyId: this.challengeKeyId,
    });
    const bodyBytes = encodeCanonical(body);
    const input = signingInput("recovery-challenge", bodyBytes);
    const signature = assertBytesLength(
      "recovery challenge signature",
      await this.challengeSigner.sign(input),
      64,
    );
    if (!verifyEd25519Raw(this.challengePublicKey, input, signature)) {
      throw new Error("recovery challenge signer returned a signature from the wrong key");
    }
    const signedChallengeCbor = encodeCanonical(signedObject(body, signature));
    this.challenges.set(bytesToHex(challengeId), {
      enrollmentId: record.enrollmentId,
      signedChallengeCbor: signedChallengeCbor.slice(),
      consumed: false,
      attempts: 0,
    });
    return { signedChallengeCbor: signedChallengeCbor.slice(), challengeId, expiresAt };
  }

  completeRecovery(input: CompleteRecoveryInput): EnrollmentRecord {
    const challenge = verifyRecoveryChallenge(input.signedChallengeCbor, this.challengePublicKey, {
      now: input.now,
      tenantId: this.tenantId,
    });
    const stored = this.challenges.get(bytesToHex(challenge.challengeId));
    if (stored === undefined) throw new Error("recovery challenge is not recognized");
    if (stored.consumed) throw new Error("recovery challenge has already been consumed");
    if (stored.attempts >= MAX_RECOVERY_ATTEMPTS) throw new Error("recovery challenge attempt limit reached");
    if (!equalBytes(stored.signedChallengeCbor, input.signedChallengeCbor)) {
      return this.failedAttempt(stored, "recovery challenge bytes do not match the issued challenge");
    }
    const enrollment = this.membership.enrollmentByRecoveryId(challenge.recoveryId);
    if (enrollment === undefined || enrollment.enrollmentId !== stored.enrollmentId || !enrollment.active) {
      return this.failedAttempt(stored, "recovery enrollment is no longer active");
    }
    if (BigInt(enrollment.recoveryGeneration) !== challenge.recoveryGeneration) {
      return this.failedAttempt(stored, "recovery challenge generation is stale");
    }
    const authorization: RecoveryAuthorizationInput = {
      tenantId: this.tenantId,
      signedChallengeHash: sha256(input.signedChallengeCbor),
      personAnchor: scalarToBytes(enrollment.personAnchor),
      newDeviceHash: input.newDeviceHash,
      newRecoveryId: input.newRecoveryId,
      newRecoveryPublicKey: input.newRecoveryPublicKey,
      expectedRecoveryGeneration: challenge.recoveryGeneration,
    };
    assertBytesLength("recovery authorization signature", input.authorizationSignature, 64);
    if (
      !verifyEd25519Raw(
        enrollment.recoveryPublicKey,
        signingInput("recovery-authorization", recoveryAuthorizationBytes(authorization)),
        input.authorizationSignature,
      )
    ) {
      return this.failedAttempt(stored, "recovery authorization signature is invalid");
    }
    let rotated: EnrollmentRecord;
    try {
      rotated = this.membership.rotateAfterVerifiedRecovery({
        enrollmentId: enrollment.enrollmentId,
        expectedRecoveryGeneration: enrollment.recoveryGeneration,
        newDeviceHash: input.newDeviceHash,
        newRecoveryId: input.newRecoveryId,
        newRecoveryPublicKey: input.newRecoveryPublicKey,
      });
    } catch (error) {
      stored.attempts += 1;
      throw error;
    }
    stored.consumed = true;
    return rotated;
  }

  private failedAttempt(record: RecoveryChallengeRecord, message: string): never {
    record.attempts += 1;
    throw new Error(message);
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}
