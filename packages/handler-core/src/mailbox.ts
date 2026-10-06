import { createPrivateKey, createPublicKey, hkdfSync, randomBytes, sign } from "node:crypto";
import {
  assertBytesLength, concatBytes, decodeCanonical, encodeCanonical, hpkeOpen, hpkeSeal, sha256,
  signingInput, utf8, verifyEd25519Raw, type CborKey, type CborValue,
} from "@cyber-cipher/protocol-core";
import { openRecoveryBackup, sealRecoveryBackup, type RecoveryBackupCiphertext } from "@cyber-cipher/membership-core";

const ED25519_PKCS8_PREFIX = new Uint8Array(Buffer.from("302e020100300506032b657004220420", "hex"));
const X25519_PKCS8_PREFIX = new Uint8Array(Buffer.from("302e020100300506032b656e04220420", "hex"));
export const MailboxDirection = { UserToHandler: 1n, HandlerToUser: 2n } as const;
export type MailboxDirectionValue = typeof MailboxDirection[keyof typeof MailboxDirection];

export interface MailboxSecrets { mailboxId: Uint8Array; followUpSeed: Uint8Array; authPublicKey: Uint8Array; hpkePublicKey: Uint8Array }
export interface MailboxCiphertext { mailboxId: Uint8Array; messageNumber: bigint; direction: MailboxDirectionValue; previousMessageHash: Uint8Array; recipientKeyId: Uint8Array; encapsulatedKey: Uint8Array; ciphertext: Uint8Array }
export interface MailboxChallenge { challengeId: Uint8Array; mailboxId: Uint8Array; challenge: Uint8Array; issuedAt: bigint; expiresAt: bigint }

function derive(seed: Uint8Array, mailboxId: Uint8Array, label: string): Uint8Array {
  return new Uint8Array(hkdfSync("sha256", seed, mailboxId, utf8(label), 32));
}
function privateKey(prefix: Uint8Array, seed: Uint8Array) { return createPrivateKey({ key: Buffer.from(concatBytes(prefix, seed)), format: "der", type: "pkcs8" }); }
function rawPublic(prefix: Uint8Array, seed: Uint8Array): Uint8Array {
  const spki = new Uint8Array(createPublicKey(privateKey(prefix, seed)).export({ format: "der", type: "spki" })); return spki.slice(-32);
}

export function createMailboxSecrets(
  followUpSeed: Uint8Array<ArrayBufferLike> = new Uint8Array(randomBytes(32)),
  mailboxId: Uint8Array<ArrayBufferLike> = new Uint8Array(randomBytes(16)),
): MailboxSecrets {
  assertBytesLength("followUpSeed", followUpSeed, 32); assertBytesLength("mailboxId", mailboxId, 16);
  const authSeed = derive(followUpSeed, mailboxId, "CYBER-CIPHER/v1/mailbox-auth");
  const hpkeSeed = derive(followUpSeed, mailboxId, "CYBER-CIPHER/v1/mailbox-hpke");
  try { return { mailboxId: mailboxId.slice(), followUpSeed: followUpSeed.slice(), authPublicKey: rawPublic(ED25519_PKCS8_PREFIX, authSeed), hpkePublicKey: rawPublic(X25519_PKCS8_PREFIX, hpkeSeed) }; }
  finally { authSeed.fill(0); hpkeSeed.fill(0); }
}

function challengeBody(value: MailboxChallenge): Uint8Array {
  return encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, value.challengeId], [3n, value.mailboxId], [4n, value.challenge], [5n, value.issuedAt], [6n, value.expiresAt]]));
}

export function signMailboxChallenge(secrets: MailboxSecrets, value: MailboxChallenge): Uint8Array {
  const seed = derive(secrets.followUpSeed, secrets.mailboxId, "CYBER-CIPHER/v1/mailbox-auth");
  try { return new Uint8Array(sign(null, signingInput("mailbox-challenge", challengeBody(value)), privateKey(ED25519_PKCS8_PREFIX, seed))); }
  finally { seed.fill(0); }
}

export function mailboxHpkePrivateKey(secrets: MailboxSecrets): Uint8Array {
  return derive(secrets.followUpSeed, secrets.mailboxId, "CYBER-CIPHER/v1/mailbox-hpke");
}

function messageAad(value: Pick<MailboxCiphertext, "mailboxId" | "messageNumber" | "direction" | "previousMessageHash" | "recipientKeyId">): Uint8Array {
  return encodeCanonical(new Map<CborKey, CborValue>([[1n, 1n], [2n, value.mailboxId], [3n, value.messageNumber], [4n, value.direction], [5n, value.previousMessageHash], [6n, value.recipientKeyId]]));
}
function messageInfo(mailboxId: Uint8Array): Uint8Array { return concatBytes(utf8("CYBER-CIPHER/v1/mailbox-message"), mailboxId); }

export async function sealMailboxMessage(input: Omit<MailboxCiphertext, "encapsulatedKey" | "ciphertext">, recipientPublicKey: Uint8Array, plaintext: Uint8Array): Promise<MailboxCiphertext> {
  const sealed = await hpkeSeal(recipientPublicKey, plaintext, messageInfo(input.mailboxId), messageAad(input));
  return { ...input, encapsulatedKey: sealed.encapsulatedKey, ciphertext: sealed.ciphertext };
}

export async function openMailboxMessage(value: MailboxCiphertext, recipientPrivateKey: Uint8Array): Promise<Uint8Array> {
  return hpkeOpen(recipientPrivateKey, { encapsulatedKey: value.encapsulatedKey, ciphertext: value.ciphertext }, messageInfo(value.mailboxId), messageAad(value));
}

export function mailboxMessageHash(value: MailboxCiphertext): Uint8Array {
  return sha256(encodeCanonical(new Map<CborKey, CborValue>([[1n, messageAad(value)], [2n, value.encapsulatedKey], [3n, value.ciphertext]])));
}

interface MailboxRecord { authPublicKey: Uint8Array; hpkePublicKey: Uint8Array; handlerKeyId: Uint8Array; messages: MailboxCiphertext[]; state: "ACTIVE" | "CLOSED" }
interface Pending { challenge: MailboxChallenge; consumed: boolean }

export class AnonymousMailboxService {
  readonly #mailboxes = new Map<string, MailboxRecord>(); readonly #pending = new Map<string, Pending>(); readonly #sessions = new Map<string, { mailbox: string; expires: number }>();
  register(secrets: Pick<MailboxSecrets, "mailboxId" | "authPublicKey" | "hpkePublicKey">, handlerKeyId: Uint8Array): void {
    const id = Buffer.from(secrets.mailboxId).toString("hex"); if (this.#mailboxes.has(id)) throw new Error("mailbox already registered");
    this.#mailboxes.set(id, { authPublicKey: assertBytesLength("mailbox auth public key", secrets.authPublicKey, 32).slice(), hpkePublicKey: assertBytesLength("mailbox HPKE public key", secrets.hpkePublicKey, 32).slice(), handlerKeyId: assertBytesLength("handler key ID", handlerKeyId, 32).slice(), messages: [], state: "ACTIVE" });
  }
  rotateHandlerKey(mailboxId: Uint8Array, handlerKeyId: Uint8Array): void { this.required(mailboxId).handlerKeyId = assertBytesLength("handler key ID", handlerKeyId, 32).slice(); }
  challenge(mailboxId: Uint8Array, now = Date.now()): MailboxChallenge {
    const mailbox = this.required(mailboxId); if (mailbox.state !== "ACTIVE") throw new Error("mailbox unavailable");
    const value = { challengeId: new Uint8Array(randomBytes(16)), mailboxId: mailboxId.slice(), challenge: new Uint8Array(randomBytes(32)), issuedAt: BigInt(now), expiresAt: BigInt(now + 60_000) };
    this.#pending.set(Buffer.from(value.challengeId).toString("hex"), { challenge: value, consumed: false }); return value;
  }
  authenticate(value: MailboxChallenge, signature: Uint8Array, now = Date.now()): string {
    const pending = this.#pending.get(Buffer.from(value.challengeId).toString("hex")); const mailbox = this.required(value.mailboxId);
    if (!pending || pending.consumed || BigInt(now) > value.expiresAt || !Buffer.from(challengeBody(pending.challenge)).equals(Buffer.from(challengeBody(value))) ||
      !verifyEd25519Raw(mailbox.authPublicKey, signingInput("mailbox-challenge", challengeBody(value)), signature)) throw new Error("mailbox authentication rejected");
    pending.consumed = true; const token = Buffer.from(randomBytes(32)).toString("base64url"); this.#sessions.set(token, { mailbox: Buffer.from(value.mailboxId).toString("hex"), expires: now + 300_000 }); return token;
  }
  messages(token: string, now = Date.now()): MailboxCiphertext[] { const mailbox = this.session(token, now); return mailbox.messages.map(copyMessage); }
  postFromUser(token: string, value: MailboxCiphertext, now = Date.now()): void { const mailbox = this.session(token, now); this.append(mailbox, value, MailboxDirection.UserToHandler); }
  postFromHandler(mailboxId: Uint8Array, value: MailboxCiphertext): void { this.append(this.required(mailboxId), value, MailboxDirection.HandlerToUser); }
  private append(mailbox: MailboxRecord, value: MailboxCiphertext, direction: MailboxDirectionValue): void {
    if (mailbox.state !== "ACTIVE" || value.direction !== direction || value.messageNumber !== BigInt(mailbox.messages.length + 1)) throw new Error("mailbox message ordering rejected");
    const recipient = direction === MailboxDirection.UserToHandler ? mailbox.handlerKeyId : sha256(mailbox.hpkePublicKey);
    if (!Buffer.from(recipient).equals(Buffer.from(value.recipientKeyId))) throw new Error("mailbox recipient key rejected");
    const expected = mailbox.messages.length === 0 ? new Uint8Array(32) : mailboxMessageHash(mailbox.messages.at(-1)!);
    if (!Buffer.from(expected).equals(Buffer.from(value.previousMessageHash))) throw new Error("mailbox message chain rejected"); mailbox.messages.push(copyMessage(value));
  }
  private required(id: Uint8Array): MailboxRecord { const value = this.#mailboxes.get(Buffer.from(id).toString("hex")); if (!value) throw new Error("mailbox unavailable"); return value; }
  private session(token: string, now: number): MailboxRecord { const value = this.#sessions.get(token); if (!value || now > value.expires) throw new Error("mailbox session rejected"); const mailbox = this.#mailboxes.get(value.mailbox); if (!mailbox) throw new Error("mailbox unavailable"); return mailbox; }
}
function copyMessage(value: MailboxCiphertext): MailboxCiphertext { return { ...value, mailboxId: value.mailboxId.slice(), previousMessageHash: value.previousMessageHash.slice(), recipientKeyId: value.recipientKeyId.slice(), encapsulatedKey: value.encapsulatedKey.slice(), ciphertext: value.ciphertext.slice() }; }

export function sealMailboxRecoveryBundle(recoverySeed: Uint8Array, tenantId: Uint8Array, recoveryId: Uint8Array, generation: bigint, secrets: MailboxSecrets): RecoveryBackupCiphertext {
  const plaintext = encodeCanonical(new Map<CborKey, CborValue>([[1n, secrets.mailboxId], [2n, secrets.followUpSeed]]));
  return sealRecoveryBackup(recoverySeed, { tenantId, recoveryId, purpose: 2n, generation }, plaintext);
}
export function openMailboxRecoveryBundle(recoverySeed: Uint8Array, tenantId: Uint8Array, recoveryId: Uint8Array, generation: bigint, value: RecoveryBackupCiphertext): MailboxSecrets {
  const decoded = decodeCanonical(openRecoveryBackup(recoverySeed, { tenantId, recoveryId, purpose: 2n, generation }, value));
  if (!(decoded instanceof Map) || !(decoded.get(1n) instanceof Uint8Array) || !(decoded.get(2n) instanceof Uint8Array)) throw new Error("mailbox recovery bundle invalid");
  return createMailboxSecrets(decoded.get(2n) as Uint8Array, decoded.get(1n) as Uint8Array);
}
