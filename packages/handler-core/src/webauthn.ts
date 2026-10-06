import { createPublicKey, randomBytes, verify } from "node:crypto";
import { concatBytes, sha256 } from "@cyber-cipher/protocol-core";

export type StaffRole = "TRIAGE" | "HANDLER" | "SUPERVISOR" | "AUDITOR";

export interface StaffCredential {
  staffId: string;
  organizationId: string;
  roles: ReadonlySet<StaffRole>;
  credentialId: Uint8Array;
  publicKeySpkiDer: Uint8Array;
  signCount: number;
}

export interface WebAuthnAssertion {
  credentialId: Uint8Array;
  clientDataJson: Uint8Array;
  authenticatorData: Uint8Array;
  signature: Uint8Array;
}

interface PendingChallenge { value: Uint8Array; staffId: string; expiresAt: number }

function b64url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
function equal(left: Uint8Array, right: Uint8Array): boolean { return Buffer.from(left).equals(Buffer.from(right)); }

export class WebAuthnStaffRegistry {
  readonly #credentials = new Map<string, StaffCredential>();
  readonly #challenges = new Map<string, PendingChallenge>();

  constructor(readonly rpId: string, readonly origin: string, readonly challengeLifetimeMs = 60_000) {
    if (!rpId || !origin.startsWith("https://")) throw new TypeError("WebAuthn requires an RP ID and HTTPS origin");
  }

  enroll(input: StaffCredential): void {
    if (input.roles.size === 0) throw new TypeError("staff must have at least one role");
    const id = b64url(input.credentialId);
    if (this.#credentials.has(id)) throw new Error("WebAuthn credential is already enrolled");
    createPublicKey({ key: Buffer.from(input.publicKeySpkiDer), format: "der", type: "spki" });
    this.#credentials.set(id, { ...input, roles: new Set(input.roles), credentialId: input.credentialId.slice(), publicKeySpkiDer: input.publicKeySpkiDer.slice() });
  }

  challenge(staffId: string, now = Date.now()): Uint8Array {
    if (![...this.#credentials.values()].some((item) => item.staffId === staffId)) throw new Error("staff credential not enrolled");
    const value = new Uint8Array(randomBytes(32));
    this.#challenges.set(b64url(value), { value, staffId, expiresAt: now + this.challengeLifetimeMs });
    return value.slice();
  }

  authenticate(assertion: WebAuthnAssertion, now = Date.now()): StaffCredential {
    const credential = this.#credentials.get(b64url(assertion.credentialId));
    if (!credential) throw new Error("WebAuthn assertion rejected");
    if (assertion.authenticatorData.length < 37) throw new Error("WebAuthn assertion rejected");
    let client: { type?: unknown; challenge?: unknown; origin?: unknown };
    try { client = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(assertion.clientDataJson)); }
    catch { throw new Error("WebAuthn assertion rejected"); }
    if (client.type !== "webauthn.get" || typeof client.challenge !== "string" || client.origin !== this.origin) throw new Error("WebAuthn assertion rejected");
    const pending = this.#challenges.get(client.challenge);
    if (!pending || pending.staffId !== credential.staffId || now > pending.expiresAt) throw new Error("WebAuthn assertion rejected");
    if (!equal(assertion.authenticatorData.slice(0, 32), sha256(new TextEncoder().encode(this.rpId)))) throw new Error("WebAuthn assertion rejected");
    const flags = assertion.authenticatorData[32]!;
    if ((flags & 0x05) !== 0x05) throw new Error("WebAuthn user verification required");
    const signCount = new DataView(assertion.authenticatorData.buffer, assertion.authenticatorData.byteOffset + 33, 4).getUint32(0);
    if (credential.signCount !== 0 && signCount <= credential.signCount) throw new Error("WebAuthn authenticator counter replay");
    const key = createPublicKey({ key: Buffer.from(credential.publicKeySpkiDer), format: "der", type: "spki" });
    if (!verify("sha256", Buffer.from(concatBytes(assertion.authenticatorData, sha256(assertion.clientDataJson))), key, assertion.signature)) throw new Error("WebAuthn assertion rejected");
    this.#challenges.delete(client.challenge);
    credential.signCount = signCount;
    return { ...credential, roles: new Set(credential.roles), credentialId: credential.credentialId.slice(), publicKeySpkiDer: credential.publicKeySpkiDer.slice() };
  }
}
