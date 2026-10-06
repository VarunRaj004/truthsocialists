import { assertBytesLength, encodeCanonical, signingInput, unwrapHandlerDek, verifyEd25519Raw, wrapHandlerDek, type CborKey, type CborValue, type HandlerDekContext, type WrappedHandlerDek } from "@cyber-cipher/protocol-core";
import type { ActionSigner } from "./audit.js";
import type { StaffCredential } from "./webauthn.js";
import type { HandlerWorkflow } from "./workflow.js";

export interface HandlerKeyVersion { organizationId: string; keyId: Uint8Array; publicKey: Uint8Array; privateKey?: Uint8Array }
export interface DekTransfer { oldOrganizationId: string; newOrganizationId: string; oldKeyId: Uint8Array; newKeyId: Uint8Array; newEnvelope: WrappedHandlerDek }
export interface SignedTransferRecord { complaintId: string; ciphertextHash: Uint8Array; actorId: string; reasonCode: string; occurredAt: bigint; transfer: DekTransfer; recordCbor: Uint8Array; signature: Uint8Array }

function encodeTransferRecord(input: Omit<SignedTransferRecord, "recordCbor" | "signature">): Uint8Array {
  return encodeCanonical(new Map<CborKey, CborValue>([
    [1n, 1n], [2n, input.complaintId], [3n, input.ciphertextHash], [4n, input.transfer.oldOrganizationId],
    [5n, input.transfer.newOrganizationId], [6n, input.transfer.oldKeyId], [7n, input.transfer.newKeyId],
    [8n, input.actorId], [9n, input.reasonCode], [10n, input.occurredAt],
  ]));
}

export async function signTransferRecord(signer: ActionSigner, input: Omit<SignedTransferRecord, "recordCbor" | "signature">): Promise<SignedTransferRecord> {
  const recordCbor = encodeTransferRecord(input);
  const signature = assertBytesLength("transfer signature", await signer.sign(signingInput("dek-transfer", recordCbor)), 64);
  return { ...input, recordCbor, signature };
}

export function verifyTransferRecord(value: SignedTransferRecord, publicKey: Uint8Array): boolean {
  const expected = encodeTransferRecord(value);
  return Buffer.from(expected).equals(Buffer.from(value.recordCbor)) && verifyEd25519Raw(publicKey, signingInput("dek-transfer", value.recordCbor), value.signature);
}

export class HandlerKeyVault {
  readonly #keys = new Map<string, HandlerKeyVersion>();
  register(value: HandlerKeyVersion): void { this.#keys.set(Buffer.from(value.keyId).toString("hex"), { ...value, keyId: value.keyId.slice(), publicKey: value.publicKey.slice(), ...(value.privateKey ? { privateKey: value.privateKey.slice() } : {}) }); }

  async withUnwrappedDek<T>(actor: StaffCredential, keyId: Uint8Array, envelope: WrappedHandlerDek, context: HandlerDekContext, operation: (dek: Uint8Array) => Promise<T>): Promise<T> {
    const key = this.#keys.get(Buffer.from(keyId).toString("hex"));
    if (!key?.privateKey || key.organizationId !== actor.organizationId) throw new Error("handler key access denied");
    const dek = await unwrapHandlerDek(key.privateKey, envelope, context);
    try { return await operation(dek); } finally { dek.fill(0); }
  }

  async rewrap(actor: StaffCredential, oldKeyId: Uint8Array, newKeyId: Uint8Array, envelope: WrappedHandlerDek, oldContext: HandlerDekContext, newContext: HandlerDekContext): Promise<DekTransfer> {
    if (!actor.roles.has("SUPERVISOR")) throw new Error("supervisor role required for transfer");
    const oldKey = this.#keys.get(Buffer.from(oldKeyId).toString("hex"));
    const newKey = this.#keys.get(Buffer.from(newKeyId).toString("hex"));
    if (!oldKey?.privateKey || !newKey || actor.organizationId !== oldKey.organizationId) throw new Error("DEK transfer denied");
    if (!Buffer.from(newContext.handlerKeyId).equals(Buffer.from(newKey.keyId))) throw new Error("destination handler key mismatch");
    const dek = await unwrapHandlerDek(oldKey.privateKey, envelope, oldContext);
    try {
      const newEnvelope = await wrapHandlerDek(newKey.publicKey, assertBytesLength("complaint DEK", dek, 32), newContext);
      return { oldOrganizationId: oldKey.organizationId, newOrganizationId: newKey.organizationId, oldKeyId: oldKey.keyId.slice(), newKeyId: newKey.keyId.slice(), newEnvelope };
    } finally { dek.fill(0); }
  }
}

export async function withAssignedCaseDek<T>(
  workflow: HandlerWorkflow,
  vault: HandlerKeyVault,
  actor: StaffCredential,
  complaintId: string,
  envelope: WrappedHandlerDek,
  context: HandlerDekContext,
  operation: (dek: Uint8Array) => Promise<T>,
  now = Date.now(),
): Promise<T> {
  const assignedCase = await workflow.openCase(actor, complaintId, now);
  if (!Buffer.from(assignedCase.handlerKeyId).equals(Buffer.from(context.handlerKeyId))) throw new Error("case handler key mismatch");
  return vault.withUnwrappedDek(actor, assignedCase.handlerKeyId, envelope, context, operation);
}
