import { assertBytesLength, encodeCanonical, sha256, signingInput, verifyEd25519Raw, type CborKey, type CborValue } from "@cyber-cipher/protocol-core";

export interface ActionSigner { publicKey: Uint8Array; sign(message: Uint8Array): Uint8Array | Promise<Uint8Array> }
export interface AccessEvent { complaintId: string; actorId: string; action: string; decision: "ALLOWED" | "DENIED"; reasonCode: string; occurredAt: bigint; eventCbor: Uint8Array; signature: Uint8Array }

function encodeAccessEvent(publicKey: Uint8Array, input: Omit<AccessEvent, "eventCbor" | "signature">): Uint8Array {
  return encodeCanonical(new Map<CborKey, CborValue>([
    [1n, 1n], [2n, input.complaintId], [3n, input.actorId], [4n, input.action],
    [5n, input.decision === "ALLOWED" ? 1n : 2n], [6n, input.reasonCode], [7n, input.occurredAt],
    [8n, sha256(publicKey)],
  ]));
}

export async function signedAccessEvent(signer: ActionSigner, input: Omit<AccessEvent, "eventCbor" | "signature">): Promise<AccessEvent> {
  const eventCbor = encodeAccessEvent(signer.publicKey, input);
  const signature = assertBytesLength("access-event signature", await signer.sign(signingInput("case-access", eventCbor)), 64);
  return { ...input, eventCbor, signature };
}

export function verifyAccessEvent(event: AccessEvent, publicKey: Uint8Array): boolean {
  const expected = encodeAccessEvent(publicKey, event);
  return Buffer.from(expected).equals(Buffer.from(event.eventCbor)) && verifyEd25519Raw(publicKey, signingInput("case-access", event.eventCbor), event.signature);
}
