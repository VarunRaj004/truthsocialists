import {
  assertBytesLength,
  decodeCanonical,
  ed25519SpkiFromRaw,
  encodeCanonical,
  keyIdFromSpkiDer,
  sha256,
  signedObject,
  signingInput,
  treeHeadBody,
  verifyEd25519Raw,
  verifyTreeHead,
  type CborKey,
  type CborValue,
  type TreeHeadBodyInput,
} from "@cyber-cipher/protocol-core";

export interface Ed25519Signer {
  publicKey: Uint8Array;
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface SignedTreeHead {
  signedTreeHeadCbor: Uint8Array;
  treeHeadHash: Uint8Array;
  body: TreeHeadBodyInput;
}

export interface WitnessSignature {
  witnessKeyId: Uint8Array;
  signature: Uint8Array;
}

export interface FinalizedTreeHead extends SignedTreeHead {
  witnessSignatures: WitnessSignature[];
  final: boolean;
}

export function keyIdForRawEd25519(publicKey: Uint8Array): Uint8Array {
  return keyIdFromSpkiDer(ed25519SpkiFromRaw(publicKey));
}

export async function signTreeHead(
  signer: Ed25519Signer,
  input: Omit<TreeHeadBodyInput, "logKeyId">,
): Promise<SignedTreeHead> {
  const body: TreeHeadBodyInput = { ...input, logKeyId: keyIdForRawEd25519(signer.publicKey) };
  const unsigned = treeHeadBody(body);
  const signature = assertBytesLength(
    "tree-head signature",
    await signer.sign(signingInput("tree-head", encodeCanonical(unsigned))),
    64,
  );
  const signedTreeHeadCbor = encodeCanonical(signedObject(unsigned, signature));
  return { signedTreeHeadCbor, treeHeadHash: sha256(signedTreeHeadCbor), body };
}

export function witnessSigningInput(treeHeadHash: Uint8Array): Uint8Array {
  return signingInput("witness-tree-head", assertBytesLength("tree-head hash", treeHeadHash, 32));
}

export async function signWitness(signer: Ed25519Signer, treeHeadHash: Uint8Array): Promise<WitnessSignature> {
  return {
    witnessKeyId: keyIdForRawEd25519(signer.publicKey),
    signature: assertBytesLength("witness signature", await signer.sign(witnessSigningInput(treeHeadHash)), 64),
  };
}

export function verifyWitnessSignature(
  value: WitnessSignature,
  treeHeadHash: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  const expected = keyIdForRawEd25519(publicKey);
  return Buffer.from(expected).equals(Buffer.from(value.witnessKeyId)) &&
    verifyEd25519Raw(publicKey, witnessSigningInput(treeHeadHash), value.signature);
}

export function encodeFinalizedTreeHead(value: FinalizedTreeHead): Uint8Array {
  const witnesses: CborValue[] = value.witnessSignatures.map((item) => new Map<CborKey, CborValue>([
    [1n, assertBytesLength("witness key ID", item.witnessKeyId, 32)],
    [2n, assertBytesLength("witness signature", item.signature, 64)],
  ]));
  return encodeCanonical(new Map<CborKey, CborValue>([
    [1n, value.signedTreeHeadCbor],
    [2n, witnesses],
  ]));
}

export function decodeFinalizedTreeHead(encoded: Uint8Array, logPublicKey: Uint8Array): FinalizedTreeHead {
  const map = decodeCanonical(encoded);
  if (!(map instanceof Map) || map.size !== 2 || !map.has(1n) || !map.has(2n)) throw new TypeError("invalid finalized tree head");
  const signed = map.get(1n);
  const rawWitnesses = map.get(2n);
  if (!(signed instanceof Uint8Array) || !Array.isArray(rawWitnesses)) throw new TypeError("invalid finalized tree head fields");
  const body = verifyTreeHead(signed, logPublicKey);
  const witnessSignatures = rawWitnesses.map((item): WitnessSignature => {
    if (!(item instanceof Map) || item.size !== 2) throw new TypeError("invalid witness signature entry");
    const witnessKeyId = item.get(1n);
    const signature = item.get(2n);
    if (!(witnessKeyId instanceof Uint8Array) || !(signature instanceof Uint8Array)) throw new TypeError("invalid witness signature fields");
    return {
      witnessKeyId: assertBytesLength("witness key ID", witnessKeyId, 32),
      signature: assertBytesLength("witness signature", signature, 64),
    };
  });
  return { signedTreeHeadCbor: signed, treeHeadHash: sha256(signed), body, witnessSignatures, final: false };
}
