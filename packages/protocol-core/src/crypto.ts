import { createHash, createPublicKey, verify } from "node:crypto";
import { BN254_SCALAR_MODULUS, PROTOCOL_PREFIX, type PoseidonDomainLabel } from "./constants.js";
import {
  base64UrlNoPadding,
  concatBytes,
  parseUnsignedBigEndian,
  unsignedBigEndian,
  utf8,
} from "./bytes.js";
import { assertBytesLength } from "./validation.js";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const LABEL_PATTERN = /^[a-z0-9-]+$/;

function assertLabel(label: string): void {
  if (!LABEL_PATTERN.test(label)) {
    throw new TypeError("protocol labels must contain only lowercase ASCII letters, digits, and hyphens");
  }
}

export function sha256(...parts: readonly Uint8Array[]): Uint8Array {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}

export function frame(label: string, ...parts: readonly Uint8Array[]): Uint8Array {
  assertLabel(label);
  const framed: Uint8Array[] = [utf8(`${PROTOCOL_PREFIX}${label}\0`)];
  for (const part of parts) {
    framed.push(unsignedBigEndian(BigInt(part.length), 8), part);
  }
  return concatBytes(...framed);
}

export function hashToField(label: string, ...parts: readonly Uint8Array[]): bigint {
  return parseUnsignedBigEndian(sha256(frame(label, ...parts))) % BN254_SCALAR_MODULUS;
}

export function poseidonDomain(label: PoseidonDomainLabel): bigint {
  return parseUnsignedBigEndian(sha256(utf8(`${PROTOCOL_PREFIX}poseidon/${label}`))) % BN254_SCALAR_MODULUS;
}

export function signingInput(objectType: string, unsignedObjectCbor: Uint8Array): Uint8Array {
  assertLabel(objectType);
  return concatBytes(utf8(`${PROTOCOL_PREFIX}${objectType}\0`), unsignedObjectCbor);
}

export function keyIdFromSpkiDer(spkiDer: Uint8Array): Uint8Array {
  if (spkiDer.length === 0) throw new TypeError("SPKI DER must not be empty");
  return sha256(spkiDer);
}

export function keyIdText(spkiDer: Uint8Array): string {
  return base64UrlNoPadding(keyIdFromSpkiDer(spkiDer));
}

export function ed25519SpkiFromRaw(publicKey: Uint8Array): Uint8Array {
  assertBytesLength("Ed25519 public key", publicKey, 32);
  return concatBytes(ED25519_SPKI_PREFIX, publicKey);
}

export function verifyEd25519Raw(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  assertBytesLength("Ed25519 public key", publicKey, 32);
  assertBytesLength("Ed25519 signature", signature, 64);
  const key = createPublicKey({
    key: Buffer.from(ed25519SpkiFromRaw(publicKey)),
    format: "der",
    type: "spki",
  });
  return verify(null, Buffer.from(message), key, Buffer.from(signature));
}
