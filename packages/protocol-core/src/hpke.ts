import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { concatBytes, unsignedBigEndian, utf8 } from "./bytes.js";
import { encodeCanonical } from "./cbor.js";
import { handlerDekAad } from "./objects.js";
import { assertBytesLength, assertUint } from "./validation.js";

export const HPKE_KEM_ID = 0x0020;
export const HPKE_KDF_ID = 0x0001;
export const HPKE_AEAD_ID = 0x0002;
export const HPKE_X25519_KEY_BYTES = 32;
export const HPKE_ENCAPSULATED_KEY_BYTES = 32;
export const HPKE_WRAPPED_DEK_BYTES = 48;

const UINT32_MAX = 0xffff_ffffn;
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

export interface HpkeRawKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function generateHpkeX25519KeyPair(): Promise<HpkeRawKeyPair> {
  const pair = await suite.kem.generateKeyPair();
  return {
    publicKey: new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey)),
    privateKey: new Uint8Array(await suite.kem.serializePrivateKey(pair.privateKey)),
  };
}

export function handlerDekInfo(matterId: Uint8Array, matterVersion: bigint): Uint8Array {
  assertBytesLength("matterId", matterId, 16);
  assertUint("matterVersion", matterVersion, UINT32_MAX);
  return concatBytes(
    utf8("CYBER-CIPHER/v1/handler-dek"),
    matterId,
    unsignedBigEndian(matterVersion, 4),
  );
}

export interface HandlerDekContext {
  matterId: Uint8Array;
  matterVersion: bigint;
  complaintId: Uint8Array;
  complaintCommitment: Uint8Array;
  handlerKeyId: Uint8Array;
}

function contextBytes(context: HandlerDekContext): { info: Uint8Array; aad: Uint8Array } {
  return {
    info: handlerDekInfo(context.matterId, context.matterVersion),
    aad: encodeCanonical(handlerDekAad(context)),
  };
}

export interface WrappedHandlerDek {
  kemId: typeof HPKE_KEM_ID;
  kdfId: typeof HPKE_KDF_ID;
  aeadId: typeof HPKE_AEAD_ID;
  encapsulatedKey: Uint8Array;
  wrappedDek: Uint8Array;
}

export async function wrapHandlerDek(
  recipientPublicKey: Uint8Array,
  dek: Uint8Array,
  context: HandlerDekContext,
): Promise<WrappedHandlerDek> {
  assertBytesLength("handler X25519 public key", recipientPublicKey, HPKE_X25519_KEY_BYTES);
  assertBytesLength("complaint DEK", dek, 32);
  const publicKey = await suite.kem.deserializePublicKey(recipientPublicKey);
  const { info, aad } = contextBytes(context);
  const sealed = await suite.seal({ recipientPublicKey: publicKey, info }, dek, aad);
  const encapsulatedKey = new Uint8Array(sealed.enc);
  const wrappedDek = new Uint8Array(sealed.ct);
  assertBytesLength("HPKE encapsulated key", encapsulatedKey, HPKE_ENCAPSULATED_KEY_BYTES);
  assertBytesLength("HPKE wrapped DEK", wrappedDek, HPKE_WRAPPED_DEK_BYTES);
  return {
    kemId: HPKE_KEM_ID,
    kdfId: HPKE_KDF_ID,
    aeadId: HPKE_AEAD_ID,
    encapsulatedKey,
    wrappedDek,
  };
}

export async function unwrapHandlerDek(
  recipientPrivateKey: Uint8Array,
  envelope: WrappedHandlerDek,
  context: HandlerDekContext,
): Promise<Uint8Array> {
  assertBytesLength("handler X25519 private key", recipientPrivateKey, HPKE_X25519_KEY_BYTES);
  if (
    envelope.kemId !== HPKE_KEM_ID ||
    envelope.kdfId !== HPKE_KDF_ID ||
    envelope.aeadId !== HPKE_AEAD_ID
  ) {
    throw new TypeError("unsupported HPKE suite identifiers");
  }
  assertBytesLength(
    "HPKE encapsulated key",
    envelope.encapsulatedKey,
    HPKE_ENCAPSULATED_KEY_BYTES,
  );
  assertBytesLength("HPKE wrapped DEK", envelope.wrappedDek, HPKE_WRAPPED_DEK_BYTES);
  const privateKey = await suite.kem.deserializePrivateKey(recipientPrivateKey);
  const { info, aad } = contextBytes(context);
  try {
    const plaintext = await suite.open(
      { recipientKey: privateKey, enc: envelope.encapsulatedKey, info },
      envelope.wrappedDek,
      aad,
    );
    return assertBytesLength("unwrapped complaint DEK", new Uint8Array(plaintext), 32);
  } catch {
    throw new Error("HPKE DEK authentication failed");
  }
}
