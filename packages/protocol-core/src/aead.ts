import { createCipheriv, createDecipheriv } from "node:crypto";
import { concatBytes } from "./bytes.js";
import { assertBytesLength } from "./validation.js";

export const AES_256_GCM_KEY_BYTES = 32;
export const AES_GCM_NONCE_BYTES = 12;
export const AES_GCM_TAG_BYTES = 16;

export interface Aes256GcmSealInput {
  key: Uint8Array;
  nonce: Uint8Array;
  plaintext: Uint8Array;
  aad: Uint8Array;
}

export interface Aes256GcmCiphertext {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export function aes256GcmSeal(input: Aes256GcmSealInput): Aes256GcmCiphertext {
  assertBytesLength("AES-256-GCM key", input.key, AES_256_GCM_KEY_BYTES);
  assertBytesLength("AES-256-GCM nonce", input.nonce, AES_GCM_NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", input.key, input.nonce, {
    authTagLength: AES_GCM_TAG_BYTES,
  });
  cipher.setAAD(input.aad);
  const ciphertext = concatBytes(cipher.update(input.plaintext), cipher.final());
  return { ciphertext, tag: new Uint8Array(cipher.getAuthTag()) };
}

export interface Aes256GcmOpenInput extends Aes256GcmCiphertext {
  key: Uint8Array;
  nonce: Uint8Array;
  aad: Uint8Array;
}

export function aes256GcmOpen(input: Aes256GcmOpenInput): Uint8Array {
  assertBytesLength("AES-256-GCM key", input.key, AES_256_GCM_KEY_BYTES);
  assertBytesLength("AES-256-GCM nonce", input.nonce, AES_GCM_NONCE_BYTES);
  assertBytesLength("AES-256-GCM tag", input.tag, AES_GCM_TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", input.key, input.nonce, {
    authTagLength: AES_GCM_TAG_BYTES,
  });
  decipher.setAAD(input.aad);
  decipher.setAuthTag(input.tag);
  try {
    return concatBytes(decipher.update(input.ciphertext), decipher.final());
  } catch {
    throw new Error("AES-256-GCM authentication failed");
  }
}
