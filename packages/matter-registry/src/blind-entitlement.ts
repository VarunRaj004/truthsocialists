import { webcrypto } from "node:crypto";
import { RSABSSA } from "@cloudflare/blindrsa-ts";
import {
  assertBytesLength,
  encodeCanonical,
  entitlementMessage,
  type EntitlementMessageInput,
} from "@cyber-cipher/protocol-core";
import { validateMatterPrivateKey, validateMatterPublicKey } from "./key-material.js";

const RSA_BYTES = 384;
const RANDOMIZER_BYTES = 32;
const suite = RSABSSA.SHA384.PSS.Randomized();

export interface BlindEntitlementClientState {
  entitlement: EntitlementMessageInput;
  messageRandomizer: Uint8Array;
  inverse: Uint8Array;
  blindedMessage: Uint8Array;
}

export interface BlindEntitlementToken {
  entitlement: EntitlementMessageInput;
  messageRandomizer: Uint8Array;
  signature: Uint8Array;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

async function importPublicKey(spkiDer: Uint8Array): Promise<CryptoKey> {
  validateMatterPublicKey(spkiDer);
  return (await webcrypto.subtle.importKey(
    "spki",
    spkiDer.slice().buffer,
    { name: "RSA-PSS", hash: "SHA-384" },
    true,
    ["verify"],
  )) as unknown as CryptoKey;
}

async function importPrivateKey(pkcs8Der: Uint8Array): Promise<CryptoKey> {
  return (await webcrypto.subtle.importKey(
    "pkcs8",
    pkcs8Der.slice().buffer,
    { name: "RSA-PSS", hash: "SHA-384" },
    true,
    ["sign"],
  )) as unknown as CryptoKey;
}

function encodedEntitlement(input: EntitlementMessageInput): Uint8Array {
  return encodeCanonical(entitlementMessage(input));
}

function cloneEntitlement(input: EntitlementMessageInput): EntitlementMessageInput {
  return {
    matterKeyId: input.matterKeyId.slice(),
    serial: input.serial.slice(),
    personCommitment: input.personCommitment.slice(),
  };
}

export async function prepareBlindEntitlement(
  publicKeySpkiDer: Uint8Array,
  entitlement: EntitlementMessageInput,
): Promise<BlindEntitlementClientState> {
  const derivedKeyId = validateMatterPublicKey(publicKeySpkiDer);
  if (!equalBytes(derivedKeyId, assertBytesLength("matterKeyId", entitlement.matterKeyId, 32))) {
    throw new Error("entitlement matterKeyId does not match the RSA public key");
  }
  const message = encodedEntitlement(entitlement);
  const prepared = suite.prepare(message);
  if (prepared.length !== message.length + RANDOMIZER_BYTES) {
    throw new Error("RFC 9474 randomized preparation returned an unexpected length");
  }
  const publicKey = await importPublicKey(publicKeySpkiDer);
  const blinded = await suite.blind(publicKey, prepared);
  assertBytesLength("blinded entitlement", blinded.blindedMsg, RSA_BYTES);
  assertBytesLength("blinding inverse", blinded.inv, RSA_BYTES);
  return {
    entitlement: cloneEntitlement(entitlement),
    messageRandomizer: prepared.slice(0, RANDOMIZER_BYTES),
    inverse: blinded.inv.slice(),
    blindedMessage: blinded.blindedMsg.slice(),
  };
}

export async function blindSignEntitlement(
  privateKeyPkcs8Der: Uint8Array,
  blindedMessage: Uint8Array,
): Promise<Uint8Array> {
  assertBytesLength("blinded entitlement", blindedMessage, RSA_BYTES);
  validateMatterPrivateKey(privateKeyPkcs8Der);
  const privateKey = await importPrivateKey(privateKeyPkcs8Der);
  const signature = await suite.blindSign(privateKey, blindedMessage);
  return assertBytesLength("blind entitlement signature", signature, RSA_BYTES).slice();
}

export async function finalizeBlindEntitlement(
  publicKeySpkiDer: Uint8Array,
  state: BlindEntitlementClientState,
  blindSignature: Uint8Array,
): Promise<BlindEntitlementToken> {
  assertBytesLength("message randomizer", state.messageRandomizer, RANDOMIZER_BYTES);
  assertBytesLength("blinding inverse", state.inverse, RSA_BYTES);
  assertBytesLength("blind entitlement signature", blindSignature, RSA_BYTES);
  const publicKey = await importPublicKey(publicKeySpkiDer);
  const prepared = new Uint8Array(RANDOMIZER_BYTES + encodedEntitlement(state.entitlement).length);
  prepared.set(state.messageRandomizer);
  prepared.set(encodedEntitlement(state.entitlement), RANDOMIZER_BYTES);
  const signature = await suite.finalize(publicKey, prepared, blindSignature, state.inverse);
  return {
    entitlement: cloneEntitlement(state.entitlement),
    messageRandomizer: state.messageRandomizer.slice(),
    signature: assertBytesLength("entitlement signature", signature, RSA_BYTES).slice(),
  };
}

export async function verifyBlindEntitlement(
  publicKeySpkiDer: Uint8Array,
  token: BlindEntitlementToken,
): Promise<boolean> {
  const derivedKeyId = validateMatterPublicKey(publicKeySpkiDer);
  if (!equalBytes(derivedKeyId, token.entitlement.matterKeyId)) return false;
  try {
    const message = encodedEntitlement(token.entitlement);
    const prepared = new Uint8Array(RANDOMIZER_BYTES + message.length);
    prepared.set(assertBytesLength("message randomizer", token.messageRandomizer, RANDOMIZER_BYTES));
    prepared.set(message, RANDOMIZER_BYTES);
    const publicKey = await importPublicKey(publicKeySpkiDer);
    return await suite.verify(
      publicKey,
      assertBytesLength("entitlement signature", token.signature, RSA_BYTES),
      prepared,
    );
  } catch {
    return false;
  }
}
