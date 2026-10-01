import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import {
  aes256GcmOpen,
  aes256GcmSeal,
  assertBytesLength,
  assertExactIntegerKeys,
  assertUint,
  decodeCanonical,
  encodeCanonical,
  integerMap,
  keyIdFromSpkiDer,
  type CborKey,
  type CborValue,
} from "@cyber-cipher/protocol-core";

const UINT32_MAX = 0xffff_ffffn;
const RSA_BITS = 3072;
const RSA_EXPONENT = 65_537n;
const PSS_SALT_BYTES = 48;

export interface MatterRsaKeyMaterial {
  matterKeyId: Uint8Array;
  publicKeySpkiDer: Uint8Array;
  privateKeyPkcs8Der: Uint8Array;
}

export interface MatterKeyContext {
  tenantId: Uint8Array;
  matterId: Uint8Array;
  matterVersion: bigint;
  matterKeyId: Uint8Array;
  kekKeyId: Uint8Array;
}

export interface EncryptMatterPrivateKeyInput extends MatterKeyContext {
  privateKeyPkcs8Der: Uint8Array;
  kek: Uint8Array;
  nonce?: Uint8Array;
}

export interface DecryptMatterPrivateKeyInput extends MatterKeyContext {
  encryptedKeyFile: Uint8Array;
  kek: Uint8Array;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function assertRsaPssProfile(key: KeyObject): void {
  if (key.asymmetricKeyType !== "rsa-pss") {
    throw new TypeError("matter key must use an RSASSA-PSS SubjectPublicKeyInfo");
  }
  const details = key.asymmetricKeyDetails;
  if (
    details?.modulusLength !== RSA_BITS ||
    details.publicExponent !== RSA_EXPONENT ||
    details.hashAlgorithm !== "sha384" ||
    details.mgf1HashAlgorithm !== "sha384" ||
    details.saltLength !== PSS_SALT_BYTES
  ) {
    throw new TypeError(
      "matter key must be RSA-3072/PSS with exponent 65537, SHA-384, MGF1-SHA384, and 48-byte salt",
    );
  }
}

export function validateMatterPublicKey(publicKeySpkiDer: Uint8Array): Uint8Array {
  if (!(publicKeySpkiDer instanceof Uint8Array) || publicKeySpkiDer.length === 0) {
    throw new TypeError("matter public key SPKI must not be empty");
  }
  const key = createPublicKey({ key: Buffer.from(publicKeySpkiDer), format: "der", type: "spki" });
  assertRsaPssProfile(key);
  const canonical = new Uint8Array(key.export({ format: "der", type: "spki" }));
  if (!equalBytes(canonical, publicKeySpkiDer)) {
    throw new TypeError("matter public key SPKI is not canonical DER");
  }
  return keyIdFromSpkiDer(canonical);
}

export function generateMatterRsaKeyMaterial(): MatterRsaKeyMaterial {
  // Node supports rsa-pss here; the current @types/node overload omits it.
  const algorithm = "rsa-pss" as "rsa";
  const options = {
    modulusLength: RSA_BITS,
    publicExponent: Number(RSA_EXPONENT),
    hashAlgorithm: "sha384",
    mgf1HashAlgorithm: "sha384",
    saltLength: PSS_SALT_BYTES,
  };
  const pair = generateKeyPairSync(algorithm, options);
  const publicKeySpkiDer = new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" }));
  const privateKeyPkcs8Der = new Uint8Array(pair.privateKey.export({ format: "der", type: "pkcs8" }));
  return {
    matterKeyId: validateMatterPublicKey(publicKeySpkiDer),
    publicKeySpkiDer,
    privateKeyPkcs8Der,
  };
}

function keyAad(context: MatterKeyContext): Uint8Array {
  assertBytesLength("tenantId", context.tenantId, 16);
  assertBytesLength("matterId", context.matterId, 16);
  assertUint("matterVersion", context.matterVersion, UINT32_MAX);
  if (context.matterVersion === 0n) throw new RangeError("matterVersion must be positive");
  assertBytesLength("matterKeyId", context.matterKeyId, 32);
  assertBytesLength("KEK key ID", context.kekKeyId, 32);
  return encodeCanonical(
    integerMap([
      [1, 1n],
      [2, context.tenantId],
      [3, context.matterId],
      [4, context.matterVersion],
      [5, context.matterKeyId],
      [6, context.kekKeyId],
    ]),
  );
}

function privateKeyId(privateKeyPkcs8Der: Uint8Array): Uint8Array {
  const privateKey = createPrivateKey({
    key: Buffer.from(privateKeyPkcs8Der),
    format: "der",
    type: "pkcs8",
  });
  assertRsaPssProfile(privateKey);
  const publicKey = createPublicKey(privateKey);
  const spki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
  return validateMatterPublicKey(spki);
}

export function encryptMatterPrivateKey(input: EncryptMatterPrivateKeyInput): Uint8Array {
  assertBytesLength("secret-manager KEK", input.kek, 32);
  if (!equalBytes(privateKeyId(input.privateKeyPkcs8Der), input.matterKeyId)) {
    throw new Error("private key does not match matterKeyId");
  }
  const nonce = input.nonce ?? new Uint8Array(randomBytes(12));
  assertBytesLength("private-key envelope nonce", nonce, 12);
  const sealed = aes256GcmSeal({
    key: input.kek,
    nonce,
    plaintext: input.privateKeyPkcs8Der,
    aad: keyAad(input),
  });
  return encodeCanonical(
    integerMap([
      [1, 1n],
      [2, input.matterKeyId],
      [3, input.kekKeyId],
      [4, nonce],
      [5, sealed.ciphertext],
      [6, sealed.tag],
    ]),
  );
}

function bytes(map: Map<CborKey, CborValue>, key: bigint, length: number | undefined, name: string): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) {
    throw new TypeError(`${name} must be ${length === undefined ? "a byte string" : `${length} bytes`}`);
  }
  return value;
}

export function decryptMatterPrivateKey(input: DecryptMatterPrivateKeyInput): Uint8Array {
  assertBytesLength("secret-manager KEK", input.kek, 32);
  const decoded = decodeCanonical(input.encryptedKeyFile);
  assertExactIntegerKeys(decoded, [1n, 2n, 3n, 4n, 5n, 6n]);
  if (decoded.get(1n) !== 1n) throw new Error("unsupported encrypted matter-key version");
  const encodedMatterKeyId = bytes(decoded, 2n, 32, "encrypted matter key ID");
  const encodedKekKeyId = bytes(decoded, 3n, 32, "encrypted matter KEK key ID");
  if (!equalBytes(encodedMatterKeyId, input.matterKeyId) || !equalBytes(encodedKekKeyId, input.kekKeyId)) {
    throw new Error("encrypted matter-key context does not match");
  }
  const plaintext = aes256GcmOpen({
    key: input.kek,
    nonce: bytes(decoded, 4n, 12, "encrypted matter-key nonce"),
    ciphertext: bytes(decoded, 5n, undefined, "encrypted matter-key ciphertext"),
    tag: bytes(decoded, 6n, 16, "encrypted matter-key tag"),
    aad: keyAad(input),
  });
  if (!equalBytes(privateKeyId(plaintext), input.matterKeyId)) {
    throw new Error("decrypted private key does not match matterKeyId");
  }
  return plaintext;
}
