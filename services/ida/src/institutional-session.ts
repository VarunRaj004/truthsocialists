import type { IncomingMessage } from "node:http";
import { timingSafeEqual } from "node:crypto";
import {
  assertBytesLength,
  assertExactIntegerKeys,
  decodeCanonical,
  ed25519SpkiFromRaw,
  encodeCanonical,
  integerMap,
  keyIdFromSpkiDer,
  signedObject,
  signingInput,
  verifyEd25519Raw,
  type CborKey,
  type CborValue,
} from "@cyber-cipher/protocol-core";
import type { EnrollmentSessionAuthorizer } from "./http.js";

const TOKEN_PREFIX = "cc1.";
const MAX_TOKEN_LENGTH = 4096;
const MAX_SESSION_LIFETIME_MS = 15n * 60n * 1000n;
const SYNTHETIC_IDENTITY_PATTERN = /^synthetic:[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,190}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface InstitutionalSessionSigner {
  publicKey: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface InstitutionalSessionClaims {
  tenantId: Uint8Array;
  sessionId: Uint8Array;
  syntheticIdentityRef: string;
  issuer: string;
  audience: string;
  issuedAt: bigint;
  expiresAt: bigint;
}

export interface InstitutionalSessionConfig {
  tenantId: Uint8Array;
  issuer: string;
  audience: string;
  publicKey: Uint8Array;
  now?: () => bigint;
}

function text(map: Map<CborKey, CborValue>, key: bigint, name: string): string {
  const value = map.get(key);
  if (typeof value !== "string" || value.length === 0 || value.normalize("NFC") !== value) {
    throw new TypeError(`${name} must be non-empty NFC text`);
  }
  return value;
}

function bytes(
  map: Map<CborKey, CborValue>,
  key: bigint,
  length: number,
  name: string,
): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be bytes`);
  return assertBytesLength(name, value, length);
}

function uint(map: Map<CborKey, CborValue>, key: bigint, name: string): bigint {
  const value = map.get(key);
  if (typeof value !== "bigint" || value < 0n) throw new TypeError(`${name} must be an unsigned integer`);
  return value;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function assertIdentity(value: string): string {
  if (!SYNTHETIC_IDENTITY_PATTERN.test(value) || value.normalize("NFC") !== value) {
    throw new TypeError("synthetic identity reference is invalid");
  }
  return value;
}

function assertContext(name: string, value: string): string {
  if (value.length === 0 || value.length > 128 || value.normalize("NFC") !== value) {
    throw new TypeError(`${name} is invalid`);
  }
  return value;
}

function sessionBody(
  claims: InstitutionalSessionClaims,
  signingKeyId: Uint8Array,
): Map<CborKey, CborValue> {
  assertBytesLength("tenantId", claims.tenantId, 16);
  assertBytesLength("sessionId", claims.sessionId, 16);
  assertIdentity(claims.syntheticIdentityRef);
  assertContext("issuer", claims.issuer);
  assertContext("audience", claims.audience);
  assertBytesLength("session signing key ID", signingKeyId, 32);
  if (claims.issuedAt < 0n || claims.expiresAt <= claims.issuedAt) {
    throw new RangeError("institutional session time window is invalid");
  }
  if (claims.expiresAt - claims.issuedAt > MAX_SESSION_LIFETIME_MS) {
    throw new RangeError("institutional session lifetime exceeds fifteen minutes");
  }
  return integerMap([
    [1, 1n],
    [2, claims.tenantId],
    [3, claims.sessionId],
    [4, claims.syntheticIdentityRef],
    [5, claims.issuer],
    [6, claims.audience],
    [7, claims.issuedAt],
    [8, claims.expiresAt],
    [9, signingKeyId],
  ]);
}

export async function createInstitutionalSessionToken(
  claims: InstitutionalSessionClaims,
  signer: InstitutionalSessionSigner,
): Promise<string> {
  const publicKey = assertBytesLength("institutional session public key", signer.publicKey, 32);
  const keyId = keyIdFromSpkiDer(ed25519SpkiFromRaw(publicKey));
  const body = sessionBody(claims, keyId);
  const bodyCbor = encodeCanonical(body);
  const signature = assertBytesLength(
    "institutional session signature",
    await signer.sign(signingInput("institutional-session", bodyCbor)),
    64,
  );
  if (!verifyEd25519Raw(publicKey, signingInput("institutional-session", bodyCbor), signature)) {
    throw new Error("institutional session signer returned a signature from the wrong key");
  }
  return `${TOKEN_PREFIX}${Buffer.from(encodeCanonical(signedObject(body, signature))).toString("base64url")}`;
}

export function verifyInstitutionalSessionToken(
  token: string,
  config: InstitutionalSessionConfig,
): InstitutionalSessionClaims {
  if (token.length > MAX_TOKEN_LENGTH || !token.startsWith(TOKEN_PREFIX)) {
    throw new TypeError("institutional session token is malformed");
  }
  const encodedText = token.slice(TOKEN_PREFIX.length);
  if (!BASE64URL_PATTERN.test(encodedText)) {
    throw new TypeError("institutional session token is malformed");
  }
  const encoded = new Uint8Array(Buffer.from(encodedText, "base64url"));
  if (Buffer.from(encoded).toString("base64url") !== encodedText) {
    throw new TypeError("institutional session token encoding is not canonical");
  }
  const wrapper = decodeCanonical(encoded);
  assertExactIntegerKeys(wrapper, [1n, 2n]);
  const body = wrapper.get(1n);
  if (body === undefined) throw new TypeError("institutional session body is missing");
  assertExactIntegerKeys(body, [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n]);
  if (uint(body, 1n, "institutional session version") !== 1n) {
    throw new Error("unsupported institutional session version");
  }
  const signature = bytes(wrapper, 2n, 64, "institutional session signature");
  const publicKey = assertBytesLength("institutional session public key", config.publicKey, 32);
  const expectedKeyId = keyIdFromSpkiDer(ed25519SpkiFromRaw(publicKey));
  const encodedKeyId = bytes(body, 9n, 32, "institutional session signing key ID");
  if (!equalBytes(encodedKeyId, expectedKeyId)) {
    throw new Error("institutional session signing key does not match");
  }
  if (
    !verifyEd25519Raw(
      publicKey,
      signingInput("institutional-session", encodeCanonical(body)),
      signature,
    )
  ) {
    throw new Error("institutional session signature is invalid");
  }
  const claims: InstitutionalSessionClaims = {
    tenantId: bytes(body, 2n, 16, "institutional session tenantId"),
    sessionId: bytes(body, 3n, 16, "institutional session ID"),
    syntheticIdentityRef: assertIdentity(text(body, 4n, "synthetic identity reference")),
    issuer: text(body, 5n, "institutional session issuer"),
    audience: text(body, 6n, "institutional session audience"),
    issuedAt: uint(body, 7n, "institutional session issuedAt"),
    expiresAt: uint(body, 8n, "institutional session expiresAt"),
  };
  sessionBody(claims, encodedKeyId);
  if (!equalBytes(claims.tenantId, assertBytesLength("tenantId", config.tenantId, 16))) {
    throw new Error("institutional session belongs to another tenant");
  }
  if (claims.issuer !== assertContext("issuer", config.issuer)) {
    throw new Error("institutional session issuer does not match");
  }
  if (claims.audience !== assertContext("audience", config.audience)) {
    throw new Error("institutional session audience does not match");
  }
  const now = (config.now ?? (() => BigInt(Date.now())))();
  if (now < claims.issuedAt) throw new Error("institutional session is not active yet");
  if (now > claims.expiresAt) throw new Error("institutional session has expired");
  return {
    ...claims,
    tenantId: claims.tenantId.slice(),
    sessionId: claims.sessionId.slice(),
  };
}

export class SignedInstitutionalSessionAuthorizer implements EnrollmentSessionAuthorizer {
  private readonly config: InstitutionalSessionConfig;

  constructor(config: InstitutionalSessionConfig) {
    assertBytesLength("tenantId", config.tenantId, 16);
    assertBytesLength("institutional session public key", config.publicKey, 32);
    assertContext("issuer", config.issuer);
    assertContext("audience", config.audience);
    const trusted = {
      tenantId: config.tenantId.slice(),
      issuer: config.issuer,
      audience: config.audience,
      publicKey: config.publicKey.slice(),
    };
    this.config = config.now === undefined ? trusted : { ...trusted, now: config.now };
  }

  async syntheticIdentityFor(request: IncomingMessage): Promise<string | undefined> {
    const authorization = request.headers.authorization;
    if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) {
      return undefined;
    }
    try {
      return verifyInstitutionalSessionToken(authorization.slice("Bearer ".length), this.config)
        .syntheticIdentityRef;
    } catch {
      return undefined;
    }
  }
}
