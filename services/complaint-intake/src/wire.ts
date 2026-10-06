import {
  assertExactIntegerKeys,
  decodeCanonical,
  decodeFieldElement,
  encodeCanonical,
  encodeFieldElement,
  integerMap,
  type CborKey,
  type CborValue,
} from "@cyber-cipher/protocol-core";
import type { BlindEntitlementToken } from "@cyber-cipher/matter-registry";
import type { Groth16ProofEnvelope } from "@cyber-cipher/zk-circuits";
import type { AcceptedComplaint } from "@cyber-cipher/complaint-store";

const REQUEST_KEYS = Array.from({ length: 20 }, (_, index) => BigInt(index + 1));

export interface ComplaintSubmissionWire {
  complaintId: Uint8Array;
  matterId: Uint8Array;
  matterVersion: number;
  signedLeaseCbor: Uint8Array;
  entitlement: BlindEntitlementToken;
  proof: Groth16ProofEnvelope;
  complaintCommitment: Uint8Array;
  ciphertext: Uint8Array;
  aeadNonce: Uint8Array;
  hpkeEnc: Uint8Array;
  wrappedDek: Uint8Array;
  handlerKeyId: Uint8Array;
}

export function decodeComplaintSubmission(encoded: Uint8Array): ComplaintSubmissionWire {
  const map = mapValue(encoded, REQUEST_KEYS);
  if (uint(map, 1n, "version") !== 1n) throw new Error("unsupported complaint request version");
  const matterVersion = uint(map, 4n, "matterVersion");
  const circuitVersion = uint(map, 12n, "circuitVersion");
  if (matterVersion === 0n || matterVersion > 0xffff_ffffn) throw new RangeError("matterVersion is invalid");
  if (circuitVersion === 0n || circuitVersion > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("circuitVersion is invalid");
  }
  const signalValue = map.get(13n);
  if (!Array.isArray(signalValue) || signalValue.length !== 8 || signalValue.some(
    (value) => !(value instanceof Uint8Array) || value.length !== 32,
  )) {
    throw new TypeError("complaint proof must contain eight canonical field elements");
  }
  const proofBytes = bytesVariable(map, 14n, "proofJson", 64 * 1024);
  let proof: unknown;
  try {
    proof = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(proofBytes));
  } catch {
    throw new TypeError("proofJson must be valid UTF-8 JSON");
  }
  if (typeof proof !== "object" || proof === null || Array.isArray(proof)) {
    throw new TypeError("proofJson must encode an object");
  }
  return {
    complaintId: bytes(map, 2n, 16, "complaintId"),
    matterId: bytes(map, 3n, 16, "matterId"),
    matterVersion: Number(matterVersion),
    signedLeaseCbor: bytesVariable(map, 5n, "signedLeaseCbor", 4096),
    entitlement: {
      entitlement: {
        matterKeyId: bytes(map, 6n, 32, "matterKeyId"),
        serial: bytes(map, 7n, 16, "serial"),
        personCommitment: bytes(map, 8n, 32, "personCommitment"),
      },
      messageRandomizer: bytes(map, 9n, 32, "messageRandomizer"),
      signature: bytes(map, 10n, 384, "entitlementSignature"),
    },
    proof: {
      artifactId: bytes(map, 11n, 32, "artifactId"),
      circuitName: "complaint",
      circuitVersion: Number(circuitVersion),
      publicSignals: (signalValue as Uint8Array[]).map((value) => decodeFieldElement(value).toString()),
      proof,
    },
    complaintCommitment: bytes(map, 15n, 32, "complaintCommitment"),
    ciphertext: bytesVariable(map, 16n, "ciphertext", 104_857_616),
    aeadNonce: bytes(map, 17n, 12, "aeadNonce"),
    hpkeEnc: bytes(map, 18n, 32, "hpkeEnc"),
    wrappedDek: bytes(map, 19n, 48, "wrappedDek"),
    handlerKeyId: bytes(map, 20n, 32, "handlerKeyId"),
  };
}

export function encodeComplaintSubmission(value: ComplaintSubmissionWire): Uint8Array {
  const proofJson = new TextEncoder().encode(JSON.stringify(value.proof.proof));
  return encodeCanonical(integerMap([
    [1, 1n],
    [2, value.complaintId],
    [3, value.matterId],
    [4, BigInt(value.matterVersion)],
    [5, value.signedLeaseCbor],
    [6, value.entitlement.entitlement.matterKeyId],
    [7, value.entitlement.entitlement.serial],
    [8, value.entitlement.entitlement.personCommitment],
    [9, value.entitlement.messageRandomizer],
    [10, value.entitlement.signature],
    [11, value.proof.artifactId],
    [12, BigInt(value.proof.circuitVersion)],
    [13, value.proof.publicSignals.map((signal) => encodeFieldElement(canonicalSignal(signal)))],
    [14, proofJson],
    [15, value.complaintCommitment],
    [16, value.ciphertext],
    [17, value.aeadNonce],
    [18, value.hpkeEnc],
    [19, value.wrappedDek],
    [20, value.handlerKeyId],
  ]));
}

export function encodeProofSessionResponse(value: {
  challengeId: Uint8Array;
  signedLeaseCbor: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
}): Uint8Array {
  return encodeCanonical(integerMap([
    [1, 1n], [2, value.challengeId], [3, value.signedLeaseCbor],
    [4, value.issuedAt], [5, value.expiresAt],
  ]));
}

export function encodeComplaintResponse(value: AcceptedComplaint): Uint8Array {
  return encodeCanonical(integerMap([
    [1, 1n],
    [2, uuidBytes(value.complaintId)],
    [3, value.receiptId],
    [4, value.signedReceiptCbor],
    [5, value.logEntryHash],
    [6, BigInt(value.acceptedAt.getTime())],
  ]));
}

export function encodeErrorResponse(code: string): Uint8Array {
  return encodeCanonical(integerMap([[1, 1n], [2, code]]));
}

function mapValue(encoded: Uint8Array, keys: readonly bigint[]): Map<CborKey, CborValue> {
  const value = decodeCanonical(encoded);
  assertExactIntegerKeys(value, keys);
  return value;
}

function bytes(map: Map<CborKey, CborValue>, key: bigint, length: number, name: string): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.length !== length) throw new TypeError(`${name} must be ${length} bytes`);
  return value;
}

function bytesVariable(map: Map<CborKey, CborValue>, key: bigint, name: string, maximum: number): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.length === 0 || value.length > maximum) {
    throw new TypeError(`${name} has an invalid size`);
  }
  return value;
}

function uint(map: Map<CborKey, CborValue>, key: bigint, name: string): bigint {
  const value = map.get(key);
  if (typeof value !== "bigint" || value < 0n) throw new TypeError(`${name} must be unsigned`);
  return value;
}

function canonicalSignal(value: string): bigint {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) throw new TypeError("public signal is not canonical decimal");
  return BigInt(value);
}

export function uuidString(value: Uint8Array): string {
  if (value.length !== 16) throw new TypeError("UUID must be 16 bytes");
  const hex = Buffer.from(value).toString("hex");
  const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid)) {
    throw new TypeError("UUID must be version 4");
  }
  return uuid;
}

function uuidBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value.replaceAll("-", ""), "hex"));
}
