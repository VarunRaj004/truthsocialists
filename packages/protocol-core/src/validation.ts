import { BN254_SCALAR_MODULUS } from "./constants.js";
import { parseUnsignedBigEndian, unsignedBigEndian } from "./bytes.js";

export function assertBytesLength(
  name: string,
  value: Uint8Array,
  expected: number,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== expected) {
    throw new TypeError(`${name} must be exactly ${expected} bytes`);
  }
  return value;
}

export function assertUint(name: string, value: bigint, maximum: bigint): bigint {
  if (value < 0n || value > maximum) {
    throw new RangeError(`${name} must be between 0 and ${maximum}`);
  }
  return value;
}

export function assertNfc(name: string, value: string): string {
  if (value.normalize("NFC") !== value) {
    throw new TypeError(`${name} must be NFC-normalized`);
  }
  return value;
}

export function decodeFieldElement(value: Uint8Array, nonZero = false): bigint {
  assertBytesLength("field element", value, 32);
  const scalar = parseUnsignedBigEndian(value);
  if (scalar >= BN254_SCALAR_MODULUS) {
    throw new RangeError("field element is not canonical for BN254");
  }
  if (nonZero && scalar === 0n) {
    throw new RangeError("field element must be non-zero");
  }
  return scalar;
}

export function encodeFieldElement(value: bigint, nonZero = false): Uint8Array {
  if (value < 0n || value >= BN254_SCALAR_MODULUS) {
    throw new RangeError("field element is outside the BN254 scalar field");
  }
  if (nonZero && value === 0n) {
    throw new RangeError("field element must be non-zero");
  }
  return unsignedBigEndian(value, 32);
}
