export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function bytesToHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

export function hexToBytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) {
    throw new TypeError("hex input must contain complete hexadecimal bytes");
  }
  return new Uint8Array(Buffer.from(value, "hex"));
}

export function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index += 1) {
    const difference = left[index]! - right[index]!;
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && compareBytes(left, right) === 0;
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function unsignedBigEndian(value: bigint, length: number): Uint8Array {
  if (value < 0n) throw new RangeError("value must be unsigned");
  const hex = value.toString(16).padStart(length * 2, "0");
  if (hex.length > length * 2) throw new RangeError(`value does not fit in ${length} bytes`);
  return hexToBytes(hex);
}

export function parseUnsignedBigEndian(value: Uint8Array): bigint {
  if (value.length === 0) return 0n;
  return BigInt(`0x${bytesToHex(value)}`);
}

export function base64UrlNoPadding(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}
