import {
  MAX_CBOR_COLLECTION_ITEMS,
  MAX_CBOR_DEPTH,
  MAX_CBOR_UINT,
} from "./constants.js";
import { bytesToHex, compareBytes, concatBytes, utf8 } from "./bytes.js";

export type CborKey = bigint | number | string;
export type CborValue =
  | bigint
  | number
  | Uint8Array
  | string
  | readonly CborValue[]
  | ReadonlyMap<CborKey, CborValue>;

function integerValue(value: bigint | number): bigint {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("CBOR numbers must be safe integers; use bigint otherwise");
    }
    return BigInt(value);
  }
  return value;
}

function encodeHead(major: number, argument: bigint): Uint8Array {
  if (argument < 0n || argument > MAX_CBOR_UINT) {
    throw new RangeError("CBOR argument is outside the uint64 range");
  }
  if (argument < 24n) return Uint8Array.of((major << 5) | Number(argument));
  if (argument <= 0xffn) return Uint8Array.of((major << 5) | 24, Number(argument));
  if (argument <= 0xffffn) {
    return Uint8Array.of(
      (major << 5) | 25,
      Number(argument >> 8n),
      Number(argument & 0xffn),
    );
  }
  if (argument <= 0xffff_ffffn) {
    const bytes = new Uint8Array(5);
    bytes[0] = (major << 5) | 26;
    new DataView(bytes.buffer).setUint32(1, Number(argument), false);
    return bytes;
  }
  const bytes = new Uint8Array(9);
  bytes[0] = (major << 5) | 27;
  new DataView(bytes.buffer).setBigUint64(1, argument, false);
  return bytes;
}

function encodeValue(value: CborValue, depth: number): Uint8Array {
  if (depth > MAX_CBOR_DEPTH) throw new RangeError("CBOR nesting is too deep");
  if (typeof value === "number" || typeof value === "bigint") {
    const integer = integerValue(value);
    return integer >= 0n
      ? encodeHead(0, integer)
      : encodeHead(1, -1n - integer);
  }
  if (value instanceof Uint8Array) {
    return concatBytes(encodeHead(2, BigInt(value.length)), value);
  }
  if (typeof value === "string") {
    const normalized = value.normalize("NFC");
    const bytes = utf8(normalized);
    return concatBytes(encodeHead(3, BigInt(bytes.length)), bytes);
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_CBOR_COLLECTION_ITEMS) {
      throw new RangeError("CBOR array contains too many items");
    }
    return concatBytes(
      encodeHead(4, BigInt(value.length)),
      ...value.map((item) => encodeValue(item, depth + 1)),
    );
  }
  if (value instanceof Map) {
    if (value.size > MAX_CBOR_COLLECTION_ITEMS) {
      throw new RangeError("CBOR map contains too many entries");
    }
    const entries = [...value.entries()].map(([key, item]) => {
      if (typeof key !== "string" && typeof key !== "number" && typeof key !== "bigint") {
        throw new TypeError("Cyber Cipher CBOR map keys must be integers or text");
      }
      if ((typeof key === "number" || typeof key === "bigint") && integerValue(key) < 0n) {
        throw new TypeError("Cyber Cipher CBOR integer map keys must be unsigned");
      }
      return {
        key: encodeValue(key, depth + 1),
        value: encodeValue(item, depth + 1),
      };
    });
    entries.sort((left, right) =>
      left.key.length === right.key.length
        ? compareBytes(left.key, right.key)
        : left.key.length - right.key.length,
    );
    for (let index = 1; index < entries.length; index += 1) {
      const previous = entries[index - 1]!;
      const current = entries[index]!;
      if (compareBytes(previous.key, current.key) === 0) {
        throw new TypeError("CBOR map contains keys with duplicate encodings");
      }
    }
    return concatBytes(
      encodeHead(5, BigInt(entries.length)),
      ...entries.flatMap((entry) => [entry.key, entry.value]),
    );
  }
  throw new TypeError("unsupported value in Cyber Cipher deterministic CBOR profile");
}

export function encodeCanonical(value: CborValue): Uint8Array {
  return encodeValue(value, 0);
}

class Decoder {
  private offset = 0;

  constructor(private readonly input: Uint8Array) {}

  decode(): CborValue {
    const value = this.readValue(0);
    if (this.offset !== this.input.length) {
      throw new TypeError("trailing bytes after canonical CBOR object");
    }
    return value;
  }

  private readByte(): number {
    const value = this.input[this.offset];
    if (value === undefined) throw new TypeError("truncated CBOR input");
    this.offset += 1;
    return value;
  }

  private readBytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.input.length) {
      throw new TypeError("truncated or oversized CBOR item");
    }
    const value = this.input.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  private readArgument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    if (additional === 24) {
      const value = BigInt(this.readByte());
      if (value < 24n) throw new TypeError("non-minimal CBOR integer/length encoding");
      return value;
    }
    if (additional === 25) {
      const bytes = this.readBytes(2);
      const value = BigInt(new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0, false));
      if (value <= 0xffn) throw new TypeError("non-minimal CBOR integer/length encoding");
      return value;
    }
    if (additional === 26) {
      const bytes = this.readBytes(4);
      const value = BigInt(new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false));
      if (value <= 0xffffn) throw new TypeError("non-minimal CBOR integer/length encoding");
      return value;
    }
    if (additional === 27) {
      const bytes = this.readBytes(8);
      const value = new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, false);
      if (value <= 0xffff_ffffn) {
        throw new TypeError("non-minimal CBOR integer/length encoding");
      }
      return value;
    }
    throw new TypeError("indefinite or reserved CBOR encoding is forbidden");
  }

  private asCollectionLength(value: bigint): number {
    if (value > BigInt(MAX_CBOR_COLLECTION_ITEMS)) {
      throw new RangeError("CBOR collection exceeds the configured item limit");
    }
    return Number(value);
  }

  private asByteLength(value: bigint): number {
    if (value > BigInt(this.input.length)) {
      throw new TypeError("CBOR byte or text string exceeds the available input");
    }
    return Number(value);
  }

  private readValue(depth: number): CborValue {
    if (depth > MAX_CBOR_DEPTH) throw new RangeError("CBOR nesting is too deep");
    const initial = this.readByte();
    const major = initial >> 5;
    const argument = this.readArgument(initial & 0x1f);
    if (major === 0) return argument;
    if (major === 1) return -1n - argument;
    if (major === 2) return this.readBytes(this.asByteLength(argument));
    if (major === 3) {
      const raw = this.readBytes(this.asByteLength(argument));
      let value: string;
      try {
        value = new TextDecoder("utf-8", { fatal: true }).decode(raw);
      } catch {
        throw new TypeError("CBOR text is not valid UTF-8");
      }
      if (value.normalize("NFC") !== value) {
        throw new TypeError("CBOR text is not NFC-normalized");
      }
      return value;
    }
    if (major === 4) {
      const length = this.asCollectionLength(argument);
      const values: CborValue[] = [];
      for (let index = 0; index < length; index += 1) {
        values.push(this.readValue(depth + 1));
      }
      return values;
    }
    if (major === 5) {
      const length = this.asCollectionLength(argument);
      const values = new Map<CborKey, CborValue>();
      const seen = new Set<string>();
      let previousKey: Uint8Array | undefined;
      for (let index = 0; index < length; index += 1) {
        const keyStart = this.offset;
        const key = this.readValue(depth + 1);
        const keyBytes = this.input.slice(keyStart, this.offset);
        if (typeof key !== "bigint" && typeof key !== "string") {
          throw new TypeError("Cyber Cipher CBOR map keys must be integers or text");
        }
        if (typeof key === "bigint" && key < 0n) {
          throw new TypeError("Cyber Cipher CBOR integer map keys must be unsigned");
        }
        if (
          previousKey !== undefined &&
          (keyBytes.length < previousKey.length ||
            (keyBytes.length === previousKey.length && compareBytes(previousKey, keyBytes) >= 0))
        ) {
          throw new TypeError("CBOR map keys are not in deterministic order");
        }
        const encodedKey = bytesToHex(keyBytes);
        if (seen.has(encodedKey)) throw new TypeError("duplicate CBOR map key");
        seen.add(encodedKey);
        previousKey = keyBytes;
        values.set(key, this.readValue(depth + 1));
      }
      return values;
    }
    throw new TypeError("CBOR tags, floats, booleans, null, and simple values are forbidden");
  }
}

export function decodeCanonical(input: Uint8Array): CborValue {
  return new Decoder(input).decode();
}

export function integerMap(entries: readonly (readonly [number | bigint, CborValue])[]): Map<CborKey, CborValue> {
  return new Map(entries);
}

export function assertExactIntegerKeys(
  value: CborValue,
  expected: readonly bigint[],
): asserts value is Map<CborKey, CborValue> {
  if (!(value instanceof Map)) throw new TypeError("expected a CBOR map");
  const actual = [...value.keys()];
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => typeof key !== "bigint" || key !== expected[index])
  ) {
    throw new TypeError("CBOR map contains missing, unknown, or incorrectly ordered keys");
  }
}
