import {
  BN254_SCALAR_MODULUS,
  decodeFieldElement,
  encodeFieldElement,
  poseidonDomain,
} from "@cyber-cipher/protocol-core";
import { poseidon2, poseidon3 } from "poseidon-lite";

function assertScalar(name: string, value: bigint, nonZero = false): bigint {
  if (value < 0n || value >= BN254_SCALAR_MODULUS) {
    throw new RangeError(`${name} is outside the BN254 scalar field`);
  }
  if (nonZero && value === 0n) throw new RangeError(`${name} must be non-zero`);
  return value;
}

export function personHash(personSecret: bigint): bigint {
  return poseidon2([poseidonDomain("person"), assertScalar("person secret", personSecret, true)]);
}

export function deviceHash(deviceSecret: bigint): bigint {
  return poseidon2([poseidonDomain("device"), assertScalar("device secret", deviceSecret, true)]);
}

export function memberLeaf(personAnchor: bigint, activeDeviceHash: bigint): bigint {
  return poseidon3([
    poseidonDomain("member-leaf"),
    assertScalar("person anchor", personAnchor),
    assertScalar("device hash", activeDeviceHash),
  ]);
}

export function emptyLeaf(): bigint {
  return poseidon2([poseidonDomain("empty-leaf"), 0n]);
}

export function merkleNode(left: bigint, right: bigint): bigint {
  return poseidon3([
    poseidonDomain("merkle-node"),
    assertScalar("left child", left),
    assertScalar("right child", right),
  ]);
}

export function scalarFromBytes(name: string, value: Uint8Array): bigint {
  try {
    return decodeFieldElement(value);
  } catch (error) {
    throw new TypeError(`${name} must be a canonical BN254 field element`, { cause: error });
  }
}

export function scalarToBytes(value: bigint): Uint8Array {
  return encodeFieldElement(assertScalar("field value", value));
}
