import { equalBytes, logLeafHash, logNodeHash, sha256 } from "@cyber-cipher/protocol-core";

export const EMPTY_LOG_ROOT = sha256(new Uint8Array());

function splitPoint(size: number): number {
  if (!Number.isSafeInteger(size) || size < 2) throw new RangeError("tree split requires at least two leaves");
  let value = 1;
  while (value * 2 < size) value *= 2;
  return value;
}

function rootRange(leaves: readonly Uint8Array[], start: number, size: number): Uint8Array {
  if (size === 0) return EMPTY_LOG_ROOT.slice();
  if (size === 1) return leaves[start]!.slice();
  const split = splitPoint(size);
  return logNodeHash(rootRange(leaves, start, split), rootRange(leaves, start + split, size - split));
}

export function merkleRoot(leafHashes: readonly Uint8Array[]): Uint8Array {
  for (const hash of leafHashes) if (hash.length !== 32) throw new TypeError("leaf hash must be 32 bytes");
  return rootRange(leafHashes, 0, leafHashes.length);
}

export function inclusionProof(leafHashes: readonly Uint8Array[], leafIndex: number, treeSize = leafHashes.length): Uint8Array[] {
  if (!Number.isSafeInteger(treeSize) || treeSize < 1 || treeSize > leafHashes.length) throw new RangeError("invalid tree size");
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) throw new RangeError("invalid leaf index");
  const build = (start: number, size: number, index: number): Uint8Array[] => {
    if (size === 1) return [];
    const split = splitPoint(size);
    return index < split
      ? [...build(start, split, index), rootRange(leafHashes, start + split, size - split)]
      : [...build(start + split, size - split, index - split), rootRange(leafHashes, start, split)];
  };
  return build(0, treeSize, leafIndex);
}

export function verifyInclusion(
  leafHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  proof: readonly Uint8Array[],
  expectedRoot: Uint8Array,
): boolean {
  if (leafHash.length !== 32 || expectedRoot.length !== 32 || leafIndex < 0 || leafIndex >= treeSize) return false;
  let index = leafIndex;
  let last = treeSize - 1;
  let root: Uint8Array<ArrayBufferLike> = leafHash.slice();
  for (const sibling of proof) {
    if (sibling.length !== 32 || last === 0) return false;
    if ((index & 1) === 1 || index === last) {
      root = logNodeHash(sibling, root);
      while ((index & 1) === 0 && index !== 0) {
        index >>= 1;
        last >>= 1;
      }
    } else {
      root = logNodeHash(root, sibling);
    }
    index >>= 1;
    last >>= 1;
  }
  return last === 0 && equalBytes(root, expectedRoot);
}

export function consistencyProof(leafHashes: readonly Uint8Array[], firstSize: number, secondSize = leafHashes.length): Uint8Array[] {
  if (!Number.isSafeInteger(firstSize) || !Number.isSafeInteger(secondSize) || firstSize < 1 || firstSize > secondSize || secondSize > leafHashes.length) {
    throw new RangeError("invalid consistency range");
  }
  const subproof = (oldSize: number, start: number, size: number, complete: boolean): Uint8Array[] => {
    if (oldSize === size) return complete ? [] : [rootRange(leafHashes, start, size)];
    const split = splitPoint(size);
    return oldSize <= split
      ? [...subproof(oldSize, start, split, complete), rootRange(leafHashes, start + split, size - split)]
      : [...subproof(oldSize - split, start + split, size - split, false), rootRange(leafHashes, start, split)];
  };
  return firstSize === secondSize ? [] : subproof(firstSize, 0, secondSize, true);
}

export function verifyConsistency(
  firstSize: number,
  secondSize: number,
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
  proof: readonly Uint8Array[],
): boolean {
  if (firstSize < 1 || firstSize > secondSize || firstRoot.length !== 32 || secondRoot.length !== 32) return false;
  if (firstSize === secondSize) return proof.length === 0 && equalBytes(firstRoot, secondRoot);
  let oldIndex = firstSize - 1;
  let newIndex = secondSize - 1;
  while ((oldIndex & 1) === 1) { oldIndex >>= 1; newIndex >>= 1; }
  let offset = 0;
  let oldHash: Uint8Array<ArrayBufferLike>;
  let newHash: Uint8Array<ArrayBufferLike>;
  if (oldIndex === 0) {
    oldHash = firstRoot.slice();
    newHash = firstRoot.slice();
  } else {
    const seed = proof[offset++];
    if (seed === undefined || seed.length !== 32) return false;
    oldHash = seed.slice();
    newHash = seed.slice();
  }
  for (; offset < proof.length; offset += 1) {
    const sibling = proof[offset]!;
    if (sibling.length !== 32 || newIndex === 0) return false;
    if ((oldIndex & 1) === 1 || oldIndex === newIndex) {
      oldHash = logNodeHash(sibling, oldHash);
      newHash = logNodeHash(sibling, newHash);
      while ((oldIndex & 1) === 0 && oldIndex !== 0) { oldIndex >>= 1; newIndex >>= 1; }
    } else {
      newHash = logNodeHash(newHash, sibling);
    }
    oldIndex >>= 1;
    newIndex >>= 1;
  }
  return newIndex === 0 && equalBytes(oldHash, firstRoot) && equalBytes(newHash, secondRoot);
}

export class TransparencyTree {
  readonly #entries: Uint8Array[] = [];
  readonly #leaves: Uint8Array[] = [];

  append(canonicalEntryCbor: Uint8Array): number {
    if (canonicalEntryCbor.length === 0) throw new TypeError("log entry must not be empty");
    const index = this.#entries.length;
    this.#entries.push(canonicalEntryCbor.slice());
    this.#leaves.push(logLeafHash(canonicalEntryCbor));
    return index;
  }

  get size(): number { return this.#leaves.length; }
  root(size = this.size): Uint8Array { return merkleRoot(this.#leaves.slice(0, size)); }
  entry(index: number): Uint8Array { const value = this.#entries[index]; if (!value) throw new RangeError("unknown leaf"); return value.slice(); }
  leafHash(index: number): Uint8Array { const value = this.#leaves[index]; if (!value) throw new RangeError("unknown leaf"); return value.slice(); }
  entries(start = 0): Uint8Array[] { return this.#entries.slice(start).map((value) => value.slice()); }
  inclusion(index: number, size = this.size): Uint8Array[] { return inclusionProof(this.#leaves, index, size); }
  consistency(first: number, second = this.size): Uint8Array[] { return consistencyProof(this.#leaves, first, second); }
}
